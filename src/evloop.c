/* Цикл событий коннектора — см. evloop.h. */
#define _GNU_SOURCE
#include "evloop.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

struct fdent {
    int fd;
    ev_fd_cb cb;
    void *arg;
    struct fdent *next;
};

struct timer {
    uint64_t id;
    long long at;
    ev_timer_cb cb;
    void *arg;
};

struct posted {
    ev_work_fn fn;
    void *arg;
    struct posted *next;
};

struct ev {
    int ep, efd, stop;
    struct fdent **tab;          /* хеш по fd */
    size_t tabn;
    struct timer *tm;            /* куча по at */
    size_t tmn, tmcap;
    uint64_t next_id;
    pthread_mutex_t mu;
    struct posted *head, *tail;  /* под mu */
};

long long ev_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void drain_posted(struct ev *ev);

static void efd_cb(struct ev *ev, int fd, uint32_t events, void *arg) {
    (void)events;
    (void)arg;
    uint64_t v;
    while (read(fd, &v, sizeof v) > 0) {}
    drain_posted(ev);
}

struct ev *ev_new(void) {
    struct ev *ev = calloc(1, sizeof *ev);
    if (!ev) return NULL;
    ev->ep = epoll_create1(EPOLL_CLOEXEC);
    ev->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ev->tabn = 256;
    ev->tab = calloc(ev->tabn, sizeof *ev->tab);
    pthread_mutex_init(&ev->mu, NULL);
    if (ev->ep < 0 || ev->efd < 0 || !ev->tab || ev_add(ev, ev->efd, EPOLLIN, efd_cb, NULL)) {
        ev_free(ev);
        return NULL;
    }
    return ev;
}

void ev_free(struct ev *ev) {
    if (!ev) return;
    for (size_t i = 0; ev->tab && i < ev->tabn; i++)
        for (struct fdent *e = ev->tab[i], *n; e; e = n) { n = e->next; free(e); }
    free(ev->tab);
    free(ev->tm);
    if (ev->ep >= 0) close(ev->ep);
    if (ev->efd >= 0) close(ev->efd);
    pthread_mutex_destroy(&ev->mu);
    free(ev);
}

static struct fdent *find(struct ev *ev, int fd) {
    for (struct fdent *e = ev->tab[(size_t)fd % ev->tabn]; e; e = e->next)
        if (e->fd == fd) return e;
    return NULL;
}

int ev_add(struct ev *ev, int fd, uint32_t events, ev_fd_cb cb, void *arg) {
    struct fdent *e = find(ev, fd);
    int op = e ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (!e) {
        e = calloc(1, sizeof *e);
        if (!e) return -1;
        e->fd = fd;
        e->next = ev->tab[(size_t)fd % ev->tabn];
        ev->tab[(size_t)fd % ev->tabn] = e;
    }
    e->cb = cb;
    e->arg = arg;
    struct epoll_event ee = { .events = events, .data.fd = fd };
    return epoll_ctl(ev->ep, op, fd, &ee);
}

int ev_mod(struct ev *ev, int fd, uint32_t events) {
    struct epoll_event ee = { .events = events, .data.fd = fd };
    return epoll_ctl(ev->ep, EPOLL_CTL_MOD, fd, &ee);
}

void ev_del(struct ev *ev, int fd) {
    struct fdent **pp = &ev->tab[(size_t)fd % ev->tabn];
    for (; *pp; pp = &(*pp)->next)
        if ((*pp)->fd == fd) {
            struct fdent *e = *pp;
            *pp = e->next;
            free(e);
            break;
        }
    epoll_ctl(ev->ep, EPOLL_CTL_DEL, fd, NULL);
}

/* ---- таймеры: двоичная куча по времени срабатывания ------------------------------------ */

static void tm_swap(struct ev *ev, size_t a, size_t b) {
    struct timer t = ev->tm[a];
    ev->tm[a] = ev->tm[b];
    ev->tm[b] = t;
}

static void tm_up(struct ev *ev, size_t i) {
    while (i && ev->tm[(i - 1) / 2].at > ev->tm[i].at) {
        tm_swap(ev, i, (i - 1) / 2);
        i = (i - 1) / 2;
    }
}

static void tm_down(struct ev *ev, size_t i) {
    for (;;) {
        size_t l = 2 * i + 1, r = l + 1, m = i;
        if (l < ev->tmn && ev->tm[l].at < ev->tm[m].at) m = l;
        if (r < ev->tmn && ev->tm[r].at < ev->tm[m].at) m = r;
        if (m == i) return;
        tm_swap(ev, i, m);
        i = m;
    }
}

uint64_t ev_timer(struct ev *ev, long ms, ev_timer_cb cb, void *arg) {
    if (ev->tmn == ev->tmcap) {
        size_t nc = ev->tmcap ? ev->tmcap * 2 : 32;
        struct timer *nt = realloc(ev->tm, nc * sizeof *nt);
        if (!nt) return 0;
        ev->tm = nt;
        ev->tmcap = nc;
    }
    uint64_t id = ++ev->next_id;
    ev->tm[ev->tmn] = (struct timer){ id, ev_now_ms() + (ms < 0 ? 0 : ms), cb, arg };
    tm_up(ev, ev->tmn++);
    return id;
}

void ev_timer_cancel(struct ev *ev, uint64_t id) {
    for (size_t i = 0; i < ev->tmn; i++)
        if (ev->tm[i].id == id) {
            ev->tm[i] = ev->tm[--ev->tmn];
            if (i < ev->tmn) { tm_down(ev, i); tm_up(ev, i); }
            return;
        }
}

/* ---- работа в потоках ------------------------------------------------------------------- */

struct job {
    struct ev *ev;
    ev_work_fn work, done;
    void *arg;
};

static void job_done(void *p) {
    struct job *j = p;
    if (j->done) j->done(j->arg);
    free(j);
}

static void *job_thread(void *p) {
    struct job *j = p;
    j->work(j->arg);
    if (ev_post(j->ev, job_done, j)) {
        /* Цикл уже не принимает (останов): результат некому отдать. */
        free(j);
    }
    return NULL;
}

int ev_spawn(struct ev *ev, ev_work_fn work, ev_work_fn done, void *arg) {
    struct job *j = malloc(sizeof *j);
    if (!j) return -1;
    *j = (struct job){ ev, work, done, arg };
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    /* Стек — 256 КиБ, а не умолчание musl (128 КиБ) и не glibc (8 МиБ): рукопожатие TLS и
     * разбор ответа держат на стеке буферы записи по 16 КиБ и цепочку сертификатов. */
    pthread_attr_setstacksize(&at, 256 * 1024);
    pthread_t th;
    int rc = pthread_create(&th, &at, job_thread, j);
    pthread_attr_destroy(&at);
    if (rc) { free(j); return -1; }
    return 0;
}

int ev_post(struct ev *ev, ev_work_fn fn, void *arg) {
    struct posted *p = malloc(sizeof *p);
    if (!p) return -1;
    p->fn = fn;
    p->arg = arg;
    p->next = NULL;
    pthread_mutex_lock(&ev->mu);
    if (ev->tail) ev->tail->next = p;
    else ev->head = p;
    ev->tail = p;
    pthread_mutex_unlock(&ev->mu);
    uint64_t one = 1;
    if (write(ev->efd, &one, sizeof one) < 0 && errno != EAGAIN) return 0;
    return 0;
}

static void drain_posted(struct ev *ev) {
    pthread_mutex_lock(&ev->mu);
    struct posted *p = ev->head;
    ev->head = ev->tail = NULL;
    pthread_mutex_unlock(&ev->mu);
    while (p) {
        struct posted *n = p->next;
        p->fn(p->arg);
        free(p);
        p = n;
    }
}

void ev_stop(struct ev *ev) { ev->stop = 1; }

int ev_run(struct ev *ev) {
    struct epoll_event evs[64];
    while (!ev->stop) {
        long long now = ev_now_ms();
        while (ev->tmn && ev->tm[0].at <= now) {
            struct timer t = ev->tm[0];
            ev->tm[0] = ev->tm[--ev->tmn];
            if (ev->tmn) tm_down(ev, 0);
            t.cb(ev, t.arg);
            if (ev->stop) return 0;
            now = ev_now_ms();
        }
        int timeout = -1;
        if (ev->tmn) {
            long long d = ev->tm[0].at - now;
            timeout = d < 0 ? 0 : d > 60000 ? 60000 : (int)d;
        }
        int n = epoll_wait(ev->ep, evs, 64, timeout);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        for (int i = 0; i < n && !ev->stop; i++) {
            struct fdent *e = find(ev, evs[i].data.fd);
            if (e) e->cb(ev, e->fd, evs[i].events, e->arg);
        }
    }
    return 0;
}
