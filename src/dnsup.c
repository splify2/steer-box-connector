/* Серверы DNS коннектора — см. dnsup.h. */
#define _GNU_SOURCE
#include "dnsup.h"
#include "dnsmsg.h"
#include "bconn.h"
#include "box.h"
#include "h2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

enum uptype { UP_UDP, UP_TCP, UP_TLS, UP_HTTPS };

struct ujob {
    uint8_t *q;
    size_t qn;
    /* асинхронный (из цикла) — cb; блокирующий — ждущий на cond */
    dnsup_cb cb;
    void *arg;
    int blocking;
    pthread_cond_t cond;
    int done;
    uint8_t *resp;
    long resp_n;
    char err[160];
    long long t0;               /* когда встал в очередь (мс, монотонные) */
    struct ujob *next;
};

struct dnsup {
    struct ev *ev;
    char tag[128];
    enum uptype type;
    char host[256], path[512];
    uint16_t port;
    struct egress eg;
    struct dnsup *resolver;
    int insecure;
    char sni[256];
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct ujob *head, *tail;
    int workers, idle;
    /* Потоки, которые сейчас открывают соединение (tcp, tls, https), вместе с заведёнными, но
     * ещё не открывшими. Новых не больше, чем соединённых плюс один: число соединений под пачкой
     * вопросов растёт вдвое за рукопожатие (1, 2, 4…), а вопрос тем временем ждёт в очереди
     * первого освободившегося. Иначе пачка на холодном старте (dnsmasq после перезапуска,
     * страница с сотней имён) открывала столько же рукопожатий TLS разом — на роутере это
     * секунды, и часть вопросов не укладывалась в срок. */
    int connecting;
    int refs;
    int dying;
    /* Адреса имени сервера — общий кэш потоков (под mu). */
    struct sockaddr_storage addrs[4];
    socklen_t lens[4];
    int naddr;
    long long addr_until;
};

const char *dnsup_tag(const struct dnsup *u) { return u->tag; }

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void *worker(void *arg);

/* Под mu: завести поток, если вопросы ждут, а свободного нет. У сервера с соединением — пока
 * открывающих не больше, чем соединённых (см. connecting). */
static void maybe_spawn_locked(struct dnsup *u) {
    if (!u->head || u->idle || u->dying) return;
    int conn = u->type != UP_UDP;
    if (conn && u->connecting > u->workers - u->connecting) return;
    u->workers++;
    u->refs++;
    if (conn) u->connecting++;       /* снимет сам поток, когда откроет соединение или выйдет */
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, 256 * 1024);
    pthread_t th;
    if (pthread_create(&th, &at, worker, u)) {
        u->workers--;
        u->refs--;
        if (conn) u->connecting--;
    }
    pthread_attr_destroy(&at);
}

struct dnsup *dnsup_new(struct ev *ev, const struct jval *cfg, const struct egress *eg, struct dnsup *resolver) {
    const char *type = jgets(cfg, "type");
    const char *server = jgets(cfg, "server");
    if (!type || !server) return NULL;
    struct dnsup *u = calloc(1, sizeof *u);
    if (!u) return NULL;
    u->ev = ev;
    snprintf(u->tag, sizeof u->tag, "%s", jgets(cfg, "tag") ? jgets(cfg, "tag") : server);
    if (!strcmp(type, "udp")) u->type = UP_UDP, u->port = 53;
    else if (!strcmp(type, "tcp")) u->type = UP_TCP, u->port = 53;
    else if (!strcmp(type, "tls")) u->type = UP_TLS, u->port = 853;
    else if (!strcmp(type, "https")) u->type = UP_HTTPS, u->port = 443;
    else { free(u); return NULL; }
    long p = jgeti(cfg, "server_port", 0);
    if (p > 0) u->port = (uint16_t)p;
    snprintf(u->host, sizeof u->host, "%s", server);
    const char *path = jgets(cfg, "path");
    snprintf(u->path, sizeof u->path, "%s", path && *path ? path : "/dns-query");
    if (eg) u->eg = *eg;
    const struct jval *tls = jget(cfg, "tls");
    u->insecure = jgetb(tls, "insecure", 0);
    const char *sni = jgets(tls, "server_name");
    snprintf(u->sni, sizeof u->sni, "%s", sni ? sni : server);
    u->resolver = resolver;
    if (resolver) dnsup_ref(resolver);
    pthread_mutex_init(&u->mu, NULL);
    pthread_cond_init(&u->cv, NULL);
    u->refs = 1;
    struct sockaddr_storage a;
    socklen_t l;
    if (!net_parse_ip(server, u->port, &a, &l)) {
        u->addrs[0] = a;
        u->lens[0] = l;
        u->naddr = 1;
        u->addr_until = -1;          /* литерал — навсегда */
    }
    return u;
}

void dnsup_ref(struct dnsup *u) {
    pthread_mutex_lock(&u->mu);
    u->refs++;
    pthread_mutex_unlock(&u->mu);
}

void dnsup_unref(struct dnsup *u) {
    if (!u) return;
    pthread_mutex_lock(&u->mu);
    int left = --u->refs;
    if (!left) {
        u->dying = 1;
        pthread_cond_broadcast(&u->cv);
    }
    int workers = u->workers;
    pthread_mutex_unlock(&u->mu);
    if (left) return;
    /* Рабочие потоки держат ссылку сами (см. worker), поэтому до нуля доходим только когда их
     * нет. */
    (void)workers;
    if (u->resolver) dnsup_unref(u->resolver);
    pthread_mutex_destroy(&u->mu);
    pthread_cond_destroy(&u->cv);
    free(u);
}

/* ---- адреса имени сервера ----------------------------------------------------------------- */

static long udp_exchange(const struct sockaddr_storage *a, socklen_t l, const struct egress *eg,
                         const uint8_t *q, size_t qn, uint8_t *resp, size_t cap, int timeout_ms);

static int server_addrs(struct dnsup *u, struct sockaddr_storage *out, socklen_t *lens, int max, char *err, size_t errn) {
    pthread_mutex_lock(&u->mu);
    long long now = (long long)time(NULL);
    if (u->naddr && (u->addr_until < 0 || now < u->addr_until)) {
        int n = u->naddr < max ? u->naddr : max;
        memcpy(out, u->addrs, (size_t)n * sizeof *out);
        memcpy(lens, u->lens, (size_t)n * sizeof *lens);
        pthread_mutex_unlock(&u->mu);
        return n;
    }
    pthread_mutex_unlock(&u->mu);
    if (!u->resolver) {
        /* Имя без domain_resolver: sing-box взял бы route.default_domain_resolver; перевод
         * сюда его уже подставил (dns.c), а если нет и его — системный резолвер. */
        int n = net_resolve(u->host, u->port, out, lens, max);
        if (n <= 0) snprintf(err, errn, "%s: имя %s не разрешилось", u->tag, u->host);
        return n;
    }
    int n = 0;
    long min_ttl = 600;
    for (int fam = 0; fam < 2 && n < max; fam++) {
        uint8_t q[512], r[4096];
        size_t qn = dns_build_query(u->host, fam ? 28 : 1, (uint16_t)(rand() & 0xffff), q, sizeof q);
        long rn = dnsup_ask_blocking(u->resolver, q, qn, r, sizeof r, DNSUP_TIMEOUT_MS);
        if (rn <= 0) continue;
        struct dns_ip ips[4];
        int ni = 0;
        long ttl = dns_walk(r, (size_t)rn, -1, 0, ips, 4, &ni);
        if (ttl > 0 && ttl < min_ttl) min_ttl = ttl;
        for (int i = 0; i < ni && n < max; i++) {
            memset(&out[n], 0, sizeof out[n]);
            if (ips[i].family == 4) {
                struct sockaddr_in *s = (struct sockaddr_in *)&out[n];
                s->sin_family = AF_INET;
                s->sin_port = htons(u->port);
                memcpy(&s->sin_addr, ips[i].a, 4);
                lens[n++] = sizeof *s;
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&out[n];
                s->sin6_family = AF_INET6;
                s->sin6_port = htons(u->port);
                memcpy(&s->sin6_addr, ips[i].a, 16);
                lens[n++] = sizeof *s;
            }
        }
    }
    if (!n) { snprintf(err, errn, "%s: имя %s не разрешилось через %s", u->tag, u->host, u->resolver->tag); return 0; }
    pthread_mutex_lock(&u->mu);
    u->naddr = n < 4 ? n : 4;
    memcpy(u->addrs, out, (size_t)u->naddr * sizeof *out);
    memcpy(u->lens, lens, (size_t)u->naddr * sizeof *lens);
    u->addr_until = (long long)time(NULL) + (min_ttl < 60 ? 60 : min_ttl);
    pthread_mutex_unlock(&u->mu);
    return n;
}

/* ---- обмен ------------------------------------------------------------------------------ */

static long udp_exchange(const struct sockaddr_storage *a, socklen_t l, const struct egress *eg,
                         const uint8_t *q, size_t qn, uint8_t *resp, size_t cap, int timeout_ms) {
    int fd = socket(a->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (net_set_egress(fd, eg, a->ss_family) || connect(fd, (const struct sockaddr *)a, l) ||
        send(fd, q, qn, 0) != (ssize_t)qn) {
        close(fd);
        return -1;
    }
    uint16_t id = (uint16_t)((q[0] << 8) | q[1]);
    long long until = (long long)time(NULL) * 1000 + timeout_ms;
    for (;;) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long long now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
        int left = (int)(until - now);
        if (left <= 0) break;
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, left) <= 0) break;
        ssize_t r = recv(fd, resp, cap, 0);
        if (r < 12) continue;
        if ((uint16_t)((resp[0] << 8) | resp[1]) != id) continue;   /* чужой — ждём своего */
        close(fd);
        return (long)r;
    }
    close(fd);
    return -1;
}

struct wconn {
    struct bconn c;
    int open;
    int fresh;                  /* ещё не открывал соединения — уже учтён в connecting */
    /* DoH по HTTP/2 (сервер выбрал h2 в ALPN): поток на вопрос, запросы чередой по одному
     * соединению (h2.c умеет один открытый поток за раз — вопросы в рабочем потоке и так идут
     * по одному). Quad9 по HTTP/1.1 не отвечает вовсе (505), поэтому без этого его DoH мёртв. */
    struct h2 h;
    int h2, h2_started;
};

static int h2io_write(void *ctx, const unsigned char *d, size_t n) {
    return bconn_write(ctx, d, n) ? -1 : 0;
}

static int h2io_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    long r = bconn_read(ctx, d, cap, DNSUP_TIMEOUT_MS);
    if (r <= 0) return -1;
    *got = (size_t)r;
    return 0;
}

static long doh2_exchange(struct dnsup *u, struct wconn *w, const uint8_t *q, size_t qn, uint8_t *resp,
                          size_t cap, char *err, size_t errn) {
    char host[300];
    if (u->port != 443) snprintf(host, sizeof host, "%s:%u", u->sni, u->port);
    else snprintf(host, sizeof host, "%s", u->sni);
    int rc;
    if (!w->h2_started) {
        struct h2_io io = { &w->c, h2io_write, h2io_read };
        rc = h2_start_ex(&w->h, &io, host, u->path, "application/dns-message", NULL, H2_POST, 0, 1);
        w->h2_started = 1;
    } else rc = h2_next(&w->h, host, u->path, "application/dns-message", NULL, H2_POST);
    if (rc || h2_write(&w->h, q, qn) || h2_end_stream(&w->h)) {
        snprintf(err, errn, "%s: HTTP/2 запрос не ушёл (%s)", u->tag, h2_strerror(rc));
        return -2;                   /* соединение — заново */
    }
    static __thread unsigned char buf[H2_MIN_READ_CAP + 64];
    size_t n = 0;
    while (!w->h.done) {
        size_t got = 0;
        rc = h2_read(&w->h, buf, sizeof buf, &got);
        if (rc) {
            snprintf(err, errn, "%s: HTTP/2: %s", u->tag, h2_strerror(rc));
            return rc == H2_ESTATUS ? -1 : -2;
        }
        if (n + got > cap) { snprintf(err, errn, "%s: ответ больше %zu байт", u->tag, cap); return -2; }
        memcpy(resp + n, buf, got);
        n += got;
    }
    if (n < 12) { snprintf(err, errn, "%s: пустой ответ HTTP/2", u->tag); return -1; }
    return (long)n;
}

static long tcp_exchange(struct dnsup *u, struct wconn *w, const uint8_t *q, size_t qn, uint8_t *resp,
                         size_t cap, char *err, size_t errn) {
    for (int attempt = 0; attempt < 2; attempt++) {
        if (!w->open) {
            struct sockaddr_storage a[4];
            socklen_t l[4];
            int n = server_addrs(u, a, l, 4, err, errn);
            if (n <= 0) return -1;
            /* DoH — обычная пара ALPN «h2, http/1.1» (выбор за сервером: RFC 8484 требует от
             * сервера HTTP/2, а HTTP/1.1 — нет); DoT — без ALPN. */
            struct bconn_opts o = { .tls = u->type == UP_TLS || u->type == UP_HTTPS, .sni = u->sni,
                                    .alpn = u->type == UP_HTTPS ? "h2" : NULL,
                                    .insecure = u->insecure, .timeout_ms = DNSUP_TIMEOUT_MS };
            pthread_mutex_lock(&u->mu);
            if (!w->fresh) u->connecting++;
            w->fresh = 0;
            pthread_mutex_unlock(&u->mu);
            int orc = bconn_open(&w->c, u->host, u->port, a, l, n, &u->eg, &o, err, errn);
            pthread_mutex_lock(&u->mu);
            u->connecting--;
            /* Соединение есть — очередь, если не разобрана, растит ещё потоки (до двух на это
             * соединение); нет — этот поток сам попробует снова со следующим вопросом. */
            if (!orc) { maybe_spawn_locked(u); maybe_spawn_locked(u); }
            pthread_mutex_unlock(&u->mu);
            if (orc) return -1;
            w->open = 1;
            w->h2 = u->type == UP_HTTPS && !strcmp(w->c.alpn, "h2");
            w->h2_started = 0;
            memset(&w->h, 0, sizeof w->h);
        }
        if (u->type == UP_HTTPS && w->h2) {
            long rn = doh2_exchange(u, w, q, qn, resp, cap, err, errn);
            if (rn == -2) { bconn_close(&w->c); w->open = 0; if (attempt == 0) continue; return -1; }
            if (w->h.done && rn > 0) {}
            return rn;
        }
        if (u->type == UP_HTTPS) {
            struct http_resp r;
            char host[300];
            if (u->port != 443) snprintf(host, sizeof host, "%s:%u", u->sni, u->port);
            else snprintf(host, sizeof host, "%s", u->sni);
            if (http_request(&w->c, "POST", host, u->path, "application/dns-message", "application/dns-message",
                             q, qn, NULL, &r, 65535, DNSUP_TIMEOUT_MS, err, errn)) {
                bconn_close(&w->c);
                w->open = 0;
                continue;                   /* соединение умерло между вопросами — заново один раз */
            }
            if (r.close) { bconn_close(&w->c); w->open = 0; }
            if (r.status != 200 || r.body_n < 12 || r.body_n > cap) {
                snprintf(err, errn, "%s: HTTP %d", u->tag, r.status);
                http_resp_free(&r);
                return -1;
            }
            memcpy(resp, r.body, r.body_n);
            long n = (long)r.body_n;
            http_resp_free(&r);
            /* Номер вопроса DoH по RFC 8484 — 0; клиенту вернётся свой номер, его ставит dns.c. */
            return n;
        }
        uint8_t len[2] = { (uint8_t)(qn >> 8), (uint8_t)qn };
        if (bconn_write(&w->c, len, 2) || bconn_write(&w->c, q, qn) ||
            bconn_read_full(&w->c, len, 2, DNSUP_TIMEOUT_MS)) {
            bconn_close(&w->c);
            w->open = 0;
            continue;
        }
        size_t rn = (size_t)(len[0] << 8 | len[1]);
        if (rn < 12 || rn > cap || bconn_read_full(&w->c, resp, rn, DNSUP_TIMEOUT_MS)) {
            bconn_close(&w->c);
            w->open = 0;
            snprintf(err, errn, "%s: ответ оборвался", u->tag);
            return -1;
        }
        if (u->type == UP_TCP) { bconn_close(&w->c); w->open = 0; }
        return (long)rn;
    }
    if (!err[0]) snprintf(err, errn, "%s: нет ответа", u->tag);
    return -1;
}

/* ---- рабочие потоки --------------------------------------------------------------------- */

struct done_msg {
    dnsup_cb cb;
    void *arg;
    uint8_t *resp;
    long n;
    char err[160];
};

static void deliver(void *p) {
    struct done_msg *m = p;
    m->cb(m->arg, m->n > 0 ? m->resp : NULL, m->n > 0 ? (size_t)m->n : 0, m->err);
    free(m->resp);
    free(m);
}

static void *worker(void *arg) {
    struct dnsup *u = arg;
    struct wconn w = { .fresh = u->type != UP_UDP };
    uint8_t *resp = malloc(DNS_MAX);
    pthread_mutex_lock(&u->mu);
    for (;;) {
        while (!u->head && !u->dying) {
            u->idle++;
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 60;
            int rc = pthread_cond_timedwait(&u->cv, &u->mu, &ts);
            u->idle--;
            if (rc == ETIMEDOUT && !u->head) goto out;
        }
        if (!u->head) break;
        struct ujob *j = u->head;
        u->head = j->next;
        if (!u->head) u->tail = NULL;
        pthread_mutex_unlock(&u->mu);
        char err[160] = "";
        long n = -1;
        if (now_ms() - j->t0 > DNSUP_TIMEOUT_MS)
            snprintf(err, sizeof err, "%s: вопрос ждал в очереди дольше %d мс", u->tag, DNSUP_TIMEOUT_MS);
        else if (resp) {
            if (u->type == UP_UDP) {
                struct sockaddr_storage a[4];
                socklen_t l[4];
                int na = server_addrs(u, a, l, 4, err, sizeof err);
                for (int i = 0; i < na && n <= 0; i++)
                    n = udp_exchange(&a[i], l[i], &u->eg, j->q, j->qn, resp, DNS_MAX, DNSUP_TIMEOUT_MS);
                if (n <= 0 && !err[0]) snprintf(err, sizeof err, "%s: нет ответа за %d мс", u->tag, DNSUP_TIMEOUT_MS);
            } else n = tcp_exchange(u, &w, j->q, j->qn, resp, DNS_MAX, err, sizeof err);
        }
        if (j->blocking) {
            pthread_mutex_lock(&u->mu);
            if (n > 0) {
                j->resp = malloc((size_t)n);
                if (j->resp) memcpy(j->resp, resp, (size_t)n);
            }
            j->resp_n = n;
            snprintf(j->err, sizeof j->err, "%s", err);
            j->done = 1;
            pthread_cond_signal(&j->cond);
            continue;               /* mu удерживается — к началу цикла */
        }
        struct done_msg *m = calloc(1, sizeof *m);
        if (m) {
            m->cb = j->cb;
            m->arg = j->arg;
            m->n = n;
            snprintf(m->err, sizeof m->err, "%s", err);
            if (n > 0 && (m->resp = malloc((size_t)n))) memcpy(m->resp, resp, (size_t)n);
            else m->n = n > 0 ? -1 : n;
            ev_post(u->ev, deliver, m);
        }
        free(j->q);
        free(j);
        pthread_mutex_lock(&u->mu);
    }
out:
    u->workers--;
    if (w.fresh) u->connecting--;
    pthread_mutex_unlock(&u->mu);
    if (w.open) bconn_close(&w.c);
    free(resp);
    dnsup_unref(u);
    return NULL;
}

static int enqueue(struct dnsup *u, struct ujob *j) {
    pthread_mutex_lock(&u->mu);
    if (u->tail) u->tail->next = j;
    else u->head = j;
    u->tail = j;
    j->t0 = now_ms();
    maybe_spawn_locked(u);
    pthread_cond_signal(&u->cv);
    int none = u->workers == 0;
    if (none) {
        /* Некому отвечать (поток не завёлся): задание — с очереди, его освободит вызывающий. */
        struct ujob **pp = &u->head, *prev = NULL;
        for (; *pp; prev = *pp, pp = &(*pp)->next)
            if (*pp == j) { *pp = j->next; if (u->tail == j) u->tail = prev; break; }
    }
    pthread_mutex_unlock(&u->mu);
    return none ? -1 : 0;
}

int dnsup_ask(struct dnsup *u, const uint8_t *q, size_t n, dnsup_cb cb, void *arg) {
    struct ujob *j = calloc(1, sizeof *j);
    if (!j || !(j->q = malloc(n))) { free(j); return -1; }
    memcpy(j->q, q, n);
    j->qn = n;
    j->cb = cb;
    j->arg = arg;
    if (enqueue(u, j)) {
        free(j->q);
        free(j);
        return -1;
    }
    return 0;
}

long dnsup_ask_blocking(struct dnsup *u, const uint8_t *q, size_t n, uint8_t *resp, size_t cap, int timeout_ms) {
    struct ujob *j = calloc(1, sizeof *j);
    if (!j || !(j->q = malloc(n))) { free(j); return -1; }
    memcpy(j->q, q, n);
    j->qn = n;
    j->blocking = 1;
    pthread_cond_init(&j->cond, NULL);
    if (enqueue(u, j)) {
        pthread_cond_destroy(&j->cond);
        free(j->q);
        free(j);
        return -1;
    }
    pthread_mutex_lock(&u->mu);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_ms / 1000 + 2;
    while (!j->done)
        if (pthread_cond_timedwait(&j->cond, &u->mu, &ts) == ETIMEDOUT) break;
    long r = -1;
    if (j->done && j->resp_n > 0 && (size_t)j->resp_n <= cap) {
        memcpy(resp, j->resp, (size_t)j->resp_n);
        r = j->resp_n;
    }
    int done = j->done;
    pthread_mutex_unlock(&u->mu);
    if (done) {
        pthread_cond_destroy(&j->cond);
        free(j->resp);
        free(j->q);
        free(j);
    }
    /* Не дождались — задание освободит рабочий поток? Нет: он уже пишет в j. Утечка одной
     * записи на зависший вопрос лучше, чем обращение к освобождённой памяти. */
    return r;
}
