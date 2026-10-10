/* Наборы правил route.rule_set: скачивание remote, слежка за local (BOX_CONNECTOR.md, приложение А).
 *
 * remote — скачивается через download_detour (или напрямую), кладётся атомарно в кэш
 * (box_ruleset_cache_path) и обновляется по update_interval; при старте берётся то, что уже есть в
 * кэше, а качается то, чего нет или что устарело. local — файлы, которые podkop и forkop
 * переписывают при уже запущенном sing-box (list_update): за их каталогами следит inotify.
 * Любое изменение — перевод конфига заново с паузой в две секунды, чтобы пачка изменений дала одно
 * перечитывание steer. */
#define _GNU_SOURCE
#include "runtime.h"
#include "sbconf.h"
#include "bconn.h"
#include "translate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <utime.h>

struct rset {
    char tag[200], url[1024], path[700], format[16], detour[160];
    long long interval_ms;
    uint64_t timer;
    int busy;
};

struct rsmgr {
    struct box_rt *rt;
    struct rset *v;
    size_t n;
    int ino;
    uint64_t debounce;
    int stopped;
    int refs;                    /* работы в пути держат менеджер */
};

static void rs_free(struct rsmgr *m) {
    if (--m->refs > 0) return;
    free(m->v);
    free(m);
}

static void fire(struct ev *ev, void *arg) {
    (void)ev;
    struct rsmgr *m = arg;
    m->debounce = 0;
    if (m->stopped) { rs_free(m); return; }
    rt_retranslate(m->rt, "наборы правил изменились");
    rs_free(m);
}

void rs_changed(struct box_rt *rt) {
    struct rsmgr *m = rt->rs;
    if (!m || m->debounce) return;
    m->refs++;
    m->debounce = ev_timer(rt->ev, 2000, fire, m);
}

/* ---- скачивание -------------------------------------------------------------------------- */

struct djob {
    struct rsmgr *m;
    size_t idx;
    char url[1024], path[700], tag[200];
    struct egress eg;
    int ok, changed;
    char err[256];
};

static void dl_work(void *p) {
    struct djob *j = p;
    unsigned char *body = NULL;
    size_t n = 0;
    int status = 0;
    if (http_get(j->url, &j->eg, 60000, 256u << 20, &body, &n, &status, j->err, sizeof j->err)) return;
    if (status != 200 || !n) {
        snprintf(j->err, sizeof j->err, "HTTP %d", status);
        free(body);
        return;
    }
    /* Не перезаписывать тем же содержимым: steer незачем перечитывать неизменившийся набор. */
    FILE *f = fopen(j->path, "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        long old = ftell(f);
        if (old == (long)n) {
            fseek(f, 0, SEEK_SET);
            unsigned char *cur = malloc(n);
            if (cur && fread(cur, 1, n, f) == n && !memcmp(cur, body, n)) {
                free(cur);
                fclose(f);
                free(body);
                utime(j->path, NULL);
                j->ok = 1;
                return;
            }
            free(cur);
        }
        fclose(f);
    }
    char tmp[720];
    snprintf(tmp, sizeof tmp, "%s.part", j->path);
    f = fopen(tmp, "wb");
    /* fclose — ровно один раз: в прежней записи «… || fclose(f)» отказ закрытия (буфер не
     * сбросился — диск полон) вёл ниже во второй fclose того же FILE, то есть в неопределённое
     * поведение. Отказ закрытия — тоже «не записался». */
    int bad = !f;
    if (f) {
        if (fwrite(body, 1, n, f) != n) bad = 1;
        if (fclose(f)) bad = 1;
    }
    if (bad) {
        snprintf(j->err, sizeof j->err, "%s: не записался", tmp);
        free(body);
        return;
    }
    free(body);
    if (rename(tmp, j->path)) { snprintf(j->err, sizeof j->err, "%s: %s", j->path, strerror(errno)); return; }
    j->ok = j->changed = 1;
}

static void schedule(struct rsmgr *m, size_t i, long long ms);

static void dl_done(void *p) {
    struct djob *j = p;
    struct rsmgr *m = j->m;
    if (!m->stopped && j->idx < m->n) {
        struct rset *s = &m->v[j->idx];
        s->busy = 0;
        if (j->ok) {
            LOGI("набор %s %s", j->tag, j->changed ? "скачан" : "не изменился");
            if (j->changed) rs_changed(m->rt);
            schedule(m, j->idx, s->interval_ms);
        } else {
            /* Не скачался — повтор через минуту, а не через сутки: без набора правила над ним
             * не стоят вовсе. */
            LOGW("набор %s не скачался (%s): %s — повтор через минуту", j->tag, j->url, j->err);
            schedule(m, j->idx, 60000);
        }
    }
    rs_free(m);
    free(j);
}

static void start_dl(struct rsmgr *m, size_t i) {
    struct rset *s = &m->v[i];
    if (s->busy || m->stopped) return;
    struct djob *j = calloc(1, sizeof *j);
    if (!j) return;
    j->m = m;
    j->idx = i;
    snprintf(j->url, sizeof j->url, "%s", s->url);
    snprintf(j->path, sizeof j->path, "%s", s->path);
    snprintf(j->tag, sizeof j->tag, "%s", s->tag);
    char err[256];
    if (rt_egress(m->rt, s->detour[0] ? s->detour : NULL, &j->eg, err, sizeof err)) {
        LOGW("набор %s: выход %s пока без устройства (%s) — повтор через 10 с", s->tag, s->detour, err);
        free(j);
        schedule(m, i, 10000);
        return;
    }
    s->busy = 1;
    m->refs++;
    if (ev_spawn(m->rt->ev, dl_work, dl_done, j)) { s->busy = 0; m->refs--; free(j); schedule(m, i, 60000); }
}

struct tick { struct rsmgr *m; size_t i; };

static void tick_cb(struct ev *ev, void *arg) {
    (void)ev;
    struct tick *t = arg;
    struct rsmgr *m = t->m;
    if (!m->stopped && t->i < m->n) {
        m->v[t->i].timer = 0;
        start_dl(m, t->i);
    }
    rs_free(m);
    free(t);
}

static void schedule(struct rsmgr *m, size_t i, long long ms) {
    struct tick *t = malloc(sizeof *t);
    if (!t) return;
    t->m = m;
    t->i = i;
    m->refs++;
    /* Таймер цикла — до суток с лишним; дольше (876000h у forkop — «не обновлять») — просто
     * не ставится. */
    if (ms > 30LL * 86400000) { m->refs--; free(t); return; }
    m->v[i].timer = ev_timer(m->rt->ev, (long)ms, tick_cb, t);
}

/* ---- local ------------------------------------------------------------------------------- */

static void ino_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)ev; (void)e;
    struct rsmgr *m = arg;
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    int hit = 0;
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n <= 0) break;
        for (char *p = buf; p < buf + n;) {
            struct inotify_event *ie = (struct inotify_event *)p;
            if (ie->len) {
                for (size_t i = 0; i < m->n; i++) {
                    if (m->v[i].url[0]) continue;
                    char tmp[700];
                    snprintf(tmp, sizeof tmp, "%s", m->v[i].path);
                    if (!strcmp(basename(tmp), ie->name)) hit = 1;
                }
            }
            p += sizeof *ie + ie->len;
        }
    }
    if (hit) rs_changed(m->rt);
}

int rs_start(struct box_rt *rt) {
    struct rsmgr *m = calloc(1, sizeof *m);
    if (!m) return -1;
    m->rt = rt;
    m->refs = 1;
    m->ino = -1;
    const struct jval *sets = jget(jget(rt->cfg, "route"), "rule_set");
    m->v = calloc(jlen(sets) + 1, sizeof *m->v);
    for (size_t i = 0; i < jlen(sets); i++) {
        const struct jval *s = jat(sets, i);
        const char *type = jgets(s, "type"), *tag = jgets(s, "tag");
        if (!type || !tag) continue;
        struct rset *r = &m->v[m->n];
        snprintf(r->tag, sizeof r->tag, "%s", tag);
        const char *fmt = jgets(s, "format");
        snprintf(r->format, sizeof r->format, "%s", fmt ? fmt : "binary");
        if (!strcmp(type, "remote")) {
            snprintf(r->url, sizeof r->url, "%s", jgets(s, "url"));
            if (!fmt) {
                size_t l = strlen(r->url);
                snprintf(r->format, sizeof r->format, "%s", l > 5 && !strcmp(r->url + l - 5, ".json") ? "source" : "binary");
            }
            box_ruleset_cache_path(rt->rsdir, tag, r->format, r->path, sizeof r->path);
            const char *dd = jgets(s, "download_detour");
            snprintf(r->detour, sizeof r->detour, "%s", dd ? dd : "");
            long long iv = sb_duration_ms(jgets(s, "update_interval"));
            r->interval_ms = iv > 0 ? iv : 86400000;
        } else if (!strcmp(type, "local")) {
            snprintf(r->path, sizeof r->path, "%s", jgets(s, "path") ? jgets(s, "path") : "");
        } else continue;
        m->n++;
    }
    rt->rs = m;
    /* Remote: свежие в кэше — по таймеру, нет или устарели — сейчас. */
    for (size_t i = 0; i < m->n; i++) {
        struct rset *r = &m->v[i];
        if (!r->url[0]) continue;
        struct stat st;
        long long age = -1;
        if (!stat(r->path, &st)) age = ((long long)time(NULL) - st.st_mtime) * 1000;
        if (age < 0 || age >= r->interval_ms) start_dl(m, i);
        else schedule(m, i, r->interval_ms - age);
    }
    /* Local: inotify на каталоги (файл заменяют переименованием — следить за ним самим нельзя). */
    m->ino = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (m->ino >= 0) {
        int any = 0;
        for (size_t i = 0; i < m->n; i++) {
            if (m->v[i].url[0] || !m->v[i].path[0]) continue;
            char dir[700];
            snprintf(dir, sizeof dir, "%s", m->v[i].path);
            if (inotify_add_watch(m->ino, dirname(dir), IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE) >= 0) any = 1;
        }
        if (any) ev_add(rt->ev, m->ino, EPOLLIN, ino_cb, m);
        else { close(m->ino); m->ino = -1; }
    }
    return 0;
}

void rs_stop(struct box_rt *rt) {
    struct rsmgr *m = rt->rs;
    if (!m) return;
    m->stopped = 1;
    for (size_t i = 0; i < m->n; i++)
        if (m->v[i].timer) {
            ev_timer_cancel(rt->ev, m->v[i].timer);
            m->refs--;                     /* ссылка отменённого таймера */
        }
    if (m->debounce) { ev_timer_cancel(rt->ev, m->debounce); m->debounce = 0; m->refs--; }
    if (m->ino >= 0) { ev_del(rt->ev, m->ino); close(m->ino); }
    rt->rs = NULL;
    rs_free(m);
}
