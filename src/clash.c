/* Clash API коннектора (experimental.clash_api) — то, что читают podkop, forkop и их интерфейсы.
 *
 * Что за чем стоит:
 *   /proxies             выходы sing-box по конфигу; type — как у sing-box (VLESS, Selector,
 *                        URLTest…), now — выбор группы по status steer, history — последний замер;
 *   PUT /proxies/<g>     выбор члена селектора — команда steer `select` (у urltest выбора нет);
 *   …/delay              замер: запрос по url через устройство выхода (как urltest sing-box —
 *                        время до ответа), результат — в history;
 *   /connections         соединения, которые steer повёл в свои выходы (`steer conns`, conntrack),
 *                        в виде sing-box: id, metadata, chains, rule; DELETE — conntrack -D;
 *   /traffic, /memory    WebSocket (и поток для curl) раз в секунду.
 *
 * Сервер однопоточный, на цикле коннектора; всё, что ждёт steer или сеть, — в рабочих потоках. */
#define _GNU_SOURCE
#include "runtime.h"
#include "sbconf.h"
#include "steerctl.h"
#include "bconn.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <pthread.h>

struct clash {
    struct box_rt *rt;
    int lfd;
    char secret[256];
    char ui_dir[600];
    struct hc *ws;               /* открытые WebSocket — список */
    uint64_t tick;
    unsigned long long last_up, last_down;   /* для /traffic: прошлые суммы */
    long long last_at;
    int stopped;                 /* clash_stop: таймер ws_tick отпустит структуру сам */
    struct hc *all;              /* все соединения — clash_stop закрывает их */
    struct jval *origins;        /* access_control_allow_origin (копия); пусто — «*» */
    int allow_pna;               /* access_control_allow_private_network */
    int refs;                    /* таймер ws_tick и каждое соединение */
};

static void cl_put(struct clash *cl) {
    if (--cl->refs) return;
    json_free(cl->origins);
    free(cl);
}

enum hstate { HS_READ, HS_WAIT, HS_WS, HS_DONE };

struct hc {
    struct clash *cl;
    int fd;
    enum hstate st;
    char *in;
    size_t in_n, in_cap;
    char method[16], path[1024], query[1024];
    char auth[300], key[100], origin[300];
    int upgrade;
    size_t body_off, clen;
    int wskind;                  /* 1 traffic, 2 connections, 3 memory, 4 logs */
    int refs;
    struct hc *next;
    struct hc *anext, **apprev;  /* в cl->all */
};

static void hc_close(struct hc *c);

/* ---- SHA-1 для ответа WebSocket (RFC 6455) — криптографии здесь не нужно, только отпечаток. */
static void sha1(const unsigned char *d, size_t n, unsigned char out[20]) {
    uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    size_t total = ((n + 9 + 63) / 64) * 64;
    unsigned char *m = calloc(1, total);
    if (!m) { memset(out, 0, 20); return; }
    memcpy(m, d, n);
    m[n] = 0x80;
    uint64_t bits = (uint64_t)n * 8;
    for (int i = 0; i < 8; i++) m[total - 1 - i] = (unsigned char)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[80];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)m[off + 4 * i] << 24 | (uint32_t)m[off + 4 * i + 1] << 16 |
                   (uint32_t)m[off + 4 * i + 2] << 8 | m[off + 4 * i + 3];
        for (int i = 16; i < 80; i++) { uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = x << 1 | x >> 31; }
        uint32_t a = h[0], b = h[1], c = h[2], dd = h[3], e = h[4];
        for (int i = 0; i < 80; i++) {
            uint32_t f, k;
            if (i < 20) { f = (b & c) | (~b & dd); k = 0x5A827999; }
            else if (i < 40) { f = b ^ c ^ dd; k = 0x6ED9EBA1; }
            else if (i < 60) { f = (b & c) | (b & dd) | (c & dd); k = 0x8F1BBCDC; }
            else { f = b ^ c ^ dd; k = 0xCA62C1D6; }
            uint32_t t = (a << 5 | a >> 27) + f + e + k + w[i];
            e = dd; dd = c; c = b << 30 | b >> 2; b = a; a = t;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e;
    }
    free(m);
    for (int i = 0; i < 5; i++) {
        out[4 * i] = (unsigned char)(h[i] >> 24); out[4 * i + 1] = (unsigned char)(h[i] >> 16);
        out[4 * i + 2] = (unsigned char)(h[i] >> 8); out[4 * i + 3] = (unsigned char)h[i];
    }
}

static void b64(const unsigned char *in, size_t n, char *out) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (i + 1 < n ? in[i + 1] : 0) << 8 | (i + 2 < n ? in[i + 2] : 0);
        out[j++] = t[v >> 18 & 63];
        out[j++] = t[v >> 12 & 63];
        out[j++] = i + 1 < n ? t[v >> 6 & 63] : '=';
        out[j++] = i + 2 < n ? t[v & 63] : '=';
    }
    out[j] = 0;
}

/* ---- ответы ----------------------------------------------------------------------------- */

static const char *reason(int code) {
    switch (code) {
    case 200: return "OK"; case 204: return "No Content"; case 400: return "Bad Request";
    case 401: return "Unauthorized"; case 404: return "Not Found"; case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error"; case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout"; default: return "OK";
    }
}

/* CORS — как у sing-box (go-chi/cors): без access_control_allow_origin — «*»; со списком —
 * только origin из него (иначе заголовка нет); доступ из публичного сайта к частной сети —
 * только при access_control_allow_private_network. */
static const char *cors_origin(const struct hc *c) {
    const struct jval *l = c->cl->origins;
    if (!jlen(l)) return "*";
    for (size_t i = 0; i < jlen(l); i++) {
        const struct jval *e = jat(l, i);
        if (e->t != J_STR) continue;
        if (!strcmp(e->s, "*")) return "*";
        if (c->origin[0] && !strcmp(e->s, c->origin)) return c->origin;
    }
    return NULL;
}

static void send_raw(struct hc *c, int code, const char *ctype, const char *body, size_t n) {
    char head[1024], acao[340] = "";
    const char *ao = cors_origin(c);
    if (ao) snprintf(acao, sizeof acao, "Access-Control-Allow-Origin: %s\r\n", ao);
    int hn = snprintf(head, sizeof head,
                      "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %zu\r\n"
                      "%s"
                      "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                      "%s"
                      "Connection: close\r\n\r\n",
                      code, reason(code), ctype ? ctype : "application/json", n, acao,
                      c->cl->allow_pna ? "Access-Control-Allow-Private-Network: true\r\n" : "");
    set_nonblock(c->fd, 0);
    write_all(c->fd, head, (size_t)hn);
    if (n) write_all(c->fd, body, n);
    c->st = HS_DONE;
}

static void send_json(struct hc *c, int code, const struct jval *v) {
    size_t n = 0;
    char *s = v ? json_to_str(v, -1, &n) : NULL;
    send_raw(c, code, "application/json; charset=utf-8", s ? s : "", s ? n : 0);
    free(s);
}

static void send_msg(struct hc *c, int code, const char *msg) {
    struct jval *o = jnew(J_OBJ);
    jobj_set(o, "message", jstr(msg));
    send_json(c, code, o);
    json_free(o);
}

/* ---- выходы ----------------------------------------------------------------------------- */

static const struct jval *st_output(struct box_rt *rt, const char *tag) {
    const char *name = rt_steer_name(rt, tag);
    return name ? jget(jget(rt->status, "outputs"), name) : NULL;
}

/* Задержка выхода: свой замер, иначе замер группы steer, где выход — член. */
static int delay_of(struct box_rt *rt, const char *tag, long long *when) {
    const struct delay_rec *d = rt_delay_get(rt, tag);
    if (d) { *when = d->time_ms; return d->delay; }
    const char *name = rt_steer_name(rt, tag);
    const struct jval *outs = jget(rt->status, "outputs");
    for (size_t i = 0; name && i < jlen(outs); i++) {
        const struct jval *lat = jget(jget(outs->o[i].val, "group"), "latency");
        const struct jval *v = jget(lat, name);
        if (v && v->t == J_NUM) { *when = 0; return (int)v->i; }
    }
    return -1;
}

static struct jval *history_of(struct box_rt *rt, const char *tag) {
    struct jval *h = jnew(J_ARR);
    long long when = 0;
    int d = delay_of(rt, tag, &when);
    if (d < 0) return h;
    if (!when) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        when = (long long)ts.tv_sec * 1000;
    }
    time_t sec = (time_t)(when / 1000);
    struct tm tm;
    gmtime_r(&sec, &tm);
    char buf[64];
    snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(when % 1000));
    struct jval *e = jnew(J_OBJ);
    jobj_set(e, "time", jstr(buf));
    jobj_set(e, "delay", jint(d));
    jarr_push(h, e);
    return h;
}

/* Член группы, который сейчас несёт её трафик (тег sing-box). */
static const char *group_now(struct box_rt *rt, const char *tag) {
    /* Селектор: член, которого перевод поднял (остальные спят, см. translate.c). */
    const char *mnow = jgets(jget(jget(rt->map, "outbounds"), tag), "now");
    if (mnow) return mnow;
    const struct jval *o = st_output(rt, tag);
    const struct jval *g = jget(o, "group");
    const char *sel = jgets(g, "selected");
    if (!sel) sel = jgets(g, "select");
    if (sel) {
        const char *t = rt_tag_of(rt, sel);
        if (t) return t;
    }
    const struct jval *ob = sb_outbound(rt->cfg, tag);
    const char *def = jgets(ob, "default");
    if (def) return def;
    const struct jval *first = jat(jget(ob, "outbounds"), 0);
    return first && first->t == J_STR ? first->s : NULL;
}

static struct jval *proxy_obj(struct box_rt *rt, const char *tag) {
    const struct jval *ob = sb_outbound(rt->cfg, tag);
    struct jval *p = jnew(J_OBJ);
    jobj_set(p, "type", jstr(rt_clash_type(rt, tag)));
    jobj_set(p, "name", jstr(tag));
    jobj_set(p, "udp", jbool(1));
    jobj_set(p, "history", history_of(rt, tag));
    if (sb_outbound_kind(ob) == SBO_GROUP) {
        const char *now = group_now(rt, tag);
        if (now) jobj_set(p, "now", jstr(now));
        struct jval *all = jnew(J_ARR);
        const struct jval *m = jget(ob, "outbounds");
        for (size_t i = 0; i < jlen(m); i++)
            if (jat(m, i)->t == J_STR) jarr_push(all, jstr(jat(m, i)->s));
        jobj_set(p, "all", all);
    }
    return p;
}

static struct jval *proxies_all(struct box_rt *rt) {
    struct jval *ps = jnew(J_OBJ);
    const struct jval *obs = jget(rt->cfg, "outbounds");
    struct jval *gall = jnew(J_ARR);
    for (size_t i = 0; i < jlen(obs); i++) {
        const char *tag = jgets(jat(obs, i), "tag");
        if (!tag) continue;
        jobj_set(ps, tag, proxy_obj(rt, tag));
        jarr_push(gall, jstr(tag));
    }
    /* GLOBAL — как у sing-box: селектор из всех выходов, now — выход по умолчанию. */
    struct jval *g = jnew(J_OBJ);
    jobj_set(g, "type", jstr("Fallback"));
    jobj_set(g, "name", jstr("GLOBAL"));
    jobj_set(g, "udp", jbool(1));
    jobj_set(g, "history", jnew(J_ARR));
    const char *fin = jgets(jget(rt->cfg, "route"), "final");
    if (!fin && jlen(obs)) fin = jgets(jat(obs, 0), "tag");
    if (fin) jobj_set(g, "now", jstr(fin));
    jobj_set(g, "all", gall);
    jobj_set(ps, "GLOBAL", g);
    struct jval *root = jnew(J_OBJ);
    jobj_set(root, "proxies", ps);
    return root;
}

/* ---- асинхронные ответы ----------------------------------------------------------------- */

static void hc_unref(struct hc *c) {
    if (--c->refs > 0) return;
    if (c->fd >= 0) close(c->fd);
    struct clash *cl = c->cl;
    if ((*c->apprev = c->anext)) c->anext->apprev = c->apprev;
    free(c->in);
    free(c);
    cl_put(cl);
}

/* Замер задержки одного выхода — в рабочем потоке. */
struct djob {
    struct hc *c;
    struct box_rt *rt;
    char tag[160], url[1024];
    int timeout;
    struct egress eg;
    int eg_ok;
    char err[256];
    int delay;              /* мс; -1 — отказ */
    int dormant;            /* спящий член селектора: замер — соединение TCP с его сервером */
    char host[256];
    uint16_t port;
    int is_group;
    /* группа: члены и их результаты */
    size_t n;
    char (*tags)[160];
    struct egress *egs;
    int *egs_ok;
    int *delays;
    char (*hosts)[256];     /* у спящих — сервер, иначе "" */
    uint16_t *ports;
};

/* Спящий член селектора (в карте dormant): его сервер и порт из конфига. 0 — да. */
static int dormant_target(struct box_rt *rt, const char *tag, char *host, size_t n, uint16_t *port) {
    if (!jgetb(jget(jget(rt->map, "outbounds"), tag), "dormant", 0)) return -1;
    const struct jval *ob = sb_outbound(rt->cfg, tag);
    const char *srv = jgets(ob, "server");
    long p = jgeti(ob, "server_port", 0);
    if (!srv || p <= 0 || p > 65535) return -1;
    snprintf(host, n, "%s", srv);
    *port = (uint16_t)p;
    return 0;
}

/* Задержка спящего члена: время соединения TCP с его сервером напрямую. Поднимать туннель ради
 * замера — тот же процесс и те же сессии, от которых селектор и избавлен; соединение с сервером
 * говорит, жив ли узел и далеко ли он. */
static int measure_dial(const char *host, uint16_t port, const struct egress *eg, int timeout,
                        char *err, size_t errn) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int fd = net_dial(host, port, eg, timeout, err, errn);
    if (fd < 0) return -1;
    close(fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    return ms > 0 ? (int)ms : 1;
}

static int measure(const char *url, const struct egress *eg, int timeout, char *err, size_t errn) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned char *body = NULL;
    size_t n;
    int status;
    if (http_get(url, eg, timeout, 1 << 20, &body, &n, &status, err, errn)) return -1;
    free(body);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000;
    if (status >= 400) { snprintf(err, errn, "HTTP %d", status); return -1; }
    return ms > 0 ? (int)ms : 1;
}

struct dmem { struct djob *j; size_t i; };

static void *delay_member(void *p) {
    struct dmem *m = p;
    struct djob *j = m->j;
    size_t i = m->i;
    char e[200];
    if (!j->egs_ok[i]) j->delays[i] = -1;
    else if (j->hosts[i][0]) j->delays[i] = measure_dial(j->hosts[i], j->ports[i], &j->egs[i], j->timeout, e, sizeof e);
    else j->delays[i] = measure(j->url, &j->egs[i], j->timeout, e, sizeof e);
    return NULL;
}

static void delay_work(void *p) {
    struct djob *j = p;
    if (!j->is_group) {
        if (!j->eg_ok) j->delay = -1;
        else if (j->dormant) j->delay = measure_dial(j->host, j->port, &j->eg, j->timeout, j->err, sizeof j->err);
        else j->delay = measure(j->url, &j->eg, j->timeout, j->err, sizeof j->err);
        return;
    }
    /* Члены — разом, как у sing-box: подряд замер подписки из полусотни узлов с мёртвыми среди
     * них шёл бы минутами. */
    pthread_t *th = calloc(j->n + 1, sizeof *th);
    struct dmem *ms = calloc(j->n + 1, sizeof *ms);
    char *started = calloc(j->n + 1, 1);
    for (size_t i = 0; i < j->n; i++) {
        ms[i].j = j;
        ms[i].i = i;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setstacksize(&at, 128 * 1024);
        if (th && ms && started && !pthread_create(&th[i], &at, delay_member, &ms[i])) started[i] = 1;
        else delay_member(&ms[i]);
        pthread_attr_destroy(&at);
    }
    for (size_t i = 0; i < j->n; i++)
        if (started && started[i]) pthread_join(th[i], NULL);
    free(th);
    free(ms);
    free(started);
}

static void delay_done(void *p) {
    struct djob *j = p;
    struct hc *c = j->c;
    if (!j->is_group) {
        rt_delay_put(j->rt, j->tag, j->delay > 0 ? j->delay : 0);
        if (c->fd >= 0) {
            if (j->delay > 0) {
                struct jval *o = jnew(J_OBJ);
                jobj_set(o, "delay", jint(j->delay));
                send_json(c, 200, o);
                json_free(o);
            } else {
                int timeout = strstr(j->err, "нет ответа") || strstr(j->err, "мс");
                send_msg(c, timeout ? 504 : 503, timeout ? "Timeout" : j->err[0] ? j->err : "An error occurred in the delay test");
            }
        }
    } else {
        struct jval *o = jnew(J_OBJ);
        for (size_t i = 0; i < j->n; i++) {
            rt_delay_put(j->rt, j->tags[i], j->delays[i] > 0 ? j->delays[i] : 0);
            if (j->delays[i] > 0) jobj_set(o, j->tags[i], jint(j->delays[i]));
        }
        if (c->fd >= 0) send_json(c, 200, o);
        json_free(o);
        free(j->tags);
        free(j->egs);
        free(j->egs_ok);
        free(j->delays);
        free(j->hosts);
        free(j->ports);
    }
    hc_close(c);
    hc_unref(c);
    free(j);
}

static void q_param(const char *query, const char *name, char *out, size_t n) {
    out[0] = 0;
    size_t nl = strlen(name);
    for (const char *p = query; p && *p;) {
        const char *amp = strchr(p, '&');
        size_t l = amp ? (size_t)(amp - p) : strlen(p);
        if (l > nl && !strncmp(p, name, nl) && p[nl] == '=') {
            size_t j = 0;
            for (size_t i = nl + 1; i < l && j + 1 < n; i++) {
                if (p[i] == '%' && i + 2 < l) {
                    char hx[3] = { p[i + 1], p[i + 2], 0 };
                    out[j++] = (char)strtol(hx, NULL, 16);
                    i += 2;
                } else out[j++] = p[i] == '+' ? ' ' : p[i];
            }
            out[j] = 0;
            return;
        }
        p = amp ? amp + 1 : NULL;
    }
}

static void url_decode(char *s) {
    char *o = s;
    for (char *p = s; *p; p++) {
        if (*p == '%' && p[1] && p[2]) {
            char hx[3] = { p[1], p[2], 0 };
            *o++ = (char)strtol(hx, NULL, 16);
            p += 2;
        } else *o++ = *p;
    }
    *o = 0;
}

static void start_delay(struct hc *c, const char *tag, int group) {
    struct box_rt *rt = c->cl->rt;
    const struct jval *ob = sb_outbound(rt->cfg, tag);
    if (!ob) { send_msg(c, 404, "Resource not found"); return; }
    struct djob *j = calloc(1, sizeof *j);
    if (!j) { send_msg(c, 500, "нет памяти"); return; }
    j->c = c;
    j->rt = rt;
    snprintf(j->tag, sizeof j->tag, "%s", tag);
    q_param(c->query, "url", j->url, sizeof j->url);
    if (!j->url[0]) snprintf(j->url, sizeof j->url, "https://www.gstatic.com/generate_204");
    char tbuf[32];
    q_param(c->query, "timeout", tbuf, sizeof tbuf);
    j->timeout = tbuf[0] ? atoi(tbuf) : 5000;
    if (j->timeout < 100) j->timeout = 100;
    if (!group) {
        /* У группы задержка — её нынешнего листа, как у sing-box. */
        const char *t = tag;
        for (int depth = 0; depth < 16 && sb_outbound_kind(sb_outbound(rt->cfg, t)) == SBO_GROUP; depth++) {
            const char *now = group_now(rt, t);
            if (!now) break;
            t = now;
        }
        if (!dormant_target(rt, t, j->host, sizeof j->host, &j->port)) {
            j->dormant = 1;
            j->eg_ok = !rt_egress(rt, NULL, &j->eg, j->err, sizeof j->err);
        } else j->eg_ok = !rt_egress(rt, t, &j->eg, j->err, sizeof j->err);
    } else {
        const struct jval *m = jget(ob, "outbounds");
        j->is_group = 1;
        j->n = jlen(m);
        j->tags = calloc(j->n + 1, sizeof *j->tags);
        j->egs = calloc(j->n + 1, sizeof *j->egs);
        j->egs_ok = calloc(j->n + 1, sizeof *j->egs_ok);
        j->delays = calloc(j->n + 1, sizeof *j->delays);
        j->hosts = calloc(j->n + 1, sizeof *j->hosts);
        j->ports = calloc(j->n + 1, sizeof *j->ports);
        if (!j->tags || !j->egs || !j->egs_ok || !j->delays || !j->hosts || !j->ports) j->n = 0;
        for (size_t i = 0; i < j->n; i++) {
            if (jat(m, i)->t != J_STR) continue;
            snprintf(j->tags[i], sizeof j->tags[i], "%s", jat(m, i)->s);
            char e[200];
            /* Член-группа — её нынешний лист, как у одиночного замера. */
            const char *t = j->tags[i];
            for (int depth = 0; depth < 16 && sb_outbound_kind(sb_outbound(rt->cfg, t)) == SBO_GROUP; depth++) {
                const char *now = group_now(rt, t);
                if (!now) break;
                t = now;
            }
            if (!dormant_target(rt, t, j->hosts[i], sizeof j->hosts[i], &j->ports[i]))
                j->egs_ok[i] = !rt_egress(rt, NULL, &j->egs[i], e, sizeof e);
            else j->egs_ok[i] = !rt_egress(rt, t, &j->egs[i], e, sizeof e);
        }
    }
    c->st = HS_WAIT;
    c->refs++;
    if (ev_spawn(rt->ev, delay_work, delay_done, j)) {
        c->refs--;
        send_msg(c, 500, "нет потока для замера");
        free(j);
    }
}

/* Выбор члена селектора. */
static void select_applied(void *arg, int rc, const char *err) {
    struct hc *c = arg;
    if (c->fd >= 0) {
        if (!rc) send_raw(c, 204, NULL, "", 0);
        else send_msg(c, 400, err && *err ? err : "select failed");
    }
    hc_close(c);
    hc_unref(c);
}

static void do_select(struct hc *c, const char *tag, const char *body) {
    struct box_rt *rt = c->cl->rt;
    const struct jval *ob = sb_outbound(rt->cfg, tag);
    if (!ob || sb_outbound_kind(ob) != SBO_GROUP) { send_msg(c, 404, "Resource not found"); return; }
    if (strcmp(jgets(ob, "type"), "selector")) { send_msg(c, 400, "Must be a Selector"); return; }
    char e[200];
    struct jval *b = json_parse(body ? body : "", body ? strlen(body) : 0, e, sizeof e);
    const char *member = jgets(b, "name");
    if (!member) { json_free(b); send_msg(c, 400, "Body invalid"); return; }
    int found = 0;
    const struct jval *m = jget(ob, "outbounds");
    for (size_t i = 0; i < jlen(m); i++)
        if (jat(m, i)->t == J_STR && !strcmp(jat(m, i)->s, member)) found = 1;
    if (!found) {
        char msg[300];
        snprintf(msg, sizeof msg, "Selector update error: not found %s", member);
        json_free(b);
        send_msg(c, 400, msg);
        return;
    }
    const char *now = group_now(rt, tag);
    if (now && !strcmp(now, member)) { json_free(b); send_raw(c, 204, NULL, "", 0); return; }
    /* Селектор в спеке — только выбранный член (translate.c): смена выбора — новый перевод и
     * reload, в рабочем потоке. Ответ — когда steer применил. */
    c->st = HS_WAIT;
    c->refs++;
    if (rt_select(rt, tag, member, select_applied, c)) {
        c->refs--;
        send_msg(c, 503, "идёт смена выбора — повторите");
    }
    json_free(b);
}

/* ---- соединения ------------------------------------------------------------------------- */

/* Карта поддельный адрес → имя из fakeip.state резолвера steer («имя, поддельный, настоящий»). */
static const char *fake_name(char *buf, size_t n, const char *state_dir, const char *ip) {
    char path[700];
    snprintf(path, sizeof path, "%s/fakeip.state", state_dir);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char line[600];
    const char *res = NULL;
    while (fgets(line, sizeof line, f)) {
        char name[300], fake[64];
        if (sscanf(line, "%299s %63s", name, fake) == 2 && !strcmp(fake, ip)) {
            snprintf(buf, n, "%s", name);
            res = buf;
            break;
        }
    }
    fclose(f);
    return res;
}

struct cjob {
    struct hc *c;
    struct box_rt *rt;
    char sock[600], state[600];
    struct jval *conns;          /* ответ steer */
    char err[256];
    int ws;                      /* для WebSocket: не ответ, а кадр */
    char kill[64];               /* DELETE: id или "*" */
};

static void conns_work(void *p) {
    struct cjob *j = p;
    j->conns = steerctl_json(j->sock, "conns", 15000, j->err, sizeof j->err);
}

/* Идентификатор соединения — из его пятёрки: тот же у каждого опроса, пока соединение живо, и
 * в виде UUID, как у sing-box (интерфейс forkop показывает и сравнивает его строкой). */
static void conn_id(const struct jval *e, char *out, size_t n) {
    char key[300];
    snprintf(key, sizeof key, "%s|%s|%lld|%s|%lld", jgets(e, "proto"), jgets(e, "src"),
             (long long)jgeti(e, "sport", 0), jgets(e, "dst"), (long long)jgeti(e, "dport", 0));
    unsigned char h[20];
    sha1((const unsigned char *)key, strlen(key), h);
    snprintf(out, n, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]);
}

/* Первое появление соединения — время start (conntrack его не хранит). */
struct seen { char id[40]; long long at; };
static struct seen *g_seen;
static size_t g_seen_n, g_seen_cap;

static long long seen_at(const char *id, long long now) {
    for (size_t i = 0; i < g_seen_n; i++)
        if (!strcmp(g_seen[i].id, id)) return g_seen[i].at;
    if (g_seen_n == g_seen_cap) {
        size_t nc = g_seen_cap ? g_seen_cap * 2 : 256;
        struct seen *ns = realloc(g_seen, nc * sizeof *ns);
        if (!ns) return now;
        g_seen = ns;
        g_seen_cap = nc;
    }
    snprintf(g_seen[g_seen_n].id, sizeof g_seen[g_seen_n].id, "%s", id);
    g_seen[g_seen_n].at = now;
    g_seen_n++;
    return now;
}

static void iso_time(long long ms, char *buf, size_t n) {
    time_t s = (time_t)(ms / 1000);
    struct tm tm;
    gmtime_r(&s, &tm);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(ms % 1000));
}

static struct jval *conns_to_clash(struct box_rt *rt, const struct jval *steer_conns, unsigned long long *up,
                                   unsigned long long *down) {
    struct jval *arr = jnew(J_ARR);
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long long now = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    const struct jval *list = jget(steer_conns, "conns");
    /* Вход sing-box, которому соответствует трафик LAN: первый tproxy конфига. */
    const char *intag = "tproxy-in";
    const struct jval *ins = jget(rt->cfg, "inbounds");
    for (size_t i = 0; i < jlen(ins); i++)
        if (jgets(jat(ins, i), "type") && !strcmp(jgets(jat(ins, i), "type"), "tproxy")) { intag = jgets(jat(ins, i), "tag"); break; }
    size_t keep = 0;
    for (size_t i = 0; i < jlen(list); i++) {
        const struct jval *e = jat(list, i);
        const char *out = jgets(e, "out");
        const char *tag = out ? rt_tag_of(rt, out) : NULL;
        if (!tag) continue;
        char id[40], when[40], host[300], port[16], sport[16];
        conn_id(e, id, sizeof id);
        iso_time(seen_at(id, now), when, sizeof when);
        struct jval *c = jnew(J_OBJ), *md = jnew(J_OBJ);
        jobj_set(c, "id", jstr(id));
        const char *proto = jgets(e, "proto");
        jobj_set(md, "network", jstr(proto ? proto : "tcp"));
        char typ[200];
        snprintf(typ, sizeof typ, "tproxy/%s", intag);
        jobj_set(md, "type", jstr(typ));
        jobj_set(md, "sourceIP", jstr(jgets(e, "src") ? jgets(e, "src") : ""));
        snprintf(sport, sizeof sport, "%lld", (long long)jgeti(e, "sport", 0));
        jobj_set(md, "sourcePort", jstr(sport));
        const char *dst = jgets(e, "dst");
        const char *name = dst ? fake_name(host, sizeof host, rt->state, dst) : NULL;
        jobj_set(md, "destinationIP", jstr(dst ? dst : ""));
        snprintf(port, sizeof port, "%lld", (long long)jgeti(e, "dport", 0));
        jobj_set(md, "destinationPort", jstr(port));
        jobj_set(md, "host", jstr(name ? name : ""));
        jobj_set(md, "dnsMode", jstr(name ? "fakeip" : "normal"));
        jobj_set(md, "processPath", jstr(""));
        jobj_set(c, "metadata", md);
        long long ub = jgeti(e, "bytes", 0), db = jgeti(e, "reply_bytes", 0);
        jobj_set(c, "upload", jint(ub));
        jobj_set(c, "download", jint(db));
        *up += (unsigned long long)ub;
        *down += (unsigned long long)db;
        jobj_set(c, "start", jstr(when));
        /* chains: от листа к правилу, как у sing-box: [лист, …, группа]. */
        struct jval *ch = jnew(J_ARR);
        const char *t = tag;
        const char *path[17];
        int np = 0;
        path[np++] = t;
        for (int d = 0; d < 16 && sb_outbound_kind(sb_outbound(rt->cfg, t)) == SBO_GROUP; d++) {
            const char *now_m = group_now(rt, t);
            if (!now_m) break;
            path[np++] = now_m;
            t = now_m;
        }
        for (int k = np - 1; k >= 0; k--) jarr_push(ch, jstr(path[k]));
        jobj_set(c, "chains", ch);
        char rule[400];
        snprintf(rule, sizeof rule, "inbound=%s => route(%s)", intag, tag);
        jobj_set(c, "rule", jstr(rule));
        jobj_set(c, "rulePayload", jstr(""));
        jarr_push(arr, c);
        keep++;
    }
    /* Память «первого появления» не растёт без конца: соединений, которых нет, не держим. */
    if (g_seen_n > keep * 2 + 256) g_seen_n = 0;
    return arr;
}

static unsigned long long proc_mem(void) {
    FILE *f = fopen("/proc/self/statm", "r");
    unsigned long long pages = 0, rss = 0;
    if (f) { if (fscanf(f, "%llu %llu", &pages, &rss) != 2) rss = 0; fclose(f); }
    return rss * 4096ULL;
}

static struct jval *conns_snapshot(struct box_rt *rt, const struct jval *steer_conns) {
    unsigned long long up = 0, down = 0;
    struct jval *arr = conns_to_clash(rt, steer_conns, &up, &down);
    struct jval *o = jnew(J_OBJ);
    jobj_set(o, "downloadTotal", jint((int64_t)down));
    jobj_set(o, "uploadTotal", jint((int64_t)up));
    jobj_set(o, "connections", arr);
    jobj_set(o, "memory", jint((int64_t)proc_mem()));
    rt->up_total = up;
    rt->down_total = down;
    return o;
}

static void ws_send(struct hc *c, const char *payload, size_t n);

static void conns_done(void *p) {
    struct cjob *j = p;
    struct hc *c = j->c;
    if (c->fd >= 0) {
        struct jval *snap = conns_snapshot(j->rt, j->conns);
        if (j->ws) {
            size_t n;
            char *s = json_to_str(snap, -1, &n);
            if (s) ws_send(c, s, n);
            free(s);
        } else {
            send_json(c, 200, snap);
            hc_close(c);
        }
        json_free(snap);
    }
    json_free(j->conns);
    hc_unref(c);
    free(j);
}

static void start_conns(struct hc *c, int ws) {
    struct box_rt *rt = c->cl->rt;
    struct cjob *j = calloc(1, sizeof *j);
    if (!j) return;
    j->c = c;
    j->rt = rt;
    j->ws = ws;
    snprintf(j->sock, sizeof j->sock, "%s", rt->sock);
    if (!ws) c->st = HS_WAIT;
    c->refs++;
    if (ev_spawn(rt->ev, conns_work, conns_done, j)) { c->refs--; free(j); if (!ws) send_msg(c, 500, "нет потока"); }
}

/* DELETE /connections[/id]: conntrack -D по пятёрке. */
struct kjob { struct hc *c; struct box_rt *rt; char sock[600]; char id[64]; int found; };

static void kill_work(void *p) {
    struct kjob *j = p;
    char err[256];
    struct jval *cs = steerctl_json(j->sock, "conns", 15000, err, sizeof err);
    const struct jval *list = jget(cs, "conns");
    for (size_t i = 0; i < jlen(list); i++) {
        const struct jval *e = jat(list, i);
        char id[40];
        conn_id(e, id, sizeof id);
        if (strcmp(j->id, "*") && strcmp(j->id, id)) continue;
        if (!jgets(e, "out")) continue;
        j->found = 1;
        char sp[16], dp[16];
        snprintf(sp, sizeof sp, "%lld", (long long)jgeti(e, "sport", 0));
        snprintf(dp, sizeof dp, "%lld", (long long)jgeti(e, "dport", 0));
        const char *fam = jgets(e, "family") && !strcmp(jgets(e, "family"), "ipv6") ? "-f" : NULL;
        pid_t pid = fork();
        if (!pid) {
            int dn = open("/dev/null", O_WRONLY);
            if (dn >= 0) { dup2(dn, 1); dup2(dn, 2); }
            if (fam)
                execlp("conntrack", "conntrack", "-D", "-f", "ipv6", "-p", jgets(e, "proto"), "-s", jgets(e, "src"),
                       "-d", jgets(e, "dst"), "--sport", sp, "--dport", dp, (char *)NULL);
            else
                execlp("conntrack", "conntrack", "-D", "-p", jgets(e, "proto"), "-s", jgets(e, "src"),
                       "-d", jgets(e, "dst"), "--sport", sp, "--dport", dp, (char *)NULL);
            _exit(127);
        }
        if (pid > 0) waitpid(pid, NULL, 0);
    }
    json_free(cs);
}

static void kill_done(void *p) {
    struct kjob *j = p;
    struct hc *c = j->c;
    if (c->fd >= 0) {
        if (j->found || !strcmp(j->id, "*")) send_raw(c, 204, NULL, "", 0);
        else send_msg(c, 404, "Resource not found");
        hc_close(c);
    }
    hc_unref(c);
    free(j);
}

/* ---- WebSocket -------------------------------------------------------------------------- */

static void ws_send(struct hc *c, const char *payload, size_t n) {
    unsigned char h[10];
    size_t hn = 0;
    h[hn++] = 0x81;
    if (n < 126) h[hn++] = (unsigned char)n;
    else if (n < 65536) { h[hn++] = 126; h[hn++] = (unsigned char)(n >> 8); h[hn++] = (unsigned char)n; }
    else {
        h[hn++] = 127;
        for (int i = 7; i >= 0; i--) h[hn++] = (unsigned char)((uint64_t)n >> (8 * i));
    }
    if (write_all(c->fd, h, hn) || write_all(c->fd, payload, n)) hc_close(c);
}

static unsigned long long dev_bytes(const char *dev, const char *which) {
    char path[200];
    snprintf(path, sizeof path, "/sys/class/net/%s/statistics/%s", dev, which);
    FILE *f = fopen(path, "r");
    unsigned long long v = 0;
    if (f) { if (fscanf(f, "%llu", &v) != 1) v = 0; fclose(f); }
    return v;
}

/* Трафик выходов steer: счётчики их устройств (туннели, интерфейсы выходов). Отправленное в
 * устройство — up, принятое — down. */
static void traffic_now(struct box_rt *rt, unsigned long long *up, unsigned long long *down) {
    *up = *down = 0;
    const struct jval *outs = jget(rt->status, "outputs");
    const char *seen[64];
    int ns = 0;
    for (size_t i = 0; i < jlen(outs); i++) {
        const struct jval *o = outs->o[i].val;
        if (jget(o, "group")) continue;
        const char *dev = jgets(o, "device");
        if (!dev) continue;
        int dup = 0;
        for (int k = 0; k < ns; k++) if (!strcmp(seen[k], dev)) dup = 1;
        if (dup || ns >= 64) continue;
        seen[ns++] = dev;
        *up += dev_bytes(dev, "tx_bytes");
        *down += dev_bytes(dev, "rx_bytes");
    }
}

static void ws_tick(struct ev *ev, void *arg) {
    struct clash *cl = arg;
    if (cl->stopped) { cl_put(cl); return; }
    unsigned long long up, down;
    traffic_now(cl->rt, &up, &down);
    long long now = ev_now_ms();
    unsigned long long ru = 0, rd = 0;
    if (cl->last_at) {
        double secs = (now - cl->last_at) / 1000.0;
        if (secs <= 0) secs = 1;
        ru = up >= cl->last_up ? (unsigned long long)((up - cl->last_up) / secs) : 0;
        rd = down >= cl->last_down ? (unsigned long long)((down - cl->last_down) / secs) : 0;
    }
    cl->last_up = up;
    cl->last_down = down;
    cl->last_at = now;
    for (struct hc *c = cl->ws, *n; c; c = n) {
        n = c->next;
        char buf[200];
        int k = 0;
        if (c->wskind == 1) k = snprintf(buf, sizeof buf, "{\"up\":%llu,\"down\":%llu}", ru, rd);
        else if (c->wskind == 3) k = snprintf(buf, sizeof buf, "{\"inuse\":%llu,\"oslimit\":0}", proc_mem());
        else if (c->wskind == 2) { start_conns(c, 1); continue; }
        if (k > 0) ws_send(c, buf, (size_t)k);
    }
    /* Закрытые — вон из списка. */
    struct hc **pp = &cl->ws;
    while (*pp) {
        if ((*pp)->fd < 0) { struct hc *d = *pp; *pp = d->next; hc_unref(d); }
        else pp = &(*pp)->next;
    }
    ev_timer(ev, 1000, ws_tick, cl);
}

static void ws_read(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct hc *c = arg;
    unsigned char buf[2048];
    ssize_t r = read(fd, buf, sizeof buf);
    if (r <= 0 && !(r < 0 && errno == EAGAIN)) { ev_del(ev, fd); hc_close(c); return; }
    /* Кадр close (0x8) от клиента — закрываем; остальное (ping, текст) не нужно. */
    if (r > 0 && (buf[0] & 0x0F) == 0x8) { ev_del(ev, fd); hc_close(c); }
}

static void ws_accept(struct hc *c, int kind) {
    char acc_in[200], acc[64];
    unsigned char h[20];
    snprintf(acc_in, sizeof acc_in, "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", c->key);
    sha1((unsigned char *)acc_in, strlen(acc_in), h);
    b64(h, 20, acc);
    char resp[400];
    int n = snprintf(resp, sizeof resp, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
    set_nonblock(c->fd, 0);
    if (write_all(c->fd, resp, (size_t)n)) { hc_close(c); return; }
    set_nonblock(c->fd, 1);
    c->st = HS_WS;
    c->wskind = kind;
    c->refs++;
    c->next = c->cl->ws;
    c->cl->ws = c;
    ev_mod(c->cl->rt->ev, c->fd, EPOLLIN);
    ev_add(c->cl->rt->ev, c->fd, EPOLLIN, ws_read, c);
}

/* ---- разбор запроса --------------------------------------------------------------------- */

static int authorized(struct hc *c) {
    const char *sec = c->cl->secret;
    if (!sec[0]) return 1;
    if (!strncasecmp(c->auth, "Bearer ", 7) && !strcmp(c->auth + 7, sec)) return 1;
    char tok[300];
    q_param(c->query, "token", tok, sizeof tok);
    return tok[0] && !strcmp(tok, sec);
}

static void serve_ui(struct hc *c, const char *rel) {
    char path[1500];
    if (strstr(rel, "..")) { send_msg(c, 400, "bad path"); return; }
    snprintf(path, sizeof path, "%s/%s", c->cl->ui_dir, *rel ? rel : "index.html");
    struct stat st;
    if (!stat(path, &st) && S_ISDIR(st.st_mode)) strncat(path, "/index.html", sizeof path - strlen(path) - 1);
    FILE *f = fopen(path, "rb");
    if (!f) { send_msg(c, 404, "Resource not found"); return; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = n > 0 ? malloc((size_t)n) : NULL;
    if (n > 0 && (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n)) { fclose(f); free(buf); send_msg(c, 500, "read"); return; }
    fclose(f);
    const char *ext = strrchr(path, '.');
    const char *ct = !ext ? "application/octet-stream" : !strcmp(ext, ".html") ? "text/html; charset=utf-8"
                   : !strcmp(ext, ".js") ? "application/javascript" : !strcmp(ext, ".css") ? "text/css"
                   : !strcmp(ext, ".svg") ? "image/svg+xml" : !strcmp(ext, ".png") ? "image/png"
                   : !strcmp(ext, ".json") ? "application/json" : !strcmp(ext, ".woff2") ? "font/woff2"
                   : "application/octet-stream";
    send_raw(c, 200, ct, buf ? buf : "", (size_t)(n > 0 ? n : 0));
    free(buf);
}

static void route_req(struct hc *c, const char *body) {
    struct box_rt *rt = c->cl->rt;
    if (!strcmp(c->method, "OPTIONS")) { send_raw(c, 204, NULL, "", 0); return; }
    if (!strncmp(c->path, "/ui", 3) && (c->path[3] == '/' || !c->path[3])) {
        serve_ui(c, c->path[3] ? c->path + 4 : "");
        return;
    }
    if (!authorized(c)) { send_msg(c, 401, "Unauthorized"); return; }
    char path[1024];
    snprintf(path, sizeof path, "%s", c->path);
    url_decode(path);
    if (!strcmp(path, "/")) {
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "hello", jstr("clash"));
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strcmp(path, "/version")) {
        char v[64];
        snprintf(v, sizeof v, "sing-box %s", rt->set.sb_version);
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "version", jstr(v));
        jobj_set(o, "premium", jbool(1));
        jobj_set(o, "meta", jbool(1));
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strcmp(path, "/configs")) {
        if (strcmp(c->method, "GET")) { send_raw(c, 204, NULL, "", 0); return; }
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "port", jint(0));
        jobj_set(o, "socks-port", jint(0));
        jobj_set(o, "redir-port", jint(0));
        jobj_set(o, "tproxy-port", jint(0));
        jobj_set(o, "mixed-port", jint(0));
        jobj_set(o, "allow-lan", jbool(0));
        jobj_set(o, "bind-address", jstr("*"));
        jobj_set(o, "mode", jstr("rule"));
        jobj_set(o, "mode-list", jnew(J_ARR));
        jobj_set(o, "log-level", jstr("info"));
        jobj_set(o, "ipv6", jbool(0));
        jobj_set(o, "tun", jnull());
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strcmp(path, "/proxies")) {
        struct jval *o = proxies_all(rt);
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strncmp(path, "/proxies/", 9)) {
        char name[700];
        snprintf(name, sizeof name, "%s", path + 9);
        char *sl = strrchr(name, '/');
        if (sl && !strcmp(sl, "/delay")) { *sl = 0; start_delay(c, name, 0); return; }
        if (!strcmp(name, "GLOBAL")) {
            struct jval *all = proxies_all(rt);
            send_json(c, 200, jget(jget(all, "proxies"), "GLOBAL"));
            json_free(all);
            return;
        }
        if (!sb_outbound(rt->cfg, name)) { send_msg(c, 404, "Resource not found"); return; }
        if (!strcmp(c->method, "PUT") || !strcmp(c->method, "PATCH")) { do_select(c, name, body); return; }
        struct jval *o = proxy_obj(rt, name);
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strncmp(path, "/group", 6)) {
        if (!strcmp(path, "/group")) {
            struct jval *all = proxies_all(rt), *arr = jnew(J_ARR);
            const struct jval *ps = jget(all, "proxies");
            for (size_t i = 0; i < jlen(ps); i++)
                if (jget(ps->o[i].val, "all")) jarr_push(arr, jdup(ps->o[i].val));
            struct jval *o = jnew(J_OBJ);
            jobj_set(o, "proxies", arr);
            send_json(c, 200, o);
            json_free(o);
            json_free(all);
            return;
        }
        char name[700];
        snprintf(name, sizeof name, "%s", path + 7);
        char *sl = strrchr(name, '/');
        if (sl && !strcmp(sl, "/delay")) {
            *sl = 0;
            const struct jval *ob = sb_outbound(rt->cfg, name);
            if (!ob || sb_outbound_kind(ob) != SBO_GROUP) { send_msg(c, 404, "Resource not found"); return; }
            start_delay(c, name, 1);
            return;
        }
        if (!sb_outbound(rt->cfg, name)) { send_msg(c, 404, "Resource not found"); return; }
        struct jval *o = proxy_obj(rt, name);
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strcmp(path, "/connections")) {
        if (!strcmp(c->method, "DELETE")) {
            struct kjob *j = calloc(1, sizeof *j);
            j->c = c;
            j->rt = rt;
            snprintf(j->sock, sizeof j->sock, "%s", rt->sock);
            snprintf(j->id, sizeof j->id, "*");
            c->st = HS_WAIT;
            c->refs++;
            if (ev_spawn(rt->ev, kill_work, kill_done, j)) { c->refs--; free(j); send_msg(c, 500, "нет потока"); }
            return;
        }
        if (c->upgrade) { ws_accept(c, 2); start_conns(c, 1); return; }
        start_conns(c, 0);
        return;
    }
    if (!strncmp(path, "/connections/", 13) && !strcmp(c->method, "DELETE")) {
        struct kjob *j = calloc(1, sizeof *j);
        j->c = c;
        j->rt = rt;
        snprintf(j->sock, sizeof j->sock, "%s", rt->sock);
        snprintf(j->id, sizeof j->id, "%s", path + 13);
        c->st = HS_WAIT;
        c->refs++;
        if (ev_spawn(rt->ev, kill_work, kill_done, j)) { c->refs--; free(j); send_msg(c, 500, "нет потока"); }
        return;
    }
    if (!strcmp(path, "/traffic") || !strcmp(path, "/memory") || !strcmp(path, "/logs")) {
        int kind = path[1] == 't' ? 1 : path[1] == 'm' ? 3 : 4;
        if (c->upgrade) { ws_accept(c, kind); return; }
        if (kind == 1) {
            unsigned long long up, down;
            traffic_now(rt, &up, &down);
            char buf[120];
            int n = snprintf(buf, sizeof buf, "{\"up\":0,\"down\":0,\"upTotal\":%llu,\"downTotal\":%llu}\n", up, down);
            send_raw(c, 200, "application/json", buf, (size_t)n);
        } else send_raw(c, 200, "application/json", "{}\n", 3);
        return;
    }
    if (!strcmp(path, "/rules")) {
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "rules", jnew(J_ARR));
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strcmp(path, "/providers/proxies") || !strcmp(path, "/providers/rules")) {
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "providers", jnew(J_OBJ));
        send_json(c, 200, o);
        json_free(o);
        return;
    }
    if (!strncmp(path, "/dns/flush", 10) || !strncmp(path, "/cache/fakeip/flush", 19)) {
        send_raw(c, 204, NULL, "", 0);
        return;
    }
    send_msg(c, 404, "Resource not found");
}

static void parse_and_route(struct hc *c) {
    char *hdr_end = strstr(c->in, "\r\n\r\n");
    if (!hdr_end) return;
    /* Заголовки режутся strtok_r в копии: тело может прийти позже, и тогда весь запрос
     * разбирается заново из c->in — нули первого прохода в нём оборвали бы поиск конца
     * заголовков, и запрос ждал бы до предела буфера. */
    char *hdr = strndup(c->in, (size_t)(hdr_end - c->in));
    if (!hdr) { hc_close(c); return; }
    char *save;
    char *first = strtok_r(hdr, "\r\n", &save);
    char target[2048] = "";
    if (!first || sscanf(first, "%15s %2047s", c->method, target) != 2) { free(hdr); send_msg(c, 400, "bad request"); hc_close(c); return; }
    char *q = strchr(target, '?');
    if (q) { *q = 0; snprintf(c->query, sizeof c->query, "%s", q + 1); }
    snprintf(c->path, sizeof c->path, "%s", target);
    for (char *h = strtok_r(NULL, "\r\n", &save); h; h = strtok_r(NULL, "\r\n", &save)) {
        char *colon = strchr(h, ':');
        if (!colon) continue;
        *colon = 0;
        char *v = colon + 1;
        while (*v == ' ') v++;
        if (!strcasecmp(h, "Authorization")) snprintf(c->auth, sizeof c->auth, "%s", v);
        else if (!strcasecmp(h, "Sec-WebSocket-Key")) snprintf(c->key, sizeof c->key, "%s", v);
        else if (!strcasecmp(h, "Upgrade") && !strcasecmp(v, "websocket")) c->upgrade = 1;
        else if (!strcasecmp(h, "Origin")) snprintf(c->origin, sizeof c->origin, "%s", v);
        else if (!strcasecmp(h, "Content-Length")) c->clen = (size_t)atol(v);
    }
    free(hdr);
    c->body_off = (size_t)(hdr_end + 4 - c->in);
    if (c->in_n - c->body_off < c->clen) return;      /* тело ещё не пришло — ждём остаток */
    char *body = c->in + c->body_off;
    body[c->clen] = 0;
    route_req(c, c->clen ? body : NULL);
    if (c->st == HS_DONE) hc_close(c);
}

static void hc_read(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct hc *c = arg;
    if (c->st != HS_READ) {
        /* Ответ ждёт рабочего потока, а клиент что-то прислал или ушёл: читать нечего, и без
         * снятия с цикла epoll звал бы сюда снова и снова (EPOLLIN по уровню). Закроет
         * соединение тот, кто ответит (hc_close). */
        ev_del(ev, fd);
        return;
    }
    if (c->in_n + 4096 + 1 > c->in_cap) {
        size_t nc = c->in_cap ? c->in_cap * 2 : 8192;
        if (nc > (4u << 20)) { send_msg(c, 400, "too large"); hc_close(c); return; }
        char *ni = realloc(c->in, nc);
        if (!ni) { hc_close(c); return; }
        c->in = ni;
        c->in_cap = nc;
    }
    ssize_t r = read(fd, c->in + c->in_n, c->in_cap - c->in_n - 1);
    if (r <= 0) {
        if (r < 0 && errno == EAGAIN) return;
        ev_del(ev, fd);
        hc_close(c);
        return;
    }
    c->in_n += (size_t)r;
    c->in[c->in_n] = 0;
    parse_and_route(c);
}

static void hc_close(struct hc *c) {
    if (c->fd < 0) return;
    ev_del(c->cl->rt->ev, c->fd);
    close(c->fd);
    c->fd = -1;
    /* Ссылка соединения отпускается здесь; ссылки ждущих ответов и списка WebSocket — их
     * владельцами (обработчики, ws_tick). */
    c->st = HS_DONE;
    hc_unref(c);
}

/* Новое соединение: своя ссылка и место в cl->all. */
static void hc_track(struct clash *cl, struct hc *c) {
    c->cl = cl;
    c->refs = 1;
    if ((c->anext = cl->all)) c->anext->apprev = &c->anext;
    c->apprev = &cl->all;
    cl->all = c;
    cl->refs++;
}

static void accept_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct clash *cl = arg;
    for (;;) {
        int cfd = accept4(fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) return;
        struct hc *c = calloc(1, sizeof *c);
        if (!c) { close(cfd); continue; }
        c->fd = cfd;
        hc_track(cl, c);
        ev_add(ev, cfd, EPOLLIN, hc_read, c);
    }
}

int clash_start(struct box_rt *rt) {
    const struct jval *api = jget(jget(rt->cfg, "experimental"), "clash_api");
    const char *ctl = jgets(api, "external_controller");
    if (!api || !ctl || !*ctl) return 0;
    struct clash *cl = calloc(1, sizeof *cl);
    if (!cl) return -1;
    cl->rt = rt;
    cl->refs = 1;                /* таймер ws_tick */
    snprintf(cl->secret, sizeof cl->secret, "%s", jgets(api, "secret") ? jgets(api, "secret") : "");
    const char *ui = jgets(api, "external_ui");
    if (ui && *ui) {
        if (ui[0] == '/') snprintf(cl->ui_dir, sizeof cl->ui_dir, "%s", ui);
        else snprintf(cl->ui_dir, sizeof cl->ui_dir, "%s/%s", rt->opts->workdir ? rt->opts->workdir : ".", ui);
    }
    struct sockaddr_storage a;
    socklen_t l;
    if (net_parse_hostport(ctl, 9090, &a, &l)) { LOGE("clash_api: адрес %s не разобрался", ctl); free(cl); return -1; }
    cl->lfd = net_listen(&a, l, 0);
    if (cl->lfd < 0) { LOGE("clash_api: %s не слушается: %s", ctl, strerror(errno)); free(cl); return -1; }
    const struct jval *ao = jget(api, "access_control_allow_origin");
    if (ao && ao->t == J_STR) { cl->origins = jnew(J_ARR); jarr_push(cl->origins, jdup(ao)); }
    else if (ao && ao->t == J_ARR) cl->origins = jdup(ao);
    cl->allow_pna = jgetb(api, "access_control_allow_private_network", 0);
    ev_add(rt->ev, cl->lfd, EPOLLIN, accept_cb, cl);
    ev_timer(rt->ev, 1000, ws_tick, cl);
    rt->clash = cl;
    LOGI("clash_api: %s", ctl);
    return 0;
}

void clash_stop(struct box_rt *rt) {
    struct clash *cl = rt->clash;
    if (!cl) return;
    ev_del(rt->ev, cl->lfd);
    close(cl->lfd);
    /* Все соединения — закрыть: ждущие ответа рабочего потока увидят fd < 0 и только отпустят
     * свою ссылку; структура живёт, пока жива последняя (cl->refs). */
    cl->refs++;
    for (struct hc *c = cl->all, *n; c; c = n) {
        n = c->anext;               /* hc_close освобождает разве что c */
        hc_close(c);
    }
    for (struct hc *c = cl->ws, *n; c; c = n) { n = c->next; hc_unref(c); }   /* ссылки списка */
    cl->ws = NULL;
    /* Таймер ws_tick держит cl: структуру отпустит он, на ближайшем срабатывании. */
    cl->stopped = 1;
    rt->clash = NULL;
    cl_put(cl);
}
