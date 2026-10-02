/* Роутер DNS sing-box в коннекторе (BOX_CONNECTOR.md, раздел 3в).
 *
 * СЛУШАТЕЛИ — входы type: direct (у podkop и forkop это всегда DNS: dns-in 127.0.0.42:53,
 * source-dns-in :1603, входы здоровья 127.0.0.42:10053+) и внутренний для своих соединений
 * коннектора (dns_resolve_blocking).
 *
 * ПРАВИЛА — dns.rules по порядку, как у sing-box. Условие rule_set коннектор не сверяет сам:
 * списки держит резолвер steer (каналы — те же наборы, что у правил маршрута, перевод заводит их и
 * для правил DNS). Правило, которое совпало бы «если имя в наборе», спрашивает dnsd с опцией «не
 * пересылать» (S3): ответ — значит, имя в канале, и это ответ клиенту (fake-IP или настоящий адрес
 * с набором канала); REFUSED — имени в наборах нет, правило не совпало, идём дальше.
 *
 * СЕРВЕРЫ — dnsup.c. fakeip-сервер — это dnsd steer: поддельный адрес и подмена в ядре — его. */
#define _GNU_SOURCE
#include "runtime.h"
#include "dnsmsg.h"
#include "dnsup.h"
#include "sbconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <regex.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <poll.h>

#define DNSD_OPT_NOFORWARD 65001
#define DNSD_PORT 5300

struct listener {
    int fd, udp;
    char tag[128];
    struct dns_srv *s;
};

struct tcpconn {
    int fd;
    struct listener *l;
    struct sockaddr_storage peer;
    uint8_t buf[2 + 65535];
    size_t n;
    int refs;                   /* вопросы в пути: соединение закрывается после них */
    int closed;
};

struct upent { char tag[128]; struct dnsup *u; int fakeip; };

struct centry {
    char key[300];
    uint8_t *resp;
    size_t n;
    long long until_ms, stored_ms;
    struct centry *next;        /* цепочка корзины */
};

struct dns_srv {
    struct box_rt *rt;
    struct listener *ls;
    size_t nls;
    int dnsd_fd;
    struct qctx *dnsd_wait[65536];
    uint16_t dnsd_seq;
    uint64_t dnsd_retry;        /* таймер повтора вопросов к dnsd (он ещё не слушал) */
    struct upent *ups;
    size_t nups;
    const char *final;
    int strategy;               /* 0 — нет, 4 — ipv4_only, 6 — ipv6_only */
    int cache_off;
    struct centry **ctab;
    size_t cbuckets, cn, ccap;
    struct listener *internal;
    uint16_t internal_port;
};

struct qctx {
    struct dns_srv *s;
    struct listener *l;
    struct tcpconn *tc;         /* NULL — UDP */
    struct sockaddr_storage peer;
    socklen_t peerlen;
    uint8_t *q;
    size_t qn;
    struct dnsq dq;
    size_t next_rule;
    long rewrite_ttl;
    int strategy;               /* -1 — по dns.strategy */
    int disable_cache;
    int must_fake;              /* спросили dnsd ради fakeip-сервера: отказ — к dns.final */
    long long dnsd_since;       /* когда вопрос ушёл к dnsd (повтор после ECONNREFUSED) */
    /* Опции до правила над набором, которое ждёт ответа dnsd: не совпало — они возвращаются. */
    int opts_saved;
    long saved_ttl;
    int saved_strategy, saved_cache;
    char via[128];              /* сервер, которым отвечаем (для кэша) */
};

/* Защита указателя на резолвер для рабочих потоков (dns_resolve_blocking): остальное состояние —
 * только в потоке цикла. */
static pthread_mutex_t g_res_mu = PTHREAD_MUTEX_INITIALIZER;
static struct dnsup *g_res_up;

/* ---- ответ клиенту ---------------------------------------------------------------------- */

static void tc_unref(struct tcpconn *c) {
    if (--c->refs > 0 || !c->closed) return;
    close(c->fd);
    free(c);
}

static void reply(struct qctx *c, const uint8_t *r, size_t n) {
    if (!r || n < 12) goto done;
    uint8_t *out = malloc(n);
    if (!out) goto done;
    memcpy(out, r, n);
    out[0] = (uint8_t)(c->dq.id >> 8);
    out[1] = (uint8_t)c->dq.id;
    if (!c->tc) {
        size_t lim = c->dq.udp_size ? c->dq.udp_size : 512;
        if (n > lim) {
            /* Не влезло в датаграмму — заголовок и вопрос с TC: клиент переспросит по TCP. */
            size_t k = dns_empty_reply(c->q, &c->dq, dns_rcode(out, n), out, n);
            out[2] |= 0x02;
            n = k;
        }
        sendto(c->l->fd, out, n, 0, (struct sockaddr *)&c->peer, c->peerlen);
    } else if (!c->tc->closed) {
        uint8_t len[2] = { (uint8_t)(n >> 8), (uint8_t)n };
        if (write_all(c->tc->fd, len, 2) || write_all(c->tc->fd, out, n)) c->tc->closed = 1;
    }
    free(out);
done:
    if (c->tc) tc_unref(c->tc);
    free(c->q);
    free(c);
}

static void reply_rcode(struct qctx *c, int rcode) {
    uint8_t out[600];
    size_t n = dns_empty_reply(c->q, &c->dq, rcode, out, sizeof out);
    reply(c, n ? out : NULL, n);
}

/* ---- кэш -------------------------------------------------------------------------------- */

/* Ёмкость — dns.cache_capacity, иначе 1024, как у sing-box. Это не потолок ради потолка: у
 * podkop dnsmasq без своего кэша (cachesize 0), и каждый вопрос сети приходит сюда, а ответ
 * держит память — ёмкость задаёт человек. */
static void cache_key(char *k, size_t n, const char *srv, const struct dnsq *q) {
    snprintf(k, n, "%s|%u|%s", srv, q->qtype, q->name);
}

static size_t chash(const char *s, size_t m) {
    size_t h = 1469598103934665603ULL;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h % m;
}

static int cache_get(struct dns_srv *s, const char *srv, const struct dnsq *q, uint8_t **out, size_t *n) {
    if (s->cache_off || !s->ctab) return 0;
    char k[300];
    cache_key(k, sizeof k, srv, q);
    long long now = ev_now_ms();
    for (struct centry *e = s->ctab[chash(k, s->cbuckets)]; e; e = e->next)
        if (!strcmp(e->key, k)) {
            if (e->until_ms <= now) return 0;
            *out = malloc(e->n);
            if (!*out) return 0;
            memcpy(*out, e->resp, e->n);
            *n = e->n;
            dns_walk(*out, *n, -1, (now - e->stored_ms) / 1000, NULL, 0, NULL);
            return 1;
        }
    return 0;
}

static void cache_put(struct dns_srv *s, const char *srv, const struct dnsq *q, const uint8_t *r, size_t n) {
    if (s->cache_off || !s->ctab) return;
    int rc = dns_rcode(r, n);
    if (rc != 0 && rc != 3) return;
    uint8_t *copy = malloc(n);
    if (!copy) return;
    memcpy(copy, r, n);
    long ttl = dns_walk(copy, n, -1, 0, NULL, 0, NULL);
    if (ttl < 0) ttl = 30;            /* пустой ответ и NXDOMAIN — коротко */
    if (ttl > 3600) ttl = 3600;
    char k[300];
    cache_key(k, sizeof k, srv, q);
    size_t b = chash(k, s->cbuckets);
    for (struct centry *e = s->ctab[b]; e; e = e->next)
        if (!strcmp(e->key, k)) {
            free(e->resp);
            e->resp = copy;
            e->n = n;
            e->stored_ms = ev_now_ms();
            e->until_ms = e->stored_ms + ttl * 1000;
            return;
        }
    if (s->cn >= s->ccap) {
        /* Полон: выбрасываем просроченные; не нашлось — первую попавшуюся корзину целиком. */
        long long now = ev_now_ms();
        for (size_t i = 0; i < s->cbuckets && s->cn >= s->ccap; i++) {
            struct centry **pp = &s->ctab[i];
            while (*pp) {
                if ((*pp)->until_ms <= now || s->cn >= s->ccap * 2) {
                    struct centry *d = *pp;
                    *pp = d->next;
                    free(d->resp);
                    free(d);
                    s->cn--;
                } else pp = &(*pp)->next;
            }
        }
        if (s->cn >= s->ccap) {
            struct centry **pp = &s->ctab[b];
            while (*pp) { struct centry *d = *pp; *pp = d->next; free(d->resp); free(d); s->cn--; }
        }
    }
    struct centry *e = calloc(1, sizeof *e);
    if (!e) { free(copy); return; }
    snprintf(e->key, sizeof e->key, "%s", k);
    e->resp = copy;
    e->n = n;
    e->stored_ms = ev_now_ms();
    e->until_ms = e->stored_ms + ttl * 1000;
    e->next = s->ctab[b];
    s->ctab[b] = e;
    s->cn++;
}

/* ---- серверы ---------------------------------------------------------------------------- */

static struct upent *up_find(struct dns_srv *s, const char *tag) {
    for (size_t i = 0; i < s->nups; i++)
        if (!strcmp(s->ups[i].tag, tag)) return &s->ups[i];
    return NULL;
}

static void eval(struct qctx *c);
static void ask_dnsd(struct qctx *c, int must);

struct upwait { struct qctx *c; long rewrite; int disable_cache; char tag[128]; };

static void up_done(void *arg, const uint8_t *r, size_t n, const char *err) {
    struct upwait *w = arg;
    struct qctx *c = w->c;
    if (!r) {
        LOGD("dns: %s для %s: %s", w->tag, c->dq.name, err && *err ? err : "нет ответа");
        free(w);
        reply_rcode(c, 2);            /* SERVFAIL */
        return;
    }
    uint8_t *copy = malloc(n);
    if (!copy) { free(w); reply_rcode(c, 2); return; }
    memcpy(copy, r, n);
    if (!w->disable_cache) cache_put(c->s, w->tag, &c->dq, copy, n);
    if (w->rewrite >= 0) dns_walk(copy, n, w->rewrite, 0, NULL, 0, NULL);
    free(w);
    reply(c, copy, n);
    free(copy);
}

/* Ответ сервером tag. */
static void resolve_with(struct qctx *c, const char *tag) {
    struct dns_srv *s = c->s;
    int strat = c->strategy >= 0 ? c->strategy : s->strategy;
    if ((strat == 4 && c->dq.qtype == 28) || (strat == 6 && c->dq.qtype == 1)) {
        reply_rcode(c, 0);           /* only — пустой ответ на другое семейство */
        return;
    }
    struct upent *u = up_find(s, tag);
    if (!u) {
        LOGW("dns: сервера %s нет — SERVFAIL на %s", tag, c->dq.name);
        reply_rcode(c, 2);
        return;
    }
    if (u->fakeip) { ask_dnsd(c, 1); return; }
    uint8_t *cached;
    size_t cn;
    if (!c->disable_cache && cache_get(s, tag, &c->dq, &cached, &cn)) {
        if (c->rewrite_ttl >= 0) dns_walk(cached, cn, c->rewrite_ttl, 0, NULL, 0, NULL);
        reply(c, cached, cn);
        free(cached);
        return;
    }
    struct upwait *w = calloc(1, sizeof *w);
    if (!w) { reply_rcode(c, 2); return; }
    w->c = c;
    w->rewrite = c->rewrite_ttl;
    w->disable_cache = c->disable_cache;
    snprintf(w->tag, sizeof w->tag, "%s", tag);
    if (dnsup_ask(u->u, c->q, c->qn, up_done, w)) { free(w); reply_rcode(c, 2); }
}

/* ---- dnsd ------------------------------------------------------------------------------- */

/* Отвечает ли dnsd: вопрос «не пересылать» о несуществующем имени — ответ (REFUSED) приходит сразу,
 * без похода наверх. Блокирующий, до ms; только при запуске частей. 0 — ответил. */
static int dnsd_ready_wait(int fd, int ms) {
    uint8_t q[300], qo[400];
    struct dnsq dq;
    size_t qn = dns_build_query("steer-box-ready.invalid", 1, 0x5b0c, q, sizeof q);
    if (!qn || dnsq_parse(q, qn, &dq)) return -1;
    size_t n = dns_add_opt(q, qn, &dq, DNSD_OPT_NOFORWARD, qo, sizeof qo);
    if (!n) return -1;
    long long until = ev_now_ms() + ms;
    while (ev_now_ms() < until) {
        if (send(fd, qo, n, 0) < 0 && errno != ECONNREFUSED) usleep(20 * 1000);
        struct pollfd p = { fd, POLLIN, 0 };
        if (poll(&p, 1, 50) <= 0) continue;
        uint8_t r[600];
        ssize_t m = recv(fd, r, sizeof r, 0);
        if (m >= 12 && r[0] == 0x5b && r[1] == 0x0c) {
            /* Ответы на прежние попытки — дочитать: номер 0x5b0c мог бы потом совпасть с номером
             * настоящего вопроса. */
            while (poll(&p, 1, 20) > 0 && recv(fd, r, sizeof r, 0) >= 0) {}
            return 0;
        }
        if (m < 0) usleep(20 * 1000);       /* ECONNREFUSED: ещё не слушает */
    }
    return -1;
}

static void ask_dnsd(struct qctx *c, int must) {
    struct dns_srv *s = c->s;
    c->must_fake = must;
    if (s->dnsd_fd < 0) {
        if (must) { resolve_with(c, s->final); return; }
        eval(c);
        return;
    }
    uint8_t buf[700];
    size_t n = dns_add_opt(c->q, c->qn, &c->dq, DNSD_OPT_NOFORWARD, buf, sizeof buf);
    if (!n) { must ? resolve_with(c, s->final) : eval(c); return; }
    /* Свой номер транзакции: ответы всех вопросов приходят на один сокет. */
    uint16_t id = 0;
    for (int tries = 0; tries < 65536; tries++) {
        id = ++s->dnsd_seq;
        if (!s->dnsd_wait[id]) break;
    }
    if (s->dnsd_wait[id]) { reply_rcode(c, 2); return; }
    buf[0] = (uint8_t)(id >> 8);
    buf[1] = (uint8_t)id;
    s->dnsd_wait[id] = c;
    c->dnsd_since = ev_now_ms();
    if (send(s->dnsd_fd, buf, n, 0) != (ssize_t)n) {
        s->dnsd_wait[id] = NULL;
        must ? resolve_with(c, s->final) : eval(c);
    }
}

/* ПОВТОР ВОПРОСОВ К DNSD. dnsd не слушает (steer только стартует, резолвер перезапускается) —
 * ядро отвечает на вопрос ECONNREFUSED, и вопрос так и висел: клиент ждал своего повтора, около
 * двух секунд (выбросы в замере перезапуска на роутере — 3 с вместо 1). Теперь ждущие вопросы
 * уходят к dnsd снова через 50 мс; кто ждёт дольше двух секунд — идёт дальше по правилам, как при
 * отказе dnsd. */
#define DNSD_RETRY_MS 50
#define DNSD_GIVEUP_MS 2000

static void dnsd_resend(struct ev *ev, void *arg) {
    (void)ev;
    struct dns_srv *s = arg;
    s->dnsd_retry = 0;
    long long now = ev_now_ms();
    for (unsigned id = 0; id < 65536; id++) {
        struct qctx *c = s->dnsd_wait[id];
        if (!c) continue;
        uint8_t buf[700];
        size_t n = now - c->dnsd_since < DNSD_GIVEUP_MS ?
                   dns_add_opt(c->q, c->qn, &c->dq, DNSD_OPT_NOFORWARD, buf, sizeof buf) : 0;
        if (n) {
            buf[0] = (uint8_t)(id >> 8);
            buf[1] = (uint8_t)id;
            if (send(s->dnsd_fd, buf, n, 0) == (ssize_t)n) continue;
        }
        s->dnsd_wait[id] = NULL;
        c->must_fake ? resolve_with(c, s->final) : eval(c);
    }
}

static void dnsd_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct dns_srv *s = arg;
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n < 0) {
            if (errno == ECONNREFUSED) {
                if (!s->dnsd_retry) s->dnsd_retry = ev_timer(ev, DNSD_RETRY_MS, dnsd_resend, s);
                continue;
            }
            return;
        }
        if (n < 12) continue;
        uint16_t id = (uint16_t)((buf[0] << 8) | buf[1]);
        struct qctx *c = s->dnsd_wait[id];
        if (!c) continue;
        s->dnsd_wait[id] = NULL;
        if (dns_rcode(buf, (size_t)n) == 5) {
            /* REFUSED: имени нет ни в одном канале. */
            if (c->must_fake) resolve_with(c, s->final);
            else eval(c);
            continue;
        }
        if (c->rewrite_ttl >= 0) dns_walk(buf, (size_t)n, c->rewrite_ttl, 0, NULL, 0, NULL);
        reply(c, buf, (size_t)n);
    }
}

/* ---- правила ---------------------------------------------------------------------------- */

/* M_UNSUP — в правиле условие, которого коннектор не сверяет: правило не совпадает ни само, ни
 * под invert (не «не совпало» — его инверсия была бы совпадением со всеми вопросами). */
enum mres { M_NO, M_YES, M_DEFER, M_UNSUP };

static int list_has(const struct jval *v, const char *s) {
    long n = jstrlist(v, NULL, 0);
    for (long i = 0; i < n; i++) {
        const char *e = v->t == J_ARR ? v->a[i]->s : v->s;
        if (!strcmp(e, s)) return 1;
    }
    return 0;
}

static int suffix_match(const char *name, const char *suf) {
    size_t nl = strlen(name), sl = strlen(suf);
    if (suf[0] == '.') return nl > sl && !strcasecmp(name + nl - sl, suf);
    if (nl == sl) return !strcasecmp(name, suf);
    return nl > sl && name[nl - sl - 1] == '.' && !strcasecmp(name + nl - sl, suf);
}

static int regex_match(const char *name, const char *re) {
    regex_t r;
    if (regcomp(&r, re, REG_EXTENDED | REG_NOSUB | REG_ICASE)) return 0;
    int m = !regexec(&r, name, 0, NULL, 0);
    regfree(&r);
    return m;
}

static int ip_in(const struct sockaddr_storage *a, const char *cidr) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", cidr);
    char *sl = strchr(buf, '/');
    int plen = -1;
    if (sl) { *sl = 0; plen = atoi(sl + 1); }
    uint8_t net[16], ip[16];
    int fam;
    if (inet_pton(AF_INET, buf, net) == 1) fam = 4;
    else if (inet_pton(AF_INET6, buf, net) == 1) fam = 6;
    else return 0;
    if (a->ss_family == AF_INET) {
        if (fam != 4) return 0;
        memcpy(ip, &((const struct sockaddr_in *)a)->sin_addr, 4);
    } else if (a->ss_family == AF_INET6) {
        const struct in6_addr *v6 = &((const struct sockaddr_in6 *)a)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(v6)) {
            if (fam != 4) return 0;
            memcpy(ip, &v6->s6_addr[12], 4);
        } else {
            if (fam != 6) return 0;
            memcpy(ip, v6, 16);
        }
    } else return 0;
    int bits = plen < 0 ? (fam == 4 ? 32 : 128) : plen;
    for (int i = 0; i < bits; i++)
        if (((ip[i / 8] ^ net[i / 8]) >> (7 - i % 8)) & 1) return 0;
    return 1;
}

static enum mres match_rule(struct qctx *c, const struct jval *r);

static enum mres match_default(struct qctx *c, const struct jval *r) {
    /* Условия, которых коннектор не знает (процесс, Wi-Fi, clash_mode, ответные ip_cidr), — правило
     * не совпадает: лучше пропустить чужое правило, чем применить его не к тем вопросам. */
    static const char *known[] = { "type", "mode", "rules", "invert", "action", "server", "strategy",
        "disable_cache", "rewrite_ttl", "client_subnet", "method", "no_drop", "rcode", "answer", "ns",
        "extra", "outbound", "inbound", "query_type", "domain", "domain_suffix", "domain_keyword",
        "domain_regex", "rule_set", "source_ip_cidr", "ip_version", "network", NULL };
    for (size_t i = 0; i < jlen(r); i++) {
        int ok = 0;
        for (int k = 0; known[k]; k++)
            if (!strcmp(r->o[i].key, known[k])) ok = 1;
        if (!ok) return M_UNSUP;
    }
    const struct jval *v;
    if ((v = jget(r, "inbound")) && !list_has(v, c->l->tag)) return M_NO;
    if ((v = jget(r, "query_type"))) {
        int hit = 0;
        for (size_t i = 0; i < (v->t == J_ARR ? v->len : 1); i++) {
            const struct jval *e = v->t == J_ARR ? v->a[i] : v;
            uint16_t t = e->t == J_NUM ? (uint16_t)e->i : e->t == J_STR ? dns_type_num(e->s) : 0;
            if (t == c->dq.qtype) hit = 1;
        }
        if (!hit) return M_NO;
    }
    if ((v = jget(r, "ip_version"))) {
        long ver = v->t == J_NUM ? v->i : 0;
        if ((ver == 4 && c->dq.qtype != 1) || (ver == 6 && c->dq.qtype != 28)) return M_NO;
    }
    if ((v = jget(r, "network")) && !list_has(v, c->tc ? "tcp" : "udp")) return M_NO;
    if ((v = jget(r, "source_ip_cidr"))) {
        long n = jstrlist(v, NULL, 0);
        int hit = 0;
        for (long i = 0; i < n && !hit; i++)
            hit = ip_in(&c->peer, v->t == J_ARR ? v->a[i]->s : v->s);
        if (!hit) return M_NO;
    }
    int has_dest = 0, dest_hit = 0;
    static const char *dk[] = { "domain", "domain_suffix", "domain_keyword", "domain_regex" };
    for (int k = 0; k < 4 && !dest_hit; k++) {
        if (!(v = jget(r, dk[k]))) continue;
        has_dest = 1;
        long n = jstrlist(v, NULL, 0);
        for (long i = 0; i < n && !dest_hit; i++) {
            const char *e = v->t == J_ARR ? v->a[i]->s : v->s;
            if (k == 0) dest_hit = !strcasecmp(c->dq.name, e);
            else if (k == 1) dest_hit = suffix_match(c->dq.name, e);
            else if (k == 2) dest_hit = strcasestr(c->dq.name, e) != NULL;
            else dest_hit = regex_match(c->dq.name, e);
        }
    }
    if (dest_hit) return M_YES;
    if (jget(r, "rule_set")) return M_DEFER;
    return has_dest ? M_NO : M_YES;
}

static enum mres match_rule(struct qctx *c, const struct jval *r) {
    enum mres m;
    const char *type = jgets(r, "type");
    if (type && !strcmp(type, "logical")) {
        const char *mode = jgets(r, "mode");
        int is_and = mode && !strcmp(mode, "and");
        const struct jval *sub = jget(r, "rules");
        int any_defer = 0, any_yes = 0, any_no = 0, any_unsup = 0;
        for (size_t i = 0; i < jlen(sub); i++) {
            enum mres x = match_rule(c, jat(sub, i));
            if (x == M_YES) any_yes = 1;
            else if (x == M_DEFER) any_defer = 1;
            else if (x == M_UNSUP) any_unsup = 1;
            else any_no = 1;
        }
        if (is_and) m = any_no ? M_NO : any_unsup ? M_UNSUP : any_defer ? M_DEFER : M_YES;
        else m = any_yes ? M_YES : any_unsup ? M_UNSUP : any_defer ? M_DEFER : M_NO;
    } else m = match_default(c, r);
    if (jgetb(r, "invert", 0)) {
        if (m == M_UNSUP) return M_UNSUP;
        if (m == M_DEFER) return M_NO;   /* «имя не в наборе» dnsd не отвечает — не угадываем */
        return m == M_YES ? M_NO : M_YES;
    }
    return m;
}

static int rcode_num(const char *s) {
    if (!s) return 0;
    static const struct { const char *n; int v; } t[] = { { "NOERROR", 0 }, { "FORMERR", 1 },
        { "SERVFAIL", 2 }, { "NXDOMAIN", 3 }, { "NOTIMP", 4 }, { "REFUSED", 5 } };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (!strcasecmp(s, t[i].n)) return t[i].v;
    return atoi(s);
}

static void apply_options(struct qctx *c, const struct jval *r) {
    const struct jval *v;
    if ((v = jget(r, "rewrite_ttl")) && v->t == J_NUM) c->rewrite_ttl = v->i;
    if (jget(r, "disable_cache")) c->disable_cache = jgetb(r, "disable_cache", 0);
    const char *st = jgets(r, "strategy");
    if (st) c->strategy = !strcmp(st, "ipv4_only") ? 4 : !strcmp(st, "ipv6_only") ? 6 : 0;
}

static void eval(struct qctx *c) {
    struct dns_srv *s = c->s;
    if (c->opts_saved) {
        /* Сюда вернулись после правила над набором, которое не совпало (REFUSED, отказ dnsd). */
        c->rewrite_ttl = c->saved_ttl;
        c->strategy = c->saved_strategy;
        c->disable_cache = c->saved_cache;
        c->opts_saved = 0;
    }
    const struct jval *rules = jget(jget(s->rt->cfg, "dns"), "rules");
    while (c->next_rule < jlen(rules)) {
        const struct jval *r = jat(rules, c->next_rule++);
        enum mres m = match_rule(c, r);
        if (m == M_NO || m == M_UNSUP) continue;
        const char *act = jgets(r, "action");
        if (!act) act = "route";
        if (m == M_DEFER) {
            /* Правило «имя в наборе»: спросить dnsd. Свои опции (rewrite_ttl) — уже сейчас: ответ
             * dnsd и есть ответ этого правила. route-options с набором — не откладывается
             * (опции без ответа), его совпадение неизвестно; пропускаем. */
            if (!strcmp(act, "route") || !strcmp(act, "reject")) {
                if (c->l == s->internal) continue;      /* свои соединения — настоящие адреса */
                if (!strcmp(act, "route")) {
                    c->saved_ttl = c->rewrite_ttl;
                    c->saved_strategy = c->strategy;
                    c->saved_cache = c->disable_cache;
                    c->opts_saved = 1;
                    apply_options(c, r);
                }
                ask_dnsd(c, 0);
                return;
            }
            continue;
        }
        if (!strcmp(act, "route-options")) { apply_options(c, r); continue; }
        if (!strcmp(act, "reject")) {
            const char *method = jgets(r, "method");
            if (method && !strcmp(method, "drop")) { reply(c, NULL, 0); return; }
            reply_rcode(c, 5);
            return;
        }
        if (!strcmp(act, "predefined")) {
            reply_rcode(c, rcode_num(jgets(r, "rcode")));
            return;
        }
        if (!strcmp(act, "route")) {
            apply_options(c, r);
            const char *srv = jgets(r, "server");
            struct upent *u = srv ? up_find(s, srv) : NULL;
            if (u && u->fakeip && c->l == s->internal) {
                /* Свои соединения коннектора идут по настоящим адресам: поддельный адрес у
                 * сокета роутера в туннель не превратится. */
                resolve_with(c, s->final);
                return;
            }
            resolve_with(c, srv ? srv : s->final);
            return;
        }
    }
    resolve_with(c, s->final);
}

/* ---- приём вопросов --------------------------------------------------------------------- */

static void handle_query(struct listener *l, struct tcpconn *tc, const uint8_t *buf, size_t n,
                         const struct sockaddr_storage *peer, socklen_t peerlen) {
    struct qctx *c = calloc(1, sizeof *c);
    if (!c) return;
    c->s = l->s;
    c->l = l;
    c->tc = tc;
    if (tc) tc->refs++;
    c->peer = *peer;
    c->peerlen = peerlen;
    c->rewrite_ttl = -1;
    c->strategy = -1;
    c->q = malloc(n);
    if (!c->q) { if (tc) tc_unref(tc); free(c); return; }
    memcpy(c->q, buf, n);
    c->qn = n;
    if (dnsq_parse(buf, n, &c->dq)) {
        /* Не вопрос — FORMERR, если хотя бы заголовок есть. */
        if (n >= 12) {
            c->dq.id = (uint16_t)((buf[0] << 8) | buf[1]);
            c->dq.qend = 12;
            uint8_t out[12];
            memcpy(out, buf, 12);
            out[2] = 0x80;
            out[3] = 1;
            out[4] = out[5] = out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
            reply(c, out, 12);
        } else reply(c, NULL, 0);
        return;
    }
    eval(c);
}

static void udp_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)ev; (void)e;
    struct listener *l = arg;
    uint8_t buf[4096];
    for (int i = 0; i < 64; i++) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof peer;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&peer, &pl);
        if (n <= 0) return;
        handle_query(l, NULL, buf, (size_t)n, &peer, pl);
    }
}

static void tcpc_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    struct tcpconn *c = arg;
    for (;;) {
        ssize_t r = read(fd, c->buf + c->n, sizeof c->buf - c->n);
        if (r <= 0) {
            if (r < 0 && errno == EAGAIN) break;
            ev_del(ev, fd);
            c->closed = 1;
            c->refs++;
            tc_unref(c);
            return;
        }
        c->n += (size_t)r;
        while (c->n >= 2) {
            size_t ml = (size_t)(c->buf[0] << 8 | c->buf[1]);
            if (c->n < 2 + ml) break;
            if (ml >= 12) handle_query(c->l, c, c->buf + 2, ml, &c->peer, sizeof c->peer);
            memmove(c->buf, c->buf + 2 + ml, c->n - 2 - ml);
            c->n -= 2 + ml;
        }
        if (c->n == sizeof c->buf) {
            ev_del(ev, fd);
            c->closed = 1;
            c->refs++;
            tc_unref(c);
            return;
        }
    }
    (void)e;
}

static void tcpl_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct listener *l = arg;
    for (;;) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof peer;
        int cfd = accept4(fd, (struct sockaddr *)&peer, &pl, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) return;
        struct tcpconn *c = calloc(1, sizeof *c);
        if (!c) { close(cfd); continue; }
        c->fd = cfd;
        c->l = l;
        c->peer = peer;
        ev_add(ev, cfd, EPOLLIN, tcpc_cb, c);
    }
}

/* ---- старт и останов -------------------------------------------------------------------- */

static int add_listener(struct dns_srv *s, const char *tag, const struct sockaddr_storage *a, socklen_t l,
                        int udp) {
    int fd = net_listen(a, l, udp);
    char where[80];
    net_fmt((const struct sockaddr *)a, where, sizeof where);
    if (fd < 0) {
        LOGE("dns: вход %s на %s (%s) не встал: %s", tag, where, udp ? "udp" : "tcp", strerror(errno));
        return -1;
    }
    struct listener *nl = realloc(s->ls, (s->nls + 1) * sizeof *nl);
    if (!nl) { close(fd); return -1; }
    s->ls = nl;
    struct listener *x = &s->ls[s->nls++];
    memset(x, 0, sizeof *x);
    x->fd = fd;
    x->udp = udp;
    x->s = s;
    snprintf(x->tag, sizeof x->tag, "%s", tag);
    return 0;
}

static void server_egress(struct box_rt *rt, const struct jval *srv, struct egress *eg) {
    char err[200];
    const char *det = jgets(srv, "detour");
    if (rt_egress(rt, det, eg, err, sizeof err)) {
        /* Выход detour ещё без устройства (steer только поднимается): идём меткой выхода —
         * это его таблица маршрутизации, и первый вопрос после подъёма уйдёт туда же. */
        memset(eg, 0, sizeof *eg);
        eg->mark = rt->default_mark;
        LOGD("dns: сервер %s: %s", jgets(srv, "tag"), err);
    }
    const char *bi = jgets(srv, "bind_interface");
    if (bi) snprintf(eg->dev, sizeof eg->dev, "%s", bi);
}

int dns_start(struct box_rt *rt) {
    struct dns_srv *s = calloc(1, sizeof *s);
    if (!s) return -1;
    s->rt = rt;
    s->dnsd_fd = -1;
    const struct jval *dns = jget(rt->cfg, "dns");
    const struct jval *servers = jget(dns, "servers");
    s->ups = calloc(jlen(servers) + 1, sizeof *s->ups);
    /* Сначала серверы без domain_resolver (им резолвер не нужен), потом остальные: резолвер
     * сервера — другой сервер, и он должен уже быть. Два прохода хватает для цепочки глубины два
     * (DoH через bootstrap) — так пишут podkop и forkop; глубже — по третьему проходу и т. д. */
    for (int pass = 0; pass < 4; pass++)
        for (size_t i = 0; i < jlen(servers); i++) {
            const struct jval *sv = jat(servers, i);
            const char *tag = jgets(sv, "tag");
            if (!tag || up_find(s, tag)) continue;
            const char *type = jgets(sv, "type");
            struct upent *e = &s->ups[s->nups];
            if (type && !strcmp(type, "fakeip")) {
                snprintf(e->tag, sizeof e->tag, "%s", tag);
                e->fakeip = 1;
                s->nups++;
                continue;
            }
            const struct jval *dr = jget(sv, "domain_resolver");
            const char *rtag = dr ? (dr->t == J_STR ? dr->s : jgets(dr, "server")) : NULL;
            if (!rtag) {
                const struct jval *ddr = jget(jget(rt->cfg, "route"), "default_domain_resolver");
                rtag = ddr ? (ddr->t == J_STR ? ddr->s : jgets(ddr, "server")) : NULL;
                if (rtag && !strcmp(rtag, tag)) rtag = NULL;
            }
            struct upent *res = rtag ? up_find(s, rtag) : NULL;
            unsigned char tmp[16];
            const char *host = jgets(sv, "server");
            int literal = host && (inet_pton(AF_INET, host, tmp) == 1 || inet_pton(AF_INET6, host, tmp) == 1);
            if (rtag && !res && !literal && pass < 3) continue;        /* резолвер ещё не заведён */
            struct egress eg;
            server_egress(rt, sv, &eg);
            struct dnsup *u = dnsup_new(rt->ev, sv, &eg, res && !res->fakeip ? res->u : NULL);
            if (!u) {
                if (pass == 3) LOGW("dns: сервер %s (%s) не заводится", tag, type ? type : "?");
                continue;
            }
            snprintf(e->tag, sizeof e->tag, "%s", tag);
            e->u = u;
            s->nups++;
        }
    s->final = jgets(dns, "final");
    if (!s->final && s->nups) s->final = s->ups[0].tag;
    if (!s->final) s->final = "";
    const char *st = jgets(dns, "strategy");
    s->strategy = st && !strcmp(st, "ipv4_only") ? 4 : st && !strcmp(st, "ipv6_only") ? 6 : 0;
    s->cache_off = jgetb(dns, "disable_cache", 0);
    s->ccap = (size_t)jgeti(dns, "cache_capacity", 1024);
    if (s->ccap < 64) s->ccap = 64;
    s->cbuckets = s->ccap;
    s->ctab = calloc(s->cbuckets, sizeof *s->ctab);
    /* Сокет к dnsd steer. */
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in da = { .sin_family = AF_INET, .sin_port = htons(DNSD_PORT) };
    da.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd >= 0 && !connect(fd, (struct sockaddr *)&da, sizeof da)) {
        s->dnsd_fd = fd;
        /* Слушатели — когда dnsd уже отвечает: имя из списка, спрошенное раньше, получило бы не
         * поддельный адрес, а ожидание (dnsd_resend). При запуске коннектора dnsd поднимается
         * вместе с steerd, это доли секунды; при перезапуске частей он уже работает. */
        if (dnsd_ready_wait(fd, 3000)) LOGW("dns: резолвер steer не ответил за 3 с — начинаю без него");
        ev_add(rt->ev, fd, EPOLLIN, dnsd_cb, s);
    } else if (fd >= 0) close(fd);
    /* Слушатели. */
    const struct jval *ins = jget(rt->cfg, "inbounds");
    for (size_t i = 0; i < jlen(ins); i++) {
        const struct jval *in = jat(ins, i);
        const char *type = jgets(in, "type");
        if (!type || strcmp(type, "direct")) continue;
        const char *tag = jgets(in, "tag");
        const char *listen = jgets(in, "listen");
        struct sockaddr_storage a;
        socklen_t l;
        if (net_parse_ip(listen ? listen : "0.0.0.0", (uint16_t)jgeti(in, "listen_port", 53), &a, &l)) {
            LOGE("dns: вход %s: адрес %s не разобрался", tag, listen ? listen : "");
            continue;
        }
        const struct jval *net = jget(in, "network");
        int want_udp = !net || list_has(net, "udp"), want_tcp = !net || list_has(net, "tcp");
        if (want_udp) add_listener(s, tag ? tag : "direct", &a, l, 1);
        if (want_tcp) add_listener(s, tag ? tag : "direct", &a, l, 0);
    }
    /* Внутренний вход — своим соединениям коннектора (dns_resolve_blocking). */
    struct sockaddr_storage ia;
    socklen_t il;
    net_parse_ip("127.0.0.1", 0, &ia, &il);
    if (!add_listener(s, "__internal", &ia, il, 1)) {
        struct sockaddr_storage got;
        socklen_t gl = sizeof got;
        getsockname(s->ls[s->nls - 1].fd, (struct sockaddr *)&got, &gl);
        s->internal_port = net_port((struct sockaddr *)&got);
    }
    for (size_t i = 0; i < s->nls; i++) {
        struct listener *x = &s->ls[i];
        if (!strcmp(x->tag, "__internal")) s->internal = x;
        ev_add(rt->ev, x->fd, EPOLLIN, x->udp ? udp_cb : tcpl_cb, x);
    }
    /* Резолвер своих соединений: route.default_domain_resolver, иначе dns.final. */
    const struct jval *ddr = jget(jget(rt->cfg, "route"), "default_domain_resolver");
    const char *rtag = ddr ? (ddr->t == J_STR ? ddr->s : jgets(ddr, "server")) : NULL;
    struct upent *ru = up_find(s, rtag ? rtag : s->final);
    if (!ru || ru->fakeip) ru = up_find(s, s->final);
    pthread_mutex_lock(&g_res_mu);
    if (g_res_up) dnsup_unref(g_res_up);
    g_res_up = ru && ru->u ? ru->u : NULL;
    if (g_res_up) dnsup_ref(g_res_up);
    pthread_mutex_unlock(&g_res_mu);
    rt->dns = s;
    LOGI("dns: входов %zu, серверов %zu, final %s", s->nls - 1, s->nups, s->final);
    return 0;
}

void dns_stop(struct box_rt *rt) {
    struct dns_srv *s = rt->dns;
    if (!s) return;
    for (size_t i = 0; i < s->nls; i++) {
        ev_del(rt->ev, s->ls[i].fd);
        close(s->ls[i].fd);
    }
    free(s->ls);
    if (s->dnsd_retry) ev_timer_cancel(rt->ev, s->dnsd_retry);
    if (s->dnsd_fd >= 0) { ev_del(rt->ev, s->dnsd_fd); close(s->dnsd_fd); }
    /* Вопросы, ждавшие dnsd, — SERVFAIL: их соединения ещё открыты. Слушатели уже закрыты,
     * поэтому ответ по UDP уйдёт в закрытый сокет — это тот же исход, что потеря датаграммы. */
    for (size_t i = 0; i < 65536; i++)
        if (s->dnsd_wait[i]) { free(s->dnsd_wait[i]->q); free(s->dnsd_wait[i]); }
    for (size_t i = 0; i < s->nups; i++) if (s->ups[i].u) dnsup_unref(s->ups[i].u);
    free(s->ups);
    for (size_t i = 0; i < s->cbuckets; i++)
        for (struct centry *e = s->ctab[i], *n; e; e = n) { n = e->next; free(e->resp); free(e); }
    free(s->ctab);
    free(s);
    rt->dns = NULL;
}

/* ---- свои соединения коннектора --------------------------------------------------------- */

/* Кэш своих разрешений: замер задержки, загрузки и mixed спрашивают одни и те же имена, и без
 * кэша каждый замер платил бы круг до сервера DNS (у DoH через выход — сотни миллисекунд), а
 * показывал бы его как задержку выхода. Срок — TTL ответа (не меньше 30 с, не больше часа). */
struct rcache { char name[256]; struct sockaddr_storage a[8]; socklen_t l[8]; int n; long long until; };
static struct rcache g_rc[64];
static pthread_mutex_t g_rc_mu = PTHREAD_MUTEX_INITIALIZER;

static int rc_get(const char *name, struct sockaddr_storage *out, socklen_t *lens, int max) {
    long long now = ev_now_ms();
    int n = 0;
    pthread_mutex_lock(&g_rc_mu);
    for (size_t i = 0; i < sizeof g_rc / sizeof g_rc[0]; i++)
        if (g_rc[i].n && g_rc[i].until > now && !strcasecmp(g_rc[i].name, name)) {
            n = g_rc[i].n < max ? g_rc[i].n : max;
            memcpy(out, g_rc[i].a, (size_t)n * sizeof *out);
            memcpy(lens, g_rc[i].l, (size_t)n * sizeof *lens);
            break;
        }
    pthread_mutex_unlock(&g_rc_mu);
    return n;
}

static void rc_put(const char *name, const struct sockaddr_storage *a, const socklen_t *l, int n, long ttl) {
    if (n <= 0) return;
    if (ttl < 30) ttl = 30;
    if (ttl > 3600) ttl = 3600;
    long long now = ev_now_ms();
    pthread_mutex_lock(&g_rc_mu);
    size_t slot = 0;
    for (size_t i = 0; i < sizeof g_rc / sizeof g_rc[0]; i++) {
        if (!strcasecmp(g_rc[i].name, name) || g_rc[i].until <= now) { slot = i; break; }
        if (g_rc[i].until < g_rc[slot].until) slot = i;
    }
    struct rcache *e = &g_rc[slot];
    snprintf(e->name, sizeof e->name, "%s", name);
    e->n = n > 8 ? 8 : n;
    memcpy(e->a, a, (size_t)e->n * sizeof *a);
    memcpy(e->l, l, (size_t)e->n * sizeof *l);
    e->until = now + ttl * 1000;
    pthread_mutex_unlock(&g_rc_mu);
}

int dns_resolve_blocking(struct box_rt *rt, const char *name, struct sockaddr_storage *out,
                         socklen_t *lens, int max) {
    (void)rt;
    if (!net_parse_ip(name, 0, &out[0], &lens[0])) return 1;
    int cached = rc_get(name, out, lens, max);
    if (cached) return cached;
    pthread_mutex_lock(&g_res_mu);
    struct dnsup *u = g_res_up;
    if (u) dnsup_ref(u);
    pthread_mutex_unlock(&g_res_mu);
    if (!u) return net_resolve(name, 0, out, lens, max);
    int n = 0;
    long ttl_min = -1;
    for (int fam = 0; fam < 2 && n < max; fam++) {
        uint8_t q[512], r[4096];
        size_t qn = dns_build_query(name, fam ? 28 : 1, (uint16_t)(rand() & 0xffff), q, sizeof q);
        long rn = qn ? dnsup_ask_blocking(u, q, qn, r, sizeof r, DNSUP_TIMEOUT_MS) : -1;
        if (rn <= 0) continue;
        struct dns_ip ips[8];
        int ni = 0;
        long t = dns_walk(r, (size_t)rn, -1, 0, ips, 8, &ni);
        if (t > 0 && (ttl_min < 0 || t < ttl_min)) ttl_min = t;
        for (int i = 0; i < ni && n < max; i++) {
            memset(&out[n], 0, sizeof out[n]);
            if (ips[i].family == 4) {
                struct sockaddr_in *s4 = (struct sockaddr_in *)&out[n];
                s4->sin_family = AF_INET;
                memcpy(&s4->sin_addr, ips[i].a, 4);
                lens[n++] = sizeof *s4;
            } else {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&out[n];
                s6->sin6_family = AF_INET6;
                memcpy(&s6->sin6_addr, ips[i].a, 16);
                lens[n++] = sizeof *s6;
            }
        }
    }
    dnsup_unref(u);
    rc_put(name, out, lens, n, ttl_min);
    return n;
}

static int box_resolver(const char *host, struct sockaddr_storage *out, socklen_t *lens, int max) {
    return dns_resolve_blocking(g_rt, host, out, lens, max);
}

void dns_install_resolver(void) { net_set_resolver(box_resolver); }
