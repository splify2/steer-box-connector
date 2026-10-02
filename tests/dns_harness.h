/* Обвязка стендов роутера DNS (dns.c): подставные серверы (dnsup), подставной резолвер steer
 * (dnsd на 127.0.0.1:5300 — отвечает REFUSED, то есть «имени нет в каналах»), клиент UDP и
 * запуск частей по конфигу из строки. Подключается после #include "../src/dns.c". */
#ifndef BOX_TEST_DNS_HARNESS_H
#define BOX_TEST_DNS_HARNESS_H
#include "check.h"
#include <pthread.h>
#include <fcntl.h>

struct box_rt *g_rt;

/* ---- подставной сервер: запоминает, кого спросили; отвечает A 1.2.3.4 с TTL 300 ---------- */
struct dnsup { char tag[128]; };
static char g_asked[128];
static int g_sync_answer = 1;               /* 0 — вопрос повисает, ответ даёт сам стенд */
static dnsup_cb g_pend_cb;
static void *g_pend_arg;
static uint8_t g_pend_q[512];
static size_t g_pend_qn;

static size_t answer_a(const uint8_t *q, size_t qn, uint8_t *out) {
    struct dnsq dq;
    if (dnsq_parse(q, qn, &dq)) return 0;
    memcpy(out, q, dq.qend);
    out[2] = 0x81; out[3] = 0x80;
    out[6] = 0; out[7] = 1; out[8] = out[9] = out[10] = out[11] = 0;
    static const uint8_t rr[] = { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x01, 0x2C, 0, 4, 1, 2, 3, 4 };
    memcpy(out + dq.qend, rr, sizeof rr);
    return dq.qend + sizeof rr;
}

struct dnsup *dnsup_new(struct ev *ev, const struct jval *cfg, const struct egress *eg, struct dnsup *r) {
    (void)ev; (void)eg; (void)r;
    struct dnsup *u = calloc(1, sizeof *u);
    snprintf(u->tag, sizeof u->tag, "%s", jgets(cfg, "tag"));
    return u;
}
void dnsup_ref(struct dnsup *u) { (void)u; }
void dnsup_unref(struct dnsup *u) { (void)u; }
const char *dnsup_tag(const struct dnsup *u) { return u->tag; }
long dnsup_ask_blocking(struct dnsup *u, const uint8_t *q, size_t n, uint8_t *resp, size_t cap, int t) {
    (void)u; (void)q; (void)n; (void)resp; (void)cap; (void)t;
    return -1;
}
int dnsup_ask(struct dnsup *u, const uint8_t *q, size_t n, dnsup_cb cb, void *arg) {
    snprintf(g_asked, sizeof g_asked, "%s", u->tag);
    if (!g_sync_answer) {
        g_pend_cb = cb;
        g_pend_arg = arg;
        memcpy(g_pend_q, q, n);
        g_pend_qn = n;
        return 0;
    }
    uint8_t out[600];
    size_t m = answer_a(q, n, out);
    cb(arg, out, m, NULL);
    return 0;
}

int rt_egress(struct box_rt *rt, const char *tag, struct egress *eg, char *err, size_t errn) {
    (void)rt; (void)tag; (void)err; (void)errn;
    memset(eg, 0, sizeof *eg);
    return 0;
}

/* ---- подставной dnsd -------------------------------------------------------------------- */
static void *dnsd_thread(void *p) {
    int fd = *(int *)p;
    for (;;) {
        uint8_t b[1500];
        struct sockaddr_storage a;
        socklen_t al = sizeof a;
        ssize_t n = recvfrom(fd, b, sizeof b, 0, (struct sockaddr *)&a, &al);
        if (n < 12) continue;
        b[2] = 0x81;
        b[3] = 0x85;                          /* REFUSED */
        sendto(fd, b, (size_t)n, 0, (struct sockaddr *)&a, al);
    }
    return NULL;
}

static void fake_dnsd(void) {
    static int fd;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(5300) };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&a, sizeof a)) { perror("dnsd 5300"); exit(2); }
    pthread_t th;
    pthread_create(&th, NULL, dnsd_thread, &fd);
}

/* ---- части по конфигу ------------------------------------------------------------------- */
static struct box_rt g_rtbox;

static struct box_rt *start(const char *cfg) {
    static int dnsd_up;
    if (!dnsd_up) { fake_dnsd(); dnsd_up = 1; }
    struct box_rt *rt = &g_rtbox;
    memset(rt, 0, sizeof *rt);
    g_rt = rt;
    char err[200];
    rt->cfg = json_parse(cfg, strlen(cfg), err, sizeof err);
    if (!rt->cfg) { fprintf(stderr, "конфиг стенда: %s\n", err); exit(2); }
    rt->ev = ev_new();
    if (dns_start(rt)) { fprintf(stderr, "dns_start\n"); exit(2); }
    return rt;
}

static void finish(struct box_rt *rt) {
    dns_stop(rt);
    ev_free(rt->ev);
    json_free(rt->cfg);
}

static void stop_cb(struct ev *ev, void *arg) { (void)arg; ev_stop(ev); }

static void run_ms(struct box_rt *rt, long ms) {
    ev_timer(rt->ev, ms, stop_cb, NULL);
    ev_run(rt->ev);
    /* ev_run выходит по ev_stop; следующий запуск — снова. */
    struct ev_hack { int ep, efd, stop; } *h = (struct ev_hack *)rt->ev;
    h->stop = 0;
}

/* Клиент UDP: сокет, адрес, вопрос в листенер l. */
static int client(struct sockaddr_storage *a, socklen_t *al) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in s = { .sin_family = AF_INET };
    s.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(fd, (struct sockaddr *)&s, sizeof s);
    *al = sizeof *a;
    getsockname(fd, (struct sockaddr *)a, al);
    return fd;
}

static struct listener *listener_of(struct box_rt *rt, const char *tag, int udp) {
    for (size_t i = 0; i < rt->dns->nls; i++)
        if (!strcmp(rt->dns->ls[i].tag, tag) && rt->dns->ls[i].udp == udp) return &rt->dns->ls[i];
    return NULL;
}

static void ask(struct box_rt *rt, int cfd, const struct sockaddr_storage *ca, socklen_t cal,
                const char *name, uint16_t qtype) {
    uint8_t q[512];
    size_t qn = dns_build_query(name, qtype, 0x1234, q, sizeof q);
    handle_query(listener_of(rt, "dns-in", 1), NULL, q, qn, ca, cal);
    (void)cfd;
}

/* Ответ клиенту: длина (0 — нет), TTL первой записи в *ttl. */
static long got(int cfd, long *ttl) {
    uint8_t r[1500];
    ssize_t n = recv(cfd, r, sizeof r, 0);
    if (n <= 0) return 0;
    if (ttl) *ttl = dns_walk(r, (size_t)n, -1, 0, NULL, 0, NULL);
    return n;
}
#endif
