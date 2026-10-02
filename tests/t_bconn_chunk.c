/* HTTP/1.1 коннектора (bconn.c): размер куска chunked от сервера — недоверенное число. Кусок
 * размером около 2^64 не должен проходить проверку предела max_body переполнением суммы и
 * писать за конец буфера тела — ни в http_request (DoH по HTTP/1.1), ни в http_get (наборы
 * правил, замер задержки Clash API с url из запроса).
 *
 * По TLS: расшифрованная запись копируется в буфер тела memcpy, и ядро тут не спасает (у
 * простого TCP read() с длиной «почти 2^64» отвечает EFAULT). Поэтому TLS здесь — подставной:
 * tls13_read отдаёт ответ кусками из памяти. */
// deps: src/net.c src/json.c tests/stub_log.c
#include "../src/bconn.c"
#include "check.h"
#include <signal.h>
#include <sys/wait.h>
#include <arpa/inet.h>

/* Ответ: кусок в 10 байт, затем кусок «почти 2^64» и 3000 байт данных. */
static char g_resp[4096];
static size_t g_resp_n, g_off;

static void resp_init(void) {
    static const char head[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                               "a\r\n0123456789\r\nfffffffffffffffa\r\n";
    memcpy(g_resp, head, sizeof head - 1);
    memset(g_resp + sizeof head - 1, 'A', 3000);
    g_resp_n = sizeof head - 1 + 3000;
    g_off = 0;
}

/* Подставной TLS: запись — всё, что осталось от ответа. */
int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) {
    (void)t;
    if (g_off >= g_resp_n) return TLS13_ECLOSED;
    size_t k = g_resp_n - g_off;
    if (k > cap) k = cap;
    memcpy(out, g_resp + g_off, k);
    g_off += k;
    *got = k;
    return 0;
}
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n) { (void)t; (void)d; (void)n; return 0; }
void tls13_free(struct tls13 *t) { (void)t; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *h, size_t hn,
                         const unsigned char *s, const struct tls13_auth *a) {
    (void)fd; (void)h; (void)hn; (void)s; (void)a;
    t->alpn[0] = 0;
    return 0;
}
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car, unsigned char *out, size_t out_n,
                              size_t *out_len) {
    (void)cfg; (void)st; (void)car; (void)out_n;
    out[0] = 0;
    *out_len = 1;
    return 0;
}
const char *tls_cert_roots(void) { return NULL; }
const char *tls13_verify_reason(void) { return ""; }

static void t_request(void) {
    resp_init();
    int sv[2];
    CHECK(!socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    struct bconn c;
    memset(&c, 0, sizeof c);
    c.fd = sv[0];
    c.tls = calloc(1, sizeof *c.tls);
    struct http_resp r;
    char err[200] = "";
    int rc = http_request(&c, "POST", "x", "/dns-query", NULL, NULL, "q", 1, NULL, &r, 100, 2000,
                          err, sizeof err);
    CHECK(rc == -1);
    http_resp_free(&r);
    bconn_close(&c);
    close(sv[1]);
}

static void t_get(void) {
    resp_init();
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    CHECK(!bind(l, (struct sockaddr *)&a, sizeof a) && !listen(l, 1));
    socklen_t al = sizeof a;
    getsockname(l, (struct sockaddr *)&a, &al);
    char url[64], err[200] = "";
    snprintf(url, sizeof url, "https://127.0.0.1:%u/set.srs", ntohs(a.sin_port));
    unsigned char *body = NULL;
    size_t n = 0;
    int status = 0;
    int rc = http_get(url, NULL, 2000, 100, &body, &n, &status, err, sizeof err);
    CHECK(rc == -1);
    if (!rc) free(body);
    close(l);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    t_request();
    t_get();
    return T_DONE();
}
