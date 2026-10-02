/* Серверы DNS коннектора (dnsup.c): вопрос, которому не нашлось рабочего потока (pthread_create
 * отказал — предел потоков), снимается с очереди и в dnsup_ask_blocking, как в dnsup_ask. Раньше
 * он оставался в очереди уже освобождённым, и следующий рабочий поток брал его из u->head. */
// deps: src/dnsmsg.c src/json.c src/net.c tests/stub_log.c
// ldflags: -Wl,--wrap=pthread_create
#include "../src/dnsup.c"
#include "check.h"

static int g_fail;
int __real_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *arg);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*f)(void *), void *arg) {
    if (g_fail) return EAGAIN;
    return __real_pthread_create(t, a, f, arg);
}

int main(void) {
    static const char cfg[] = "{\"type\":\"udp\",\"tag\":\"u\",\"server\":\"127.0.0.1\",\"server_port\":9}";
    char err[100];
    struct jval *c = json_parse(cfg, strlen(cfg), err, sizeof err);
    struct dnsup *u = dnsup_new(NULL, c, NULL, NULL);
    uint8_t q[512], r[512];
    size_t qn = dns_build_query("x.org", 1, 7, q, sizeof q);
    g_fail = 1;
    CHECK(dnsup_ask_blocking(u, q, qn, r, sizeof r, 100) == -1);
    CHECK(u->head == NULL && u->tail == NULL);
    CHECK(dnsup_ask(u, q, qn, NULL, NULL) == -1);
    CHECK(u->head == NULL && u->tail == NULL);
    json_free(c);
    return T_DONE();
}
