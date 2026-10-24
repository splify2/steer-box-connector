/* Серверы DNS коннектора (dnsup.c): блокирующий вопрос, не дождавшийся ответа за срок, не теряет
 * задание. Раньше ждущий уходил, а задание оставалось в памяти навсегда (утечка на каждый
 * зависший вопрос); теперь его освобождает рабочий поток, дописав вопрос. */
// deps: src/dnsmsg.c src/json.c src/net.c tests/stub_log.c
// ldflags: -Wl,--wrap=pthread_cond_destroy
#include "../src/dnsup.c"
#include "check.h"
#include <arpa/inet.h>

static int g_destroyed;
int __real_pthread_cond_destroy(pthread_cond_t *c);
int __wrap_pthread_cond_destroy(pthread_cond_t *c) {
    g_destroyed++;
    return __real_pthread_cond_destroy(c);
}

int main(void) {
    /* Сервер, который молчит: рабочий ждёт 4 с, а ждущий сдаётся через 2 с. */
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(srv, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(srv, (struct sockaddr *)&a, &al);
    char cfg[200], err[100];
    snprintf(cfg, sizeof cfg, "{\"type\":\"udp\",\"tag\":\"u\",\"server\":\"127.0.0.1\",\"server_port\":%d}", ntohs(a.sin_port));
    struct jval *c = json_parse(cfg, strlen(cfg), err, sizeof err);
    struct dnsup *u = dnsup_new(NULL, c, NULL, NULL);
    uint8_t q[512], r[512];
    size_t qn = dns_build_query("x.org", 1, 7, q, sizeof q);
    int before = g_destroyed;
    CHECK(dnsup_ask_blocking(u, q, qn, r, sizeof r, 100) == -1);
    CHECK(g_destroyed == before);          /* ждущий задание не трогает: рабочий ещё пишет в него */
    for (int i = 0; i < 100 && g_destroyed == before; i++) usleep(100000);
    CHECK(g_destroyed == before + 1);      /* дописав вопрос, рабочий освободил задание */
    json_free(c);
    return T_DONE();
}
