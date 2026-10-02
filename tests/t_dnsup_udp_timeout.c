/* Серверы DNS (dnsup.c), udp_exchange: срок ответа — timeout_ms целиком. Конец срока считался от
 * time(NULL) * 1000 (секунды без долей), а «сейчас» — в миллисекундах: ожидание было короче на
 * долю текущей секунды, то есть от timeout - 1 с до timeout. */
// deps: src/dnsmsg.c src/json.c src/net.c tests/stub_log.c
#include "../src/dnsup.c"
#include "check.h"
#include <arpa/inet.h>

int main(void) {
    /* Сервер, который молчит. */
    int srv = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET };
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(srv, (struct sockaddr *)&a, sizeof a);
    socklen_t al = sizeof a;
    getsockname(srv, (struct sockaddr *)&a, &al);
    uint8_t q[512], r[512];
    size_t qn = dns_build_query("x.org", 1, 7, q, sizeof q);
    for (int i = 0; i < 3; i++) {
        long long t0 = now_ms();
        long n = udp_exchange((struct sockaddr_storage *)&a, al, NULL, q, qn, r, sizeof r, 600);
        long long dt = now_ms() - t0;
        CHECK(n == -1);
        CHECK(dt >= 590);
        if (dt < 590) fprintf(stderr, "ждал %lld мс из 600\n", dt);
    }
    return T_DONE();
}
