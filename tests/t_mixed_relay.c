/* Проброс входа mixed: байты идут через splice (внутри ядра, без копирования в буфер процесса),
 * доходят целиком в обе стороны, и полузакрытие одной стороны не рвёт другую.
 * deps — всё, что тянет mixed.c, глушит --unresolved-symbols=ignore-all стенда. */
#include "../src/mixed.c"
#include "check.h"
#include <netinet/tcp.h>
#include <pthread.h>

static void tcp_pair(int *x, int *y) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof a;
    bind(l, (struct sockaddr *)&a, sizeof a);
    listen(l, 1);
    getsockname(l, (struct sockaddr *)&a, &al);
    *x = socket(AF_INET, SOCK_STREAM, 0);
    connect(*x, (struct sockaddr *)&a, sizeof a);
    *y = accept(l, NULL, NULL);
    close(l);
}

struct rl { int a, b; };
static void *run_relay(void *p) {
    struct rl *r = p;
    relay(r->a, r->b);
    return NULL;
}

struct pump { int fd; const unsigned char *buf; size_t n; };
static void *pump_write(void *p) {
    struct pump *w = p;
    size_t off = 0;
    while (off < w->n) {
        ssize_t k = write(w->fd, w->buf + off, w->n - off);
        if (k <= 0) break;
        off += (size_t)k;
    }
    shutdown(w->fd, SHUT_WR);
    return NULL;
}

static size_t read_all(int fd, unsigned char *buf, size_t cap) {
    size_t n = 0;
    for (;;) {
        ssize_t k = read(fd, buf + n, cap - n);
        if (k <= 0) break;
        n += (size_t)k;
        if (n == cap) break;
    }
    return n;
}

int main(void) {
    enum { N = 5 << 20 };
    unsigned char *up = malloc(N), *down = malloc(N), *got = malloc(N + 1);
    for (size_t i = 0; i < N; i++) { up[i] = (unsigned char)(i * 7 + 3); down[i] = (unsigned char)(i * 13 + 1); }

    int client, a, b, server;
    tcp_pair(&client, &a);   /* клиент входа ↔ вход */
    tcp_pair(&b, &server);   /* соединение наружу ↔ сервер */
    struct rl r = { a, b };
    pthread_t rt, wt;
    pthread_create(&rt, NULL, run_relay, &r);

    /* Клиент → сервер, затем клиент закрывает запись: сервер видит конец, но ответ ещё идёт. */
    struct pump w1 = { client, up, N };
    pthread_create(&wt, NULL, pump_write, &w1);
    size_t n1 = read_all(server, got, N + 1);
    pthread_join(wt, NULL);
    CHECK((N) == ((long)n1)); /* клиент → сервер: дошло всё */
    CHECK((0) == (memcmp(got, up, N))); /* клиент → сервер: байт в байт */

    struct pump w2 = { server, down, N };
    pthread_create(&wt, NULL, pump_write, &w2);
    size_t n2 = read_all(client, got, N + 1);
    pthread_join(wt, NULL);
    CHECK((N) == ((long)n2)); /* сервер → клиент после полузакрытия: дошло всё */
    CHECK((0) == (memcmp(got, down, N))); /* сервер → клиент: байт в байт */

    pthread_join(rt, NULL);
    CHECK((1) == (g_relay_spliced >= (unsigned long)2 * N)); /* байты шли через splice, а не через буфер процесса */

    close(client); close(a); close(b); close(server);
    free(up); free(down); free(got);
    return T_DONE();
}
