/* Проброс входа mixed: объём идёт через splice (внутри ядра, без копирования в буфер процесса), короткие
 * реплики — копией, без трубы; байты доходят целиком в обе стороны, и полузакрытие одной стороны не рвёт
 * другую.
 * Остальное, что тянет mixed.c, глушит --unresolved-symbols=ignore-all стенда; net.c — по-настоящему:
 * копия пишет через write_all. */
// deps: src/net.c tests/stub_log.c
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
    /* Объём — через splice: копией только первые порции каждого направления, пока буфер не заполнился. */
    CHECK((1) == (g_relay_spliced >= (unsigned long)2 * N * 9 / 10)); /* поток в мегабайты шёл через splice */
    CHECK((1) == (g_relay_spliced + g_relay_copied == (unsigned long)2 * N)); /* и ни байта мимо счёта */

    close(client); close(a); close(b); close(server);

    /* Короткие реплики — копией: запрос в 64 байта, ответ в 64, тысячу раз. Трубе тут делать нечего. */
    tcp_pair(&client, &a);
    tcp_pair(&b, &server);
    struct rl r2 = { a, b };
    g_relay_spliced = g_relay_copied = 0;
    pthread_create(&rt, NULL, run_relay, &r2);
    int bad = 0;
    for (int k = 0; k < 1000; k++) {
        unsigned char q[64], back[64];
        memset(q, (unsigned char)k, sizeof q);
        if (write(client, q, sizeof q) != (ssize_t)sizeof q) { bad++; break; }
        if (read_all(server, back, sizeof back) != sizeof back || memcmp(back, q, sizeof q)) { bad++; break; }
        if (write(server, back, sizeof back) != (ssize_t)sizeof back) { bad++; break; }
        if (read_all(client, q, sizeof q) != sizeof q || memcmp(back, q, sizeof q)) { bad++; break; }
    }
    CHECK((0) == (bad)); /* тысяча реплик туда и обратно — байт в байт */
    shutdown(client, SHUT_WR);
    shutdown(server, SHUT_WR);
    pthread_join(rt, NULL);             /* счётчики — после выхода проброса: он считает после записи */
    CHECK((0) == ((long)g_relay_spliced)); /* короткие реплики — копией, без splice */
    CHECK((1) == (g_relay_copied == 1000ul * 128)); /* все через копию */
    close(client); close(a); close(b); close(server);
    free(up); free(down); free(got);
    return T_DONE();
}
