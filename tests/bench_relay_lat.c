/* Задержка проброса входа mixed: обмен 64 байтами туда и обратно через relay, как меряют задержку прокси
 * (клиент → прокси → эхо → прокси → клиент по уже открытому соединению). Не стенд, а замер: в tests/run.sh
 * не входит (имя не t_*). Сборка и запуск:
 *   cc -O2 -D_GNU_SOURCE -Isrc $(find steer/src -type d | sed 's/^/-I/') -o build/bench_relay_lat \
 *      tests/bench_relay_lat.c src/net.c tests/stub_log.c -lpthread -Wl,--unresolved-symbols=ignore-all
 *   build/bench_relay_lat [замеров=20000] [ядро_клиента=0] [ядро_прокси=1] [ядро_эха=2]
 * Печатает p50, p90, p99 в микросекундах. Чтобы сравнить с прежним relay, тот же файл собирается с
 * -DMIXED_C=\"путь/к/старому/mixed.c\". */
#ifndef MIXED_C
#define MIXED_C "../src/mixed.c"
#endif
#include MIXED_C
#include <netinet/tcp.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

static void pin(int cpu) {
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(cpu, &s);
    pthread_setaffinity_np(pthread_self(), sizeof s, &s);
}

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
    int one = 1;
    setsockopt(*x, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
}

struct arg { int a, b, cpu; };
static void *th_relay(void *p) { struct arg *g = p; pin(g->cpu); relay(g->a, g->b); return NULL; }
static void *th_echo(void *p) {
    struct arg *g = p;
    pin(g->cpu);
    unsigned char m[64];
    for (;;) {
        size_t got = 0;
        while (got < sizeof m) {
            ssize_t r = read(g->a, m + got, sizeof m - got);
            if (r <= 0) return NULL;
            got += (size_t)r;
        }
        if (write(g->a, m, sizeof m) != (ssize_t)sizeof m) return NULL;
    }
}

static int cmp(const void *x, const void *y) {
    double a = *(const double *)x, b = *(const double *)y;
    return a < b ? -1 : a > b;
}

int main(int argc, char **argv) {
    int rounds = argc > 1 ? atoi(argv[1]) : 20000;
    int ccpu = argc > 2 ? atoi(argv[2]) : 0, pcpu = argc > 3 ? atoi(argv[3]) : 1, ecpu = argc > 4 ? atoi(argv[4]) : 2;
    int client, pa, pb, server;
    tcp_pair(&client, &pa);
    tcp_pair(&pb, &server);
    pthread_t tr, te;
    struct arg ra = { pa, pb, pcpu }, ea = { server, -1, ecpu };
    pthread_create(&tr, NULL, th_relay, &ra);
    pthread_create(&te, NULL, th_echo, &ea);
    pin(ccpu);
    unsigned char m[64];
    memset(m, 'x', sizeof m);
    double *lat = calloc((size_t)rounds, sizeof *lat);
    for (int i = -500; i < rounds; i++) {      /* 500 на разогрев */
        struct timespec t0, t1;
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (write(client, m, sizeof m) != (ssize_t)sizeof m) return 1;
        size_t got = 0;
        while (got < sizeof m) {
            ssize_t r = read(client, m + got, sizeof m - got);
            if (r <= 0) return 1;
            got += (size_t)r;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if (i >= 0) lat[i] = (double)(t1.tv_sec - t0.tv_sec) * 1e6 + (double)(t1.tv_nsec - t0.tv_nsec) / 1e3;
    }
    qsort(lat, (size_t)rounds, sizeof *lat, cmp);
    printf("p50 %.1f мкс  p90 %.1f  p99 %.1f  (замеров %d)\n", lat[rounds / 2], lat[rounds * 9 / 10],
           lat[rounds * 99 / 100], rounds);
    return 0;
}
