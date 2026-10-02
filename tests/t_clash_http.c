/* Clash API (clash.c), разбор запроса и ожидание ответа.
 *
 * 1. Тело, пришедшее отдельным сегментом после заголовков (PUT /proxies/<g> из браузера), —
 *    запрос всё равно разбирается: strtok_r первого прохода раньше резал заголовки нулями в
 *    самом буфере, и второй проход не находил «\r\n\r\n» — запрос висел до 4 МиБ.
 * 2. Соединение, чей ответ ждёт рабочего потока (замер задержки до timeout из запроса, смена
 *    выбора), а клиент уже закрыл своё, — не крутит цикл: hc_read на каждом EPOLLIN
 *    возвращался, ничего не прочитав, и epoll звал его снова (100% ЦП на время замера). */
// deps: src/json.c src/evloop.c src/net.c src/sbconf.c tests/stub_log.c
#include "../src/clash.c"
#include "check.h"
#include <signal.h>
#include <sys/resource.h>

struct box_rt *g_rt;
static struct box_rt g_box;
static struct clash g_cl;

static struct hc *conn(int fd) {
    struct hc *c = calloc(1, sizeof *c);
    c->fd = fd;
    hc_track(&g_cl, c);              /* как accept_cb */
    set_nonblock(fd, 1);
    ev_add(g_box.ev, fd, EPOLLIN, hc_read, c);
    return c;
}

static void stop_cb(struct ev *ev, void *arg) { (void)arg; ev_stop(ev); }

static void run_ms(long ms) {
    ev_timer(g_box.ev, ms, stop_cb, NULL);
    ev_run(g_box.ev);
    struct ev_hack { int ep, efd, stop; } *h = (struct ev_hack *)g_box.ev;
    h->stop = 0;
}

static long cpu_ms(void) {
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1000L +
           (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1000L;
}

static void t_split_body(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    conn(sv[0]);
    const char *h = "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
    if (write(sv[1], h, strlen(h)) < 0) perror("write");
    run_ms(30);
    if (write(sv[1], "hello", 5) < 0) perror("write");
    run_ms(30);
    char r[512] = "";
    set_nonblock(sv[1], 1);
    ssize_t n = read(sv[1], r, sizeof r - 1);
    CHECK(n > 12 && !strncmp(r, "HTTP/1.1 200", 12));
    close(sv[1]);
}

static void t_wait_no_spin(void) {
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct hc *c = conn(sv[0]);
    c->st = HS_WAIT;            /* ответ — за рабочим потоком */
    c->refs++;                  /* его ссылка */
    close(sv[1]);               /* клиент ушёл */
    long t0 = cpu_ms();
    run_ms(400);
    long spent = cpu_ms() - t0;
    CHECK(spent < 150);
    if (spent >= 150) fprintf(stderr, "ЦП за 400 мс ожидания: %ld мс\n", spent);
    /* Работа закончилась: ответ некому, соединение закрывается. */
    hc_close(c);
    hc_unref(c);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_rt = &g_box;
    g_box.ev = ev_new();
    g_box.cfg = jnew(J_OBJ);
    g_cl.rt = &g_box;
    g_cl.refs = 1;                   /* как clash_start: ссылка таймера */
    t_split_body();
    t_wait_no_spin();
    return T_DONE();
}
