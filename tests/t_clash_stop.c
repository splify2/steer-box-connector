/* Clash API (clash.c): clash_stop (перечитывание конфига — restart_parts) закрывал только
 * WebSocket. Обычные соединения — ждущие заголовков или ответа рабочего потока (замер
 * задержки) — оставались в цикле со ссылкой на struct clash, которую ws_tick освобождает на
 * следующей секунде: следующий их байт или готовый замер обращались к освобождённой памяти. */
// deps: src/json.c src/net.c src/sbconf.c tests/stub_log.c
#include "../src/clash.c"
#include "../src/evloop.c"
#include "check.h"
#include <signal.h>

struct box_rt *g_rt;
static struct box_rt g_box;

static void stop_cb(struct ev *ev, void *arg) { (void)arg; ev_stop(ev); }

static void run_ms(long ms) {
    ev_timer(g_box.ev, ms, stop_cb, NULL);
    ev_run(g_box.ev);
    g_box.ev->stop = 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_rt = &g_box;
    g_box.ev = ev_new();
    static const char cfg[] = "{\"experimental\":{\"clash_api\":{\"external_controller\":\"127.0.0.1:0\"}}}";
    char err[100];
    g_box.cfg = json_parse(cfg, strlen(cfg), err, sizeof err);
    struct box_opts o = { 0 };
    g_box.opts = &o;
    CHECK(!clash_start(&g_box));
    struct sockaddr_storage a;
    socklen_t al = sizeof a;
    getsockname(g_box.clash->lfd, (struct sockaddr *)&a, &al);

    /* Соединение с половиной запроса — и второе, чей ответ ждёт «рабочего потока». */
    int c1 = socket(AF_INET, SOCK_STREAM, 0), c2 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(!connect(c1, (struct sockaddr *)&a, al) && !connect(c2, (struct sockaddr *)&a, al));
    if (write(c1, "GET / HTTP/1.1\r\n", 16) < 0) perror("write");
    run_ms(50);
    if (write(c2, "GET / HTTP/1.1\r\n", 16) < 0) perror("write");
    run_ms(50);
    /* Второе — в ожидании: так его оставляет start_delay. */
    struct hc *w = NULL;
    for (int fd = 3; fd < 64 && !w; fd++) {
        struct sockaddr_storage pa;
        socklen_t pl = sizeof pa;
        struct sockaddr_storage la;
        socklen_t ll = sizeof la;
        if (getpeername(fd, (struct sockaddr *)&pa, &pl) || getsockname(fd, (struct sockaddr *)&la, &ll)) continue;
        if (net_port((struct sockaddr *)&la) != net_port((struct sockaddr *)&a)) continue;
        struct sockaddr_storage c2a;
        socklen_t c2l = sizeof c2a;
        getsockname(c2, (struct sockaddr *)&c2a, &c2l);
        if (net_port((struct sockaddr *)&pa) != net_port((struct sockaddr *)&c2a)) continue;
        /* hc этого дескриптора — arg его записи в цикле. */
        struct fdent *e = find(g_box.ev, fd);
        w = e ? e->arg : NULL;
    }
    CHECK(w != NULL);
    if (w) { w->st = HS_WAIT; w->refs++; }

    clash_stop(&g_box);
    run_ms(1500);                 /* ws_tick отпускает структуру */

    /* Первый клиент дописывает запрос, второму приходит готовый замер. */
    if (write(c1, "\r\n", 2) < 0) perror("write");
    run_ms(50);
    if (w) {
        if (w->fd >= 0) send_msg(w, 200, "{}");
        hc_close(w);
        hc_unref(w);
    }
    char buf[64];
    CHECK(read(c1, buf, sizeof buf) == 0);    /* соединение закрыто остановом, ответа нет */
    return T_DONE();
}
