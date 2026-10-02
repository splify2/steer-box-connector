/* Clash API (clash.c), CORS как у sing-box: Access-Control-Allow-Origin — «*», если
 * access_control_allow_origin пуст, иначе только origin из списка; заголовок
 * Access-Control-Allow-Private-Network — только при access_control_allow_private_network.
 * Раньше коннектор отражал любой Origin и всегда разрешал доступ к частной сети: любой сайт,
 * открытый в браузере человека в LAN, проходил предзапрос и менял выбор селекторов, рвал
 * соединения и заказывал роутеру замер по своему url (секрета forkop по умолчанию не ставит). */
// deps: src/json.c src/evloop.c src/net.c src/sbconf.c tests/stub_log.c
#include "../src/clash.c"
#include "check.h"
#include <signal.h>

struct box_rt *g_rt;
static struct box_rt g_box;

static void stop_cb(struct ev *ev, void *arg) { (void)arg; ev_stop(ev); }

static void run_ms(long ms) {
    ev_timer(g_box.ev, ms, stop_cb, NULL);
    ev_run(g_box.ev);
    struct ev_hack { int ep, efd, stop; } *h = (struct ev_hack *)g_box.ev;
    h->stop = 0;
}

/* Предзапрос с Origin к клешу с конфигом api; ответ — в buf. */
static void preflight(const char *api, const char *origin, char *buf, size_t n) {
    char cfg[400], err[100];
    snprintf(cfg, sizeof cfg, "{\"experimental\":{\"clash_api\":{\"external_controller\":\"127.0.0.1:0\"%s}}}", api);
    json_free(g_box.cfg);
    g_box.cfg = json_parse(cfg, strlen(cfg), err, sizeof err);
    CHECK(!clash_start(&g_box));
    struct sockaddr_storage a;
    socklen_t al = sizeof a;
    getsockname(g_box.clash->lfd, (struct sockaddr *)&a, &al);
    int c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(!connect(c, (struct sockaddr *)&a, al));
    char req[300];
    int k = snprintf(req, sizeof req, "OPTIONS /proxies/x HTTP/1.1\r\nOrigin: %s\r\n"
                     "Access-Control-Request-Private-Network: true\r\n\r\n", origin);
    if (write(c, req, (size_t)k) < 0) perror("write");
    run_ms(50);
    ssize_t r = read(c, buf, n - 1);
    buf[r > 0 ? r : 0] = 0;
    close(c);
    clash_stop(&g_box);
    run_ms(1100);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_rt = &g_box;
    g_box.ev = ev_new();
    struct box_opts o = { 0 };
    g_box.opts = &o;
    char b[2048];

    preflight("", "https://evil.example", b, sizeof b);
    CHECK(strstr(b, "Access-Control-Allow-Origin: *\r\n") != NULL);
    CHECK(!strstr(b, "Access-Control-Allow-Private-Network"));

    preflight(",\"access_control_allow_origin\":[\"http://192.168.1.1\"],"
              "\"access_control_allow_private_network\":true", "https://evil.example", b, sizeof b);
    CHECK(!strstr(b, "Access-Control-Allow-Origin"));

    preflight(",\"access_control_allow_origin\":[\"http://192.168.1.1\"],"
              "\"access_control_allow_private_network\":true", "http://192.168.1.1", b, sizeof b);
    CHECK(strstr(b, "Access-Control-Allow-Origin: http://192.168.1.1\r\n") != NULL);
    CHECK(strstr(b, "Access-Control-Allow-Private-Network: true\r\n") != NULL);
    return T_DONE();
}
