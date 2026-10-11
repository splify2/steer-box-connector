/* Настоящий вход mixed коннектора как отдельный прокси для замера задержки и пропускной способности
 * (не стенд: имя не t_*, в tests/run.sh не входит). Берёт mixed_start, accept_cb, SOCKS/HTTP-разбор,
 * dial, net_connect и relay из src/mixed.c без изменений, цикл событий — src/evloop.c, разбор конфига —
 * src/json.c. Подставлены только то, что в полном `run` тянуло бы steerd и правила nft: rt_egress
 * (выход direct — без устройства и метки) и dns_resolve_blocking (цель — адрес литералом).
 * Сборка (MIXED_C — путь к другому mixed.c, например к прежнему из git):
 *   cc -O2 -D_GNU_SOURCE -Isrc $(find steer/src -type d | sed 's/^/-I/') -o build/bench_mixed_proxy \
 *      tests/bench_mixed_proxy.c src/evloop.c src/json.c src/net.c tests/stub_log.c -lpthread -lm \
 *      -Wl,--unresolved-symbols=ignore-all
 * Запуск: build/bench_mixed_proxy [порт=45002]   (слушает 127.0.0.1, SOCKS5 без пароля) */
#ifndef MIXED_C
#define MIXED_C "../src/mixed.c"
#endif
#include MIXED_C
#include "evloop.h"
#include <signal.h>

struct box_rt *g_rt;

int rt_egress(struct box_rt *rt, const char *tag, struct egress *eg, char *err, size_t errn) {
    (void)rt; (void)tag; (void)err; (void)errn;
    memset(eg, 0, sizeof *eg);
    return 0;
}

int dns_resolve_blocking(struct box_rt *rt, const char *name, struct sockaddr_storage *out, socklen_t *lens, int max) {
    (void)rt; (void)max;
    return net_parse_ip(name, 0, out, lens) ? 0 : 1;
}

int main(int argc, char **argv) {
    char cfg[256], err[128];
    snprintf(cfg, sizeof cfg,
             "{\"inbounds\":[{\"type\":\"mixed\",\"tag\":\"mixed-in\",\"listen\":\"127.0.0.1\",\"listen_port\":%d}],"
             "\"route\":{\"final\":\"direct\"}}", argc > 1 ? atoi(argv[1]) : 45002);
    static struct box_rt rt;
    rt.ev = ev_new();
    rt.cfg = json_parse(cfg, strlen(cfg), err, sizeof err);
    if (!rt.ev || !rt.cfg) { fprintf(stderr, "init: %s\n", err); return 1; }
#ifdef RELAY_SPIN_NS
    if (getenv("SPIN_US")) g_spin_ns = atoll(getenv("SPIN_US")) * 1000;   /* SPIN_US=0 — без опроса, для сравнения */
#endif
    signal(SIGPIPE, SIG_IGN);   /* как main.c коннектора */
    g_rt = &rt;
    if (mixed_start(&rt)) return 1;
    return ev_run(rt.ev);
}
