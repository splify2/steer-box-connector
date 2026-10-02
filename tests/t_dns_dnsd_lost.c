/* Роутер DNS (dns.c): вопрос к dnsd steer («не пересылать»), на который ответа так и не пришло
 * (dnsd перезапускался и потерял датаграмму из очереди старого сокета), не висит вечно: через
 * DNSD_GIVEUP_MS разбор правил идёт дальше, как при отказе dnsd. Раньше выход по сроку был только
 * у вопросов, получивших ECONNREFUSED, — потерянный вопрос держал qctx (и соединение TCP) до
 * конца работы, а клиент не получал ответа. */
// deps: src/dnsmsg.c src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/dns.c"
#include "dns_harness.h"

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"fakeip\",\"tag\":\"fakeip-server\"},"
    "                    {\"type\":\"udp\",\"tag\":\"dns-server\",\"server\":\"1.1.1.1\"}],"
    "  \"rules\":[{\"rule_set\":[\"sec\"],\"action\":\"route\",\"server\":\"fakeip-server\"}],"
    "  \"final\":\"dns-server\"}}";

int main(void) {
    struct sockaddr_storage ca;
    socklen_t cal;
    int cfd = client(&ca, &cal);
    struct box_rt *rt = start(CFG);
    g_dnsd_drop = "lost";
    ask(rt, cfd, &ca, cal, "lost.example", 1);
    run_ms(rt, DNSD_GIVEUP_MS + 1200);
    long ttl = 0;
    CHECK(got(cfd, &ttl) > 0);
    CHECK(!strcmp(g_asked, "dns-server"));
    size_t waiting = 0;
    for (size_t i = 0; i < 65536; i++) if (rt->dns->dnsd_wait[i]) waiting++;
    CHECK(waiting == 0);
    finish(rt);
    return T_DONE();
}
