/* Роутер DNS (dns.c): правило над набором (rule_set) спрашивает dnsd «не пересылать»; его
 * опции (rewrite_ttl, strategy, disable_cache) ставятся до ответа, ведь ответ dnsd и есть ответ
 * правила. Если dnsd ответил REFUSED (имени в наборе нет), правило не совпало — и его опции не
 * должны доставаться ответу следующего правила. У forkop так устроено каждое правило секции:
 * { rule_set, server, rewrite_ttl: dns_rewrite_ttl }. */
// deps: src/dnsmsg.c src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/dns.c"
#include "dns_harness.h"

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"fakeip\",\"tag\":\"fakeip-server\"},"
    "                    {\"type\":\"udp\",\"tag\":\"dns-server\",\"server\":\"1.1.1.1\"}],"
    "  \"rules\":[{\"rule_set\":[\"sec\"],\"action\":\"route\",\"server\":\"fakeip-server\","
    "             \"rewrite_ttl\":60,\"strategy\":\"ipv6_only\"}],"
    "  \"final\":\"dns-server\"}}";

int main(void) {
    struct sockaddr_storage ca;
    socklen_t cal;
    int cfd = client(&ca, &cal);
    struct box_rt *rt = start(CFG);
    ask(rt, cfd, &ca, cal, "outside.org", 1);
    run_ms(rt, 300);
    long ttl = -2;
    long n = got(cfd, &ttl);
    CHECK(n > 0);
    CHECK(!strcmp(g_asked, "dns-server"));      /* strategy ipv6_only правила не отказал A */
    CHECK(ttl == 300);
    if (ttl != 300) fprintf(stderr, "TTL ответа %ld\n", ttl);
    finish(rt);
    return T_DONE();
}
