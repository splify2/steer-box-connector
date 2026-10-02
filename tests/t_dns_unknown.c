/* Роутер DNS (dns.c): условие, которого коннектор не сверяет (ip_cidr ответа), — правило не
 * совпадает, и invert этого не меняет. Конфиг — «source-aware bypass» forkop
 * (generator.uc, add_source_aware_bypass_dns_rules): and(имя секции, НЕ ответ из fake-IP) →
 * dnsmasq-server; иначе — dns-server. Ответ dnsmasq для имени секции — поддельный адрес, и
 * sing-box это правило пропускает. Коннектор раньше считал «ip_cidr» несовпавшим, invert
 * превращал это в совпадение, и клиент обхода получал fake-IP вместо настоящего адреса. */
// deps: src/dnsmsg.c src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/dns.c"
#include "dns_harness.h"

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"dnsmasq-server\",\"server\":\"127.0.0.1\"},"
    "                    {\"type\":\"udp\",\"tag\":\"dns-server\",\"server\":\"1.1.1.1\"}],"
    "  \"rules\":[{\"type\":\"logical\",\"mode\":\"and\",\"rules\":["
    "              {\"domain_suffix\":[\"example.com\"]},"
    "              {\"ip_cidr\":[\"198.18.0.0/15\"],\"invert\":true}],"
    "             \"action\":\"route\",\"server\":\"dnsmasq-server\"},"
    "            {\"domain_suffix\":[\"example.com\"],\"query_type\":[\"A\",\"AAAA\"],"
    "             \"action\":\"route\",\"server\":\"dns-server\"}],"
    "  \"final\":\"dns-server\"}}";

/* Одиночное правило с неизвестным условием и invert — тоже не совпадает. */
static const char CFG2[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"a\",\"server\":\"127.0.0.1\"},"
    "                    {\"type\":\"udp\",\"tag\":\"b\",\"server\":\"1.1.1.1\"}],"
    "  \"rules\":[{\"process_name\":[\"curl\"],\"invert\":true,\"server\":\"a\"}],"
    "  \"final\":\"b\"}}";

int main(void) {
    struct sockaddr_storage ca;
    socklen_t cal;
    int cfd = client(&ca, &cal);

    struct box_rt *rt = start(CFG);
    g_asked[0] = 0;
    ask(rt, cfd, &ca, cal, "www.example.com", 1);
    CHECK(!strcmp(g_asked, "dns-server"));
    if (strcmp(g_asked, "dns-server")) fprintf(stderr, "спрошен %s\n", g_asked);
    /* Имя вне секции — final, как и было. */
    g_asked[0] = 0;
    ask(rt, cfd, &ca, cal, "other.org", 1);
    CHECK(!strcmp(g_asked, "dns-server"));
    finish(rt);

    rt = start(CFG2);
    g_asked[0] = 0;
    ask(rt, cfd, &ca, cal, "x.org", 1);
    CHECK(!strcmp(g_asked, "b"));
    finish(rt);
    return T_DONE();
}
