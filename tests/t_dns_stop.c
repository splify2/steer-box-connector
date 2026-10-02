/* Роутер DNS (dns.c): dns_stop (перечитывание конфига по SIGHUP — restart_parts) при вопросах в
 * пути. Ответ сервера, пришедший после останова, раньше писал в кэш освобождённой dns_srv и слал
 * ответ через закрытый (а то и чужой, с тем же номером) дескриптор слушателя; соединение TCP,
 * принятое до останова, оставалось в цикле со ссылкой на освобождённый слушатель. */
// deps: src/dnsmsg.c src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/dns.c"
#include "dns_harness.h"
#include <signal.h>

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"dns-server\",\"server\":\"1.1.1.1\"}],"
    "  \"final\":\"dns-server\"}}";

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_storage ca;
    socklen_t cal;
    int cfd = client(&ca, &cal);
    struct box_rt *rt = start(CFG);

    /* Вопрос по UDP повис у сервера. */
    g_sync_answer = 0;
    ask(rt, cfd, &ca, cal, "slow.org", 1);
    CHECK(g_pend_cb != NULL);

    /* Соединение TCP с вопросом в пути и ещё одно — простаивает (принимает их tcpl_cb). */
    struct listener *tl = listener_of(rt, "dns-in", 0);
    struct sockaddr_storage la;
    socklen_t lal = sizeof la;
    getsockname(tl->fd, (struct sockaddr *)&la, &lal);
    int t1 = socket(AF_INET, SOCK_STREAM, 0), t2 = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(!connect(t1, (struct sockaddr *)&la, lal) && !connect(t2, (struct sockaddr *)&la, lal));
    dnsup_cb tcb = NULL;
    void *targ = NULL;
    uint8_t q[514];
    size_t qn = dns_build_query("slow-tcp.org", 1, 0x4243, q + 2, sizeof q - 2);
    q[0] = (uint8_t)(qn >> 8);
    q[1] = (uint8_t)qn;
    if (write(t1, q, qn + 2) < 0) perror("write");
    void *ucb_arg = g_pend_arg;
    dnsup_cb ucb = g_pend_cb;
    uint8_t uq[512];
    size_t uqn = g_pend_qn;
    memcpy(uq, g_pend_q, uqn);
    run_ms(rt, 50);
    tcb = g_pend_cb;
    targ = g_pend_arg;
    CHECK(targ != ucb_arg);

    /* Останов частей, как в restart_parts. */
    dns_stop(rt);

    /* Ответы серверов приходят после останова. */
    uint8_t a[600];
    size_t an = answer_a(uq, uqn, a);
    ucb(ucb_arg, a, an, NULL);
    an = answer_a(q + 2, qn, a);
    tcb(targ, a, an, NULL);
    /* Простаивавший клиент TCP пишет после останова. */
    if (write(t2, q, qn + 2) < 0) perror("write");
    run_ms(rt, 50);
    long ttl;
    CHECK(got(cfd, &ttl) == 0);               /* ответа через закрытый слушатель нет */
    ev_free(rt->ev);
    json_free(rt->cfg);
    return T_DONE();
}
