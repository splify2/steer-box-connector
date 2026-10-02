/* Роутер DNS (dns.c), вход TCP: ответ, который уходит сразу (reject, кэш, predefined), а записать
 * его нельзя (клиент закрыл свою сторону на приём), закрывал соединение и освобождал его прямо
 * внутри tcpc_cb — а тот дальше двигал буфер того же соединения (use-after-free), и дескриптор
 * закрывался без ev_del. */
// deps: src/dnsmsg.c src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/dns.c"
#include "dns_harness.h"
#include <signal.h>

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"direct\",\"tag\":\"dns-in\",\"listen\":\"127.0.0.1\",\"listen_port\":0}],"
    " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"dns-server\",\"server\":\"1.1.1.1\"}],"
    "  \"rules\":[{\"domain\":[\"blocked.test\"],\"action\":\"reject\"}],"
    "  \"final\":\"dns-server\"}}";

static struct tcpconn *conn(struct box_rt *rt, int fd) {
    struct tcpconn *c = calloc(1, sizeof *c);
    c->fd = fd;
    tc_track(listener_of(rt, "dns-in", 0), c);       /* как tcpl_cb */
    fcntl(fd, F_SETFL, O_NONBLOCK);
    ev_add(rt->ev, fd, EPOLLIN, tcpc_cb, c);
    return c;
}

static void send_q(int fd, const char *name) {
    uint8_t q[514];
    size_t qn = dns_build_query(name, 1, 0x4242, q + 2, sizeof q - 2);
    q[0] = (uint8_t)(qn >> 8);
    q[1] = (uint8_t)qn;
    if (write(fd, q, qn + 2) != (ssize_t)(qn + 2)) perror("write");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    struct box_rt *rt = start(CFG);

    /* Две пачки по вопросу в одном чтении: после первого ответа запись уже не идёт. */
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    struct tcpconn *c = conn(rt, sv[0]);
    send_q(sv[1], "blocked.test");
    send_q(sv[1], "blocked.test");
    shutdown(sv[0], SHUT_WR);
    tcpc_cb(rt->ev, sv[0], EPOLLIN, c);
    close(sv[1]);
    run_ms(rt, 50);

    /* Обычное соединение отвечает. */
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    c = conn(rt, sv[0]);
    send_q(sv[1], "blocked.test");
    run_ms(rt, 100);
    uint8_t r[600];
    ssize_t n = read(sv[1], r, sizeof r);
    CHECK(n > 14 && (r[5] & 0x0F) == 5);      /* длина, заголовок: REFUSED */
    close(sv[1]);
    run_ms(rt, 50);
    finish(rt);
    return T_DONE();
}
