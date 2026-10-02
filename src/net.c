/* Сокеты коннектора — см. net.h. */
#define _GNU_SOURCE
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

int net_parse_ip(const char *s, uint16_t port, struct sockaddr_storage *out, socklen_t *len) {
    memset(out, 0, sizeof *out);
    char buf[64];
    snprintf(buf, sizeof buf, "%s", s);
    size_t l = strlen(buf);
    if (l > 1 && buf[0] == '[' && buf[l - 1] == ']') { memmove(buf, buf + 1, l - 2); buf[l - 2] = 0; }
    struct sockaddr_in *s4 = (struct sockaddr_in *)out;
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)out;
    if (inet_pton(AF_INET, buf, &s4->sin_addr) == 1) {
        s4->sin_family = AF_INET;
        s4->sin_port = htons(port);
        *len = sizeof *s4;
        return 0;
    }
    if (inet_pton(AF_INET6, buf, &s6->sin6_addr) == 1) {
        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        *len = sizeof *s6;
        return 0;
    }
    return -1;
}

int net_parse_hostport(const char *s, uint16_t defport, struct sockaddr_storage *out, socklen_t *len) {
    char host[80];
    uint16_t port = defport;
    if (s[0] == '[') {
        const char *e = strchr(s, ']');
        if (!e || (size_t)(e - s) >= sizeof host) return -1;
        memcpy(host, s + 1, (size_t)(e - s - 1));
        host[e - s - 1] = 0;
        if (e[1] == ':') port = (uint16_t)atoi(e + 2);
    } else {
        const char *c = strrchr(s, ':');
        if (c && strchr(s, ':') == c) {
            if ((size_t)(c - s) >= sizeof host) return -1;
            memcpy(host, s, (size_t)(c - s));
            host[c - s] = 0;
            port = (uint16_t)atoi(c + 1);
        } else snprintf(host, sizeof host, "%s", s);
    }
    if (!host[0]) snprintf(host, sizeof host, "0.0.0.0");
    return net_parse_ip(host, port, out, len);
}

void net_fmt_ip(const struct sockaddr *sa, char *buf, size_t n) {
    if (sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)sa)->sin_addr, buf, (socklen_t)n);
    else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        /* Адрес IPv4, пришедший на сокет с двумя стеками, — «::ffff:a.b.c.d»: печатаем как IPv4,
         * чтобы правила source_ip_cidr и Clash API видели тот же адрес, что и человек. */
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
            inet_ntop(AF_INET, &s6->sin6_addr.s6_addr[12], buf, (socklen_t)n);
        else inet_ntop(AF_INET6, &s6->sin6_addr, buf, (socklen_t)n);
    } else snprintf(buf, n, "?");
}

void net_fmt(const struct sockaddr *sa, char *buf, size_t n) {
    char ip[64];
    net_fmt_ip(sa, ip, sizeof ip);
    if (strchr(ip, ':')) snprintf(buf, n, "[%s]:%u", ip, net_port(sa));
    else snprintf(buf, n, "%s:%u", ip, net_port(sa));
}

uint16_t net_port(const struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) return ntohs(((const struct sockaddr_in *)sa)->sin_port);
    if (sa->sa_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
    return 0;
}

int set_nonblock(int fd, int on) {
    int fl = fcntl(fd, F_GETFL);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, on ? fl | O_NONBLOCK : fl & ~O_NONBLOCK);
}

int write_all(int fd, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) {
                struct pollfd pf = { fd, POLLOUT, 0 };
                if (poll(&pf, 1, 5000) <= 0) return -1;
                continue;
            }
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

int net_listen(const struct sockaddr_storage *a, socklen_t len, int udp) {
    int fd = socket(a->ss_family, (udp ? SOCK_DGRAM : SOCK_STREAM) | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (a->ss_family == AF_INET6) {
        /* «::» у sing-box — оба стека (forkop слушает source-dns-in на [::]:1603 и ждёт на нём и
         * IPv4). Конкретный адрес IPv6 — только IPv6. */
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)a;
        int v6only = !IN6_IS_ADDR_UNSPECIFIED(&s6->sin6_addr);
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
    }
    /* Адрес 127.0.0.42 и адрес LAN могут ещё не стоять на интерфейсе при старте (netifd поднимает
     * br-lan позже нас после перезагрузки): IP_FREEBIND даёт слушать заранее. */
    setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof one);
    if (bind(fd, (const struct sockaddr *)a, len) || (!udp && listen(fd, 128))) {
        int e = errno;
        close(fd);
        errno = e;
        return -1;
    }
    return fd;
}

int net_set_egress(int fd, const struct egress *eg, int family) {
    (void)family;
    if (!eg) return 0;
    if (eg->dev[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, eg->dev, (socklen_t)strlen(eg->dev) + 1))
        return -1;
    if (eg->mark) {
        int m = (int)eg->mark;
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &m, sizeof m)) return -1;
    }
    return 0;
}

int net_connect(const struct sockaddr_storage *a, socklen_t len, const struct egress *eg,
                int timeout_ms, char *err, size_t errn) {
    int fd = socket(a->ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    char where[80];
    net_fmt((const struct sockaddr *)a, where, sizeof where);
    if (fd < 0) { snprintf(err, errn, "socket: %s", strerror(errno)); return -1; }
    if (net_set_egress(fd, eg, a->ss_family)) {
        snprintf(err, errn, "привязка к %s: %s", eg && eg->dev[0] ? eg->dev : "метке", strerror(errno));
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    if (connect(fd, (const struct sockaddr *)a, len) && errno != EINPROGRESS) {
        snprintf(err, errn, "%s: %s", where, strerror(errno));
        close(fd);
        return -1;
    }
    struct pollfd pf = { fd, POLLOUT, 0 };
    int pr = poll(&pf, 1, timeout_ms);
    if (pr <= 0) {
        snprintf(err, errn, "%s: нет ответа за %d мс", where, timeout_ms);
        close(fd);
        return -1;
    }
    int so = 0;
    socklen_t sl = sizeof so;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so, &sl);
    if (so) {
        snprintf(err, errn, "%s: %s", where, strerror(so));
        close(fd);
        return -1;
    }
    set_nonblock(fd, 0);
    return fd;
}

static net_resolver_fn g_resolver;

void net_set_resolver(net_resolver_fn fn) { g_resolver = fn; }

int net_resolve(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens, int max) {
    if (!net_parse_ip(host, port, &out[0], &lens[0])) return 1;
    if (g_resolver) {
        int n = g_resolver(host, out, lens, max);
        for (int i = 0; i < n; i++) {
            if (out[i].ss_family == AF_INET) ((struct sockaddr_in *)&out[i])->sin_port = htons(port);
            else if (out[i].ss_family == AF_INET6) ((struct sockaddr_in6 *)&out[i])->sin6_port = htons(port);
        }
        if (n > 0) return n;
    }
    struct addrinfo hints = { .ai_socktype = SOCK_STREAM }, *res = NULL;
    char ps[8];
    snprintf(ps, sizeof ps, "%u", port);
    if (getaddrinfo(host, ps, &hints, &res)) return 0;
    int n = 0;
    /* IPv4 впереди: туннели steer несут IPv4 всегда, IPv6 — не все. */
    for (int pass = 0; pass < 2; pass++)
        for (struct addrinfo *ai = res; ai && n < max; ai = ai->ai_next) {
            if ((pass == 0) != (ai->ai_family == AF_INET)) continue;
            memcpy(&out[n], ai->ai_addr, ai->ai_addrlen);
            lens[n] = ai->ai_addrlen;
            n++;
        }
    freeaddrinfo(res);
    return n;
}

int net_dial(const char *host, uint16_t port, const struct egress *eg, int timeout_ms,
             char *err, size_t errn) {
    struct sockaddr_storage a[8];
    socklen_t l[8];
    int n = net_resolve(host, port, a, l, 8);
    if (n <= 0) { snprintf(err, errn, "имя %s не разрешилось", host); return -1; }
    for (int i = 0; i < n; i++) {
        int fd = net_connect(&a[i], l[i], eg, timeout_ms, err, errn);
        if (fd >= 0) return fd;
    }
    return -1;
}
