/* Входы mixed, socks и http коннектора: прокси для своих загрузок podkop и forkop (service-mixed-in
 * 127.0.0.1:4534, у forkop ещё 4535 и 4536+) и прокси секции в LAN (<секция>-mixed-in).
 *
 * Протоколы: SOCKS5 (без аутентификации и логин/пароль, RFC 1929; CONNECT), SOCKS4/4a, HTTP —
 * CONNECT и запрос с абсолютным URI (wget с http_proxy, curl -x без -p). UDP ASSOCIATE не ведётся:
 * загрузкам он не нужен, и отказ называется кодом протокола.
 *
 * Выход — по правилам маршрута для этого входа (у podkop и forkop это правило `inbound: <вход>` с
 * outbound секции), иначе route.final. Соединение до цели идёт через устройство выхода
 * (rt_egress); имя цели разрешает DNS коннектора настоящим адресом. Каждое соединение — в своём
 * рабочем потоке: данные через него идут блокирующим копированием. */
#define _GNU_SOURCE
#include "runtime.h"
#include "sbconf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>

struct mlist {
    int fd;
    char tag[128];
    char out[160];               /* выход по правилам */
    struct jval *users;          /* копия users входа */
    struct mlist *next;
};

struct mixed_srv {
    struct box_rt *rt;
    struct mlist *ls;
};

struct mconn {
    struct box_rt *rt;
    int fd;
    char tag[128];
    struct egress eg;
    int eg_ok;
    char eg_err[200];
    struct jval *users;          /* своя копия */
};

/* Выход для входа tag: первое правило route, которое касается этого входа и не требует
 * ничего, кроме входа (так пишут podkop и forkop). Правила с условиями по назначению для
 * загрузок не встречаются; если такое стоит выше — оно пропускается с отметкой в журнале. */
static void out_for_inbound(struct box_rt *rt, const char *tag, char *out, size_t n) {
    const struct jval *rules = jget(jget(rt->cfg, "route"), "rules");
    for (size_t i = 0; i < jlen(rules); i++) {
        const struct jval *r = jat(rules, i);
        const struct jval *in = jget(r, "inbound");
        long k = in ? jstrlist(in, NULL, 0) : 0;
        int hit = 0;
        for (long j = 0; j < k; j++)
            if (!strcmp(in->t == J_ARR ? in->a[j]->s : in->s, tag)) hit = 1;
        if (!hit) continue;
        const char *act = jgets(r, "action");
        if (act && strcmp(act, "route")) continue;
        int extra = 0;
        for (size_t f = 0; f < jlen(r); f++)
            if (strcmp(r->o[f].key, "inbound") && strcmp(r->o[f].key, "action") && strcmp(r->o[f].key, "outbound"))
                extra = 1;
        if (extra) {
            LOGD("mixed %s: правило route.rules[%zu] с условиями по назначению не ведётся", tag, i);
            continue;
        }
        snprintf(out, n, "%s", jgets(r, "outbound") ? jgets(r, "outbound") : "");
        return;
    }
    const char *fin = jgets(jget(rt->cfg, "route"), "final");
    snprintf(out, n, "%s", fin ? fin : "");
}

/* ---- проброс ---------------------------------------------------------------------------- */

static void relay(int a, int b) {
    char buf[32768];
    struct pollfd p[2] = { { a, POLLIN, 0 }, { b, POLLIN, 0 } };
    int open_a = 1, open_b = 1;
    while (open_a || open_b) {
        p[0].events = open_a ? POLLIN : 0;
        p[1].events = open_b ? POLLIN : 0;
        /* Простой без трафика пять минут — соединение мертво (как udp_timeout sing-box для TCP
         * не бывает, но зависший сервер держал бы поток вечно). */
        int r = poll(p, 2, 300000);
        if (r <= 0) break;
        for (int i = 0; i < 2; i++) {
            if (!(p[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            int from = i ? b : a, to = i ? a : b;
            ssize_t n = read(from, buf, sizeof buf);
            if (n <= 0) {
                shutdown(to, SHUT_WR);
                if (i) open_b = 0; else open_a = 0;
                continue;
            }
            if (write_all(to, buf, (size_t)n)) return;
        }
    }
}

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    while (n) {
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, 15000) <= 0) return -1;
        ssize_t r = read(fd, p, n);
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

static int check_user(const struct jval *users, const char *u, const char *p) {
    if (!jlen(users)) return 1;
    for (size_t i = 0; i < jlen(users); i++) {
        const char *uu = jgets(jat(users, i), "username"), *pp = jgets(jat(users, i), "password");
        if (uu && pp && !strcmp(uu, u) && !strcmp(pp, p)) return 1;
    }
    return 0;
}

static int dial(struct mconn *m, const char *host, uint16_t port, char *err, size_t errn) {
    if (!m->eg_ok) { snprintf(err, errn, "%s", m->eg_err); return -1; }
    struct sockaddr_storage a[8];
    socklen_t l[8];
    int n = dns_resolve_blocking(m->rt, host, a, l, 8);
    if (n <= 0) { snprintf(err, errn, "имя %s не разрешилось", host); return -1; }
    for (int i = 0; i < n; i++) {
        if (a[i].ss_family == AF_INET) ((struct sockaddr_in *)&a[i])->sin_port = htons(port);
        else ((struct sockaddr_in6 *)&a[i])->sin6_port = htons(port);
        int fd = net_connect(&a[i], l[i], &m->eg, 10000, err, errn);
        if (fd >= 0) return fd;
    }
    return -1;
}

static void do_socks5(struct mconn *m) {
    unsigned char b[512];
    if (read_full(m->fd, b, 1) || read_full(m->fd, b + 1, b[0])) return;
    int need_auth = jlen(m->users) > 0, offered_pw = 0, offered_none = 0;
    for (int i = 0; i < b[0]; i++) {
        if (b[1 + i] == 2) offered_pw = 1;
        if (b[1 + i] == 0) offered_none = 1;
    }
    unsigned char rep[2] = { 5, 0xFF };
    if (need_auth && offered_pw) rep[1] = 2;
    else if (!need_auth && offered_none) rep[1] = 0;
    if (write_all(m->fd, rep, 2) || rep[1] == 0xFF) return;
    if (rep[1] == 2) {
        unsigned char ul, pl;
        char u[256], p[256];
        if (read_full(m->fd, b, 2)) return;
        ul = b[1];
        if (read_full(m->fd, u, ul) || read_full(m->fd, &pl, 1) || read_full(m->fd, p, pl)) return;
        u[ul] = 0;
        p[pl] = 0;
        unsigned char ok[2] = { 1, (unsigned char)(check_user(m->users, u, p) ? 0 : 1) };
        if (write_all(m->fd, ok, 2) || ok[1]) return;
    }
    if (read_full(m->fd, b, 4)) return;
    unsigned char cmd = b[1], atyp = b[3];
    char host[300];
    if (atyp == 1) {
        if (read_full(m->fd, b, 4)) return;
        inet_ntop(AF_INET, b, host, sizeof host);
    } else if (atyp == 4) {
        if (read_full(m->fd, b, 16)) return;
        inet_ntop(AF_INET6, b, host, sizeof host);
    } else if (atyp == 3) {
        unsigned char l;
        if (read_full(m->fd, &l, 1) || read_full(m->fd, host, l)) return;
        host[l] = 0;
    } else return;
    unsigned char pb[2];
    if (read_full(m->fd, pb, 2)) return;
    uint16_t port = (uint16_t)(pb[0] << 8 | pb[1]);
    unsigned char fail[10] = { 5, 7, 0, 1, 0, 0, 0, 0, 0, 0 };
    if (cmd != 1) { write_all(m->fd, fail, 10); return; }    /* только CONNECT */
    char err[256];
    int up = dial(m, host, port, err, sizeof err);
    if (up < 0) {
        LOGD("mixed %s: %s:%u — %s", m->tag, host, port, err);
        fail[1] = 4;                                          /* host unreachable */
        write_all(m->fd, fail, 10);
        return;
    }
    unsigned char ok[10] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    if (!write_all(m->fd, ok, 10)) relay(m->fd, up);
    close(up);
}

static void do_socks4(struct mconn *m) {
    unsigned char b[8];
    if (read_full(m->fd, b, 7)) return;              /* первый байт (4) уже прочитан */
    uint16_t port = (uint16_t)(b[1] << 8 | b[2]);
    char user[256], host[300];
    size_t ul = 0;
    for (;;) { char ch; if (read_full(m->fd, &ch, 1)) return; if (!ch) break; if (ul + 1 < sizeof user) user[ul++] = ch; }
    user[ul] = 0;
    if (b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] != 0) {   /* 4a: имя после user */
        size_t hl = 0;
        for (;;) { char ch; if (read_full(m->fd, &ch, 1)) return; if (!ch) break; if (hl + 1 < sizeof host) host[hl++] = ch; }
        host[hl] = 0;
    } else inet_ntop(AF_INET, b + 3, host, sizeof host);
    unsigned char rep[8] = { 0, 91, 0, 0, 0, 0, 0, 0 };
    if (b[0] != 1 || (jlen(m->users) && !check_user(m->users, user, ""))) { write_all(m->fd, rep, 8); return; }
    char err[256];
    int up = dial(m, host, port, err, sizeof err);
    if (up < 0) { LOGD("mixed %s: %s:%u — %s", m->tag, host, port, err); write_all(m->fd, rep, 8); return; }
    rep[1] = 90;
    if (!write_all(m->fd, rep, 8)) relay(m->fd, up);
    close(up);
}

static int b64dec(const char *in, char *out, size_t cap) {
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    unsigned v = 0;
    int bits = 0;
    for (; *in && *in != '='; in++) {
        const char *p = strchr(t, *in);
        if (!p) continue;
        v = v << 6 | (unsigned)(p - t);
        bits += 6;
        if (bits >= 8) { bits -= 8; if (j + 1 < cap) out[j++] = (char)(v >> bits & 0xFF); }
    }
    out[j] = 0;
    return (int)j;
}

static void do_http(struct mconn *m, unsigned char first) {
    char head[16384];
    size_t n = 0;
    head[n++] = (char)first;
    while (n + 1 < sizeof head) {
        struct pollfd pf = { m->fd, POLLIN, 0 };
        if (poll(&pf, 1, 15000) <= 0) return;
        ssize_t r = read(m->fd, head + n, sizeof head - n - 1);
        if (r <= 0) return;
        n += (size_t)r;
        head[n] = 0;
        if (strstr(head, "\r\n\r\n")) break;
    }
    char *end = strstr(head, "\r\n\r\n");
    if (!end) return;
    char method[16], target[4096], ver[16];
    if (sscanf(head, "%15s %4095s %15s", method, target, ver) != 3) return;
    if (jlen(m->users)) {
        const char *pa = strcasestr(head, "\r\nProxy-Authorization: Basic ");
        char cred[512] = "";
        if (pa) {
            pa += 29;
            char enc[600];
            size_t k = 0;
            while (pa[k] && pa[k] != '\r' && k + 1 < sizeof enc) { enc[k] = pa[k]; k++; }
            enc[k] = 0;
            b64dec(enc, cred, sizeof cred);
        }
        char *colon = strchr(cred, ':');
        if (!colon) cred[0] = 0;
        else *colon = 0;
        if (!colon || !check_user(m->users, cred, colon + 1)) {
            const char *r = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"sing-box\"\r\nContent-Length: 0\r\n\r\n";
            write_all(m->fd, r, strlen(r));
            return;
        }
    }
    char host[300];
    uint16_t port;
    char err[256];
    if (!strcasecmp(method, "CONNECT")) {
        char *c = strrchr(target, ':');
        if (!c) return;
        *c = 0;
        snprintf(host, sizeof host, "%s", target[0] == '[' ? target + 1 : target);
        char *rb = strchr(host, ']');
        if (rb) *rb = 0;
        port = (uint16_t)atoi(c + 1);
        int up = dial(m, host, port, err, sizeof err);
        if (up < 0) {
            LOGD("mixed %s: %s:%u — %s", m->tag, host, port, err);
            const char *r = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            write_all(m->fd, r, strlen(r));
            return;
        }
        const char *ok = "HTTP/1.1 200 Connection established\r\n\r\n";
        if (!write_all(m->fd, ok, strlen(ok))) {
            /* Байты после заголовка (клиент начал TLS, не дождавшись ответа) — серверу. */
            size_t after = n - (size_t)(end + 4 - head);
            if (after) write_all(up, end + 4, after);
            relay(m->fd, up);
        }
        close(up);
        return;
    }
    /* Абсолютный URI: http://host[:port]/path — переписать в относительный и переслать. */
    if (strncasecmp(target, "http://", 7)) {
        const char *r = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        write_all(m->fd, r, strlen(r));
        return;
    }
    char *hp = target + 7, *path = strchr(hp, '/');
    char hostport[300];
    snprintf(hostport, sizeof hostport, "%.*s", path ? (int)(path - hp) : (int)strlen(hp), hp);
    port = 80;
    char *colon = strrchr(hostport, ':');
    if (colon && !strchr(hostport, ']')) { *colon = 0; port = (uint16_t)atoi(colon + 1); }
    snprintf(host, sizeof host, "%s", hostport);
    int up = dial(m, host, port, err, sizeof err);
    if (up < 0) {
        LOGD("mixed %s: %s:%u — %s", m->tag, host, port, err);
        const char *r = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
        write_all(m->fd, r, strlen(r));
        return;
    }
    char line[4200];
    int ln = snprintf(line, sizeof line, "%s %s %s\r\n", method, path ? path : "/", ver);
    char *rest = strstr(head, "\r\n");
    if (write_all(up, line, (size_t)ln)) { close(up); return; }
    /* Заголовки — без Proxy-*: они нам, а не серверу. */
    for (char *h = rest + 2; h < end + 2;) {
        char *e = strstr(h, "\r\n");
        if (!e) break;
        if (strncasecmp(h, "Proxy-", 6)) write_all(up, h, (size_t)(e + 2 - h));
        h = e + 2;
    }
    write_all(up, "\r\n", 2);
    size_t after = n - (size_t)(end + 4 - head);
    if (after) write_all(up, end + 4, after);
    relay(m->fd, up);
    close(up);
}

static void conn_work(void *p) {
    struct mconn *m = p;
    set_nonblock(m->fd, 0);
    unsigned char first;
    if (read_full(m->fd, &first, 1)) return;
    if (first == 5) do_socks5(m);
    else if (first == 4) do_socks4(m);
    else do_http(m, first);
}

static void conn_done(void *p) {
    struct mconn *m = p;
    close(m->fd);
    json_free(m->users);
    free(m);
}

static void accept_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct mlist *l = arg;
    struct box_rt *rt = g_rt;
    for (;;) {
        int cfd = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) return;
        struct mconn *m = calloc(1, sizeof *m);
        if (!m) { close(cfd); continue; }
        m->rt = rt;
        m->fd = cfd;
        snprintf(m->tag, sizeof m->tag, "%s", l->tag);
        m->eg_ok = !rt_egress(rt, l->out[0] ? l->out : NULL, &m->eg, m->eg_err, sizeof m->eg_err);
        m->users = jdup(l->users);
        if (ev_spawn(ev, conn_work, conn_done, m)) { close(cfd); json_free(m->users); free(m); }
    }
}

int mixed_start(struct box_rt *rt) {
    struct mixed_srv *s = calloc(1, sizeof *s);
    if (!s) return -1;
    s->rt = rt;
    const struct jval *ins = jget(rt->cfg, "inbounds");
    for (size_t i = 0; i < jlen(ins); i++) {
        const struct jval *in = jat(ins, i);
        const char *type = jgets(in, "type");
        if (!type || (strcmp(type, "mixed") && strcmp(type, "socks") && strcmp(type, "http"))) continue;
        const char *listen = jgets(in, "listen");
        struct sockaddr_storage a;
        socklen_t l;
        if (net_parse_ip(listen ? listen : "0.0.0.0", (uint16_t)jgeti(in, "listen_port", 0), &a, &l)) continue;
        int fd = net_listen(&a, l, 0);
        if (fd < 0) {
            LOGE("mixed %s: %s:%lld не слушается: %s", jgets(in, "tag"), listen ? listen : "", (long long)jgeti(in, "listen_port", 0), strerror(errno));
            continue;
        }
        struct mlist *m = calloc(1, sizeof *m);
        if (!m) { LOGE("mixed %s: нет памяти", jgets(in, "tag") ? jgets(in, "tag") : type); close(fd); continue; }
        m->fd = fd;
        snprintf(m->tag, sizeof m->tag, "%s", jgets(in, "tag") ? jgets(in, "tag") : type);
        out_for_inbound(rt, m->tag, m->out, sizeof m->out);
        m->users = jdup(jget(in, "users"));
        m->next = s->ls;
        s->ls = m;
        ev_add(rt->ev, fd, EPOLLIN, accept_cb, m);
        LOGI("mixed %s: %s:%lld → %s", m->tag, listen ? listen : "0.0.0.0", (long long)jgeti(in, "listen_port", 0),
             m->out[0] ? m->out : "напрямую");
    }
    rt->mixed = s;
    return 0;
}

void mixed_stop(struct box_rt *rt) {
    struct mixed_srv *s = rt->mixed;
    if (!s) return;
    for (struct mlist *m = s->ls, *n; m; m = n) {
        n = m->next;
        ev_del(rt->ev, m->fd);
        close(m->fd);
        json_free(m->users);
        free(m);
    }
    free(s);
    rt->mixed = NULL;
}
