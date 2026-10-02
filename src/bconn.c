/* Поток байт к серверу и HTTP/1.1 над ним — см. bconn.h. */
#define _GNU_SOURCE
#include "bconn.h"
#include "tls13.h"
#include "reality.h"
#include "roots.h"
#include "certverify.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>

static void set_timeo(int fd, int ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

int bconn_open(struct bconn *c, const char *host, uint16_t port, const struct sockaddr_storage *addrs,
               const socklen_t *lens, int naddr, const struct egress *eg, const struct bconn_opts *o,
               char *err, size_t errn) {
    memset(c, 0, sizeof *c);
    c->fd = -1;
    struct sockaddr_storage a[8];
    socklen_t l[8];
    int n = naddr;
    if (!addrs || naddr <= 0) {
        n = net_resolve(host, port, a, l, 8);
        if (n <= 0) { snprintf(err, errn, "имя %s не разрешилось", host); return -1; }
        addrs = a;
        lens = l;
    }
    int tmo = o && o->timeout_ms > 0 ? o->timeout_ms : 10000;
    for (int i = 0; i < n && c->fd < 0; i++) {
        struct sockaddr_storage x = addrs[i];
        if (x.ss_family == AF_INET) ((struct sockaddr_in *)&x)->sin_port = htons(port);
        else if (x.ss_family == AF_INET6) ((struct sockaddr_in6 *)&x)->sin6_port = htons(port);
        c->fd = net_connect(&x, lens[i], eg, tmo, err, errn);
    }
    if (c->fd < 0) return -1;
    set_timeo(c->fd, tmo);
    if (!o || !o->tls) return 0;
    struct reality_cfg cfg = { .sni = o->sni ? o->sni : host, .plain = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    /* ALPN у steer — пара «h2, http/1.1», как у браузера (cfg.alpn в обычном TLS её не
     * меняет). Коннектору HTTP/2 здесь не нужен (DoH, скачивание — HTTP/1.1), поэтому только
     * http/1.1 — носителем alpn_http11; ALPS снят по той же причине, что у DoH резолвера steer:
     * dns.google ждёт после него блок настроек и рвёт соединение (reality.h, no_alps). */
    /* alpn «http/1.1» — только он; иначе обычная пара «h2, http/1.1» (alpn задан) или пара и
     * без надобности (NULL — у DoT сервер её просто не выбирает). */
    struct reality_carrier car = { .alpn_http11 = o->alpn && !strcmp(o->alpn, "http/1.1"), .no_alps = 1 };
    if (reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof hello, &hello_n) ||
        write_all(c->fd, hello, hello_n)) {
        snprintf(err, errn, "%s: ClientHello не ушёл", host);
        bconn_close(c);
        return -1;
    }
    c->tls = calloc(1, sizeof *c->tls);
    if (!c->tls) { snprintf(err, errn, "нет памяти"); bconn_close(c); return -1; }
    struct cert_policy pol = { .insecure = o->insecure };
    struct tls13_auth auth = { .host = cfg.sni, .roots = tls_cert_roots(), .policy = &pol };
    int rc = tls13_handshake_auth(c->tls, c->fd, hello, hello_n, rst.priv, &auth);
    if (rc) {
        const char *why = tls13_verify_reason();
        snprintf(err, errn, "%s: рукопожатие TLS не удалось (%d%s%s)", host, rc,
                 why && *why ? ": " : "", why && *why ? why : "");
        bconn_close(c);
        return -1;
    }
    snprintf(c->alpn, sizeof c->alpn, "%s", c->tls->alpn);
    if (getenv("BOX_TRACE")) fprintf(stderr, "tls %s alpn=%s\n", host, c->alpn);
    return 0;
}

int bconn_write(struct bconn *c, const void *buf, size_t n) {
    if (c->tls) {
        /* Запись TLS — до 16 КиБ; tls13_write режет сам, если умеет, но не полагаемся. */
        const unsigned char *p = buf;
        while (n) {
            size_t k = n > 16000 ? 16000 : n;
            if (tls13_write(c->tls, p, k)) return -1;
            p += k;
            n -= k;
        }
        return 0;
    }
    return write_all(c->fd, buf, n);
}

long bconn_read(struct bconn *c, void *buf, size_t cap, int timeout_ms) {
    if (c->rn > c->roff) {
        size_t k = c->rn - c->roff;
        if (k > cap) k = cap;
        memcpy(buf, c->rbuf + c->roff, k);
        c->roff += k;
        return (long)k;
    }
    if (timeout_ms > 0) set_timeo(c->fd, timeout_ms);
    if (!c->tls) {
        ssize_t r = read(c->fd, buf, cap);
        return r < 0 ? -1 : (long)r;
    }
    if (!c->rbuf) {
        c->rcap = 16384 + 256;
        c->rbuf = malloc(c->rcap);
        if (!c->rbuf) return -1;
    }
    for (;;) {
        size_t got = 0;
        int rc = tls13_read(c->tls, c->rbuf, c->rcap, &got);
        if (rc) { if (getenv("BOX_TRACE")) fprintf(stderr, "tls13_read rc=%d\n", rc); return rc == TLS13_ECLOSED ? 0 : -1; }
        if (!got) continue;               /* служебная запись (билет сессии) */
        c->roff = 0;
        c->rn = got;
        size_t k = got > cap ? cap : got;
        memcpy(buf, c->rbuf, k);
        c->roff = k;
        return (long)k;
    }
}

int bconn_read_full(struct bconn *c, void *buf, size_t n, int timeout_ms) {
    unsigned char *p = buf;
    while (n) {
        long r = bconn_read(c, p, n, timeout_ms);
        if (r <= 0) return -1;
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

long bconn_read_line(struct bconn *c, char *buf, size_t cap, int timeout_ms) {
    size_t j = 0;
    for (;;) {
        char ch;
        long r = bconn_read(c, &ch, 1, timeout_ms);
        if (r <= 0) return -1;
        if (ch == '\n') break;
        if (j + 1 < cap) buf[j++] = ch;
    }
    if (j && buf[j - 1] == '\r') j--;
    buf[j] = 0;
    return (long)j;
}

void bconn_close(struct bconn *c) {
    if (c->tls) { tls13_free(c->tls); free(c->tls); }
    if (c->fd >= 0) close(c->fd);
    free(c->rbuf);
    memset(c, 0, sizeof *c);
    c->fd = -1;
}

/* ---- HTTP/1.1 --------------------------------------------------------------------------- */

void http_resp_free(struct http_resp *r) {
    free(r->body);
    memset(r, 0, sizeof *r);
}

int http_request(struct bconn *c, const char *method, const char *host, const char *path,
                 const char *ctype, const char *accept, const void *body, size_t bodyn,
                 const char *extra_headers, struct http_resp *r, size_t max_body, int timeout_ms,
                 char *err, size_t errn) {
    memset(r, 0, sizeof *r);
    char head[2048];
    int hn = snprintf(head, sizeof head,
                      "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Go-http-client/1.1\r\n"
                      "%s%s%s%s%s%s%s",
                      method, path && *path ? path : "/", host,
                      ctype ? "Content-Type: " : "", ctype ? ctype : "", ctype ? "\r\n" : "",
                      accept ? "Accept: " : "", accept ? accept : "", accept ? "\r\n" : "",
                      extra_headers ? extra_headers : "");
    if (hn < 0 || (size_t)hn >= sizeof head - 64) { snprintf(err, errn, "запрос слишком длинный"); return -1; }
    if (body) hn += snprintf(head + hn, sizeof head - (size_t)hn, "Content-Length: %zu\r\n", bodyn);
    hn += snprintf(head + hn, sizeof head - (size_t)hn, "\r\n");
    if (bconn_write(c, head, (size_t)hn) || (body && bodyn && bconn_write(c, body, bodyn))) {
        snprintf(err, errn, "запрос HTTP не ушёл");
        return -1;
    }
    char line[4096];
    if (bconn_read_line(c, line, sizeof line, timeout_ms) < 0) {
        snprintf(err, errn, "нет ответа HTTP");
        return -1;
    }
    if (sscanf(line, "HTTP/%*s %d", &r->status) != 1) {
        snprintf(err, errn, "ответ не HTTP: %.60s", line);
        return -1;
    }
    long long clen = -1;
    int chunked = 0;
    for (;;) {
        long l = bconn_read_line(c, line, sizeof line, timeout_ms);
        if (l < 0) { snprintf(err, errn, "заголовки HTTP оборвались"); return -1; }
        if (!l) break;
        if (!strncasecmp(line, "content-length:", 15)) clen = atoll(line + 15);
        else if (!strncasecmp(line, "transfer-encoding:", 18) && strcasestr(line + 18, "chunked")) chunked = 1;
        else if (!strncasecmp(line, "connection:", 11) && strcasestr(line + 11, "close")) r->close = 1;
    }
    size_t cap = 0;
    if (!strcasecmp(method, "HEAD") || r->status == 204 || r->status == 304) return 0;
    if (chunked) {
        for (;;) {
            if (bconn_read_line(c, line, sizeof line, timeout_ms) < 0) { snprintf(err, errn, "тело оборвалось"); return -1; }
            size_t k = (size_t)strtoul(line, NULL, 16);
            if (!k) {
                while (bconn_read_line(c, line, sizeof line, timeout_ms) > 0) {}
                break;
            }
            /* Размер куска — число сервера: сравнение без суммы, иначе кусок около 2^64
             * переполнял бы её и проходил проверку (тело всегда не больше max_body). */
            if (k > max_body - r->body_n) { snprintf(err, errn, "тело больше %zu байт", max_body); return -1; }
            if (r->body_n + k + 1 > cap) {
                cap = (r->body_n + k + 1) * 2;
                unsigned char *nb = realloc(r->body, cap);
                if (!nb) { snprintf(err, errn, "нет памяти"); return -1; }
                r->body = nb;
            }
            if (bconn_read_full(c, r->body + r->body_n, k, timeout_ms)) { snprintf(err, errn, "тело оборвалось"); return -1; }
            r->body_n += k;
            bconn_read_line(c, line, sizeof line, timeout_ms);
        }
    } else if (clen >= 0) {
        if ((size_t)clen > max_body) { snprintf(err, errn, "тело больше %zu байт", max_body); return -1; }
        r->body = malloc((size_t)clen + 1);
        if (!r->body) { snprintf(err, errn, "нет памяти"); return -1; }
        if (clen && bconn_read_full(c, r->body, (size_t)clen, timeout_ms)) { snprintf(err, errn, "тело оборвалось"); return -1; }
        r->body_n = (size_t)clen;
    } else {
        /* Ни длины, ни chunked — тело до закрытия соединения. */
        r->close = 1;
        for (;;) {
            if (r->body_n + 16384 + 1 > cap) {
                cap = cap ? cap * 2 : 65536;
                if (cap > max_body + 16384 + 1) cap = max_body + 16384 + 1;
                unsigned char *nb = realloc(r->body, cap);
                if (!nb) { snprintf(err, errn, "нет памяти"); return -1; }
                r->body = nb;
            }
            long k = bconn_read(c, r->body + r->body_n, cap - r->body_n - 1, timeout_ms);
            if (k <= 0) break;
            r->body_n += (size_t)k;
            if (r->body_n > max_body) { snprintf(err, errn, "тело больше %zu байт", max_body); return -1; }
        }
    }
    if (r->body) r->body[r->body_n] = 0;
    return 0;
}

static int split_url(const char *url, int *tls, char *host, size_t hn, uint16_t *port, char *path, size_t pn) {
    const char *p = url;
    if (!strncasecmp(p, "https://", 8)) { *tls = 1; p += 8; *port = 443; }
    else if (!strncasecmp(p, "http://", 7)) { *tls = 0; p += 7; *port = 80; }
    else { *tls = 0; *port = 80; }             /* как sing-box tools fetch: без схемы — http */
    const char *slash = strchr(p, '/');
    size_t hl = slash ? (size_t)(slash - p) : strlen(p);
    char hp[300];
    if (hl >= sizeof hp) return -1;
    memcpy(hp, p, hl);
    hp[hl] = 0;
    char *colon = hp[0] == '[' ? strstr(hp, "]:") : strrchr(hp, ':');
    if (colon && hp[0] == '[') colon++;
    if (colon && (hp[0] == '[' || strchr(hp, ':') == colon)) { *port = (uint16_t)atoi(colon + 1); *colon = 0; }
    if (hp[0] == '[') { size_t l = strlen(hp); memmove(hp, hp + 1, l); if (l > 1) hp[l - 2] = 0; }
    snprintf(host, hn, "%s", hp);
    snprintf(path, pn, "%s", slash ? slash : "/");
    return host[0] ? 0 : -1;
}

static const char *g_ua;

void http_set_user_agent(const char *ua) { g_ua = ua; }

int http_get(const char *url, const struct egress *eg, int timeout_ms, size_t max_body,
             unsigned char **out, size_t *outn, int *status, char *err, size_t errn) {
    char cur[2048];
    snprintf(cur, sizeof cur, "%s", url);
    for (int hop = 0; hop < 6; hop++) {
        int tls;
        uint16_t port;
        char host[256], path[1800];
        if (split_url(cur, &tls, host, sizeof host, &port, path, sizeof path)) {
            snprintf(err, errn, "адрес %s не разобрался", cur);
            return -1;
        }
        struct bconn c;
        struct bconn_opts o = { .tls = tls, .alpn = tls ? "http/1.1" : NULL, .timeout_ms = timeout_ms };
        if (bconn_open(&c, host, port, NULL, NULL, 0, eg, &o, err, errn)) return -1;
        char hosthdr[300];
        if ((tls && port != 443) || (!tls && port != 80)) snprintf(hosthdr, sizeof hosthdr, "%s:%u", host, port);
        else snprintf(hosthdr, sizeof hosthdr, "%s", host);
        struct http_resp r;
        /* Location нужен для редиректа: http_request его не хранит — читаем заголовки сами
         * через второй заход было бы дороже; редиректы у раздачи наборов (GitHub releases →
         * objects.githubusercontent.com) — обычное дело, поэтому заголовок ловим здесь. */
        char head[2048];
        int hn = snprintf(head, sizeof head, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"
                          "Accept: */*\r\nConnection: close\r\n\r\n", path, hosthdr,
                          g_ua ? g_ua : "Go-http-client/1.1");
        if (bconn_write(&c, head, (size_t)hn)) { bconn_close(&c); snprintf(err, errn, "запрос не ушёл"); return -1; }
        char line[4096], location[2048] = "";
        memset(&r, 0, sizeof r);
        if (bconn_read_line(&c, line, sizeof line, timeout_ms) < 0 || sscanf(line, "HTTP/%*s %d", &r.status) != 1) {
            bconn_close(&c);
            snprintf(err, errn, "нет ответа HTTP от %s", host);
            return -1;
        }
        long long clen = -1;
        int chunked = 0;
        for (;;) {
            long l = bconn_read_line(&c, line, sizeof line, timeout_ms);
            if (l < 0) { bconn_close(&c); snprintf(err, errn, "заголовки оборвались"); return -1; }
            if (!l) break;
            if (!strncasecmp(line, "content-length:", 15)) clen = atoll(line + 15);
            else if (!strncasecmp(line, "transfer-encoding:", 18) && strcasestr(line, "chunked")) chunked = 1;
            else if (!strncasecmp(line, "location:", 9)) {
                const char *v = line + 9;
                while (*v == ' ') v++;
                snprintf(location, sizeof location, "%s", v);
            }
        }
        if (r.status >= 300 && r.status < 400 && location[0]) {
            bconn_close(&c);
            if (location[0] == '/') {
                char base[400];
                snprintf(base, sizeof base, "%s://%s", tls ? "https" : "http", hosthdr);
                snprintf(cur, sizeof cur, "%s%s", base, location);
            } else snprintf(cur, sizeof cur, "%s", location);
            continue;
        }
        size_t cap = 0, n = 0;
        unsigned char *body = NULL;
        int bad = 0;
        if (chunked) {
            for (;;) {
                if (bconn_read_line(&c, line, sizeof line, timeout_ms) < 0) { bad = 1; break; }
                size_t k = (size_t)strtoul(line, NULL, 16);
                if (!k) break;
                if (k > max_body - n) { bad = 2; break; }   /* без суммы: см. http_request */
                if (n + k + 1 > cap) {
                    cap = (n + k + 1) * 2;
                    unsigned char *nb = realloc(body, cap);
                    if (!nb) { bad = 1; break; }
                    body = nb;
                }
                if (bconn_read_full(&c, body + n, k, timeout_ms)) { bad = 1; break; }
                n += k;
                bconn_read_line(&c, line, sizeof line, timeout_ms);
            }
        } else {
            for (;;) {
                if (clen >= 0 && (long long)n >= clen) break;
                if (n + 65536 + 1 > cap) {
                    cap = cap ? cap * 2 : 65536 * 2;
                    unsigned char *nb = realloc(body, cap);
                    if (!nb) { bad = 1; break; }
                    body = nb;
                }
                long k = bconn_read(&c, body + n, cap - n - 1, timeout_ms);
                if (k < 0) { if (clen >= 0) bad = 1; break; }
                if (k == 0) { if (clen >= 0 && (long long)n < clen) bad = 1; break; }
                n += (size_t)k;
                if (n > max_body) { bad = 2; break; }
            }
        }
        bconn_close(&c);
        if (bad) {
            free(body);
            snprintf(err, errn, bad == 2 ? "ответ больше %zu байт" : "ответ оборвался", max_body);
            return -1;
        }
        if (!body) body = calloc(1, 1);
        else body[n] = 0;
        *out = body;
        *outn = n;
        *status = r.status;
        return 0;
    }
    snprintf(err, errn, "слишком много перенаправлений");
    return -1;
}
