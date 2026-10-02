/* Поток байт коннектора к серверу: TCP или TLS 1.3 поверх него (DoT, DoH, скачивание наборов,
 * замер задержки, tools fetch). Блокирующий — только из рабочих потоков.
 *
 * TLS — движка steer: тот же ClientHello с обликом Chrome (reality_build_hello_carry, plain) и
 * проверка цепочки до корней роутера (tls13_handshake_auth), что у DoH резолвера steer. Своего TLS
 * у коннектора нет. */
#ifndef BOX_BCONN_H
#define BOX_BCONN_H
#include <stddef.h>
#include <stdint.h>
#include "net.h"

struct tls13;

struct bconn {
    int fd;
    struct tls13 *tls;
    unsigned char *rbuf;        /* расшифрованное, но не отданное */
    size_t roff, rn, rcap;
    char alpn[16];              /* что выбрал сервер */
};

struct bconn_opts {
    int tls;
    const char *sni;            /* NULL — host */
    const char *alpn;           /* «http/1.1» и т. п.; NULL — без ALPN */
    int insecure;
    int timeout_ms;
};

/* host — имя или литерал; addrs — уже найденные адреса (n > 0) или NULL (тогда net_resolve). */
int bconn_open(struct bconn *c, const char *host, uint16_t port, const struct sockaddr_storage *addrs,
               const socklen_t *lens, int naddr, const struct egress *eg, const struct bconn_opts *o,
               char *err, size_t errn);
int bconn_write(struct bconn *c, const void *buf, size_t n);
/* До cap байт; >0 — прочитано, 0 — конец потока, -1 — ошибка или срок. */
long bconn_read(struct bconn *c, void *buf, size_t cap, int timeout_ms);
/* Ровно n байт или -1. */
int bconn_read_full(struct bconn *c, void *buf, size_t n, int timeout_ms);
/* Строку до \n (без неё, \r срезается). Длина или -1. */
long bconn_read_line(struct bconn *c, char *buf, size_t cap, int timeout_ms);
void bconn_close(struct bconn *c);

/* HTTP/1.1 поверх bconn: одна вспомогательная функция на запрос. body — тело запроса (POST) или
 * NULL (GET). Ответ: код, тело (выделенное), длина. keep — оставить соединение открытым
 * (DoH держит его между вопросами). 0 — ответ получен (код любой). */
struct http_resp {
    int status;
    unsigned char *body;
    size_t body_n;
    int close;                  /* сервер сказал Connection: close */
};
int http_request(struct bconn *c, const char *method, const char *host, const char *path,
                 const char *ctype, const char *accept, const void *body, size_t bodyn,
                 const char *extra_headers, struct http_resp *r, size_t max_body, int timeout_ms,
                 char *err, size_t errn);
void http_resp_free(struct http_resp *r);

/* User-Agent запросов http_get; NULL — Go-http-client/1.1, как у sing-box. tools fetch ставит
 * curl: ifconfig.me и подобные отвечают голым адресом только такому клиенту, а podkop принимает
 * от `tools fetch ifconfig.me` только голый адрес. */
void http_set_user_agent(const char *ua);

/* GET url целиком (http:// или https://, редиректы до пяти — как у curl -L по умолчанию в
 * sing-box). out — выделенное тело. */
int http_get(const char *url, const struct egress *eg, int timeout_ms, size_t max_body,
             unsigned char **out, size_t *outn, int *status, char *err, size_t errn);

#endif
