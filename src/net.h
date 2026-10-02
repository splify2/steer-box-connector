/* Сокеты коннектора: слушатели, исходящие соединения через выход, адреса. */
#ifndef BOX_NET_H
#define BOX_NET_H
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Как исходящий сокет коннектора идёт наружу (BOX_CONNECTOR.md, раздел 3в):
 *   dev  — SO_BINDTODEVICE на устройство выхода (туннель steer, интерфейс). Привязка, а не метка:
 *          podkop в mangle_output целиком переписывает метку пакетам к адресам своих списков, и
 *          пакет с меткой выхода steer ушёл бы в main; привязку не переписывает никто;
 *   mark — SO_MARK (route.default_mark: forkop ждёт 0x08000000 на каждом исходящем sing-box, его
 *          mangle_output пропускает такие пакеты), 0 — без метки. */
struct egress {
    char dev[16];
    uint32_t mark;
};

/* «адрес:порт», «[v6]:порт», «:порт» → sockaddr. 0 — разобралось. */
int net_parse_hostport(const char *s, uint16_t defport, struct sockaddr_storage *out, socklen_t *len);
/* Адрес литералом (без порта) → sockaddr с портом port. */
int net_parse_ip(const char *s, uint16_t port, struct sockaddr_storage *out, socklen_t *len);
void net_fmt(const struct sockaddr *sa, char *buf, size_t n);   /* «1.2.3.4:53», «[::1]:53» */
void net_fmt_ip(const struct sockaddr *sa, char *buf, size_t n);
uint16_t net_port(const struct sockaddr *sa);

/* Слушатели. udp — 1 у UDP. transparent не бывает: прозрачных сокетов коннектор не держит
 * нарочно (иначе tproxy podkop/forkop отдал бы трафик нам). Возвращают fd или -1 (errno). */
int net_listen(const struct sockaddr_storage *a, socklen_t len, int udp);

/* Соединение TCP через egress со сроком timeout_ms. fd (блокирующий) или -1, причина в err. */
int net_connect(const struct sockaddr_storage *a, socklen_t len, const struct egress *eg,
                int timeout_ms, char *err, size_t errn);
/* Имя → адреса (getaddrinfo без привязки: имя разрешает системный резолвер, то есть dnsmasq и
 * наш 127.0.0.42). Возвращает число адресов. */
int net_resolve(const char *host, uint16_t port, struct sockaddr_storage *out, socklen_t *lens, int max);
/* Резолвер, которым net_resolve разрешает имена, если он задан (sing-box run ставит свой — DNS
 * коннектора с настоящими адресами: системный через dnsmasq отдал бы роутеру fake-IP, а у сокета
 * самого роутера поддельный адрес никуда не ведёт). Возвращает число адресов; порт ставит
 * net_resolve. NULL — getaddrinfo. */
typedef int (*net_resolver_fn)(const char *host, struct sockaddr_storage *out, socklen_t *lens, int max);
void net_set_resolver(net_resolver_fn fn);

/* Соединиться с host:port (имя или литерал) по первому ответившему адресу. */
int net_dial(const char *host, uint16_t port, const struct egress *eg, int timeout_ms,
             char *err, size_t errn);

int net_set_egress(int fd, const struct egress *eg, int family);
int write_all(int fd, const void *buf, size_t n);
int set_nonblock(int fd, int on);

#endif
