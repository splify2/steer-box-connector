/* Серверы DNS коннектора: udp, tcp, tls (DoT), https (DoH, HTTP/1.1).
 *
 * У каждого сервера — очередь вопросов и рабочие потоки, каждый со своим соединением (у tls и https —
 * постоянным: рукопожатие TLS на каждый вопрос стоило бы сотни миллисекунд на роутере). Новый поток
 * заводится, когда все заняты и очередь не пуста; у сервера с соединением — по одному: следующий,
 * когда предыдущий соединился (пачка вопросов не открывает сотню рукопожатий разом).
 * Простаивающий минуту поток выходит. Пределом служит число потоков процесса.
 *
 * Имя сервера (server: dns.google) разрешается его domain_resolver — другим сервером из того же
 * конфига, по UDP, — а не системным резолвером: тот ходит через dnsmasq обратно в коннектор. */
#ifndef BOX_DNSUP_H
#define BOX_DNSUP_H
#include <stddef.h>
#include <stdint.h>
#include "net.h"
#include "evloop.h"
#include "json.h"

struct dnsup;

/* Ответ сервера — в потоке цикла. resp == NULL — отказ (err — почему). */
typedef void (*dnsup_cb)(void *arg, const uint8_t *resp, size_t n, const char *err);

/* cfg — объект сервера из dns.servers; eg — куда идут его сокеты (detour, default_mark);
 * resolver — сервер для его имени (NULL — имя должно быть адресом). */
struct dnsup *dnsup_new(struct ev *ev, const struct jval *cfg, const struct egress *eg, struct dnsup *resolver);
void dnsup_ref(struct dnsup *u);
void dnsup_unref(struct dnsup *u);
const char *dnsup_tag(const struct dnsup *u);

/* Из потока цикла. */
int dnsup_ask(struct dnsup *u, const uint8_t *q, size_t n, dnsup_cb cb, void *arg);
/* Из рабочего потока: ждать ответа. Длина ответа или -1. */
long dnsup_ask_blocking(struct dnsup *u, const uint8_t *q, size_t n, uint8_t *resp, size_t cap, int timeout_ms);

/* Срок одного вопроса: тот же, что у резолвера steer (4 с) — больше клиент всё равно не ждёт. */
#define DNSUP_TIMEOUT_MS 4000

#endif
