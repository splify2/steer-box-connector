/* Разговор коннектора со своим экземпляром steer: сокет управления (docs/ctl.md) и запуск steerd.
 *
 * Сокет блокирующий и короткий (запрос — ответ строкой JSON), поэтому вызовы — только из рабочих
 * потоков или там, где цикл и так ждёт steer (старт, перечитывание конфига). */
#ifndef BOX_STEERCTL_H
#define BOX_STEERCTL_H
#include <stddef.h>
#include "json.h"

/* Ответ сокета целиком (объект с v, cmd, code, stdout…) или NULL; причина — в err. body —
 * тело запроса (apply, check) или NULL. */
struct jval *steerctl_call(const char *sock, const char *line, const char *body, size_t bodyn,
                           int timeout_ms, char *err, size_t errn);

/* То же, но вернуть stdout команды разобранным как JSON (status, conns, dns-log). code != 0 —
 * NULL и stderr в err. */
struct jval *steerctl_json(const char *sock, const char *line, int timeout_ms, char *err, size_t errn);

/* Простая команда (reload, select …): 0 — code 0; иначе текст stderr в err. */
int steerctl_run(const char *sock, const char *line, int timeout_ms, char *err, size_t errn);

#endif
