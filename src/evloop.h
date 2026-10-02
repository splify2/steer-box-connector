/* Цикл событий коннектора: epoll, таймеры и работа в потоках.
 *
 * ПОЧЕМУ СВОЙ. Цикл демона steer (src/daemon/loop.c) живёт в steerd, а не в libsteer, и тянет за
 * собой демон. Коннектору нужно три вещи: дескрипторы (слушатели DNS, Clash API, mixed), таймеры
 * (обновление наборов, замеры) и блокирующая работа вне цикла (рукопожатия TLS у DoT/DoH,
 * скачивание, проброс соединений mixed). Последнее — в потоках: результат возвращается в цикл
 * через eventfd, и обработчик результата исполняется уже в потоке цикла, поэтому состоянию
 * коннектора блокировки не нужны.
 *
 * Все функции, кроме ev_post, зовутся только из потока цикла. */
#ifndef BOX_EVLOOP_H
#define BOX_EVLOOP_H
#include <stdint.h>

struct ev;
typedef void (*ev_fd_cb)(struct ev *ev, int fd, uint32_t events, void *arg);
typedef void (*ev_timer_cb)(struct ev *ev, void *arg);
/* Работа в потоке: work исполняется в рабочем потоке, done — потом в потоке цикла. */
typedef void (*ev_work_fn)(void *arg);

struct ev *ev_new(void);
void ev_free(struct ev *ev);

int  ev_add(struct ev *ev, int fd, uint32_t events, ev_fd_cb cb, void *arg);   /* EPOLLIN… */
int  ev_mod(struct ev *ev, int fd, uint32_t events);
void ev_del(struct ev *ev, int fd);

/* Таймер через ms миллисекунд; возвращает номер (0 — отказ). */
uint64_t ev_timer(struct ev *ev, long ms, ev_timer_cb cb, void *arg);
void ev_timer_cancel(struct ev *ev, uint64_t id);

/* Отдать работу пулу потоков. Поток — свой на каждую работу (detached): работы у коннектора
 * редкие и долгие (рукопожатие, скачивание, проброс соединения), а очередь общего пула стояла бы
 * за одним медленным сервером. Предел — настоящий ресурс, число потоков процесса (RLIMIT_NPROC и
 * память под стеки); отказ pthread_create возвращается вызывающему. */
int ev_spawn(struct ev *ev, ev_work_fn work, ev_work_fn done, void *arg);

/* Вызвать fn(arg) в потоке цикла — из любого потока. */
int ev_post(struct ev *ev, ev_work_fn fn, void *arg);

void ev_stop(struct ev *ev);
int  ev_run(struct ev *ev);      /* до ev_stop */

long long ev_now_ms(void);       /* монотонные миллисекунды */

#endif
