/* Работающий коннектор (`sing-box run`): общее состояние частей.
 *
 * Всё состояние живёт в потоке цикла (evloop.h). Рабочие потоки получают копии того, что им нужно,
 * и возвращают результат через ev_spawn/done, а не трогают это напрямую. */
#ifndef BOX_RUNTIME_H
#define BOX_RUNTIME_H
#include <stdint.h>
#include <sys/types.h>
#include "box.h"
#include "json.h"
#include "net.h"
#include "evloop.h"

struct dns_srv;
struct clash;
struct mixed_srv;
struct rsmgr;

/* Замер задержки выхода для Clash API (history). Хранится у коннектора: Clash API отдаёт его в
 * /proxies, а интерфейс podkop и forkop перечитывает /proxies сразу после замера. */
struct delay_rec {
    char tag[160];
    long long time_ms;          /* время Unix замера, мс */
    int delay;                  /* мс; 0 — не ответил */
};

struct box_rt {
    struct ev *ev;
    struct box_settings set;
    const struct box_opts *opts;
    struct jval *cfg;           /* действующий конфиг sing-box */
    struct jval *map;           /* box-map.json последнего перевода */
    char inst[512];             /* каталог своего экземпляра steer */
    char spec[600], state[600], sock[600], rsdir[600];
    pid_t steerd;
    uint32_t default_mark;      /* route.default_mark */
    char default_dev[16];       /* route.default_interface */
    struct jval *status;        /* последний `steer status` (обновляется рабочим потоком) */
    long long status_at;
    int status_busy;
    struct dns_srv *dns;
    struct clash *clash;
    struct mixed_srv *mixed;
    struct rsmgr *rs;
    int *dummy_fds;             /* слушатели tproxy-заглушки (только для netstat) */
    size_t dummy_n;
    struct delay_rec *delays;
    size_t delays_n, delays_cap;
    long long started_ms;
    int reloading;              /* идёт перевод с reload в рабочем потоке (смена выбора) */
    int pending_reload, pending_retranslate;    /* пришли, пока он шёл */
    struct jval *selected;      /* выбор селекторов: тег → тег члена; <state_dir>/selected.json */
    unsigned long long up_total, down_total;   /* для /traffic */
};

extern struct box_rt *g_rt;

/* Куда идут собственные соединения коннектора для выхода с тегом sing-box tag: устройство
 * (туннель, интерфейс, лист группы по последнему status) и метка route.default_mark. 0 —
 * известно; -1 — выход без устройства сейчас (группа в отказе, block). direct — без устройства,
 * с меткой (или default_interface). */
int rt_egress(struct box_rt *rt, const char *tag, struct egress *eg, char *err, size_t errn);

/* Тег sing-box → имя выхода steer (по box-map) или NULL; и обратно. */
const char *rt_steer_name(struct box_rt *rt, const char *tag);
const char *rt_tag_of(struct box_rt *rt, const char *steer_name);
const char *rt_clash_type(struct box_rt *rt, const char *tag);

/* Задержки для Clash API. */
void rt_delay_put(struct box_rt *rt, const char *tag, int delay);
const struct delay_rec *rt_delay_get(struct box_rt *rt, const char *tag);

/* Попросить свежий status (рабочим потоком). */
void rt_status_refresh(struct box_rt *rt);

/* Перечитать конфиг и применить (SIGHUP, изменился набор правил). */
void rt_reload(struct box_rt *rt, const char *why);

/* Части. Возвращают 0 или -1 (причина уже в журнале). */
int  dns_start(struct box_rt *rt);
void dns_stop(struct box_rt *rt);
int  clash_start(struct box_rt *rt);
void clash_stop(struct box_rt *rt);
int  mixed_start(struct box_rt *rt);
void mixed_stop(struct box_rt *rt);
int  rs_start(struct box_rt *rt);
void rs_stop(struct box_rt *rt);
/* Набор правил скачан или изменился на диске — перевести и применить заново (с задержкой, чтобы
 * пачка изменений давала одно перечитывание). */
void rs_changed(struct box_rt *rt);

/* Резолвер коннектора для его собственных соединений (mixed, загрузки): имя → адрес по правилам
 * DNS sing-box, без похода через dnsmasq. Блокирующий — только из рабочих потоков. Возвращает
 * число адресов. */
void dns_install_resolver(void);
/* Перевести действующий конфиг заново и применить (набор правил скачан или изменился). */
void rt_retranslate(struct box_rt *rt, const char *why);
/* Сменить выбор селектора и применить: перевод и reload — в рабочем потоке, done(arg, rc, err) —
 * в потоке цикла. -1 — не начато (идёт другой такой перевод). */
int rt_select(struct box_rt *rt, const char *selector, const char *member,
              void (*done)(void *arg, int rc, const char *err), void *arg);
int dns_resolve_blocking(struct box_rt *rt, const char *name, struct sockaddr_storage *out,
                         socklen_t *lens, int max);

#endif
