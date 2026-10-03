/* Перевод конфига sing-box в спеку steer v2 (BOX_CONNECTOR.md в хабе, разделы 3–3в).
 *
 * На выходе — каталог своего экземпляра steer:
 *   spec.json         спека v2 (JSON — тоже YAML, движок читает её тем же разбором);
 *   box-map.json      таблица соответствий: тег sing-box → имя steer у выходов и групп, номер
 *                     правила sing-box → имя правила steer. По ней Clash API показывает теги, а
 *                     журнал называет правила словами sing-box;
 *   lists/<имя>.lst, .pfx  списки, собранные из наборов source (JSON) и из условий в самих правилах;
 *   sub/<выход>       узел туннеля: outbound sing-box (vless — подписка steer читает конфиг
 *                     sing-box) или ссылка (hysteria2 и протоколы steer-proxy).
 *
 * Перевод чистый: он не трогает ядро и сеть и годится для `check` и стендов. Чего перевести
 * нельзя, то снимается со строкой предупреждения (выход без вида в steer, правило с условием,
 * которого ядро не выражает), — кроме того, что делает перевод неверным: это ошибка. */
#ifndef BOX_TRANSLATE_H
#define BOX_TRANSLATE_H
#include <stdint.h>
#include "json.h"

struct tr_opts {
    const char *dir;               /* каталог экземпляра: туда пишутся файлы */
    const char *ruleset_dir;       /* где лежат скачанные remote-наборы (<тег>.srs|.json) */
    const char **lan_devices;      /* устройства раздачи; NULL — br-lan */
    size_t lan_n;
    uint32_t egress_mark;          /* route.default_mark — метка своих сокетов steer (S8) */
    int router_self;               /* каналы на сам роутер (STEER_ROUTER_SELF): правила-двойники */
    const struct jval *selected;   /* выбор селекторов: тег селектора → тег члена (Clash API) */
};

struct tr_result {
    struct jval *spec;
    struct jval *map;
    unsigned warnings;
    unsigned missing_sets;         /* remote-наборов, которых ещё нет на диске */
};

/* 0 — переведено и записано; -1 — ошибка, текст в err. */
int box_translate(const struct jval *cfg, const struct tr_opts *o, struct tr_result *res,
                  char *err, size_t errn);
void box_translate_free(struct tr_result *res);

/* Узел выхода sing-box (vless, hysteria2, trojan…) строкой подписки steer — то, что перевод пишет в
 * файл подписки выхода. NULL — тип не переводится (причина в err). Освобождает вызывающий. */
char *box_node_text(const struct jval *ob, char *err, size_t errn);

/* Путь, куда положить скачанный remote-набор с тегом tag (одно место на коннектор). */
void box_ruleset_cache_path(const char *dir, const char *tag, const char *format, char *out, size_t n);

#endif
