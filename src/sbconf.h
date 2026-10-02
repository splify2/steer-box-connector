/* Конфиг sing-box глазами коннектора: проверка (`check`) и общие помощники для перевода в спеку.
 *
 * МОДЕЛЬ — ДЕРЕВО JSON, А НЕ ПАРАЛЛЕЛЬНЫЕ СТРУКТУРЫ. Конфиг sing-box широкий (сотни ключей), а
 * коннектору из большинства объектов нужно по два-три поля. Второе описание схемы в структурах C
 * отставало бы от первого при каждом выпуске sing-box. Поэтому части коннектора читают дерево
 * помощниками ниже, а проверка — один проход, который знает, что каждая часть потом прочтёт.
 *
 * СТРОГОСТЬ. Ошибка — то, из-за чего перевод был бы неверным: тип значения, обязательное поле,
 * ссылка на несуществующий тег, круг detour, то, чего коннектор не умеет. Незнакомый ключ —
 * предупреждение: sing-box на него отказывает, но podkop и forkop проверяют `check` каждый
 * сгенерированный конфиг, и ложный отказ сорвал бы им запуск, тогда как лишняя терпимость ничего не
 * ломает. */
#ifndef BOX_SBCONF_H
#define BOX_SBCONF_H
#include <stddef.h>
#include "json.h"

/* Итог проверки: число ошибок и предупреждений, тексты — в журнал по ходу. */
struct sbcheck {
    unsigned errors, warnings;
    char first[512];           /* первая ошибка — то, что check печатает строкой FATAL */
};

int sb_check(const struct jval *cfg, struct sbcheck *res);

/* Помощники для частей коннектора. */
struct jval *sb_outbound(const struct jval *cfg, const char *tag);   /* в outbounds и endpoints */
struct jval *sb_inbound(const struct jval *cfg, const char *tag);
struct jval *sb_dns_server(const struct jval *cfg, const char *tag);
struct jval *sb_rule_set(const struct jval *cfg, const char *tag);

/* Длительность sing-box («30s», «3m», «1h30m», «1d», «876000h») в миллисекундах; -1 — не разобралась. */
long long sb_duration_ms(const char *s);

/* Вид выхода по типу: что делает коннектор с outbound этого типа. */
enum sb_okind {
    SBO_UNKNOWN,
    SBO_DIRECT,        /* direct без bind_interface и routing_mark — обычный путь */
    SBO_INTERFACE,     /* direct с bind_interface — kind: interface */
    SBO_REMARK,        /* direct с routing_mark (zapret у forkop) — дайлер «заново от роутера» */
    SBO_BLOCK,         /* block — kind: block */
    SBO_DNS,           /* dns (устаревший) */
    SBO_GROUP,         /* selector, urltest */
    SBO_TUNNEL,        /* протокол: vless, vmess, trojan, shadowsocks, socks, http, hysteria2 */
};
enum sb_okind sb_outbound_kind(const struct jval *ob);

#endif
