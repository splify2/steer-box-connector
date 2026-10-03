/* Общее для частей коннектора: опции командной строки sing-box, журнал, настройки коннектора. */
#ifndef BOX_H
#define BOX_H
#include <stddef.h>
#include <stdint.h>
#include "json.h"

/* Версия коннектора — версия steer, с которым он собран: он модуль steer, и пакет его зависит от
 * steer-core той же версии (STEER_VERSION ставит сборка, build/build-libs.sh и Makefile). */
#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif
#ifndef STEER_REV
#define STEER_REV "dev"
#endif
#define BOX_VERSION STEER_VERSION

/* Глобальные ключи sing-box: `-c` (можно несколько — конфиги сливаются), `-C` (каталог: все
 * *.json по алфавиту), `-D` (рабочий каталог), `--disable-color`. Стоят они и до, и после
 * подкоманды: podkop пишет `sing-box -c X check`, forkop — `tools fetch … -c X -D Y`. */
struct box_opts {
    const char **configs;
    size_t nconfigs;
    const char **confdirs;
    size_t nconfdirs;
    const char *workdir;
    int no_color;
};

/* Настройки самого коннектора — /etc/config/steer-box (UCI), секция `main`. Их правит страница
 * LuCI «Steer Connector». Файла нет — умолчания. */
struct box_settings {
    char variant[16];          /* extended | stable — каким sing-box представляться */
    char sb_version[32];       /* номер версии в строке `version`, например 1.12.22 */
    char steerd[128];          /* путь движка */
    char state_dir[128];       /* каталог спеки и состояния своего экземпляра steer */
    uint32_t mark_mask;        /* поле метки steer (биты подряд); 0 — подобрать */
    unsigned rule_pref;        /* приоритет ip rule выходов steer; 0 — подобрать */
    char log_level[16];        /* пусто — из конфига sing-box */
};

void box_settings_load(struct box_settings *s);

/* Журнал в стиле sing-box: «ERROR[0000] текст» в stderr. procd кладёт stderr в logread с тегом
 * sing-box, и forkop ищет там строки по этому тегу. */
enum box_level { BL_TRACE, BL_DEBUG, BL_INFO, BL_WARN, BL_ERROR, BL_FATAL };
void box_log_level(enum box_level min);
int  box_level_parse(const char *s, enum box_level *out);
void box_log(enum box_level lvl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
#define LOGT(...) box_log(BL_TRACE, __VA_ARGS__)
#define LOGD(...) box_log(BL_DEBUG, __VA_ARGS__)
#define LOGI(...) box_log(BL_INFO, __VA_ARGS__)
#define LOGW(...) box_log(BL_WARN, __VA_ARGS__)
#define LOGE(...) box_log(BL_ERROR, __VA_ARGS__)

/* Конфиг по опциям: каждый -c и каждый *.json из -C, слитые по правилам sing-box. NULL — отказ,
 * текст в err. */
struct jval *box_load_config(const struct box_opts *o, char *err, size_t errn);

/* Подкоманды. Возвращают код выхода процесса. */
int cmd_version(void);
int cmd_check(const struct box_opts *o);
int cmd_format(const struct box_opts *o, int argc, char **argv);
int cmd_merge(const struct box_opts *o, int argc, char **argv);
int cmd_generate(int argc, char **argv);
int cmd_ruleset(const struct box_opts *o, int argc, char **argv);
int cmd_tools(const struct box_opts *o, int argc, char **argv);
int cmd_run(const struct box_opts *o);
/* Скрытая: перевести конфиг в спеку steer в каталог и напечатать её (отладка, стенды, LuCI). */
int cmd_box_needs(const struct box_opts *o);
int cmd_box_translate(const struct box_opts *o, int argc, char **argv);

/* Случайные байты из ядра; 0 — получены. */
int box_random(void *buf, size_t n);

#endif
