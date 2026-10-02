/* sing-box от steer-box-connector: точка входа и общие кирпичи (журнал, настройки, загрузка
 * конфига). Подкоманды — в своих файлах. */
#define _GNU_SOURCE
#include "box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>

/* ---- журнал ----------------------------------------------------------------------------- */

static enum box_level g_min = BL_INFO;
static time_t g_start;

void box_log_level(enum box_level min) { g_min = min; }

int box_level_parse(const char *s, enum box_level *out) {
    static const char *names[] = { "trace", "debug", "info", "warn", "error", "fatal" };
    if (!s) return -1;
    for (int i = 0; i < 6; i++)
        if (!strcmp(s, names[i])) { *out = (enum box_level)i; return 0; }
    if (!strcmp(s, "panic")) { *out = BL_FATAL; return 0; }
    if (!strcmp(s, "warning")) { *out = BL_WARN; return 0; }
    return -1;
}

void box_log(enum box_level lvl, const char *fmt, ...) {
    static const char *tags[] = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL" };
    if (lvl < g_min) return;
    if (!g_start) g_start = time(NULL);
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* Число в скобках у sing-box — секунды с запуска; оставляем тот же вид строки, на него
     * смотрят люди, привыкшие к sing-box, и разборы журнала forkop. */
    fprintf(stderr, "%s[%04ld] %s\n", tags[lvl], (long)(time(NULL) - g_start), buf);
}

/* ---- настройки коннектора --------------------------------------------------------------- */

static void set_str(char *dst, size_t n, const char *v) {
    snprintf(dst, n, "%s", v);
}

void box_settings_load(struct box_settings *s) {
    memset(s, 0, sizeof *s);
    set_str(s->variant, sizeof s->variant, "extended");
    set_str(s->sb_version, sizeof s->sb_version, "1.12.22");
    set_str(s->steerd, sizeof s->steerd, "/usr/sbin/steerd");
    set_str(s->state_dir, sizeof s->state_dir, "/var/run/sing-box");
    const char *path = getenv("STEER_BOX_UCI");
    FILE *f = fopen(path ? path : "/etc/config/steer-box", "r");
    if (!f) return;
    char line[512];
    int in_main = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char kw[16], key[64], val[256];
        if (!strncmp(p, "config", 6)) {
            /* config steer-box 'main' */
            in_main = strstr(p, "'main'") || strstr(p, "\"main\"") || strstr(p, " main");
            continue;
        }
        if (!in_main) continue;
        if (sscanf(p, "%15s %63s", kw, key) != 2 || strcmp(kw, "option")) continue;
        char *q = strchr(p, '\'');
        char *e = q ? strchr(q + 1, '\'') : NULL;
        if (!q || !e) {
            q = strchr(p, '"');
            e = q ? strchr(q + 1, '"') : NULL;
        }
        if (q && e) {
            size_t n = (size_t)(e - q - 1);
            if (n >= sizeof val) n = sizeof val - 1;
            memcpy(val, q + 1, n);
            val[n] = 0;
        } else if (sscanf(p, "%*s %*s %255s", val) != 1) continue;
        if (!strcmp(key, "variant")) set_str(s->variant, sizeof s->variant, val);
        else if (!strcmp(key, "version") && val[0]) set_str(s->sb_version, sizeof s->sb_version, val);
        else if (!strcmp(key, "steerd")) set_str(s->steerd, sizeof s->steerd, val);
        else if (!strcmp(key, "state_dir")) set_str(s->state_dir, sizeof s->state_dir, val);
        else if (!strcmp(key, "mark_mask")) s->mark_mask = (uint32_t)strtoul(val, NULL, 0);
        else if (!strcmp(key, "rule_pref")) s->rule_pref = (unsigned)strtoul(val, NULL, 0);
        else if (!strcmp(key, "log_level")) set_str(s->log_level, sizeof s->log_level, val);
    }
    fclose(f);
}

int box_random(void *buf, size_t n) {
    unsigned char *p = buf;
    while (n) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += r;
        n -= (size_t)r;
    }
    return 0;
}

/* ---- загрузка конфига ------------------------------------------------------------------- */

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int merge_into(struct jval **acc, struct jval *v, const char *path, char *err, size_t errn) {
    if (v->t != J_OBJ) {
        snprintf(err, errn, "%s: конфиг должен быть объектом JSON", path);
        json_free(v);
        return -1;
    }
    if (!*acc) { *acc = v; return 0; }
    int rc = json_merge(*acc, v);
    json_free(v);
    if (rc) snprintf(err, errn, "%s: не сливается с предыдущими конфигами", path);
    return rc;
}

struct jval *box_load_config(const struct box_opts *o, char *err, size_t errn) {
    struct jval *acc = NULL;
    for (size_t i = 0; i < o->nconfigs; i++) {
        const char *path = o->configs[i];
        struct jval *v;
        if (!strcmp(path, "stdin") || !strcmp(path, "-")) {
            size_t cap = 65536, n = 0;
            char *buf = malloc(cap);
            while (buf) {
                size_t r = fread(buf + n, 1, cap - n, stdin);
                n += r;
                if (n < cap) break;
                char *nb = realloc(buf, cap *= 2);
                if (!nb) { free(buf); buf = NULL; }
                else buf = nb;
            }
            if (!buf) { snprintf(err, errn, "stdin: нет памяти"); json_free(acc); return NULL; }
            char e2[256];
            v = json_parse(buf, n, e2, sizeof e2);
            free(buf);
            if (!v) { snprintf(err, errn, "stdin:%s", e2); json_free(acc); return NULL; }
        } else if (!(v = json_parse_file(path, err, errn))) {
            json_free(acc);
            return NULL;
        }
        if (merge_into(&acc, v, path, err, errn)) { json_free(acc); return NULL; }
    }
    for (size_t d = 0; d < o->nconfdirs; d++) {
        DIR *dir = opendir(o->confdirs[d]);
        if (!dir) {
            snprintf(err, errn, "%s: %s", o->confdirs[d], strerror(errno));
            json_free(acc);
            return NULL;
        }
        char **names = NULL;
        size_t n = 0, cap = 0;
        struct dirent *de;
        while ((de = readdir(dir))) {
            size_t l = strlen(de->d_name);
            if (l < 6 || strcmp(de->d_name + l - 5, ".json")) continue;
            if (n == cap) {
                char **nn = realloc(names, (cap = cap ? cap * 2 : 8) * sizeof *names);
                if (!nn) break;
                names = nn;
            }
            names[n++] = strdup(de->d_name);
        }
        closedir(dir);
        qsort(names, n, sizeof *names, cmp_str);
        int bad = 0;
        for (size_t i = 0; i < n; i++) {
            char path[1024];
            snprintf(path, sizeof path, "%s/%s", o->confdirs[d], names[i]);
            struct jval *v = bad ? NULL : json_parse_file(path, err, errn);
            if (!bad && (!v || merge_into(&acc, v, path, err, errn))) bad = 1;
            free(names[i]);
        }
        free(names);
        if (bad) { json_free(acc); return NULL; }
    }
    if (!acc) {
        /* sing-box без -c читает config.json рабочего каталога (так зовёт podkop
         * `tools fetch … -D /etc/sing-box`). */
        char path[1024];
        snprintf(path, sizeof path, "%s/config.json", o->workdir ? o->workdir : ".");
        acc = json_parse_file(path, err, errn);
        if (acc && acc->t != J_OBJ) {
            snprintf(err, errn, "%s: конфиг должен быть объектом JSON", path);
            json_free(acc);
            acc = NULL;
        }
    }
    return acc;
}

/* ---- точка входа ------------------------------------------------------------------------ */

static void usage(void) {
    puts("Usage:\n"
         "  sing-box [command]\n\n"
         "Available Commands:\n"
         "  check       Check configuration\n"
         "  format      Format configuration\n"
         "  generate    Generate things\n"
         "  merge       Merge configurations\n"
         "  rule-set    Manage rule-sets\n"
         "  run         Run service\n"
         "  tools       Experimental tools\n"
         "  version     Print current version of sing-box\n\n"
         "Flags:\n"
         "  -c, --config stringArray             set configuration file path\n"
         "  -C, --config-directory stringArray   set configuration directory path\n"
         "  -D, --directory string               set working directory\n"
         "      --disable-color                  disable color output\n\n"
         "steer-box-connector " BOX_VERSION ": sing-box на движке steer");
}

static int push(const char ***arr, size_t *n, const char *v) {
    const char **na = realloc(*arr, (*n + 1) * sizeof **arr);
    if (!na) return -1;
    na[(*n)++] = v;
    *arr = na;
    return 0;
}

int main(int argc, char **argv) {
    struct box_opts o = { 0 };
    char **rest = calloc((size_t)argc + 1, sizeof *rest);
    int nrest = 0;
    if (!rest) return 1;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        const char *val = NULL;
        int which = 0;
        if (!strcmp(a, "-c") || !strcmp(a, "--config")) which = 'c';
        else if (!strcmp(a, "-C") || !strcmp(a, "--config-directory")) which = 'C';
        else if (!strcmp(a, "-D") || !strcmp(a, "--directory")) which = 'D';
        else if (!strncmp(a, "--config=", 9)) { which = 'c'; val = a + 9; }
        else if (!strncmp(a, "--config-directory=", 19)) { which = 'C'; val = a + 19; }
        else if (!strncmp(a, "--directory=", 12)) { which = 'D'; val = a + 12; }
        else if (!strcmp(a, "--disable-color")) { o.no_color = 1; continue; }
        if (!which) { rest[nrest++] = argv[i]; continue; }
        if (!val) {
            if (i + 1 >= argc) {
                fprintf(stderr, "FATAL[0000] ключ %s без значения\n", a);
                return 1;
            }
            val = argv[++i];
        }
        if (which == 'c') push(&o.configs, &o.nconfigs, val);
        else if (which == 'C') push(&o.confdirs, &o.nconfdirs, val);
        else o.workdir = val;
    }
    if (o.workdir && chdir(o.workdir)) {
        fprintf(stderr, "FATAL[0000] рабочий каталог %s: %s\n", o.workdir, strerror(errno));
        return 1;
    }
    if (!nrest) { usage(); return 0; }
    const char *cmd = rest[0];
    if (!strcmp(cmd, "version")) return cmd_version();
    if (!strcmp(cmd, "check")) return cmd_check(&o);
    if (!strcmp(cmd, "run")) return cmd_run(&o);
    if (!strcmp(cmd, "format")) return cmd_format(&o, nrest - 1, rest + 1);
    if (!strcmp(cmd, "merge")) return cmd_merge(&o, nrest - 1, rest + 1);
    if (!strcmp(cmd, "generate")) return cmd_generate(nrest - 1, rest + 1);
    if (!strcmp(cmd, "rule-set")) return cmd_ruleset(&o, nrest - 1, rest + 1);
    if (!strcmp(cmd, "tools")) return cmd_tools(&o, nrest - 1, rest + 1);
    if (!strcmp(cmd, "box-needs")) return cmd_box_needs(&o);
    if (!strcmp(cmd, "box-translate")) return cmd_box_translate(&o, nrest - 1, rest + 1);
    if (!strcmp(cmd, "help") || !strcmp(cmd, "-h") || !strcmp(cmd, "--help")) { usage(); return 0; }
    if (!strcmp(cmd, "-v") || !strcmp(cmd, "--version")) return cmd_version();
    fprintf(stderr, "Error: unknown command \"%s\" for \"sing-box\"\n", cmd);
    return 1;
}
