/* Перевод конфига sing-box в спеку steer v2 — см. translate.h. */
#define _GNU_SOURCE
#include "translate.h"
#include "sbconf.h"
#include "box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/* Имя steer: буквы, цифры, «_», «-», «.», не длиннее 31 байта (name_ok и name[32] в
 * src/model/spec.h). Тег sing-box бывает и длиннее, и с любыми знаками, поэтому имя выводится из
 * тега, а при обрезке или совпадении получает хвост из хеша тега. */
#define STEER_NAME_MAX 31

struct names {
    char **tag, **name;
    size_t n, cap;
};

struct tr {
    const struct jval *cfg;
    const struct tr_opts *o;
    struct jval *spec, *outputs, *lists, *rules, *clients, *map, *map_out, *map_rules;
    struct names onames;           /* выходы */
    struct names lnames;           /* списки */
    struct names cnames;           /* клиенты */
    unsigned dev_seq, file_seq, rule_seq;
    unsigned warnings, missing_sets;
    char *err;
    size_t errn;
    int failed;
    int have_direct, have_block;
    /* Теги наборов, у которых перед правилом route стоит resolve: правило получает realip. */
    const char **resolve_sets;
    size_t resolve_n;
    int resolve_all;               /* resolve без условий — все следующие правила */
    int quic_reject;               /* reject protocol quic до правил в туннели */
    int self_used;                 /* заведён клиент router (self) */
    long override_port;            /* правило route-options: подмена порта у списков правила */
};

static void tw(struct tr *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void tw(struct tr *t, const char *fmt, ...) {
    char buf[600];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    t->warnings++;
    LOGW("перевод: %s", buf);
}

static int tfail(struct tr *t, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int tfail(struct tr *t, const char *fmt, ...) {
    if (t->failed) return -1;
    t->failed = 1;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(t->err, t->errn, fmt, ap);
    va_end(ap);
    return -1;
}

static unsigned fnv(const char *s) {
    unsigned h = 2166136261u;
    for (; *s; s++) h = (h ^ (unsigned char)*s) * 16777619u;
    return h;
}

static const char *names_find(const struct names *nm, const char *tag) {
    for (size_t i = 0; i < nm->n; i++)
        if (!strcmp(nm->tag[i], tag)) return nm->name[i];
    return NULL;
}

static int names_taken(const struct names *nm, const char *name) {
    for (size_t i = 0; i < nm->n; i++)
        if (!strcmp(nm->name[i], name)) return 1;
    return 0;
}

/* Имя для тега: то же самое при каждом вызове с тем же тегом. reserved — имена, которые нельзя
 * занимать (у выходов — «direct» и «block», их заводит сам перевод). */
/* Кириллица → латиница для имён (А..я по порядку кодов, затем Ё и ё). */
static const char *const CYR[] = {
    "A", "B", "V", "G", "D", "E", "Zh", "Z", "I", "J", "K", "L", "M", "N", "O", "P", "R", "S", "T",
    "U", "F", "H", "C", "Ch", "Sh", "Sch", "", "Y", "", "E", "Yu", "Ya",
    "a", "b", "v", "g", "d", "e", "zh", "z", "i", "j", "k", "l", "m", "n", "o", "p", "r", "s", "t",
    "u", "f", "h", "c", "ch", "sh", "sch", "", "y", "", "e", "yu", "ya",
};

/* Основа имени из тега sing-box: имена узлов подписок — «🇳🇱 📱 ⭐️ Мобильный #2», а имя steer —
 * [A-Za-z0-9_.-]. Латиница и цифры остаются, кириллица пишется латиницей, остальное (эмодзи,
 * флаги, знаки) выпадает, промежутки между словами — один дефис: «Mobilnyj-2». Прежняя замена
 * каждого байта на «_» давала в журнале «__________________________-6caf» у всех узлов. */
static size_t name_base(const char *tag, char *base, size_t cap) {
    size_t j = 0;
    int gap = 0;
    for (const unsigned char *p = (const unsigned char *)tag; *p && j + 4 < cap;) {
        unsigned c = *p;
        const char *add = NULL;
        char one[2] = { 0, 0 };
        size_t len = 1;
        if (c < 0x80) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                c == '_' || c == '.') { one[0] = (char)c; add = one; }
        } else {
            unsigned cp = 0;
            if ((c & 0xe0) == 0xc0 && p[1]) { cp = (c & 0x1f) << 6 | (p[1] & 0x3f); len = 2; }
            else if ((c & 0xf0) == 0xe0 && p[1] && p[2]) len = 3;
            else if ((c & 0xf8) == 0xf0 && p[1] && p[2] && p[3]) len = 4;
            if (cp >= 0x410 && cp <= 0x44f) add = CYR[cp - 0x410];
            else if (cp == 0x401) add = "E";
            else if (cp == 0x451) add = "e";
            else if (len >= 3) { p += len; continue; }      /* эмодзи и прочее — без следа */
        }
        p += len;
        if (!add) { gap = 1; continue; }
        if (!*add) continue;
        if (gap && j) base[j++] = '-';
        gap = 0;
        for (; *add && j + 1 < cap; add++) base[j++] = *add;
    }
    base[j] = 0;
    return j;
}

static const char *names_get(struct names *nm, const char *tag, const char *prefix) {
    const char *have = names_find(nm, tag);
    if (have) return have;
    char base[64];
    size_t j = 0;
    if (prefix) j = (size_t)snprintf(base, sizeof base, "%s", prefix);
    j += name_base(tag, base + j, sizeof base - j);
    if (!j) j = (size_t)snprintf(base, sizeof base, "out");
    char name[STEER_NAME_MAX + 1];
    if (j <= STEER_NAME_MAX && !names_taken(nm, base) && strcmp(base, "direct") && strcmp(base, "block"))
        snprintf(name, sizeof name, "%s", base);
    else {
        unsigned h = fnv(tag);
        for (unsigned k = 0;; k++) {
            char tail[16];
            snprintf(tail, sizeof tail, "-%04x", (h + k) & 0xffff);
            size_t keep = STEER_NAME_MAX - strlen(tail);
            snprintf(name, sizeof name, "%.*s%s", (int)(j < keep ? j : keep), base, tail);
            if (!names_taken(nm, name)) break;
        }
    }
    if (nm->n == nm->cap) {
        size_t nc = nm->cap ? nm->cap * 2 : 16;
        char **a = realloc(nm->tag, nc * sizeof *a), **b;
        if (!a) return NULL;
        nm->tag = a;
        b = realloc(nm->name, nc * sizeof *b);
        if (!b) return NULL;
        nm->name = b;
        nm->cap = nc;
    }
    nm->tag[nm->n] = strdup(tag);
    nm->name[nm->n] = strdup(name);
    return nm->name[nm->n++];
}

static void names_free(struct names *nm) {
    for (size_t i = 0; i < nm->n; i++) { free(nm->tag[i]); free(nm->name[i]); }
    free(nm->tag);
    free(nm->name);
}

/* ---- файлы ------------------------------------------------------------------------------ */

static int mkdirs(const char *path) {
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            if (mkdir(buf, 0755) && errno != EEXIST) return -1;
            *p = '/';
        }
    return mkdir(buf, 0755) && errno != EEXIST ? -1 : 0;
}

/* Записать файл атомарно: steer читает спеку и списки, пока коннектор их переписывает. */
static int write_file(struct tr *t, const char *path, const char *data, size_t n) {
    char tmp[1100];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return tfail(t, "%s: %s", tmp, strerror(errno));
    if (n && fwrite(data, 1, n, f) != n) { fclose(f); return tfail(t, "%s: не записался", tmp); }
    if (fclose(f)) return tfail(t, "%s: не записался", tmp);
    if (rename(tmp, path)) return tfail(t, "%s: %s", path, strerror(errno));
    return 0;
}

void box_ruleset_cache_path(const char *dir, const char *tag, const char *format, char *out, size_t n) {
    char safe[200];
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)tag; *p && j < sizeof safe - 1; p++)
        safe[j++] = (*p == '/' || *p < 0x20) ? '_' : (char)*p;
    safe[j] = 0;
    snprintf(out, n, "%s/%s.%s", dir, safe, format && !strcmp(format, "source") ? "json" : "srs");
}

/* ---- списки ----------------------------------------------------------------------------- */

/* Сужение списка: протокол и порты (ключи proto и ports списка steer). */
struct narrow {
    int tcp, udp;                  /* оба 0 — протокол не сужен */
    char ports[1024];              /* «443,50000-65535» или пусто */
};

static int narrow_same(const struct narrow *a, const struct narrow *b) {
    return a->tcp == b->tcp && a->udp == b->udp && !strcmp(a->ports, b->ports);
}

/* Строки, накопленные для одного списка: имена (в записи steer) и подсети. */
struct strbuf { char *p; size_t n, cap; };

static int sb_add(struct strbuf *b, const char *s) {
    size_t l = strlen(s);
    if (b->n + l + 2 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 4096;
        while (nc < b->n + l + 2) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) return -1;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, l);
    b->n += l;
    b->p[b->n++] = '\n';
    b->p[b->n] = 0;
    return 0;
}

struct pending_list {
    struct narrow nw;
    struct strbuf dom, pfx;
    const char *srs;               /* набор .srs — путь */
};

/* Сужение из правила sing-box (network, port, port_range). 0 — разобралось; -1 — значение,
 * которого steer не выражает (тогда правило снимается). */
static int narrow_from_rule(struct tr *t, const struct jval *r, struct narrow *nw, const char *where) {
    memset(nw, 0, sizeof *nw);
    struct jval *net = jget(r, "network");
    if (net) {
        const char *l[4];
        long n = jstrlist(net, l, 4);
        for (long i = 0; i < n && i < 4; i++) {
            if (!strcmp(l[i], "tcp")) nw->tcp = 1;
            else if (!strcmp(l[i], "udp")) nw->udp = 1;
            else { tw(t, "%s: network «%s» не выражается", where, l[i]); return -1; }
        }
        if (nw->tcp && nw->udp) nw->tcp = nw->udp = 0;
    }
    size_t j = 0;
    struct jval *port = jget(r, "port");
    for (size_t i = 0; port && i < (port->t == J_ARR ? port->len : 1); i++) {
        const struct jval *p = port->t == J_ARR ? port->a[i] : port;
        if (p->t != J_NUM) { tw(t, "%s: port не число", where); return -1; }
        j += (size_t)snprintf(nw->ports + j, sizeof nw->ports - j, "%s%lld", j ? "," : "", (long long)p->i);
        if (j >= sizeof nw->ports) { tw(t, "%s: портов слишком много для одной строки", where); return -1; }
    }
    struct jval *pr = jget(r, "port_range");
    long prn = pr ? jstrlist(pr, NULL, 0) : 0;
    if (prn > 0) {
        const char **l = calloc((size_t)prn, sizeof *l);
        if (!l) return -1;
        jstrlist(pr, l, (size_t)prn);
        for (long i = 0; i < prn; i++) {
            const char *c = strchr(l[i], ':');
            if (!c) { tw(t, "%s: port_range «%s» без «:»", where, l[i]); free(l); return -1; }
            long a = c == l[i] ? 1 : strtol(l[i], NULL, 10);
            long b = c[1] ? strtol(c + 1, NULL, 10) : 65535;
            j += (size_t)snprintf(nw->ports + j, sizeof nw->ports - j, "%s%ld-%ld", j ? "," : "", a, b);
            if (j >= sizeof nw->ports) { free(l); tw(t, "%s: портов слишком много", where); return -1; }
        }
        free(l);
    }
    return 0;
}

/* Ключи, которые переводятся в список. Всё остальное в правиле набора — повод снять правило. */
static int list_keys_ok(struct tr *t, const struct jval *r, const char *where) {
    static const char *ok[] = { "domain", "domain_suffix", "domain_keyword", "domain_regex",
                                "ip_cidr", "ip_is_private", "network", "port", "port_range", NULL };
    for (size_t i = 0; i < jlen(r); i++) {
        const char *k = r->o[i].key;
        int good = 0;
        for (int j = 0; ok[j]; j++)
            if (!strcmp(k, ok[j])) good = 1;
        if (!good) {
            tw(t, "%s: условие «%s» в наборе ядро не выражает — правило набора снято", where, k);
            return 0;
        }
    }
    return 1;
}

/* Домены и подсети одного правила sing-box — в строки списка steer (записи — srs.h steer:
 * «=x» точное, «x» имя с поддоменами, «*.x» буквальный суффикс, «*слово*», «re:…»). */
static int add_dest(struct pending_list *pl, const struct jval *r) {
    const char *l[1];
    struct { const char *key; const char *pre, *post; } m[] = {
        { "domain", "=", "" }, { "domain_suffix", "", "" }, { "domain_keyword", "*", "*" },
        { "domain_regex", "re:", "" },
    };
    for (size_t k = 0; k < sizeof m / sizeof m[0]; k++) {
        struct jval *v = jget(r, m[k].key);
        long n = v ? jstrlist(v, NULL, 0) : 0;
        for (long i = 0; i < n; i++) {
            const struct jval *e = v->t == J_ARR ? v->a[i] : v;
            const char *s = e->s;
            char line[1100];
            if (!strcmp(m[k].key, "domain_suffix") && s[0] == '.') snprintf(line, sizeof line, "*%s", s);
            else snprintf(line, sizeof line, "%s%s%s", m[k].pre, s, m[k].post);
            if (sb_add(&pl->dom, line)) return -1;
        }
    }
    (void)l;
    struct jval *ip = jget(r, "ip_cidr");
    long n = ip ? jstrlist(ip, NULL, 0) : 0;
    for (long i = 0; i < n; i++)
        if (sb_add(&pl->pfx, ip->t == J_ARR ? ip->a[i]->s : ip->s)) return -1;
    if (jgetb(r, "ip_is_private", 0)) {
        static const char *priv[] = { "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
                                      "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fe80::/10", NULL };
        for (int i = 0; priv[i]; i++)
            if (sb_add(&pl->pfx, priv[i])) return -1;
    }
    return 0;
}

struct plist_set { struct pending_list *v; size_t n, cap; };

static struct pending_list *plist_for(struct plist_set *s, const struct narrow *nw) {
    for (size_t i = 0; i < s->n; i++)
        if (!s->v[i].srs && narrow_same(&s->v[i].nw, nw)) return &s->v[i];
    if (s->n == s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 4;
        struct pending_list *nv = realloc(s->v, nc * sizeof *nv);
        if (!nv) return NULL;
        s->v = nv;
        s->cap = nc;
    }
    memset(&s->v[s->n], 0, sizeof s->v[s->n]);
    s->v[s->n].nw = *nw;
    return &s->v[s->n++];
}

static void plist_free(struct plist_set *s) {
    for (size_t i = 0; i < s->n; i++) { free(s->v[i].dom.p); free(s->v[i].pfx.p); }
    free(s->v);
    memset(s, 0, sizeof *s);
}

/* Правила набора source (или inline) — в ожидающие списки по сужению. */
static int collect_rules(struct tr *t, struct plist_set *ps, const struct jval *rules, const char *where) {
    for (size_t i = 0; i < jlen(rules); i++) {
        const struct jval *r = jat(rules, i);
        char w[300];
        snprintf(w, sizeof w, "%s.rules[%zu]", where, i);
        const char *type = jgets(r, "type");
        if (type && !strcmp(type, "logical")) {
            tw(t, "%s: логическое правило в наборе ядро не выражает — снято", w);
            continue;
        }
        if (jgetb(r, "invert", 0)) { tw(t, "%s: invert в наборе ядро не выражает — снято", w); continue; }
        if (!list_keys_ok(t, r, w)) continue;
        struct narrow nw;
        if (narrow_from_rule(t, r, &nw, w)) continue;
        struct pending_list *pl = plist_for(ps, &nw);
        if (!pl || add_dest(pl, r)) return tfail(t, "нет памяти");
    }
    return 0;
}

/* Сужение правила route сверх сужения списка: у steer одно сужение на список, поэтому правило с
 * портом над набором с портом — пересечение, которое здесь не считается (в настоящих конфигах
 * podkop и forkop его нет). */
static int narrow_merge(struct tr *t, struct narrow *dst, const struct narrow *rule, const char *where) {
    if (!rule->tcp && !rule->udp && !rule->ports[0]) return 0;
    if ((dst->tcp || dst->udp || dst->ports[0]) && !narrow_same(dst, rule)) {
        tw(t, "%s: сужение правила поверх сужения набора не выражается — взято сужение правила", where);
    }
    *dst = *rule;
    return 0;
}

/* Сужение списка steer: proto и ports («443,50000-65535» → [443, "50000-65535"]). */
static void list_narrow(struct jval *l, const struct narrow *nw) {
    if (nw->tcp != nw->udp) jobj_set(l, "proto", jstr(nw->tcp ? "tcp" : "udp"));
    if (!nw->ports[0]) return;
    struct jval *a = jnew(J_ARR);
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", nw->ports);
    char *save;
    for (char *s = strtok_r(buf, ",", &save); s; s = strtok_r(NULL, ",", &save))
        jarr_push(a, strchr(s, '-') ? jstr(s) : jint(strtol(s, NULL, 10)));
    jobj_set(l, "ports", a);
}

/* Завести список steer из ожидающего. Возвращает имя или NULL (пустой список — не заводится). */
static const char *emit_list(struct tr *t, struct pending_list *pl, const char *tag) {
    if (!pl->srs && !pl->dom.n && !pl->pfx.n) return NULL;
    char key[300];
    snprintf(key, sizeof key, "%s#%u", tag, t->file_seq++);
    const char *name = names_get(&t->lnames, key, NULL);
    if (!name) { tfail(t, "нет памяти"); return NULL; }
    struct jval *l = jnew(J_OBJ);
    if (pl->srs) {
        struct jval *a = jnew(J_ARR);
        jarr_push(a, jstr(pl->srs));
        jobj_set(l, "srs", a);
    }
    char path[1100];
    if (pl->dom.n) {
        snprintf(path, sizeof path, "%s/lists/%s.lst", t->o->dir, name);
        if (write_file(t, path, pl->dom.p, pl->dom.n)) { json_free(l); return NULL; }
        struct jval *a = jnew(J_ARR);
        jarr_push(a, jstr(path));
        jobj_set(l, "domains_file", a);
    }
    if (pl->pfx.n) {
        snprintf(path, sizeof path, "%s/lists/%s.pfx", t->o->dir, name);
        if (write_file(t, path, pl->pfx.p, pl->pfx.n)) { json_free(l); return NULL; }
        struct jval *a = jnew(J_ARR);
        jarr_push(a, jstr(path));
        jobj_set(l, "prefixes_file", a);
    }
    list_narrow(l, &pl->nw);
    if (t->override_port > 0) jobj_set(l, "override_port", jint(t->override_port));
    jobj_set(t->lists, name, l);
    return name;
}

/* Набор route.rule_set по тегу — в ожидающие списки. Возвращает 0; набор, которого ещё нет на
 * диске (remote не скачан), — 1, и правило над ним пока не ставится. */
static int collect_set(struct tr *t, struct plist_set *ps, const char *tag) {
    const struct jval *rs = sb_rule_set(t->cfg, tag);
    if (!rs) return tfail(t, "набора «%s» нет", tag);
    const char *type = jgets(rs, "type");
    const char *format = jgets(rs, "format");
    if (!type) type = "inline";
    char where[260];
    snprintf(where, sizeof where, "rule_set %s", tag);
    if (!strcmp(type, "inline")) return collect_rules(t, ps, jget(rs, "rules"), where);
    char path[1100];
    if (!strcmp(type, "local")) snprintf(path, sizeof path, "%s", jgets(rs, "path"));
    else box_ruleset_cache_path(t->o->ruleset_dir, tag, format, path, sizeof path);
    struct stat st;
    if (stat(path, &st)) {
        t->missing_sets++;
        LOGI("перевод: набора %s пока нет на диске (%s) — правила над ним встанут после загрузки", tag, path);
        return 1;
    }
    if (!format) {
        size_t l = strlen(path);
        format = l > 5 && !strcmp(path + l - 5, ".json") ? "source" : "binary";
    }
    if (!strcmp(format, "binary")) {
        struct narrow nw = { 0 };
        if (ps->n == ps->cap) {
            size_t nc = ps->cap ? ps->cap * 2 : 4;
            struct pending_list *nv = realloc(ps->v, nc * sizeof *nv);
            if (!nv) return tfail(t, "нет памяти");
            ps->v = nv;
            ps->cap = nc;
        }
        memset(&ps->v[ps->n], 0, sizeof ps->v[ps->n]);
        ps->v[ps->n].nw = nw;
        ps->v[ps->n].srs = jgets(rs, "path") && !strcmp(type, "local") ? jgets(rs, "path") : NULL;
        if (!ps->v[ps->n].srs) {
            /* Путь кэша живёт в стеке — копия в дереве спеки появится в emit_list. Держим его в
             * пуле строк перевода через карту. */
            struct jval *keep = jget(t->map, "_paths");
            if (!keep) { keep = jnew(J_ARR); jobj_set(t->map, "_paths", keep); }
            jarr_push(keep, jstr(path));
            ps->v[ps->n].srs = keep->a[keep->len - 1]->s;
        }
        ps->n++;
        return 0;
    }
    char err[512];
    struct jval *src = json_parse_file(path, err, sizeof err);
    if (!src) { tw(t, "%s: %s — набор пропущен", where, err); return 1; }
    int rc = collect_rules(t, ps, jget(src, "rules"), where);
    json_free(src);
    return rc;
}

/* ---- выходы ----------------------------------------------------------------------------- */

static void map_out(struct tr *t, const char *tag, const char *name, const char *type) {
    struct jval *e = jnew(J_OBJ);
    jobj_set(e, "name", jstr(name));
    jobj_set(e, "type", jstr(type));
    jobj_set(t->map_out, tag, e);
}

/* Тип выхода в Clash API (как его называет sing-box). */
static const char *clash_type(const char *type) {
    static const struct { const char *t, *c; } cl[] = {
        { "vless", "VLESS" }, { "vmess", "VMess" }, { "trojan", "Trojan" },
        { "shadowsocks", "Shadowsocks" }, { "socks", "SOCKS" }, { "http", "HTTP" },
        { "hysteria2", "Hysteria2" }, { "direct", "Direct" }, { "block", "Block" },
        { "selector", "Selector" }, { "urltest", "URLTest" },
    };
    for (size_t i = 0; type && i < sizeof cl / sizeof cl[0]; i++)
        if (!strcmp(cl[i].t, type)) return cl[i].c;
    return type ? type : "Unknown";
}

static const char *ensure_direct(struct tr *t) {
    if (!t->have_direct) {
        struct jval *d = jnew(J_OBJ);
        jobj_set(d, "kind", jstr("direct"));
        jobj_set(t->outputs, "direct", d);
        t->have_direct = 1;
    }
    return "direct";
}

/* Узел туннеля — файл подписки. vless: сам outbound sing-box (подписка steer читает конфиг
 * sing-box, docs/vless.md, «Формат подписки»); остальные — ссылкой. */
static int b64url_enc(const char *in, char *out, size_t n);

static void pct(struct strbuf *b, const char *s) {
    static const char hx[] = "0123456789ABCDEF";
    char tmp[4];
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '.' || *p == '_' || *p == '~') {
            tmp[0] = (char)*p; tmp[1] = 0;
        } else {
            tmp[0] = '%'; tmp[1] = hx[*p >> 4]; tmp[2] = hx[*p & 15]; tmp[3] = 0;
        }
        size_t l = strlen(tmp);
        if (b->n + l + 2 > b->cap) {
            size_t nc = b->cap ? b->cap * 2 : 256;
            char *np = realloc(b->p, nc);
            if (!np) return;
            b->p = np;
            b->cap = nc;
        }
        memcpy(b->p + b->n, tmp, l);
        b->n += l;
        b->p[b->n] = 0;
    }
}

static void raw(struct strbuf *b, const char *s) {
    size_t l = strlen(s);
    if (b->n + l + 2 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->n + l + 2) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) return;
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, l);
    b->n += l;
    b->p[b->n] = 0;
}

static void qparam(struct strbuf *b, int *first, const char *k, const char *v) {
    if (!v || !*v) return;
    raw(b, *first ? "?" : "&");
    *first = 0;
    raw(b, k);
    raw(b, "=");
    pct(b, v);
}

static void host_port(struct strbuf *b, const char *host, long port) {
    char buf[300];
    if (strchr(host, ':')) snprintf(buf, sizeof buf, "[%s]:%ld", host, port);
    else snprintf(buf, sizeof buf, "%s:%ld", host, port);
    raw(b, buf);
}

/* Общая часть ссылок поверх транспорта и TLS (trojan, vmess через v2rayN не идёт — у него свой
 * формат): type, security, sni, fp, pbk, sid, alpn, path, host, serviceName, mode. */
static void tls_transport_params(struct strbuf *b, int *first, const struct jval *ob) {
    const struct jval *tls = jget(ob, "tls");
    const struct jval *tr = jget(ob, "transport");
    const char *type = tr ? jgets(tr, "type") : NULL;
    qparam(b, first, "type", type ? type : "tcp");
    if (tls && jgetb(tls, "enabled", 0)) {
        const struct jval *rl = jget(tls, "reality");
        int reality = rl && jgetb(rl, "enabled", 0);
        qparam(b, first, "security", reality ? "reality" : "tls");
        qparam(b, first, "sni", jgets(tls, "server_name"));
        const struct jval *u = jget(tls, "utls");
        if (u && jgetb(u, "enabled", 0)) qparam(b, first, "fp", jgets(u, "fingerprint"));
        if (reality) {
            qparam(b, first, "pbk", jgets(rl, "public_key"));
            qparam(b, first, "sid", jgets(rl, "short_id"));
        }
        const struct jval *alpn = jget(tls, "alpn");
        if (alpn) {
            const char *l[8];
            long n = jstrlist(alpn, l, 8);
            char buf[256] = "";
            for (long i = 0; i < n && i < 8; i++)
                snprintf(buf + strlen(buf), sizeof buf - strlen(buf), "%s%s", i ? "," : "", l[i]);
            qparam(b, first, "alpn", buf);
        }
        if (jgetb(tls, "insecure", 0)) qparam(b, first, "allowInsecure", "1");
    } else qparam(b, first, "security", "none");
    if (!tr) return;
    if (type && (!strcmp(type, "ws") || !strcmp(type, "httpupgrade"))) {
        const char *path = jgets(tr, "path");
        long ed = jgeti(tr, "max_early_data", 0);
        char pbuf[600];
        if (ed > 0) snprintf(pbuf, sizeof pbuf, "%s%sed=%ld", path ? path : "/",
                             path && strchr(path, '?') ? "&" : "?", ed);
        else snprintf(pbuf, sizeof pbuf, "%s", path ? path : "/");
        qparam(b, first, "path", pbuf);
        const char *host = jgets(tr, "host");
        if (!host) host = jgets(jget(tr, "headers"), "Host");
        qparam(b, first, "host", host);
    } else if (type && !strcmp(type, "grpc")) {
        qparam(b, first, "serviceName", jgets(tr, "service_name"));
    } else if (type && (!strcmp(type, "xhttp") || !strcmp(type, "http"))) {
        qparam(b, first, "path", jgets(tr, "path"));
        const struct jval *h = jget(tr, "host");
        const char *host = h && h->t == J_STR ? h->s : (h && h->t == J_ARR && h->len ? h->a[0]->s : NULL);
        qparam(b, first, "host", host);
        qparam(b, first, "mode", jgets(tr, "mode"));
    }
}

/* Узлу vless нужна ссылка, а не конфиг sing-box: транспорт xhttp или шифрование VLESS. */
static int vless_needs_link(const struct jval *ob) {
    const struct jval *tr = jget(ob, "transport");
    const char *tt = tr ? jgets(tr, "type") : NULL;
    const char *enc = jgets(ob, "encryption");
    return (tt && !strcmp(tt, "xhttp")) || (enc && *enc && strcmp(enc, "none"));
}

static int node_text(struct tr *t, const struct jval *ob, struct strbuf *b) {
    const char *type = jgets(ob, "type");
    const char *server = jgets(ob, "server");
    long port = jgeti(ob, "server_port", 443);
    int first = 1;
    if (!strcmp(type, "vless") && vless_needs_link(ob)) {
        /* Ссылка vless:// — у xhttp и у шифрования VLESS. Разбор конфига sing-box в ядре steer
         * берёт у транспорта path и host только для ws и httpupgrade, а encryption не читает
         * вовсе: узел xhttp от forkop (extended) уходил с путём «/» без host и mode, а узел с
         * encryption — без шифрования, и сервер его не принимал. Ссылка несёт всё это (как
         * подписки Xray): path, host, mode, extra с xPaddingBytes, encryption, flow. */
        const char *enc = jgets(ob, "encryption");
        raw(b, "vless://");
        pct(b, jgets(ob, "uuid") ? jgets(ob, "uuid") : "");
        raw(b, "@");
        host_port(b, server, port);
        qparam(b, &first, "encryption", enc && *enc ? enc : "none");
        qparam(b, &first, "flow", jgets(ob, "flow"));
        tls_transport_params(b, &first, ob);
        const struct jval *tr = jget(ob, "transport");
        const struct jval *pad = tr ? jget(tr, "x_padding_bytes") : NULL;
        char pb[64] = "";
        if (pad && pad->t == J_STR && pad->s[0]) snprintf(pb, sizeof pb, "%s", pad->s);
        else if (pad && pad->t == J_NUM) snprintf(pb, sizeof pb, "%lld", (long long)pad->i);
        if (pb[0] && !strpbrk(pb, "\"\\")) {
            char ex[128];
            snprintf(ex, sizeof ex, "{\"xPaddingBytes\":\"%s\"}", pb);
            qparam(b, &first, "extra", ex);
        }
        if (jgets(ob, "tag")) { raw(b, "#"); pct(b, jgets(ob, "tag")); }
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "vless")) {
        /* Конфиг sing-box: подписка steer его читает. detour и тег не нужны узлу — цепочку
         * ведёт ключ over выхода. */
        struct jval *copy = jdup(ob);
        jobj_del(copy, "detour");
        struct jval *wrap = jnew(J_OBJ), *arr = jnew(J_ARR);
        jarr_push(arr, copy);
        jobj_set(wrap, "outbounds", arr);
        size_t n;
        char *s = json_to_str(wrap, 2, &n);
        json_free(wrap);
        if (!s) return tfail(t, "нет памяти");
        raw(b, s);
        raw(b, "\n");
        free(s);
        return 0;
    }
    if (!strcmp(type, "hysteria2")) {
        raw(b, "hysteria2://");
        pct(b, jgets(ob, "password") ? jgets(ob, "password") : "");
        raw(b, "@");
        host_port(b, server, port);
        raw(b, "/");
        const struct jval *tls = jget(ob, "tls");
        qparam(b, &first, "sni", jgets(tls, "server_name"));
        if (jgetb(tls, "insecure", 0)) qparam(b, &first, "insecure", "1");
        const struct jval *obfs = jget(ob, "obfs");
        if (obfs) {
            qparam(b, &first, "obfs", jgets(obfs, "type"));
            qparam(b, &first, "obfs-password", jgets(obfs, "password"));
        }
        char num[32];
        if (jget(ob, "up_mbps")) { snprintf(num, sizeof num, "%lld", (long long)jgeti(ob, "up_mbps", 0)); qparam(b, &first, "up", num); }
        if (jget(ob, "down_mbps")) { snprintf(num, sizeof num, "%lld", (long long)jgeti(ob, "down_mbps", 0)); qparam(b, &first, "down", num); }
        const struct jval *sp = jget(ob, "server_ports");
        long spn = sp ? jstrlist(sp, NULL, 0) : 0;
        if (spn > 0) {
            char buf[512] = "";
            const char **l = calloc((size_t)spn, sizeof *l);
            if (!l) { tfail(t, "нет памяти"); return -1; }
            jstrlist(sp, l, (size_t)spn);
            for (long i = 0; i < spn; i++) {
                char r[64];
                snprintf(r, sizeof r, "%s", l[i]);
                char *c = strchr(r, ':');
                if (c) *c = '-';
                snprintf(buf + strlen(buf), sizeof buf - strlen(buf), "%s%s", i ? "," : "", r);
            }
            free(l);
            qparam(b, &first, "mport", buf);
        }
        const char *hop = jgets(ob, "hop_interval");
        if (hop) {
            long long ms = sb_duration_ms(hop);
            if (ms > 0) { snprintf(num, sizeof num, "%lld", ms / 1000); qparam(b, &first, "hop-interval", num); }
        }
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "trojan")) {
        raw(b, "trojan://");
        pct(b, jgets(ob, "password") ? jgets(ob, "password") : "");
        raw(b, "@");
        host_port(b, server, port);
        tls_transport_params(b, &first, ob);
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "shadowsocks")) {
        /* SIP002 без base64: method:password процентным кодированием — так у 2022 не ломается
         * двоеточие пары ключей iPSK:uPSK. */
        char mp[1024];
        snprintf(mp, sizeof mp, "%s:%s", jgets(ob, "method"), jgets(ob, "password") ? jgets(ob, "password") : "");
        raw(b, "ss://");
        char enc[1400];
        if (b64url_enc(mp, enc, sizeof enc)) return tfail(t, "ss: слишком длинный пароль");
        raw(b, enc);
        raw(b, "@");
        host_port(b, server, port);
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "socks")) {
        const char *ver = jgets(ob, "version");
        raw(b, !ver || !strcmp(ver, "5") ? "socks5://" : !strcmp(ver, "4a") ? "socks4a://" : "socks4://");
        if (jgets(ob, "username")) {
            pct(b, jgets(ob, "username"));
            raw(b, ":");
            pct(b, jgets(ob, "password") ? jgets(ob, "password") : "");
            raw(b, "@");
        }
        host_port(b, server, port);
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "http")) {
        const struct jval *tls = jget(ob, "tls");
        raw(b, tls && jgetb(tls, "enabled", 0) ? "https://" : "http://");
        if (jgets(ob, "username")) {
            pct(b, jgets(ob, "username"));
            raw(b, ":");
            pct(b, jgets(ob, "password") ? jgets(ob, "password") : "");
            raw(b, "@");
        }
        host_port(b, server, port);
        if (tls) {
            qparam(b, &first, "sni", jgets(tls, "server_name"));
            if (jgetb(tls, "insecure", 0)) qparam(b, &first, "allowInsecure", "1");
        }
        raw(b, "\n");
        return 0;
    }
    if (!strcmp(type, "vmess")) {
        /* v2rayN: base64 от JSON с полями add, port, id, aid, scy, net, type, host, path, tls,
         * sni, alpn, fp. */
        struct jval *v = jnew(J_OBJ);
        jobj_set(v, "v", jstr("2"));
        jobj_set(v, "ps", jstr(jgets(ob, "tag")));
        jobj_set(v, "add", jstr(server));
        jobj_set(v, "port", jint(port));
        jobj_set(v, "id", jstr(jgets(ob, "uuid")));
        jobj_set(v, "aid", jint(jgeti(ob, "alter_id", 0)));
        jobj_set(v, "scy", jstr(jgets(ob, "security") ? jgets(ob, "security") : "auto"));
        const struct jval *tr = jget(ob, "transport");
        const char *net = tr ? jgets(tr, "type") : "tcp";
        jobj_set(v, "net", jstr(net));
        jobj_set(v, "type", jstr("none"));
        if (tr) {
            const char *host = jgets(tr, "host");
            if (!host) host = jgets(jget(tr, "headers"), "Host");
            if (host) jobj_set(v, "host", jstr(host));
            const char *path = jgets(tr, "path");
            if (!path) path = jgets(tr, "service_name");
            if (path) jobj_set(v, "path", jstr(path));
        }
        const struct jval *tls = jget(ob, "tls");
        if (tls && jgetb(tls, "enabled", 0)) {
            jobj_set(v, "tls", jstr("tls"));
            if (jgets(tls, "server_name")) jobj_set(v, "sni", jstr(jgets(tls, "server_name")));
            const struct jval *u = jget(tls, "utls");
            if (u && jgets(u, "fingerprint")) jobj_set(v, "fp", jstr(jgets(u, "fingerprint")));
        }
        char *s = json_to_str(v, -1, NULL);
        json_free(v);
        if (!s) return tfail(t, "нет памяти");
        size_t need = strlen(s) * 2 + 16;
        char *enc = malloc(need);
        if (!enc || b64url_enc(s, enc, need)) { free(s); free(enc); return tfail(t, "нет памяти"); }
        /* v2rayN пишет обычный base64; читатели принимают оба алфавита, но обычный —
         * общепринятый. */
        for (char *p = enc; *p; p++) { if (*p == '-') *p = '+'; else if (*p == '_') *p = '/'; }
        raw(b, "vmess://");
        raw(b, enc);
        raw(b, "\n");
        free(s);
        free(enc);
        return 0;
    }
    return tfail(t, "outbound %s: тип %s не переводится", jgets(ob, "tag"), type);
}

char *box_node_text(const struct jval *ob, char *err, size_t errn) {
    struct tr t;
    memset(&t, 0, sizeof t);
    char e0[8];
    t.err = err ? err : e0;
    t.errn = err ? errn : sizeof e0;
    struct strbuf b = { 0 };
    if (!ob || !jgets(ob, "type") || !jgets(ob, "server") || node_text(&t, ob, &b)) {
        if (!t.failed) snprintf(t.err, t.errn, "узел не переводится");
        free(b.p);
        return NULL;
    }
    return b.p;
}

static int b64url_enc(const char *in, char *out, size_t n) {
    static const char tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t len = strlen(in), j = 0;
    if ((len + 2) / 3 * 4 + 1 > n) return -1;
    const unsigned char *p = (const unsigned char *)in;
    for (size_t i = 0; i < len; i += 3) {
        unsigned v = (unsigned)p[i] << 16 | (i + 1 < len ? p[i + 1] : 0) << 8 | (i + 2 < len ? p[i + 2] : 0);
        out[j++] = tab[v >> 18 & 63];
        out[j++] = tab[v >> 12 & 63];
        if (i + 1 < len) out[j++] = tab[v >> 6 & 63];
        if (i + 2 < len) out[j++] = tab[v & 63];
    }
    out[j] = 0;
    return 0;
}

/* Протокол туннеля steer по типу outbound. */
static const char *tunnel_protocol(const char *type) {
    if (!strcmp(type, "vless") || !strcmp(type, "hysteria2") || !strcmp(type, "trojan") ||
        !strcmp(type, "vmess") || !strcmp(type, "socks") || !strcmp(type, "http"))
        return type;
    if (!strcmp(type, "shadowsocks")) return "shadowsocks";
    return NULL;
}

static int64_t mark_of(const struct jval *v) {
    if (!v) return -1;
    if (v->t == J_NUM) return v->i;
    if (v->t == J_STR) return (int64_t)strtoull(v->s, NULL, 0);
    return -1;
}

/* Выход по тегу: завести (один раз) и вернуть имя. NULL — у выхода нет вида в steer (тогда
 * правила в него снимаются). Группы — после членов: члены заводятся рекурсивно. */
static const char *emit_output(struct tr *t, const char *tag, int depth);

/* SELECTOR — выбор человека (Clash API), как у sing-box: трафик несёт один член, остальные спят.
 * В спеку попадает только выбранный член (с его вложенными выходами), а не все: у forkop в
 * selector лежит вся подписка — десятки узлов, — и группа steer из них держала бы туннель,
 * процесс и запасные сессии на каждый (49 узлов — около 100 МБ памяти роутера и сотни
 * соединений к серверам). Смена выбора (PUT /proxies/<селектор>) — новый перевод и reload.
 *
 * Выбранный член — из tr_opts.selected, иначе default, иначе первый. Не переводится (нет вида) —
 * следующий по порядку. Спящие члены попадают в карту с dormant: Clash API показывает их и меряет
 * им задержку сам, а правило, которое ведёт в такой член напрямую, всё равно его поднимет. */
static const char *emit_selector(struct tr *t, const char *tag, const struct jval *ob, int depth) {
    map_out(t, tag, "", "Selector");           /* отметка от круга */
    const struct jval *m = jget(ob, "outbounds");
    const char *want = jgets(t->o->selected, tag);
    const char *def = jgets(ob, "default");
    int ok_want = 0, ok_def = 0;
    for (size_t i = 0; i < jlen(m); i++) {
        if (jat(m, i)->t != J_STR) continue;
        if (want && !strcmp(jat(m, i)->s, want)) ok_want = 1;
        if (def && !strcmp(jat(m, i)->s, def)) ok_def = 1;
    }
    const char *first = ok_want ? want : ok_def ? def : NULL;
    const char *now = NULL, *name = NULL;
    if (first) {
        name = emit_output(t, first, depth + 1);
        if (name) now = first;
        else tw(t, "селектор %s: выбранный %s не переводится — беру следующий", tag, first);
    }
    for (size_t i = 0; !name && i < jlen(m); i++) {
        const char *mt = jat(m, i)->s;
        if (jat(m, i)->t != J_STR || (first && !strcmp(mt, first))) continue;
        if ((name = emit_output(t, mt, depth + 1))) now = mt;
    }
    for (size_t i = 0; i < jlen(m); i++) {
        const char *mt = jat(m, i)->s;
        if (jat(m, i)->t != J_STR || (now && !strcmp(mt, now)) || jget(t->map_out, mt)) continue;
        const struct jval *mob = sb_outbound(t->cfg, mt);
        struct jval *e = jnew(J_OBJ);
        jobj_set(e, "name", jstr(""));
        jobj_set(e, "type", jstr(clash_type(jgets(mob, "type"))));
        jobj_set(e, "dormant", jbool(1));
        jobj_set(t->map_out, mt, e);
    }
    if (!name) {
        tw(t, "селектор %s: ни одного члена с видом в steer — правила в него сняты", tag);
        return NULL;
    }
    struct jval *e = jnew(J_OBJ);
    jobj_set(e, "name", jstr(name));
    jobj_set(e, "type", jstr("Selector"));
    jobj_set(e, "now", jstr(now));
    jobj_set(t->map_out, tag, e);
    return name;
}

static const char *emit_output(struct tr *t, const char *tag, int depth) {
    struct jval *have = jget(t->map_out, tag);
    if (have && !jgetb(have, "dormant", 0)) {
        const char *n = jgets(have, "name");
        return n && *n ? n : NULL;
    }
    const struct jval *ob = sb_outbound(t->cfg, tag);
    if (!ob || depth > 32) return NULL;
    const char *type = jgets(ob, "type");
    enum sb_okind k = sb_outbound_kind(ob);
    int64_t mark = mark_of(jget(ob, "routing_mark"));
    if (k == SBO_REMARK && t->o->egress_mark && mark == (int64_t)t->o->egress_mark) k = SBO_DIRECT;
    switch (k) {
    case SBO_DIRECT: {
        const char *n = ensure_direct(t);
        map_out(t, tag, n, "Direct");
        return n;
    }
    case SBO_INTERFACE: {
        const char *name = names_get(&t->onames, tag, NULL);
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "kind", jstr("interface"));
        jobj_set(o, "device", jstr(jgets(ob, "bind_interface")));
        jobj_set(o, "on_fail", jstr("drop"));
        jobj_set(t->outputs, name, o);
        map_out(t, tag, name, "Direct");
        return name;
    }
    case SBO_BLOCK: {
        tw(t, "выход %s (block): вида block в steer пока нет — правила в него сняты", tag);
        map_out(t, tag, "", "Block");
        return NULL;
    }
    case SBO_REMARK:
        tw(t, "выход %s: direct с routing_mark %#llx (zapret forkop) пока не переводится — "
           "правила в него сняты", tag, (unsigned long long)mark);
        map_out(t, tag, "", "Direct");
        return NULL;
    case SBO_DNS:
        map_out(t, tag, "", "DNS");
        return NULL;
    case SBO_TUNNEL: {
        const char *proto = tunnel_protocol(type);
        const char *name = names_get(&t->onames, tag, NULL);
        if (!name) { tfail(t, "нет памяти"); return NULL; }
        char dir[1100], path[1100];
        snprintf(dir, sizeof dir, "%s/sub", t->o->dir);
        mkdirs(dir);
        snprintf(path, sizeof path, "%s/%s", dir, name);
        struct strbuf b = { 0 };
        if (node_text(t, ob, &b)) { free(b.p); return NULL; }
        if (write_file(t, path, b.p, b.n)) { free(b.p); return NULL; }
        free(b.p);
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "kind", jstr("tunnel"));
        jobj_set(o, "protocol", jstr(proto));
        jobj_set(o, "subscription", jstr(path));
        char dev[16];
        snprintf(dev, sizeof dev, "sbx%u", t->dev_seq++);
        jobj_set(o, "device", jstr(dev));
        /* tls.insecure — ключ insecure выхода у всех видов с TLS (vless, trojan, vmess, http).
         * Без него steer-proxy пропускает узел trojan/https с allowInsecure («включите insecure у
         * выхода явно»), а vmess сверяет сертификат. У hysteria2 ключа нет: insecure=1 в ссылке. */
        const struct jval *tls = jget(ob, "tls");
        if (tls && jgetb(tls, "enabled", 0) && jgetb(tls, "insecure", 0) &&
            (!strcmp(type, "vless") || !strcmp(type, "trojan") || !strcmp(type, "vmess") ||
             !strcmp(type, "http")))
            jobj_set(o, "insecure", jbool(1));
        const char *det = jgets(ob, "detour");
        if (det) {
            const char *over = emit_output(t, det, depth + 1);
            if (over && strcmp(over, "direct")) jobj_set(o, "over", jstr(over));
        }
        jobj_set(t->outputs, name, o);
        static const struct { const char *t, *c; } cl[] = {
            { "vless", "VLESS" }, { "vmess", "VMess" }, { "trojan", "Trojan" },
            { "shadowsocks", "Shadowsocks" }, { "socks", "SOCKS" }, { "http", "HTTP" },
            { "hysteria2", "Hysteria2" },
        };
        const char *ct = type;
        for (size_t i = 0; i < sizeof cl / sizeof cl[0]; i++)
            if (!strcmp(cl[i].t, type)) ct = cl[i].c;
        map_out(t, tag, name, ct);
        return name;
    }
    case SBO_GROUP:
        if (!strcmp(type, "selector")) return emit_selector(t, tag, ob, depth);
        {
        int urltest = !strcmp(type, "urltest");
        /* Сначала отметка, чтобы круг групп не уводил в бесконечность. */
        map_out(t, tag, "", urltest ? "URLTest" : "Selector");
        struct jval *members = jnew(J_ARR);
        const struct jval *m = jget(ob, "outbounds");
        const char *def = jgets(ob, "default"), *def_name = NULL;
        for (size_t i = 0; i < jlen(m); i++) {
            const char *mt = jat(m, i)->s;
            const char *mn = emit_output(t, mt, depth + 1);
            if (!mn) continue;
            if (!strcmp(mn, "direct")) {
                tw(t, "группа %s: член %s — direct, а член группы steer должен иметь устройство; снят",
                   tag, mt);
                continue;
            }
            int dup = 0;
            for (size_t k2 = 0; k2 < members->len; k2++)
                if (!strcmp(members->a[k2]->s, mn)) dup = 1;
            if (dup) continue;
            jarr_push(members, jstr(mn));
            if (def && !strcmp(def, mt)) def_name = mn;
        }
        if (!members->len) {
            json_free(members);
            tw(t, "группа %s: ни одного члена с видом в steer — правила в неё сняты", tag);
            return NULL;
        }
        const char *name = names_get(&t->onames, tag, NULL);
        struct jval *o = jnew(J_OBJ);
        jobj_set(o, "kind", jstr("group"));
        jobj_set(o, "members", members);
        if (urltest) {
            jobj_set(o, "pick", jstr("latency"));
            const char *url = jgets(ob, "url");
            jobj_set(o, "url", jstr(url ? url : "https://www.gstatic.com/generate_204"));
            long long iv = sb_duration_ms(jgets(ob, "interval"));
            long ivs = iv > 0 ? (long)(iv / 1000) : 180;
            if (ivs < 5) ivs = 5;
            jobj_set(o, "interval", jint(ivs));
            jobj_set(o, "tolerance", jint(jgeti(ob, "tolerance", 50)));
            long long idle = sb_duration_ms(jgets(ob, "idle_timeout"));
            if (idle >= 0) jobj_set(o, "idle_timeout", jint(idle / 1000));
        } else {
            jobj_set(o, "pick", jstr("manual"));
            if (def_name) jobj_set(o, "default", jstr(def_name));
        }
        jobj_set(o, "on_fail", jstr("drop"));
        jobj_set(t->outputs, name, o);
        map_out(t, tag, name, urltest ? "URLTest" : "Selector");
        return name;
        }
    default:
        tw(t, "выход %s: тип %s не переводится — правила в него сняты", tag, type ? type : "?");
        map_out(t, tag, "", type ? type : "?");
        return NULL;
    }
}

/* ---- правила ---------------------------------------------------------------------------- */

static int is_lan_inbound(const struct tr *t, const char *tag) {
    const struct jval *in = sb_inbound(t->cfg, tag);
    const char *type = jgets(in, "type");
    return type && (!strcmp(type, "tproxy") || !strcmp(type, "tun") || !strcmp(type, "redirect"));
}

/* Правило касается трафика LAN (того, что podkop/forkop заворачивают в tproxy)? Без inbound —
 * да; с inbound — если среди них есть вход tproxy. */
static int rule_for_lan(const struct tr *t, const struct jval *r) {
    struct jval *in = jget(r, "inbound");
    if (!in) return 1;
    long n = jstrlist(in, NULL, 0);
    if (n <= 0) return 1;
    const char **l = calloc((size_t)n, sizeof *l);
    if (!l) return 0;
    jstrlist(in, l, (size_t)n);
    int yes = 0;
    for (long i = 0; i < n; i++)
        if (is_lan_inbound(t, l[i])) yes = 1;
    free(l);
    return yes;
}

/* Клиент из source_ip_cidr. */
static const char *emit_client(struct tr *t, const struct jval *src) {
    char *s = json_to_str(src, -1, NULL);
    if (!s) return NULL;
    const char *name = names_find(&t->cnames, s);
    if (!name) {
        char cn[16];
        snprintf(cn, sizeof cn, "c%zu", t->cnames.n);
        name = names_get(&t->cnames, s, NULL);
        /* Имя клиента — по порядку, а не из адресов: адреса бывают длинными, а имя видно только
         * в status. names_get уже завёл имя из ключа — заменяем его. */
        free(t->cnames.name[t->cnames.n - 1]);
        t->cnames.name[t->cnames.n - 1] = strdup(cn);
        name = t->cnames.name[t->cnames.n - 1];
        struct jval *c = jnew(J_OBJ), *a = jnew(J_ARR);
        long n = jstrlist(src, NULL, 0);
        for (long i = 0; i < n; i++)
            jarr_push(a, jstr(src->t == J_ARR ? src->a[i]->s : src->s));
        jobj_set(c, "addr", a);
        jobj_set(t->clients, name, c);
    }
    free(s);
    return name;
}

static int set_resolves(const struct tr *t, const char *tag) {
    if (t->resolve_all) return 1;
    for (size_t i = 0; i < t->resolve_n; i++)
        if (!strcmp(t->resolve_sets[i], tag)) return 1;
    return 0;
}

/* Условия, которые перевод знает. Остальное — правило снимается с предупреждением. */
static int rule_keys_ok(struct tr *t, const struct jval *r, const char *where) {
    static const char *ok[] = { "inbound", "action", "outbound", "rule_set", "domain", "domain_suffix",
                                "domain_keyword", "domain_regex", "ip_cidr", "ip_is_private",
                                "source_ip_cidr", "network", "port", "port_range", "protocol",
                                "ip_version", "override_port", NULL };
    for (size_t i = 0; i < jlen(r); i++) {
        const char *k = r->o[i].key;
        int good = 0;
        for (int j = 0; ok[j]; j++)
            if (!strcmp(k, ok[j])) good = 1;
        if (!good) {
            tw(t, "%s: условие «%s» ядро не выражает — правило снято", where, k);
            return 0;
        }
    }
    return 1;
}

/* Одно правило sing-box → правила steer (по одному на сужение). */
static int emit_rule_ex(struct tr *t, size_t idx, const struct jval *r, const char *out_name,
                        const char *sb_out, int force_realip, const char *dns_up, const char *section) {
    char where[64];
    snprintf(where, sizeof where, "%s[%zu]", section, idx);
    if (!rule_keys_ok(t, r, where)) return 0;
    if (jget(r, "protocol")) {
        tw(t, "%s: protocol у правила с выходом ядро не выражает — правило снято", where);
        return 0;
    }
    const char *client = NULL;
    struct jval *src = jget(r, "source_ip_cidr");
    if (src) client = emit_client(t, src);
    struct narrow rnw;
    if (narrow_from_rule(t, r, &rnw, where)) return 0;
    struct plist_set ps = { 0 };
    struct jval *rsv = jget(r, "rule_set");
    long nrs = rsv ? jstrlist(rsv, NULL, 0) : 0;
    int realip = force_realip, any_set = 0, missing = 0;
    const char **sets = nrs > 0 ? calloc((size_t)nrs, sizeof *sets) : NULL;
    if (nrs > 0 && !sets) return tfail(t, "нет памяти");
    if (nrs > 0) jstrlist(rsv, sets, (size_t)nrs);
    for (long i = 0; i < nrs; i++) {
        int rc = collect_set(t, &ps, sets[i]);
        if (rc < 0) { free(sets); plist_free(&ps); return -1; }
        if (rc == 1) missing++;
        else any_set = 1;
        if (set_resolves(t, sets[i])) realip = 1;
    }
    free(sets);
    /* Свои условия правила — ещё один список. */
    struct pending_list own = { 0 };
    if (add_dest(&own, r)) { plist_free(&ps); return tfail(t, "нет памяти"); }
    int has_own = own.dom.n || own.pfx.n;
    int has_dest = has_own || any_set;
    if (!has_dest && (nrs > 0 || missing)) {
        free(own.dom.p);
        free(own.pfx.p);
        plist_free(&ps);
        return 0;                      /* все наборы ещё не скачаны — правило встанет потом */
    }
    if (has_own) {
        struct pending_list *pl = plist_for(&ps, &rnw);
        if (!pl) { free(own.dom.p); free(own.pfx.p); plist_free(&ps); return tfail(t, "нет памяти"); }
        if (own.dom.n) sb_add(&pl->dom, own.dom.p), pl->dom.n--, pl->dom.p[pl->dom.n] = 0;
        if (own.pfx.n) sb_add(&pl->pfx, own.pfx.p), pl->pfx.n--, pl->pfx.p[pl->pfx.n] = 0;
    }
    free(own.dom.p);
    free(own.pfx.p);
    /* Списки по сужениям: каждый — своё правило steer, правила подряд с тем же выходом. */
    char tagbuf[64];
    snprintf(tagbuf, sizeof tagbuf, "r%zu", idx);
    if (!has_dest) {
        if (!client) {
            tw(t, "%s: правило без условий назначения и клиента — весь трафик LAN; снято, "
               "чтобы не забрать лишнего", where);
            plist_free(&ps);
            return 0;
        }
        struct jval *rule = jnew(J_OBJ);
        char label[32];
        snprintf(label, sizeof label, "sb%zu", idx);
        jobj_set(rule, "name", jstr(label));
        struct jval *fr = jnew(J_ARR);
        jarr_push(fr, jstr(client));
        jobj_set(rule, "for", fr);
        if (rnw.tcp || rnw.udp || rnw.ports[0]) {
            struct pending_list all = { .nw = rnw };
            const char *ln = NULL;
            char key[64];
            snprintf(key, sizeof key, "all-%zu", idx);
            /* Список «весь трафик» с сужением: all: true. */
            ln = names_get(&t->lnames, key, NULL);
            struct jval *l = jnew(J_OBJ);
            jobj_set(l, "all", jbool(1));
            list_narrow(l, &all.nw);
            jobj_set(t->lists, ln, l);
            struct jval *to = jnew(J_ARR);
            jarr_push(to, jstr(ln));
            jobj_set(rule, "to", to);
        } else jobj_set(rule, "to", jstr("all"));
        jobj_set(rule, "out", jstr(out_name));
        jarr_push(t->rules, rule);
        struct jval *mr = jnew(J_OBJ);
        jobj_set(mr, "rule", jint((int64_t)idx));
        jobj_set(mr, "outbound", jstr(sb_out));
        jobj_set(t->map_rules, label, mr);
        plist_free(&ps);
        return 0;
    }
    for (size_t i = 0; i < ps.n; i++) {
        struct pending_list *pl = &ps.v[i];
        narrow_merge(t, &pl->nw, &rnw, where);
    }
    /* Правила с одним сужением сводятся в одно правило steer (to — несколько списков). */
    int *done = calloc(ps.n ? ps.n : 1, sizeof *done);
    if (!done) { plist_free(&ps); return tfail(t, "нет памяти"); }
    unsigned part = 0;
    for (size_t i = 0; i < ps.n; i++) {
        if (done[i]) continue;
        struct jval *to = jnew(J_ARR);
        for (size_t j = i; j < ps.n; j++) {
            if (done[j] || !narrow_same(&ps.v[i].nw, &ps.v[j].nw)) continue;
            done[j] = 1;
            const char *ln = emit_list(t, &ps.v[j], tagbuf);
            if (t->failed) { json_free(to); free(done); plist_free(&ps); return -1; }
            if (ln) jarr_push(to, jstr(ln));
        }
        if (!to->len) { json_free(to); continue; }
        struct jval *rule = jnew(J_OBJ);
        char label[32];
        const char *pre = section[0] == 'd' ? "dns" : "sb";
        if (part) snprintf(label, sizeof label, "%s%zu.%u", pre, idx, part);
        else snprintf(label, sizeof label, "%s%zu", pre, idx);
        part++;
        jobj_set(rule, "name", jstr(label));
        if (client) {
            struct jval *fr = jnew(J_ARR);
            jarr_push(fr, jstr(client));
            jobj_set(rule, "for", fr);
        }
        jobj_set(rule, "to", to);
        jobj_set(rule, "out", jstr(out_name));
        if (realip) jobj_set(rule, "resolve", jstr("realip"));
        if (dns_up) jobj_set(rule, "dns", jstr(dns_up));
        jarr_push(t->rules, rule);
        if (!client && t->o->router_self) {
            /* Двойник на сам роутер: у sing-box его трафик к адресам из списков (podkop и forkop
             * метят его в mangle_output) возвращается через lo в tproxy-in и идёт по тем же
             * правилам. Правило с source_ip_cidr — только про клиентов LAN, двойника у него нет. */
            struct jval *tw2 = jdup(rule);
            char l2[40];
            snprintf(l2, sizeof l2, "%s.r", label);
            jobj_set(tw2, "name", jstr(l2));
            struct jval *fr = jnew(J_ARR);
            jarr_push(fr, jstr("router"));
            jobj_set(tw2, "for", fr);
            jarr_push(t->rules, tw2);
            t->self_used = 1;
        }
        struct jval *mr = jnew(J_OBJ);
        jobj_set(mr, "rule", jint((int64_t)idx));
        jobj_set(mr, "outbound", jstr(sb_out));
        jobj_set(t->map_rules, label, mr);
    }
    free(done);
    plist_free(&ps);
    return 0;
}

static int emit_rule(struct tr *t, size_t idx, const struct jval *r, const char *out_name,
                     const char *sb_out, int force_realip) {
    return emit_rule_ex(t, idx, r, out_name, sb_out, force_realip, NULL, "route.rules");
}

/* ---- DNS -------------------------------------------------------------------------------- */

/* Сервер DNS sing-box → апстрим steer ({ url, out, ips|bootstrap }). NULL — не переводится. */
static struct jval *dns_upstream(struct tr *t, const struct jval *srv) {
    const char *type = jgets(srv, "type");
    const char *host = jgets(srv, "server");
    if (!type || !host) return NULL;
    long port = jgeti(srv, "server_port", 0);
    char url[600];
    const char *scheme = !strcmp(type, "udp") ? "udp" : !strcmp(type, "tcp") ? "tcp"
                       : !strcmp(type, "tls") ? "tls" : !strcmp(type, "https") ? "https"
                       : !strcmp(type, "quic") ? "quic" : NULL;
    if (!scheme) {
        tw(t, "dns: сервер %s типа %s в апстрим steer не переводится", jgets(srv, "tag"), type);
        return NULL;
    }
    unsigned char a[16];
    int is_ip = inet_pton(AF_INET, host, a) == 1 || inet_pton(AF_INET6, host, a) == 1;
    const char *h = host;
    char hb[300];
    if (strchr(host, ':')) { snprintf(hb, sizeof hb, "[%s]", host); h = hb; }
    if (port) snprintf(url, sizeof url, "%s://%s:%ld", scheme, h, port);
    else snprintf(url, sizeof url, "%s://%s", scheme, h);
    if (!strcmp(scheme, "https")) {
        const char *path = jgets(srv, "path");
        snprintf(url + strlen(url), sizeof url - strlen(url), "%s", path && *path ? path : "/dns-query");
    }
    if ((!strcmp(scheme, "udp") || !strcmp(scheme, "tcp")) && !is_ip) {
        tw(t, "dns: сервер %s (%s) — у udp/tcp steer нужен адрес, не имя; не переводится",
           jgets(srv, "tag"), host);
        return NULL;
    }
    struct jval *u = jnew(J_OBJ);
    jobj_set(u, "url", jstr(url));
    const char *det = jgets(srv, "detour");
    if (det) {
        const char *o = emit_output(t, det, 0);
        if (o && strcmp(o, "direct")) jobj_set(u, "out", jstr(o));
    }
    if (!is_ip && strcmp(scheme, "udp") && strcmp(scheme, "tcp")) {
        /* Имя сервера DoT/DoH/DoQ: bootstrap — сервер из domain_resolver, если это udp с
         * адресом. */
        const struct jval *dr = jget(srv, "domain_resolver");
        const char *rt = dr ? (dr->t == J_STR ? dr->s : jgets(dr, "server")) : NULL;
        const struct jval *rs = rt ? sb_dns_server(t->cfg, rt) : NULL;
        const char *rh = rs ? jgets(rs, "server") : NULL;
        if (rh && jgets(rs, "type") && !strcmp(jgets(rs, "type"), "udp") &&
            (inet_pton(AF_INET, rh, a) == 1 || inet_pton(AF_INET6, rh, a) == 1)) {
            struct jval *bs = jnew(J_ARR);
            jarr_push(bs, jstr(rh));
            jobj_set(u, "bootstrap", bs);
        }
    }
    return u;
}

static int emit_dns(struct tr *t) {
    const struct jval *dns = jget(t->cfg, "dns");
    struct jval *d = jnew(J_OBJ);
    jobj_set(d, "mode", jstr("fakeip"));
    struct jval *ups = jnew(J_OBJ);
    struct jval *boot = jnew(J_ARR);
    const struct jval *servers = jget(dns, "servers");
    for (size_t i = 0; i < jlen(servers); i++) {
        const struct jval *s = jat(servers, i);
        const char *type = jgets(s, "type");
        if (type && !strcmp(type, "fakeip")) {
            const char *r4 = jgets(s, "inet4_range");
            if (r4 && strcmp(r4, "198.18.0.0/15"))
                tw(t, "dns: пул fake-IP %s — у steer пул 198.18.0.0/15, берётся он", r4);
            continue;
        }
        struct jval *u = dns_upstream(t, s);
        if (!u) continue;
        const char *name = names_get(&t->onames, jgets(s, "tag"), "dns-");
        jobj_set(ups, name, u);
        struct jval *bs = jget(u, "bootstrap");
        for (size_t k = 0; k < jlen(bs); k++) {
            int dup = 0;
            for (size_t m = 0; m < boot->len; m++)
                if (!strcmp(boot->a[m]->s, bs->a[k]->s)) dup = 1;
            if (!dup && boot->len < 4) jarr_push(boot, jstr(bs->a[k]->s));
        }
    }
    /* Апстрим имён под правилами: тот, что sing-box отдаёт именам вне правил DNS (dns.final), —
     * им клиенты получают настоящие адреса, им же движок узнаёт адрес для подмены fake-IP. */
    const char *fin = jgets(dns, "final");
    if (!fin && jlen(servers)) fin = jgets(jat(servers, 0), "tag");
    if (fin) {
        const char *fn = names_find(&t->onames, fin);
        if (fn && jget(ups, fn)) jobj_set(d, "upstream", jstr(fn));
    }
    if (ups->len) jobj_set(d, "upstreams", ups);
    else json_free(ups);
    if (boot->len) jobj_set(d, "bootstrap", boot);
    else json_free(boot);
    jobj_set(t->spec, "dns", d);
    return 0;
}

/* ---- сборка ----------------------------------------------------------------------------- */

int box_translate(const struct jval *cfg, const struct tr_opts *o, struct tr_result *res,
                  char *err, size_t errn) {
    memset(res, 0, sizeof *res);
    struct tr t = { .cfg = cfg, .o = o, .err = err, .errn = errn };
    char lists_dir[1100];
    snprintf(lists_dir, sizeof lists_dir, "%s/lists", o->dir);
    if (mkdirs(lists_dir)) return snprintf(err, errn, "%s: %s", lists_dir, strerror(errno)), -1;
    t.spec = jnew(J_OBJ);
    t.outputs = jnew(J_OBJ);
    t.lists = jnew(J_OBJ);
    t.rules = jnew(J_ARR);
    t.clients = jnew(J_OBJ);
    t.map = jnew(J_OBJ);
    t.map_out = jnew(J_OBJ);
    t.map_rules = jnew(J_OBJ);
    jobj_set(t.spec, "version", jint(2));
    struct jval *lan = jnew(J_OBJ), *devs = jnew(J_ARR);
    if (o->lan_n)
        for (size_t i = 0; i < o->lan_n; i++) jarr_push(devs, jstr(o->lan_devices[i]));
    else jarr_push(devs, jstr("br-lan"));
    jobj_set(lan, "devices", devs);
    jobj_set(t.spec, "lan", lan);

    /* Выходы — только те, в которые ведут правила, DNS и выбор селекторов (emit_output по ходу):
     * у sing-box выход без трафика соединений не держит, а здесь каждый туннель — процесс и
     * сессии. Остальные — в карту спящими (ниже), Clash API показывает их все. */
    const struct jval *obs = jget(cfg, "outbounds");

    const struct jval *rules = jget(jget(cfg, "route"), "rules");
    for (size_t i = 0; i < jlen(rules) && !t.failed; i++) {
        const struct jval *r = jat(rules, i);
        if (!rule_for_lan(&t, r)) continue;
        const char *act = jgets(r, "action");
        if (!act) act = "route";
        char where[64];
        snprintf(where, sizeof where, "route.rules[%zu]", i);
        if (!strcmp(act, "sniff") || !strcmp(act, "hijack-dns")) continue;
        if (!strcmp(act, "resolve")) {
            struct jval *rs = jget(r, "rule_set");
            long n = rs ? jstrlist(rs, NULL, 0) : 0;
            if (n <= 0) { t.resolve_all = 1; continue; }
            const char **l = realloc(t.resolve_sets, (t.resolve_n + (size_t)n) * sizeof *l);
            if (!l) { tfail(&t, "нет памяти"); break; }
            t.resolve_sets = l;
            jstrlist(rs, l + t.resolve_n, (size_t)n);
            t.resolve_n += (size_t)n;
            continue;
        }
        if (!strcmp(act, "route-options")) {
            /* override_port — подмена порта у имён правила (podkop и forkop так ведут проверку
             * FakeIP: fakeip.podkop.fyi на 8443). Правило маршрута не выбирает: соединение у
             * sing-box идёт дальше по правилам. Имена route-options — проверочные, других правил
             * у них нет, и дальше они уходят в route.final — туда же их ведёт и правило steer.
             * Подмена — у списка (lists.*.override_port), по карте fake-IP, поэтому — только для
             * имён: domain и domain_suffix. */
            long op = jgeti(r, "override_port", 0);
            int names_only = (jget(r, "domain") || jget(r, "domain_suffix")) && !jget(r, "rule_set") &&
                             !jget(r, "ip_cidr") && !jget(r, "domain_keyword") && !jget(r, "domain_regex");
            int other = 0;
            for (size_t k = 0; k < jlen(r); k++) {
                const char *key = r->o[k].key;
                if (strcmp(key, "action") && strcmp(key, "override_port") && strcmp(key, "domain") &&
                    strcmp(key, "domain_suffix") && strcmp(key, "inbound") && strcmp(key, "network"))
                    other = 1;
            }
            if (op <= 0 || op > 65535 || !names_only || other) {
                tw(&t, "%s: route-options переводится только как override_port у domain и "
                   "domain_suffix — правило снято", where);
                continue;
            }
            const char *fin = jgets(jget(cfg, "route"), "final");
            const char *out = fin ? emit_output(&t, fin, 0) : ensure_direct(&t);
            if (!out) out = ensure_direct(&t);
            t.override_port = op;
            int rc = emit_rule(&t, i, r, out, fin ? fin : "direct", 0);
            t.override_port = 0;
            if (rc) break;
            continue;
        }
        if (!strcmp(act, "reject")) {
            const char *l[4];
            long n = jget(r, "protocol") ? jstrlist(jget(r, "protocol"), l, 4) : 0;
            if (n == 1 && !strcmp(l[0], "quic") && jlen(r) <= 3) {
                t.quic_reject = 1;
                tw(&t, "%s: отказ QUIC пока не переводится (нужен вид block)", where);
                continue;
            }
            tw(&t, "%s: reject пока не переводится (нужен вид block в steer)", where);
            continue;
        }
        const char *ob = NULL, *out = NULL;
        if (!strcmp(act, "bypass")) {
            ob = "direct";
            out = ensure_direct(&t);
        } else if (!strcmp(act, "route")) {
            ob = jgets(r, "outbound");
            out = ob ? emit_output(&t, ob, 0) : NULL;
            if (!out) continue;
        } else continue;
        if (emit_rule(&t, i, r, out, ob, 0)) break;
    }
    if (!t.failed) emit_dns(&t);
    /* Каналы из правил DNS (BOX_CONNECTOR.md, раздел 3в): списки держит резолвер steer, и имя,
     * которому правила DNS дают fake-IP или свой сервер, должно быть в его канале — иначе на
     * вопрос коннектора («не пересылать») dnsd ответит отказом. Такие правила идут ПОСЛЕ правил
     * маршрута: имя, у которого есть правило маршрута, берёт его канал (первое совпадение);
     * остальным — канал в direct: fake-IP с подменой на настоящий адрес (правило с fakeip-сервером)
     * или настоящий адрес через свой апстрим (секции DNS forkop). */
    const struct jval *drules = jget(jget(cfg, "dns"), "rules");
    for (size_t i = 0; i < jlen(drules) && !t.failed; i++) {
        const struct jval *r = jat(drules, i);
        const char *act = jgets(r, "action");
        if (act && strcmp(act, "route")) continue;
        const char *srv = jgets(r, "server");
        const struct jval *sv = srv ? sb_dns_server(cfg, srv) : NULL;
        if (!sv) continue;
        int has_dest = jget(r, "rule_set") || jget(r, "domain") || jget(r, "domain_suffix") ||
                       jget(r, "domain_keyword") || jget(r, "domain_regex");
        if (!has_dest || jget(r, "type")) continue;
        /* Условия, которые не про имя (inbound, query_type, source_ip_cidr), каналу не нужны:
         * их проверяет коннектор до вопроса к dnsd. Снимаем их с копии правила. */
        struct jval *rc = jdup(r);
        static const char *drop[] = { "inbound", "query_type", "action", "server", "rewrite_ttl",
                                      "disable_cache", "strategy", "client_subnet", "source_ip_cidr", "outbound", NULL };
        for (int k = 0; drop[k]; k++) jobj_del(rc, drop[k]);
        const char *type = jgets(sv, "type");
        const char *up = NULL;
        if (type && strcmp(type, "fakeip")) {
            up = names_find(&t.onames, srv);
            if (!up || !jget(jget(jget(t.spec, "dns"), "upstreams"), up)) { json_free(rc); continue; }
        }
        /* Наборы, у которых уже есть канал из правил маршрута, второй раз не нужны: имя возьмёт
         * первый канал, а копия держала бы тот же список в ядре дважды. */
        struct jval *rsv = jget(rc, "rule_set");
        if (rsv) {
            struct jval *left = jnew(J_ARR);
            long n = jstrlist(rsv, NULL, 0);
            const struct jval *rrules = jget(jget(cfg, "route"), "rules");
            for (long k = 0; k < n; k++) {
                const char *tg = rsv->t == J_ARR ? rsv->a[k]->s : rsv->s;
                int used = 0;
                for (size_t m = 0; m < jlen(rrules) && !used; m++) {
                    const struct jval *rr = jat(rrules, m);
                    const char *ra = jgets(rr, "action");
                    if ((ra && strcmp(ra, "route")) || !rule_for_lan(&t, rr)) continue;
                    const struct jval *x = jget(rr, "rule_set");
                    long xn = x ? jstrlist(x, NULL, 0) : 0;
                    for (long q = 0; q < xn; q++)
                        if (!strcmp(x->t == J_ARR ? x->a[q]->s : x->s, tg)) used = 1;
                }
                if (!used) jarr_push(left, jstr(tg));
            }
            if (left->len) jobj_set(rc, "rule_set", left);
            else { json_free(left); jobj_del(rc, "rule_set"); }
        }
        int dest_left = jget(rc, "rule_set") || jget(rc, "domain") || jget(rc, "domain_suffix") ||
                        jget(rc, "domain_keyword") || jget(rc, "domain_regex");
        const char *out = ensure_direct(&t);
        if (dest_left) emit_rule_ex(&t, i, rc, out, "direct", up != NULL, up, "dns.rules");
        json_free(rc);
    }
    if (!t.failed) {
        if (t.self_used) {
            struct jval *c = jnew(J_OBJ);
            jobj_set(c, "self", jbool(1));
            jobj_set(t.clients, "router", c);
        }
        if (t.clients->len) jobj_set(t.spec, "clients", t.clients);
        else json_free(t.clients), t.clients = NULL;
        if (t.lists->len) jobj_set(t.spec, "lists", t.lists);
        else json_free(t.lists), t.lists = NULL;
        if (!t.outputs->len) ensure_direct(&t);
        for (size_t i = 0; i < jlen(obs); i++) {
            const char *tg = jgets(jat(obs, i), "tag");
            if (!tg || jget(t.map_out, tg)) continue;
            struct jval *e = jnew(J_OBJ);
            jobj_set(e, "name", jstr(""));
            jobj_set(e, "type", jstr(clash_type(jgets(jat(obs, i), "type"))));
            jobj_set(e, "dormant", jbool(1));
            jobj_set(t.map_out, tg, e);
        }
        jobj_set(t.spec, "outputs", t.outputs);
        if (t.rules->len) jobj_set(t.spec, "rules", t.rules);
        else json_free(t.rules), t.rules = NULL;
        jobj_set(t.map, "outbounds", t.map_out);
        jobj_set(t.map, "rules", t.map_rules);
        jobj_del(t.map, "_paths");
        char path[1100];
        size_t n;
        char *s = json_to_str(t.spec, 2, &n);
        snprintf(path, sizeof path, "%s/spec.json", o->dir);
        if (!s || write_file(&t, path, s, n)) t.failed = 1;
        free(s);
        s = json_to_str(t.map, 2, &n);
        snprintf(path, sizeof path, "%s/box-map.json", o->dir);
        if (!t.failed && (!s || write_file(&t, path, s, n))) t.failed = 1;
        free(s);
    }
    names_free(&t.onames);
    names_free(&t.lnames);
    names_free(&t.cnames);
    free(t.resolve_sets);
    res->warnings = t.warnings;
    res->missing_sets = t.missing_sets;
    if (t.failed) {
        json_free(t.spec);
        json_free(t.map);
        if (!err[0]) snprintf(err, errn, "перевод не удался");
        return -1;
    }
    res->spec = t.spec;
    res->map = t.map;
    return 0;
}

void box_translate_free(struct tr_result *res) {
    json_free(res->spec);
    json_free(res->map);
    memset(res, 0, sizeof *res);
}

int cmd_box_translate(const struct box_opts *o, int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "FATAL[0000] box-translate <каталог>\n");
        return 1;
    }
    char err[512];
    struct jval *cfg = box_load_config(o, err, sizeof err);
    if (!cfg) { fprintf(stderr, "FATAL[0000] %s\n", err); return 1; }
    struct sbcheck ck;
    box_log_level(BL_WARN);
    if (sb_check(cfg, &ck)) { fprintf(stderr, "FATAL[0000] %s\n", ck.first); json_free(cfg); return 1; }
    char rsdir[1100];
    snprintf(rsdir, sizeof rsdir, "%s/rulesets", argv[0]);
    mkdir(argv[0], 0755);
    char absdir[4096];
    if (!realpath(argv[0], absdir)) { fprintf(stderr, "FATAL[0000] %s: %s\n", argv[0], strerror(errno)); json_free(cfg); return 1; }
    snprintf(rsdir, sizeof rsdir, "%s/rulesets", absdir);
    struct tr_opts to = { .dir = absdir, .ruleset_dir = rsdir };
    struct tr_result res;
    int rc = box_translate(cfg, &to, &res, err, sizeof err);
    json_free(cfg);
    if (rc) { fprintf(stderr, "FATAL[0000] %s\n", err); return 1; }
    json_write(stdout, res.spec, 2);
    putchar('\n');
    fprintf(stderr, "предупреждений: %u, наборов ещё не скачано: %u\n", res.warnings, res.missing_sets);
    box_translate_free(&res);
    return 0;
}

/* box-needs: какие пакеты steer нужны конфигу — JSON-массив имён (страница LuCI ставит их). */
int cmd_box_needs(const struct box_opts *o) {
    char err[512];
    struct jval *cfg = box_load_config(o, err, sizeof err);
    struct jval *need = jnew(J_ARR);
    jarr_push(need, jstr("steer-core"));
    const struct jval *obs = jget(cfg, "outbounds");
    int vless = 0, hy2 = 0, proxy = 0;
    for (size_t i = 0; i < jlen(obs); i++) {
        const char *t = jgets(jat(obs, i), "type");
        if (!t) continue;
        if (!strcmp(t, "vless")) vless = 1;
        else if (!strcmp(t, "hysteria2")) hy2 = 1;
        else if (!strcmp(t, "trojan") || !strcmp(t, "shadowsocks") || !strcmp(t, "socks") ||
                 !strcmp(t, "http") || !strcmp(t, "vmess")) proxy = 1;
    }
    if (vless) jarr_push(need, jstr("steer-vless"));
    if (hy2) jarr_push(need, jstr("steer-hysteria2"));
    if (proxy) jarr_push(need, jstr("steer-proxy"));
    json_write(stdout, need, -1);
    putchar('\n');
    json_free(need);
    json_free(cfg);
    return 0;
}
