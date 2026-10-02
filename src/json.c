#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <math.h>

/* ---- построение ------------------------------------------------------------------------- */

struct jval *jnew(enum jtype t) {
    struct jval *v = calloc(1, sizeof *v);
    if (v) v->t = t;
    return v;
}

struct jval *jstrn(const char *s, size_t n) {
    struct jval *v = jnew(J_STR);
    if (!v) return NULL;
    v->s = malloc(n + 1);
    if (!v->s) { free(v); return NULL; }
    memcpy(v->s, s, n);
    v->s[n] = 0;
    v->len = n;
    return v;
}

struct jval *jstr(const char *s) { return jstrn(s ? s : "", s ? strlen(s) : 0); }

struct jval *jint(int64_t i) {
    struct jval *v = jnew(J_NUM);
    if (v) { v->is_int = 1; v->i = i; v->d = (double)i; }
    return v;
}

struct jval *jnum(double d) {
    struct jval *v = jnew(J_NUM);
    if (!v) return NULL;
    v->d = d;
    /* Целое значение пишется целым: Clash API отдаёт задержки и байты числами без точки. */
    if (d == floor(d) && fabs(d) < 9.0e15) { v->is_int = 1; v->i = (int64_t)d; }
    return v;
}

struct jval *jbool(int b) {
    struct jval *v = jnew(J_BOOL);
    if (v) v->b = !!b;
    return v;
}

struct jval *jnull(void) { return jnew(J_NULL); }

static int grow(struct jval *v, size_t elem) {
    if (v->len < v->cap) return 0;
    size_t nc = v->cap ? v->cap * 2 : 4;
    void *p = realloc(v->t == J_ARR ? (void *)v->a : (void *)v->o, nc * elem);
    if (!p) return -1;
    if (v->t == J_ARR) v->a = p; else v->o = p;
    v->cap = nc;
    return 0;
}

int jarr_push(struct jval *arr, struct jval *v) {
    if (!arr || arr->t != J_ARR || !v) return -1;
    if (grow(arr, sizeof *arr->a)) return -1;
    arr->a[arr->len++] = v;
    return 0;
}

int jobj_set(struct jval *obj, const char *key, struct jval *v) {
    if (!obj || obj->t != J_OBJ || !v) return -1;
    for (size_t i = 0; i < obj->len; i++)
        if (!strcmp(obj->o[i].key, key)) {
            json_free(obj->o[i].val);
            obj->o[i].val = v;
            return 0;
        }
    if (grow(obj, sizeof *obj->o)) return -1;
    char *k = strdup(key);
    if (!k) return -1;
    obj->o[obj->len].key = k;
    obj->o[obj->len].val = v;
    obj->len++;
    return 0;
}

int jobj_del(struct jval *obj, const char *key) {
    if (!obj || obj->t != J_OBJ) return 0;
    for (size_t i = 0; i < obj->len; i++)
        if (!strcmp(obj->o[i].key, key)) {
            free(obj->o[i].key);
            json_free(obj->o[i].val);
            memmove(&obj->o[i], &obj->o[i + 1], (obj->len - i - 1) * sizeof *obj->o);
            obj->len--;
            return 1;
        }
    return 0;
}

void json_free(struct jval *v) {
    if (!v) return;
    switch (v->t) {
    case J_STR: free(v->s); break;
    case J_ARR:
        for (size_t i = 0; i < v->len; i++) json_free(v->a[i]);
        free(v->a);
        break;
    case J_OBJ:
        for (size_t i = 0; i < v->len; i++) { free(v->o[i].key); json_free(v->o[i].val); }
        free(v->o);
        break;
    default: break;
    }
    free(v);
}

struct jval *jdup(const struct jval *v) {
    if (!v) return NULL;
    struct jval *c;
    switch (v->t) {
    case J_STR: c = jstrn(v->s, v->len); break;
    case J_ARR:
        c = jnew(J_ARR);
        for (size_t i = 0; c && i < v->len; i++)
            if (jarr_push(c, jdup(v->a[i]))) { json_free(c); return NULL; }
        break;
    case J_OBJ:
        c = jnew(J_OBJ);
        for (size_t i = 0; c && i < v->len; i++)
            if (jobj_set(c, v->o[i].key, jdup(v->o[i].val))) { json_free(c); return NULL; }
        break;
    default:
        c = jnew(v->t);
        if (c) { c->b = v->b; c->is_int = v->is_int; c->i = v->i; c->d = v->d; }
    }
    if (c) { c->line = v->line; c->col = v->col; }
    return c;
}

/* ---- доступ ----------------------------------------------------------------------------- */

struct jval *jget(const struct jval *obj, const char *key) {
    if (!obj || obj->t != J_OBJ) return NULL;
    for (size_t i = 0; i < obj->len; i++)
        if (!strcmp(obj->o[i].key, key)) return obj->o[i].val;
    return NULL;
}

const char *jgets(const struct jval *obj, const char *key) {
    struct jval *v = jget(obj, key);
    return v && v->t == J_STR ? v->s : NULL;
}

int jgetb(const struct jval *obj, const char *key, int def) {
    struct jval *v = jget(obj, key);
    return v && v->t == J_BOOL ? v->b : def;
}

int64_t jgeti(const struct jval *obj, const char *key, int64_t def) {
    struct jval *v = jget(obj, key);
    if (!v || v->t != J_NUM) return def;
    return v->is_int ? v->i : (int64_t)v->d;
}

size_t jlen(const struct jval *v) {
    return v && (v->t == J_ARR || v->t == J_OBJ) ? v->len : 0;
}

struct jval *jat(const struct jval *arr, size_t i) {
    return arr && arr->t == J_ARR && i < arr->len ? arr->a[i] : NULL;
}

long jstrlist(const struct jval *v, const char **out, size_t max) {
    if (!v || v->t == J_NULL) return 0;
    if (v->t == J_STR) {
        if (out && max) out[0] = v->s;
        return 1;
    }
    if (v->t != J_ARR) return -1;
    for (size_t i = 0; i < v->len; i++) {
        if (v->a[i]->t != J_STR) return -1;
        if (out && i < max) out[i] = v->a[i]->s;
    }
    return (long)v->len;
}

/* ---- разбор ----------------------------------------------------------------------------- */

struct parser {
    const char *p, *end, *line_start;
    unsigned line;
    char *err;
    size_t errn;
    int failed;
    unsigned depth;
};

/* Глубина — не потолок ради потолка: разбор рекурсивный, и документ из миллиона «[» уронил бы
 * процесс переполнением стека, то есть sing-box check падал бы вместо ответа. 512 — на порядки
 * глубже любого настоящего конфига (там 6–7 уровней), и стек на это есть всегда. */
#define JSON_MAX_DEPTH 512

static void fail(struct parser *ps, const char *fmt, ...) {
    if (ps->failed) return;
    ps->failed = 1;
    if (!ps->err || !ps->errn) return;
    int k = snprintf(ps->err, ps->errn, "%u:%u: ", ps->line,
                     (unsigned)(ps->p - ps->line_start) + 1);
    if (k < 0 || (size_t)k >= ps->errn) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ps->err + k, ps->errn - k, fmt, ap);
    va_end(ap);
}

static void skip_ws(struct parser *ps) {
    while (ps->p < ps->end) {
        char c = *ps->p;
        if (c == '\n') { ps->p++; ps->line++; ps->line_start = ps->p; continue; }
        if (c == ' ' || c == '\t' || c == '\r') { ps->p++; continue; }
        if (c == '/' && ps->p + 1 < ps->end && ps->p[1] == '/') {
            while (ps->p < ps->end && *ps->p != '\n') ps->p++;
            continue;
        }
        if (c == '/' && ps->p + 1 < ps->end && ps->p[1] == '*') {
            ps->p += 2;
            while (ps->p + 1 < ps->end && !(ps->p[0] == '*' && ps->p[1] == '/')) {
                if (*ps->p == '\n') { ps->line++; ps->line_start = ps->p + 1; }
                ps->p++;
            }
            if (ps->p + 1 >= ps->end) { fail(ps, "незакрытый комментарий"); return; }
            ps->p += 2;
            continue;
        }
        break;
    }
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= c - '0';
        else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    *out = v;
    return 0;
}

static size_t utf8_put(char *o, unsigned cp) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | cp >> 6); o[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | cp >> 12); o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    o[0] = (char)(0xF0 | cp >> 18); o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    o[2] = (char)(0x80 | ((cp >> 6) & 0x3F)); o[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* Строка после открывающей кавычки. Возвращает выделенную строку и её длину. */
static char *parse_string(struct parser *ps, size_t *outn) {
    const char *s = ps->p;
    /* Длина раскодированной строки не больше закодированной: \uXXXX (6 байт) даёт не больше 4,
     * пара суррогатов (12) — 4. Поэтому буфер — длина до закрывающей кавычки. */
    const char *q = s;
    while (q < ps->end && *q != '"') {
        if (*q == '\\') q++;
        q++;
    }
    if (q >= ps->end) { fail(ps, "незакрытая строка"); return NULL; }
    char *buf = malloc((size_t)(q - s) + 1);
    if (!buf) { fail(ps, "нет памяти"); return NULL; }
    size_t n = 0;
    while (ps->p < q) {
        unsigned char c = (unsigned char)*ps->p;
        if (c < 0x20) { fail(ps, "управляющий символ в строке"); free(buf); return NULL; }
        if (c != '\\') { buf[n++] = (char)c; ps->p++; continue; }
        ps->p++;
        char e = *ps->p++;
        switch (e) {
        case '"': buf[n++] = '"'; break;
        case '\\': buf[n++] = '\\'; break;
        case '/': buf[n++] = '/'; break;
        case 'b': buf[n++] = '\b'; break;
        case 'f': buf[n++] = '\f'; break;
        case 'n': buf[n++] = '\n'; break;
        case 'r': buf[n++] = '\r'; break;
        case 't': buf[n++] = '\t'; break;
        case 'u': {
            unsigned cp;
            if (q - ps->p < 4 || hex4(ps->p, &cp)) { fail(ps, "неверное \\u"); free(buf); return NULL; }
            ps->p += 4;
            if (cp >= 0xD800 && cp < 0xDC00) {
                unsigned lo;
                if (q - ps->p >= 6 && ps->p[0] == '\\' && ps->p[1] == 'u' && !hex4(ps->p + 2, &lo) &&
                    lo >= 0xDC00 && lo < 0xE000) {
                    ps->p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else cp = 0xFFFD;
            } else if (cp >= 0xDC00 && cp < 0xE000) cp = 0xFFFD;
            if (cp == 0) { fail(ps, "нулевой символ в строке"); free(buf); return NULL; }
            n += utf8_put(buf + n, cp);
            break;
        }
        default: fail(ps, "неизвестная последовательность \\%c", e); free(buf); return NULL;
        }
    }
    ps->p = q + 1;
    buf[n] = 0;
    *outn = n;
    return buf;
}

static struct jval *parse_value(struct parser *ps);

static struct jval *parse_number(struct parser *ps) {
    const char *s = ps->p;
    int is_int = 1;
    if (ps->p < ps->end && *ps->p == '-') ps->p++;
    if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { fail(ps, "неверное число"); return NULL; }
    if (*ps->p == '0') ps->p++;
    else while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    if (ps->p < ps->end && *ps->p == '.') {
        is_int = 0;
        ps->p++;
        if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { fail(ps, "неверное число"); return NULL; }
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    if (ps->p < ps->end && (*ps->p == 'e' || *ps->p == 'E')) {
        is_int = 0;
        ps->p++;
        if (ps->p < ps->end && (*ps->p == '+' || *ps->p == '-')) ps->p++;
        if (ps->p >= ps->end || !(*ps->p >= '0' && *ps->p <= '9')) { fail(ps, "неверное число"); return NULL; }
        while (ps->p < ps->end && *ps->p >= '0' && *ps->p <= '9') ps->p++;
    }
    char tmp[64];
    size_t n = (size_t)(ps->p - s);
    if (n >= sizeof tmp) { fail(ps, "слишком длинное число"); return NULL; }
    memcpy(tmp, s, n);
    tmp[n] = 0;
    struct jval *v = jnew(J_NUM);
    if (!v) { fail(ps, "нет памяти"); return NULL; }
    v->d = strtod(tmp, NULL);
    if (is_int) {
        errno = 0;
        long long ll = strtoll(tmp, NULL, 10);
        if (errno == 0) { v->is_int = 1; v->i = ll; }
    }
    return v;
}

static int lit(struct parser *ps, const char *w) {
    size_t n = strlen(w);
    if ((size_t)(ps->end - ps->p) < n || memcmp(ps->p, w, n)) return 0;
    ps->p += n;
    return 1;
}

static struct jval *parse_value(struct parser *ps) {
    skip_ws(ps);
    if (ps->failed) return NULL;
    if (ps->p >= ps->end) { fail(ps, "неожиданный конец"); return NULL; }
    unsigned line = ps->line, col = (unsigned)(ps->p - ps->line_start) + 1;
    struct jval *v = NULL;
    char c = *ps->p;
    if (c == '{' || c == '[') {
        if (++ps->depth > JSON_MAX_DEPTH) { fail(ps, "вложенность глубже %d", JSON_MAX_DEPTH); return NULL; }
    }
    if (c == '{') {
        ps->p++;
        v = jnew(J_OBJ);
        if (!v) { fail(ps, "нет памяти"); return NULL; }
        for (;;) {
            skip_ws(ps);
            if (ps->failed) break;
            if (ps->p < ps->end && *ps->p == '}') { ps->p++; break; }
            if (ps->p >= ps->end || *ps->p != '"') { fail(ps, "ожидался ключ в кавычках"); break; }
            ps->p++;
            size_t kn;
            char *k = parse_string(ps, &kn);
            if (!k) break;
            if (jget(v, k)) { fail(ps, "ключ \"%s\" повторяется", k); free(k); break; }
            skip_ws(ps);
            if (ps->p >= ps->end || *ps->p != ':') { fail(ps, "ожидалось «:» после ключа"); free(k); break; }
            ps->p++;
            struct jval *m = parse_value(ps);
            if (!m) { free(k); break; }
            if (grow(v, sizeof *v->o)) { fail(ps, "нет памяти"); free(k); json_free(m); break; }
            v->o[v->len].key = k;
            v->o[v->len].val = m;
            v->len++;
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == '}') { ps->p++; break; }
            fail(ps, "ожидалось «,» или «}»");
            break;
        }
        ps->depth--;
    } else if (c == '[') {
        ps->p++;
        v = jnew(J_ARR);
        if (!v) { fail(ps, "нет памяти"); return NULL; }
        for (;;) {
            skip_ws(ps);
            if (ps->failed) break;
            if (ps->p < ps->end && *ps->p == ']') { ps->p++; break; }
            struct jval *m = parse_value(ps);
            if (!m) break;
            if (jarr_push(v, m)) { fail(ps, "нет памяти"); json_free(m); break; }
            skip_ws(ps);
            if (ps->p < ps->end && *ps->p == ',') { ps->p++; continue; }
            if (ps->p < ps->end && *ps->p == ']') { ps->p++; break; }
            fail(ps, "ожидалось «,» или «]»");
            break;
        }
        ps->depth--;
    } else if (c == '"') {
        ps->p++;
        size_t n;
        char *s = parse_string(ps, &n);
        if (!s) return NULL;
        v = jnew(J_STR);
        if (!v) { free(s); fail(ps, "нет памяти"); return NULL; }
        v->s = s;
        v->len = n;
    } else if (c == '-' || (c >= '0' && c <= '9')) {
        v = parse_number(ps);
    } else if (lit(ps, "true")) {
        v = jbool(1);
    } else if (lit(ps, "false")) {
        v = jbool(0);
    } else if (lit(ps, "null")) {
        v = jnull();
    } else {
        fail(ps, "неожиданный символ «%c»", c);
        return NULL;
    }
    if (ps->failed) { json_free(v); return NULL; }
    if (v) { v->line = line; v->col = col; }
    return v;
}

struct jval *json_parse(const char *text, size_t n, char *err, size_t errn) {
    struct parser ps = { .p = text, .end = text + n, .line_start = text, .line = 1,
                         .err = err, .errn = errn };
    if (err && errn) err[0] = 0;
    /* BOM UTF-8 — как у Go encoding/json он не принимается, но редакторы его пишут. */
    if (n >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB &&
        (unsigned char)text[2] == 0xBF)
        ps.p += 3, ps.line_start += 3;
    struct jval *v = parse_value(&ps);
    if (!v) return NULL;
    skip_ws(&ps);
    if (!ps.failed && ps.p < ps.end) fail(&ps, "лишнее после конца документа");
    if (ps.failed) { json_free(v); return NULL; }
    return v;
}

struct jval *json_parse_file(const char *path, char *err, size_t errn) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errn, "%s: %s", path, strerror(errno));
        return NULL;
    }
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap);
    for (;;) {
        if (!buf) { fclose(f); snprintf(err, errn, "%s: нет памяти", path); return NULL; }
        size_t r = fread(buf + n, 1, cap - n, f);
        n += r;
        if (n < cap) break;
        cap *= 2;
        char *nb = realloc(buf, cap);
        if (!nb) { free(buf); buf = NULL; continue; }
        buf = nb;
    }
    int rerr = ferror(f);
    fclose(f);
    if (rerr) { free(buf); snprintf(err, errn, "%s: ошибка чтения", path); return NULL; }
    char e2[256];
    struct jval *v = json_parse(buf, n, e2, sizeof e2);
    free(buf);
    if (!v) snprintf(err, errn, "%s:%s", path, e2);
    return v;
}

/* ---- запись ----------------------------------------------------------------------------- */

void json_write_str(FILE *f, const char *s) {
    static const char hx[] = "0123456789abcdef";
    putc('"', f);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        case '\b': fputs("\\b", f); break;
        case '\f': fputs("\\f", f); break;
        default:
            if (c < 0x20) { fputs("\\u00", f); putc(hx[c >> 4], f); putc(hx[c & 15], f); }
            else putc(c, f);
        }
    }
    putc('"', f);
}

static void wr_indent(FILE *f, int indent, int level) {
    putc('\n', f);
    for (int i = 0; i < indent * level; i++) putc(' ', f);
}

static void wr(FILE *f, const struct jval *v, int indent, int level) {
    switch (v->t) {
    case J_NULL: fputs("null", f); break;
    case J_BOOL: fputs(v->b ? "true" : "false", f); break;
    case J_NUM:
        if (v->is_int) fprintf(f, "%lld", (long long)v->i);
        else if (isfinite(v->d)) fprintf(f, "%.17g", v->d);
        else fputs("null", f);
        break;
    case J_STR: json_write_str(f, v->s); break;
    case J_ARR:
        if (!v->len) { fputs("[]", f); break; }
        putc('[', f);
        for (size_t i = 0; i < v->len; i++) {
            if (i) putc(',', f);
            if (indent >= 0) wr_indent(f, indent, level + 1);
            wr(f, v->a[i], indent, level + 1);
        }
        if (indent >= 0) wr_indent(f, indent, level);
        putc(']', f);
        break;
    case J_OBJ:
        if (!v->len) { fputs("{}", f); break; }
        putc('{', f);
        for (size_t i = 0; i < v->len; i++) {
            if (i) putc(',', f);
            if (indent >= 0) wr_indent(f, indent, level + 1);
            json_write_str(f, v->o[i].key);
            fputs(indent >= 0 ? ": " : ":", f);
            wr(f, v->o[i].val, indent, level + 1);
        }
        if (indent >= 0) wr_indent(f, indent, level);
        putc('}', f);
        break;
    }
}

int json_write(FILE *f, const struct jval *v, int indent) {
    if (!v) return -1;
    wr(f, v, indent, 0);
    return ferror(f) ? -1 : 0;
}

char *json_to_str(const struct jval *v, int indent, size_t *outn) {
    char *buf = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return NULL;
    json_write(f, v, indent);
    if (fclose(f)) { free(buf); return NULL; }
    if (outn) *outn = n;
    return buf;
}

/* ---- слияние ---------------------------------------------------------------------------- */

int json_merge(struct jval *a, const struct jval *b) {
    if (!a || !b) return -1;
    if (a->t == J_OBJ && b->t == J_OBJ) {
        for (size_t i = 0; i < b->len; i++) {
            struct jval *cur = jget(a, b->o[i].key);
            if (cur && (cur->t == J_OBJ || cur->t == J_ARR) && cur->t == b->o[i].val->t) {
                if (json_merge(cur, b->o[i].val)) return -1;
            } else if (jobj_set(a, b->o[i].key, jdup(b->o[i].val))) return -1;
        }
        return 0;
    }
    if (a->t == J_ARR && b->t == J_ARR) {
        for (size_t i = 0; i < b->len; i++)
            if (jarr_push(a, jdup(b->a[i]))) return -1;
        return 0;
    }
    return -1;
}
