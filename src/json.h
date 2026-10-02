/* JSON коннектора: дерево документа, разбор и запись.
 *
 * ЗАЧЕМ СВОЙ, А НЕ ynode steer. Конфиг sing-box и его наборы правил — JSON, который коннектор
 * не только читает, но и пишет: `format`, `merge`, `rule-set decompile`, ответы Clash API. Для
 * записи нужно знать, что число было целым (`1602`, а не `1602.0`), и сохранить порядок ключей —
 * дерево libyaml ни того, ни другого не держит. Потолков узлов и байт здесь нет: набор правил с
 * сотней тысяч доменов законен, и пределом служит память (отказ называет её).
 *
 * ЧТО ПРИНИМАЕТСЯ. RFC 8259 плюс то, что принимает sing-box: комментарии в стиле C и C++ и запятая
 * перед закрывающей скобкой. Ключ, повторённый в объекте, — отказ: sing-box читает его последним
 * значением, а мы не угадываем, какое из двух человек имел в виду.
 *
 * ПАМЯТЬ. Узлы и строки выделяются по одному; json_free освобождает дерево целиком. */
#ifndef BOX_JSON_H
#define BOX_JSON_H
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum jtype { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ };

struct jval;

struct jmember {
    char *key;
    struct jval *val;
};

struct jval {
    enum jtype t;
    unsigned line, col;        /* где начинается значение — для сообщений check */
    int b;                     /* J_BOOL */
    int is_int;                /* J_NUM: записано целым, без точки и экспоненты */
    int64_t i;                 /* J_NUM при is_int */
    double d;                  /* J_NUM всегда */
    char *s;                   /* J_STR: строка UTF-8 с нулём на конце */
    size_t len;                /* J_STR: длина; J_ARR/J_OBJ: число элементов */
    size_t cap;
    struct jval **a;           /* J_ARR */
    struct jmember *o;         /* J_OBJ, в порядке записи */
};

/* Разбор. NULL — отказ, текст «строка:столбец: что» в err (до errn байт). */
struct jval *json_parse(const char *text, size_t n, char *err, size_t errn);
struct jval *json_parse_file(const char *path, char *err, size_t errn);
void json_free(struct jval *v);

/* Построение. Возвращают NULL только при нехватке памяти. */
struct jval *jnew(enum jtype t);
struct jval *jstr(const char *s);
struct jval *jstrn(const char *s, size_t n);
struct jval *jint(int64_t i);
struct jval *jnum(double d);
struct jval *jbool(int b);
struct jval *jnull(void);
int jarr_push(struct jval *arr, struct jval *v);              /* 0 — принято */
int jobj_set(struct jval *obj, const char *key, struct jval *v); /* заменяет прежнее значение */
int jobj_del(struct jval *obj, const char *key);               /* 1 — был и удалён */
struct jval *jdup(const struct jval *v);

/* Доступ. Все терпят NULL на входе. */
struct jval *jget(const struct jval *obj, const char *key);
const char *jgets(const struct jval *obj, const char *key);    /* строка или NULL */
int jgetb(const struct jval *obj, const char *key, int def);
int64_t jgeti(const struct jval *obj, const char *key, int64_t def);
size_t jlen(const struct jval *v);                              /* массив/объект; иначе 0 */
struct jval *jat(const struct jval *arr, size_t i);

/* «Строка или массив строк» — как sing-box пишет Listable[string] (`rule_set`, `domain`,
 * `inbound`, `source_ip_cidr` в конфигах podkop и forkop бывают и тем, и другим). Возвращает
 * число строк; out[i] — указатели в дерево. out может быть NULL — тогда только число. Элемент
 * массива не строка — -1. */
long jstrlist(const struct jval *v, const char **out, size_t max);

/* Запись. indent < 0 — в одну строку; иначе отступ в столько пробелов. Без завершающего
 * перевода строки. */
int json_write(FILE *f, const struct jval *v, int indent);
/* То же в выделенную строку (освобождает вызывающий). */
char *json_to_str(const struct jval *v, int indent, size_t *outn);
/* Строку JSON-литералом — для тех, кто пишет JSON руками (Clash API). */
void json_write_str(FILE *f, const char *s);

/* Слияние b в a по правилам `sing-box merge`: объекты сливаются по ключам вглубь, массивы
 * дописываются, остальное заменяется. a меняется на месте, b не трогается. */
int json_merge(struct jval *a, const struct jval *b);

#endif
