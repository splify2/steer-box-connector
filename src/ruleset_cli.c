/* sing-box rule-set decompile|format|match.
 *
 * decompile — набор .srs в исходник JSON. Зовут его podkop (`rulesets.sh`: потом
 * `jq '.rules[].ip_cidr[]'`, поэтому массивы всегда) и forkop (`components/updates.uc`: ip_cidr,
 * port, port_range, логические правила). Читатель — тот же, что у steer (src/model/srs.c):
 * набор он отдаёт клаузами (одно назначение — имена или подсети, сужение, клиенты, исключения), и
 * правило JSON собирается из клаузы. Правило sing-box с именами И подсетями даёт две клаузы — и
 * в выводе два правила; это то же множество, что у sing-box (правила набора — «или»).
 *
 * compile (JSON → srs) коннектору не нужен: свои наборы JSON он переводит в списки steer сам
 * (translate.c), а podkop и forkop compile не зовут. Команда отвечает словами, а не молчит. */
#define _GNU_SOURCE
#include "box.h"
#include "json.h"
#include "srs.h"
#include "err.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct dc {
    struct jval **dom[5];        /* по видам srs_dom: массивы строк на клаузу */
    struct jval **cidr, **xdom, **xcidr;
    size_t n;
};

static int walk_cb(void *ctx, const struct srs_elem *el) {
    struct dc *d = ctx;
    if (el->clause >= d->n) return 0;
    if (el->kind == SRS_EL_DOMAIN) {
        struct jval **slot = el->excl ? &d->xdom[el->clause] : &d->dom[el->dom][el->clause];
        if (!*slot) *slot = jnew(J_ARR);
        char buf[1100];
        const char *s = el->str;
        if (el->dom == SRS_DOM_WILDCARD) {
            /* «*.x.com» у steer — буквальный суффикс «.x.com», у sing-box это domain_suffix с точкой. */
            snprintf(buf, sizeof buf, "%s", s[0] == '*' ? s + 1 : s);
            s = buf;
        }
        jarr_push(*slot, jstrn(s, strlen(s)));
    } else {
        struct jval **slot = el->excl ? &d->xcidr[el->clause] : &d->cidr[el->clause];
        if (!*slot) *slot = jnew(J_ARR);
        char ip[64], buf[80];
        inet_ntop(el->family == 4 ? AF_INET : AF_INET6, el->addr, ip, sizeof ip);
        snprintf(buf, sizeof buf, "%s/%d", ip, el->plen);
        jarr_push(*slot, jstr(buf));
    }
    return 0;
}

static int decompile(const char *in, const char *out) {
    struct err e = { "" };
    const struct srs_set *s = NULL;
    if (srs_open(in, &s, &e)) {
        fprintf(stderr, "FATAL[0000] %s: %s\n", in, e.msg[0] ? e.msg : "не набор sing-box");
        return 1;
    }
    struct dc d = { 0 };
    d.n = srs_clause_n(s);
    for (int k = 0; k < 5; k++) d.dom[k] = calloc(d.n + 1, sizeof *d.dom[k]);
    d.cidr = calloc(d.n + 1, sizeof *d.cidr);
    d.xdom = calloc(d.n + 1, sizeof *d.xdom);
    d.xcidr = calloc(d.n + 1, sizeof *d.xcidr);
    if (srs_walk(s, SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, walk_cb, &d, &e)) {
        fprintf(stderr, "FATAL[0000] %s: %s\n", in, e.msg);
        srs_release(s);
        return 1;
    }
    struct jval *rules = jnew(J_ARR);
    static const char *dkey[5] = { "domain", "domain_suffix", "domain_suffix", "domain_keyword", "domain_regex" };
    for (size_t i = 0; i < d.n; i++) {
        const struct srs_clause *c = srs_clause(s, i);
        struct jval *r = jnew(J_OBJ);
        for (int k = 0; k < 5; k++) {
            if (!d.dom[k][i]) continue;
            struct jval *have = jget(r, dkey[k]);
            if (have) {
                for (size_t m = 0; m < d.dom[k][i]->len; m++) jarr_push(have, jdup(d.dom[k][i]->a[m]));
                json_free(d.dom[k][i]);
            } else jobj_set(r, dkey[k], d.dom[k][i]);
        }
        if (d.cidr[i]) jobj_set(r, "ip_cidr", d.cidr[i]);
        if (c->l4.proto == CH_PROTO_TCP) jobj_set(r, "network", jstr("tcp"));
        else if (c->l4.proto == CH_PROTO_UDP) jobj_set(r, "network", jstr("udp"));
        if (c->l4.ports_n) {
            struct jval *port = jnew(J_ARR), *range = jnew(J_ARR);
            for (size_t p = 0; p < c->l4.ports_n; p++) {
                if (c->l4.ports[p].lo == c->l4.ports[p].hi) jarr_push(port, jint(c->l4.ports[p].lo));
                else {
                    char b[32];
                    snprintf(b, sizeof b, "%u:%u", c->l4.ports[p].lo, c->l4.ports[p].hi);
                    jarr_push(range, jstr(b));
                }
            }
            if (port->len) jobj_set(r, "port", port); else json_free(port);
            if (range->len) jobj_set(r, "port_range", range); else json_free(range);
        }
        if (c->src_n) {
            struct jval *src = jnew(J_ARR);
            for (size_t k = 0; k < c->src_n; k++) {
                struct in_addr a = { htonl(c->src[k].net) };
                char ip[32], b[48];
                inet_ntop(AF_INET, &a, ip, sizeof ip);
                snprintf(b, sizeof b, "%s/%d", ip, c->src[k].plen);
                jarr_push(src, jstr(b));
            }
            jobj_set(r, "source_ip_cidr", src);
        }
        if (d.xdom[i] || d.xcidr[i]) {
            /* Исключения клаузы — «и не эти»: логическое and с invert, как у sing-box. */
            struct jval *lg = jnew(J_OBJ), *sub = jnew(J_ARR), *x = jnew(J_OBJ);
            jobj_set(lg, "type", jstr("logical"));
            jobj_set(lg, "mode", jstr("and"));
            jarr_push(sub, r);
            if (d.xdom[i]) jobj_set(x, "domain_suffix", d.xdom[i]);
            if (d.xcidr[i]) jobj_set(x, "ip_cidr", d.xcidr[i]);
            jobj_set(x, "invert", jbool(1));
            jarr_push(sub, x);
            jobj_set(lg, "rules", sub);
            r = lg;
        }
        if (jlen(r)) jarr_push(rules, r);
        else json_free(r);
    }
    for (int k = 0; k < 5; k++) free(d.dom[k]);
    free(d.cidr);
    free(d.xdom);
    free(d.xcidr);
    if (srs_skipped(s)) fprintf(stderr, "WARN[0000] %s: %s\n", in, srs_skipped(s));
    srs_release(s);
    struct jval *root = jnew(J_OBJ);
    jobj_set(root, "version", jint(3));
    jobj_set(root, "rules", rules);
    FILE *f = out ? fopen(out, "w") : stdout;
    if (!f) { fprintf(stderr, "FATAL[0000] %s: не открывается\n", out); json_free(root); return 1; }
    json_write(f, root, 2);
    fputc('\n', f);
    if (f != stdout && fclose(f)) { json_free(root); return 1; }
    json_free(root);
    return 0;
}

int cmd_ruleset(const struct box_opts *o, int argc, char **argv) {
    (void)o;
    if (argc < 1) {
        puts("Usage:\n  sing-box rule-set [command]\n\nAvailable Commands:\n"
             "  decompile   Decompile rule-set binary to json\n  format      Format rule-set json");
        return 0;
    }
    const char *in = NULL, *out = NULL;
    int write_back = 0;
    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--output")) && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--write")) write_back = 1;
        else if (!in) in = argv[i];
    }
    if (!strcmp(argv[0], "decompile")) {
        if (!in) { fprintf(stderr, "Error: accepts 1 arg(s), received 0\n"); return 1; }
        if (!out) {
            /* sing-box без -o пишет рядом: x.srs → x.json. */
            static char def[1100];
            size_t l = strlen(in);
            snprintf(def, sizeof def, "%.*s.json", (int)(l > 4 && !strcmp(in + l - 4, ".srs") ? l - 4 : l), in);
            out = def;
        }
        return decompile(in, out);
    }
    if (!strcmp(argv[0], "format")) {
        if (!in) { fprintf(stderr, "Error: accepts 1 arg(s), received 0\n"); return 1; }
        char err[512];
        struct jval *v = json_parse_file(in, err, sizeof err);
        if (!v) { fprintf(stderr, "FATAL[0000] %s\n", err); return 1; }
        FILE *f = write_back ? fopen(in, "w") : stdout;
        if (!f) { json_free(v); return 1; }
        json_write(f, v, 2);
        fputc('\n', f);
        if (f != stdout) fclose(f);
        json_free(v);
        return 0;
    }
    if (!strcmp(argv[0], "compile")) {
        fprintf(stderr, "FATAL[0000] rule-set compile коннектор не делает: наборы JSON он читает сам, "
                        "их не нужно собирать в .srs\n");
        return 1;
    }
    fprintf(stderr, "Error: unknown command \"%s\" for \"sing-box rule-set\"\n", argv[0]);
    return 1;
}
