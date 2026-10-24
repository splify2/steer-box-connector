/* Перевод (translate.c): отчёт «что не переводится». Каждое предупреждение — запись
 * {where, why, instead, todo} с непустыми полями; отчёт пишется файлом (report_path) и печатается
 * человеку; конфиг без непереводимого даёт «Всё переведено». */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

static const char BAD[] =
    "{\"outbounds\":["
    " {\"type\":\"vless\",\"tag\":\"v\",\"server\":\"10.0.0.1\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\"},"
    " {\"type\":\"tor\",\"tag\":\"tor-out\"},"
    " {\"type\":\"direct\",\"tag\":\"direct-out\"}],"
    " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"d1\",\"server\":\"dns.example\"}]},"
    " \"route\":{\"rules\":["
    "  {\"domain\":[\"a.example\"],\"outbound\":\"tor-out\"},"
    "  {\"domain\":[\"b.example\"],\"network\":\"icmp\",\"outbound\":\"v\"},"
    "  {\"domain\":[\"c.example\"],\"action\":\"reject\"}],"
    "  \"final\":\"direct-out\"}}";

static const char GOOD[] =
    "{\"outbounds\":["
    " {\"type\":\"vless\",\"tag\":\"v\",\"server\":\"10.0.0.1\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\"},"
    " {\"type\":\"direct\",\"tag\":\"direct-out\"}],"
    " \"route\":{\"rules\":[{\"domain\":[\"a.example\"],\"outbound\":\"v\"}],"
    "  \"final\":\"direct-out\"}}";

static int has_where(const struct jval *items, const char *w) {
    for (size_t i = 0; i < jlen(items); i++) {
        const char *x = jgets(jat(items, i), "where");
        if (x && !strcmp(x, w)) return 1;
    }
    return 0;
}

int main(void) {
    char dir[] = "/tmp/t_translate_report.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char rpath[300], err[300];
    snprintf(rpath, sizeof rpath, "%s/report.json", dir);
    struct tr_opts o = { .dir = dir, .ruleset_dir = dir, .report_path = rpath };
    struct tr_result res;

    struct jval *cfg = json_parse(BAD, strlen(BAD), err, sizeof err);
    CHECK(cfg != NULL);
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    CHECK(res.warnings >= 3);
    CHECK(res.report != NULL && res.report->len == res.warnings);
    for (size_t i = 0; res.report && i < res.report->len; i++) {
        const struct jval *e = res.report->a[i];
        CHECK(jgets(e, "where") && *jgets(e, "where"));
        CHECK(jgets(e, "why") && *jgets(e, "why"));
        CHECK(jgets(e, "instead") && *jgets(e, "instead"));
        CHECK(jgets(e, "todo") && *jgets(e, "todo"));
        if (!jgets(e, "todo") || !*jgets(e, "todo")) fprintf(stderr, "пустая запись %zu\n", i);
    }
    CHECK(has_where(res.report, "outbounds[tag=tor-out]"));
    CHECK(has_where(res.report, "route.rules[2]"));

    /* файл отчёта: тот же счёт и те же записи */
    struct jval *saved = json_parse_file(rpath, err, sizeof err);
    CHECK(saved != NULL);
    CHECK(jgeti(saved, "count", -1) == (int64_t)res.warnings);
    CHECK(jlen(jget(saved, "items")) == res.report->len);
    CHECK(jgetb(saved, "have", 0) == 1);
    CHECK(has_where(jget(saved, "items"), "outbounds[tag=tor-out]"));

    /* печать человеку */
    char *buf = NULL;
    size_t bn = 0;
    FILE *m = open_memstream(&buf, &bn);
    box_report_print(m, saved);
    fclose(m);
    CHECK(buf && strstr(buf, "Не переводится: ") && strstr(buf, "Что делать: ") && strstr(buf, "tor-out"));
    free(buf);
    json_free(saved);
    box_translate_free(&res);
    json_free(cfg);

    /* всё переведено */
    cfg = json_parse(GOOD, strlen(GOOD), err, sizeof err);
    CHECK(cfg != NULL);
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    CHECK(res.warnings == 0 && res.report && res.report->len == 0);
    saved = json_parse_file(rpath, err, sizeof err);
    CHECK(saved != NULL && jgeti(saved, "count", -1) == 0 && jlen(jget(saved, "items")) == 0);
    m = open_memstream(&buf, &bn);
    box_report_print(m, saved);
    fclose(m);
    CHECK(buf && !strcmp(buf, "Всё переведено.\n"));
    free(buf);
    json_free(saved);
    box_translate_free(&res);
    json_free(cfg);

    /* без report_path файл не пишется */
    unlink(rpath);
    o.report_path = NULL;
    cfg = json_parse(BAD, strlen(BAD), err, sizeof err);
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    CHECK(access(rpath, F_OK) != 0);
    box_translate_free(&res);
    json_free(cfg);
    return T_DONE();
}
