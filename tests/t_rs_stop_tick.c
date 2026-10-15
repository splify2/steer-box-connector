/* rs_stop (rulesets.c): отменённый таймер набора правил не вызовет tick_cb, поэтому struct tick
 * освобождает сам rs_stop — прежде утекал при каждом перечитывании конфига. LeakSanitizer в
 * run.sh выключен, поэтому free оборачивается и запоминает освобождённое. */
// deps: src/json.c src/sbconf.c tests/stub_log.c
#include <stdlib.h>
static void *g_freed[64];
static int g_nfreed;
static void t_free(void *p) { if (g_nfreed < 64) g_freed[g_nfreed++] = p; free(p); }
#define free t_free
#include "../src/rulesets.c"
#include "../src/evloop.c"
#undef free
#include "check.h"
#include <fcntl.h>

struct box_rt *g_rt;

void box_ruleset_cache_path(const char *dir, const char *tag, const char *format, char *out, size_t n) {
    snprintf(out, n, "%s/%s.%s", dir, tag, format);
}

static int was_freed(void *p) {
    for (int i = 0; i < g_nfreed; i++) if (g_freed[i] == p) return 1;
    return 0;
}

int main(void) {
    struct box_rt rt;
    memset(&rt, 0, sizeof rt);
    g_rt = &rt;
    rt.ev = ev_new();
    char dir[] = "/tmp/t_rs_stop_XXXXXX";
    CHECK(mkdtemp(dir) != NULL);
    snprintf(rt.rsdir, sizeof rt.rsdir, "%s", dir);
    char path[700], err[100];
    box_ruleset_cache_path(dir, "a", "binary", path, sizeof path);
    FILE *f = fopen(path, "w");   /* свежий кэш: старт ставит таймер, а не скачивает */
    CHECK(f != NULL);
    if (f) { fputs("x", f); fclose(f); }
    static const char cfg[] = "{\"route\":{\"rule_set\":[{\"type\":\"remote\",\"tag\":\"a\","
        "\"url\":\"https://h.example/a.srs\",\"update_interval\":\"1h\"}]}}";
    rt.cfg = json_parse(cfg, strlen(cfg), err, sizeof err);
    CHECK(rt.cfg != NULL);
    CHECK(!rs_start(&rt));
    struct rsmgr *m = rt.rs;
    struct tick *tk = m->v[0].tk;
    CHECK(tk != NULL && m->v[0].timer != 0);
    rs_stop(&rt);
    CHECK(was_freed(tk));
    unlink(path);
    rmdir(dir);
    return T_DONE();
}
