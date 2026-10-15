/* http_get: Location без «/» — не адрес, а путь от каталога текущего; https → http не
 * допускается. Разбор Location (redirect_target) вызывается напрямую, без сети. */
// deps: src/net.c src/json.c tests/stub_log.c
#include "../src/bconn.c"
#include "check.h"

static int rt(int tls, const char *path, const char *loc, char *cur, char *err) {
    err[0] = 0;
    return redirect_target(cur, 2048, tls, "h.example", path, loc, err, 200);
}

int main(void) {
    char cur[2048], err[200];
    CHECK(!rt(1, "/a/b/c.srs?x=1", "d.srs", cur, err));
    CHECK(!strcmp(cur, "https://h.example/a/b/d.srs"));
    CHECK(!rt(0, "/", "d.srs", cur, err));
    CHECK(!strcmp(cur, "http://h.example/d.srs"));
    CHECK(!rt(1, "/a/b", "/z", cur, err));
    CHECK(!strcmp(cur, "https://h.example/z"));
    CHECK(!rt(1, "/a", "//o.example/q", cur, err));
    CHECK(!strcmp(cur, "https://o.example/q"));
    CHECK(!rt(1, "/a", "https://objects.example/f", cur, err));
    CHECK(!strcmp(cur, "https://objects.example/f"));
    CHECK(!rt(0, "/a", "https://o.example/f", cur, err));
    CHECK(!rt(0, "/a", "http://o.example/f", cur, err));
    CHECK(!strcmp(cur, "http://o.example/f"));
    CHECK(rt(1, "/a", "http://o.example/f", cur, err) == -1);
    CHECK(err[0] != 0);
    return T_DONE();
}
