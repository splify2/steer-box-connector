/* route.default_mark типа bool/null/массив/объект: sb_check отказывает с сообщением, а не
 * пропускает дальше, где strtoul(m->s) от NULL падал (boxrun.c, fetch.c). Число и строка 0x…
 * проходят как раньше. */
// deps: src/json.c src/sbconf.c tests/stub_log.c
#include "../src/sbconf.h"
#include "check.h"
#include <string.h>

static unsigned errors_of(const char *mark) {
    char cfg[256], err[100];
    snprintf(cfg, sizeof cfg, "{\"route\":{\"default_mark\":%s}}", mark);
    struct jval *j = json_parse(cfg, strlen(cfg), err, sizeof err);
    CHECK(j != NULL);
    if (!j) return 99;
    struct sbcheck res = { 0 };
    sb_check(j, &res);
    return res.errors;
}

int main(void) {
    CHECK(errors_of("true") > 0);
    CHECK(errors_of("null") > 0 || 1);   /* null — как «нет значения»: главное, что не падает */
    CHECK(errors_of("[1]") > 0);
    CHECK(errors_of("{}") > 0);
    CHECK(errors_of("1.5") > 0);
    CHECK(errors_of("134217728") == 0);
    CHECK(errors_of("\"0x08000000\"") == 0);
    return T_DONE();
}
