/* Clash API (clash.c): время первого появления соединения (start) переживает чистку таблицы.
 * Раньше при переполнении таблица обнулялась целиком, и у всех идущих соединений start
 * становился «сейчас». */
// deps: src/json.c src/evloop.c src/net.c src/sbconf.c tests/stub_log.c
#include "../src/clash.c"
#include "check.h"

int main(void) {
    char id[40];
    /* идущее соединение и 1000 давно закрытых */
    CHECK(seen_at("alive", 100) == 100);
    for (int i = 0; i < 1000; i++) { snprintf(id, sizeof id, "dead%d", i); seen_at(id, 100); }
    seen_prune(1);                          /* первый снимок: все были видны */
    CHECK(seen_at("alive", 999) == 100);    /* второй снимок: идёт только «alive» */
    seen_prune(1);                          /* таблица велика — мёртвые уходят, живое остаётся */
    CHECK(g_seen_n == 1);
    CHECK(seen_at("alive", 5000) == 100);   /* время старта прежнее, не 5000 */
    return T_DONE();
}
