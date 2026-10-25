/* Серверы DNS, которых коннектор не заводит (dnsup.c: udp, tcp, tls, https): sb_check отказывает
 * с причиной. Прежде quic и h3 проходили проверку, сервер не заводился, и каждый вопрос к нему
 * получал SERVFAIL при запущенной службе. */
// deps: src/json.c src/sbconf.c tests/stub_log.c
#include "../src/sbconf.h"
#include "check.h"
#include <string.h>

static unsigned errors_of(const char *type) {
    char cfg[400], err[100];
    snprintf(cfg, sizeof cfg,
             "{\"dns\":{\"servers\":[{\"type\":\"%s\",\"tag\":\"d\",\"server\":\"9.9.9.9\"}],\"final\":\"d\"}}", type);
    struct jval *j = json_parse(cfg, strlen(cfg), err, sizeof err);
    CHECK(j != NULL);
    if (!j) return 99;
    struct sbcheck res = { 0 };
    sb_check(j, &res);
    return res.errors;
}

int main(void) {
    CHECK(errors_of("udp") == 0);
    CHECK(errors_of("tcp") == 0);
    CHECK(errors_of("tls") == 0);
    CHECK(errors_of("https") == 0);
    CHECK(errors_of("quic") > 0);
    CHECK(errors_of("h3") > 0);
    return T_DONE();
}
