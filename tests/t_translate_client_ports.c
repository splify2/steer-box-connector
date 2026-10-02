/* Перевод (translate.c): правило только с клиентом (source_ip_cidr) и сужением — «весь трафик
 * клиента на эти порты». Список all: true получал протокол, но не порты: правило с port: 443
 * уводило в выход весь трафик клиента. */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

static const char CFG[] =
    "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"vpn\",\"bind_interface\":\"wg0\"},"
    "               {\"type\":\"direct\",\"tag\":\"direct-out\"}],"
    " \"route\":{\"rules\":[{\"source_ip_cidr\":[\"192.168.1.10/32\"],\"port\":[443],"
    "                      \"port_range\":[\"8000:8100\"],\"network\":\"tcp\",\"outbound\":\"vpn\"}],"
    "          \"final\":\"direct-out\"}}";

int main(void) {
    char dir[] = "/tmp/t_translate.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char err[300];
    struct jval *cfg = json_parse(CFG, strlen(CFG), err, sizeof err);
    struct tr_opts o = { .dir = dir, .ruleset_dir = dir };
    struct tr_result res;
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    const struct jval *lists = jget(res.spec, "lists");
    const struct jval *all = NULL;
    for (size_t i = 0; i < jlen(lists); i++)
        if (jgetb(lists->o[i].val, "all", 0)) all = lists->o[i].val;
    CHECK(all != NULL);
    CHECK(jgets(all, "proto") && !strcmp(jgets(all, "proto"), "tcp"));
    const struct jval *ports = jget(all, "ports");
    CHECK(jlen(ports) == 2);
    CHECK(jlen(ports) == 2 && jat(ports, 0)->t == J_NUM && jat(ports, 0)->i == 443);
    CHECK(jlen(ports) == 2 && jat(ports, 1)->t == J_STR && !strcmp(jat(ports, 1)->s, "8000-8100"));
    if (all) json_write(stderr, all, -1), fputc('\n', stderr);
    box_translate_free(&res);
    json_free(cfg);
    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
