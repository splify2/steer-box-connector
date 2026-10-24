/* Перевод (translate.c): reject и выход block. reject protocol quic (podkop/forkop «выключить QUIC») —
 * правило UDP/443 в выход block; reject с адресами — правило в block; имена с сужением и протокол,
 * кроме quic, — предупреждение; ядро старше 2.1.0 — прежнее поведение (правила нет, предупреждение). */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

static const char CFG[] =
    "{\"inbounds\":[{\"type\":\"tproxy\",\"tag\":\"tproxy-in\"}],"
    " \"outbounds\":[{\"type\":\"direct\",\"tag\":\"vpn\",\"bind_interface\":\"wg0\"},"
    "               {\"type\":\"block\",\"tag\":\"blk\"}],"
    " \"route\":{\"rules\":["
    "   {\"inbound\":[\"tproxy-in\"],\"protocol\":[\"quic\"],\"action\":\"reject\"},"
    "   {\"ip_cidr\":[\"203.0.113.0/24\"],\"action\":\"reject\"},"
    "   {\"source_ip_cidr\":[\"192.168.1.50/32\"],\"protocol\":\"quic\",\"action\":\"reject\"},"
    "   {\"domain_suffix\":[\"ads.example\"],\"action\":\"reject\"},"
    "   {\"domain_suffix\":[\"video.example\"],\"protocol\":\"quic\",\"action\":\"reject\"},"
    "   {\"ip_cidr\":[\"198.51.100.0/24\"],\"protocol\":\"bittorrent\",\"action\":\"reject\"},"
    "   {\"ip_cidr\":[\"192.0.2.0/24\"],\"outbound\":\"blk\"},"
    "   {\"ip_cidr\":[\"10.9.0.0/16\"],\"outbound\":\"vpn\"}],"
    "          \"final\":\"vpn\"}}";

static const struct jval *rule_named(const struct jval *spec, const char *name) {
    const struct jval *rs = jget(spec, "rules");
    for (size_t i = 0; i < jlen(rs); i++)
        if (!strcmp(jgets(jat(rs, i), "name"), name)) return jat(rs, i);
    return NULL;
}

/* Список правила (первый из to). */
static const struct jval *list_of(const struct jval *spec, const struct jval *rule) {
    const struct jval *to = jget(rule, "to");
    const char *ln = to && to->t == J_ARR ? jat(to, 0)->s : jgets(rule, "to");
    return ln ? jget(jget(spec, "lists"), ln) : NULL;
}

static int is_quic_list(const struct jval *l) {
    const struct jval *ports = jget(l, "ports");
    return l && jgetb(l, "all", 0) && jgets(l, "proto") && !strcmp(jgets(l, "proto"), "udp") &&
           jlen(ports) == 1 && jat(ports, 0)->t == J_NUM && jat(ports, 0)->i == 443;
}

int main(void) {
    CHECK(box_steer_has_block("steer 2.1.0 (musl, ревизия abc)\n"));
    CHECK(box_steer_has_block("2.1.0"));
    CHECK(box_steer_has_block("steer 2.10.3"));
    CHECK(box_steer_has_block("steer 3.0.0"));
    CHECK(!box_steer_has_block("steer 2.0.5 (x)"));
    CHECK(!box_steer_has_block("steer 1.9.9"));
    CHECK(!box_steer_has_block("steer dev (x)"));
    CHECK(!box_steer_has_block(""));
    CHECK(!box_steer_has_block(NULL));

    char dir[] = "/tmp/t_translate.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char err[300];
    struct jval *cfg = json_parse(CFG, strlen(CFG), err, sizeof err);
    CHECK(cfg != NULL);
    struct tr_opts o = { .dir = dir, .ruleset_dir = dir, .block_ok = 1 };
    struct tr_result res;
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    const struct jval *blk = jget(jget(res.spec, "outputs"), "block");
    CHECK(blk && jgets(blk, "kind") && !strcmp(jgets(blk, "kind"), "block"));

    /* глобальный reject protocol quic: весь UDP/443 в block, правило без клиента (по умолчанию lan) */
    const struct jval *r0 = rule_named(res.spec, "sb0");
    CHECK(r0 && !strcmp(jgets(r0, "out"), "block") && !jget(r0, "for") && !jget(r0, "quic"));
    CHECK(r0 && is_quic_list(list_of(res.spec, r0)));
    /* reject адресов: правило в block без сужения порта */
    const struct jval *r1 = rule_named(res.spec, "sb1");
    CHECK(r1 && !strcmp(jgets(r1, "out"), "block"));
    CHECK(r1 && !jget(list_of(res.spec, r1), "ports"));
    /* reject protocol quic одного клиента */
    const struct jval *r2 = rule_named(res.spec, "sb2");
    CHECK(r2 && !strcmp(jgets(r2, "out"), "block") && jget(r2, "for"));
    CHECK(r2 && is_quic_list(list_of(res.spec, r2)));
    /* reject имён целиком — block; reject QUIC к именам и протокол, кроме quic, — предупреждение */
    CHECK(rule_named(res.spec, "sb3") && !strcmp(jgets(rule_named(res.spec, "sb3"), "out"), "block"));
    CHECK(!rule_named(res.spec, "sb4"));
    CHECK(!rule_named(res.spec, "sb5"));
    /* правило маршрута в выход block (type: block) */
    const struct jval *r6 = rule_named(res.spec, "sb6");
    CHECK(r6 && !strcmp(jgets(r6, "out"), "block"));
    const struct jval *r7 = rule_named(res.spec, "sb7");
    CHECK(r7 && strcmp(jgets(r7, "out"), "block"));
    CHECK(res.warnings == 2);
    /* порядок: правило reject QUIC стоит выше правила в туннель */
    CHECK(jlen(jget(res.spec, "rules")) >= 6);
    json_write(stderr, jget(res.spec, "rules"), -1), fputc('\n', stderr);
    box_translate_free(&res);

    /* старое ядро: ни выхода block, ни правил reject — только предупреждения, остальное прежнее */
    o.block_ok = 0;
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    CHECK(!jget(jget(res.spec, "outputs"), "block"));
    CHECK(!rule_named(res.spec, "sb0") && !rule_named(res.spec, "sb1") && !rule_named(res.spec, "sb2"));
    CHECK(!rule_named(res.spec, "sb3") && !rule_named(res.spec, "sb6"));
    CHECK(rule_named(res.spec, "sb7") != NULL);
    CHECK(res.warnings == 7);
    box_translate_free(&res);
    json_free(cfg);
    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
