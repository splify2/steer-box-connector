/* Перевод (translate.c): tls.insecure узла — ключ insecure выхода у всех видов с TLS. Прежде он
 * ставился только у vless, и steer-proxy пропускал узел trojan и https с allowInsecure
 * («включите insecure у выхода явно»), а vmess сверял сертификат — узел с самоподписанным
 * сертификатом не работал. У hysteria2 и протоколов без TLS ключа нет (ядро его отвергает). */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

#define TLS_INS "\"tls\":{\"enabled\":true,\"server_name\":\"a.example\",\"insecure\":true}"
static const char CFG[] =
    "{\"outbounds\":["
    " {\"type\":\"vless\",\"tag\":\"v\",\"server\":\"10.0.0.1\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\"," TLS_INS "},"
    " {\"type\":\"trojan\",\"tag\":\"t\",\"server\":\"10.0.0.2\",\"server_port\":443,"
    "  \"password\":\"p\"," TLS_INS "},"
    " {\"type\":\"vmess\",\"tag\":\"m\",\"server\":\"10.0.0.3\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\"," TLS_INS "},"
    " {\"type\":\"http\",\"tag\":\"h\",\"server\":\"10.0.0.4\",\"server_port\":443," TLS_INS "},"
    " {\"type\":\"http\",\"tag\":\"hp\",\"server\":\"10.0.0.5\",\"server_port\":8080},"
    " {\"type\":\"hysteria2\",\"tag\":\"y\",\"server\":\"10.0.0.6\",\"server_port\":443,"
    "  \"password\":\"p\"," TLS_INS "},"
    " {\"type\":\"trojan\",\"tag\":\"ts\",\"server\":\"10.0.0.7\",\"server_port\":443,"
    "  \"password\":\"p\",\"tls\":{\"enabled\":true,\"server_name\":\"a.example\"}},"
    " {\"type\":\"direct\",\"tag\":\"direct-out\"}],"
    " \"route\":{\"rules\":["
    "  {\"domain\":[\"v.example\"],\"outbound\":\"v\"},"
    "  {\"domain\":[\"t.example\"],\"outbound\":\"t\"},"
    "  {\"domain\":[\"m.example\"],\"outbound\":\"m\"},"
    "  {\"domain\":[\"h.example\"],\"outbound\":\"h\"},"
    "  {\"domain\":[\"hp.example\"],\"outbound\":\"hp\"},"
    "  {\"domain\":[\"y.example\"],\"outbound\":\"y\"},"
    "  {\"domain\":[\"ts.example\"],\"outbound\":\"ts\"}],"
    "  \"final\":\"direct-out\"}}";

/* Выход steer по тегу sing-box — через карту перевода. */
static const struct jval *out_of(const struct tr_result *r, const char *tag) {
    const struct jval *m = jget(r->map, "outbounds");
    const char *name = jgets(jget(m, tag), "name");
    return name ? jget(jget(r->spec, "outputs"), name) : NULL;
}

int main(void) {
    char dir[] = "/tmp/t_translate.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char err[300];
    struct jval *cfg = json_parse(CFG, strlen(CFG), err, sizeof err);
    CHECK(cfg != NULL);
    struct tr_opts o = { .dir = dir, .ruleset_dir = dir };
    struct tr_result res;
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    static const struct { const char *tag; int ins; } want[] = {
        { "v", 1 }, { "t", 1 }, { "m", 1 }, { "h", 1 }, { "hp", 0 }, { "y", 0 }, { "ts", 0 },
    };
    for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
        const struct jval *ob = out_of(&res, want[i].tag);
        CHECK(ob != NULL);
        if (!ob) { fprintf(stderr, "нет выхода %s\n", want[i].tag); continue; }
        if (jgetb(ob, "insecure", 0) != want[i].ins) {
            fprintf(stderr, "%s: insecure %d, ждали %d\n", want[i].tag, jgetb(ob, "insecure", 0), want[i].ins);
            CHECK(0);
        }
    }
    box_translate_free(&res);
    json_free(cfg);
    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
