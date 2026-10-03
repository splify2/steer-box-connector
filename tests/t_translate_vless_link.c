/* Перевод (translate.c): узел vless с транспортом xhttp или с шифрованием VLESS (encryption)
 * уходит в подписку steer ссылкой vless://, а не конфигом sing-box. Разбор конфига sing-box в
 * ядре берёт path и host транспорта только у ws/httpupgrade и не читает encryption: узел xhttp
 * от forkop (extended) терял путь, host и mode, узел с encryption — шифрование. Обычный узел
 * (reality, ws) — по-прежнему конфигом sing-box: в нём заголовки ws и ранние данные. */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

static const char CFG[] =
    "{\"outbounds\":["
    " {\"type\":\"vless\",\"tag\":\"x\",\"server\":\"10.0.0.1\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\",\"flow\":\"\","
    "  \"tls\":{\"enabled\":true,\"server_name\":\"cdn.example\",\"utls\":{\"enabled\":true,\"fingerprint\":\"chrome\"}},"
    "  \"transport\":{\"type\":\"xhttp\",\"mode\":\"packet-up\",\"path\":\"/xh/p\",\"host\":\"cdn.example\","
    "                 \"x_padding_bytes\":\"100-1000\",\"no_grpc_header\":false,\"sc_max_each_post_bytes\":1000000}},"
    " {\"type\":\"vless\",\"tag\":\"e\",\"server\":\"10.0.0.2\",\"server_port\":8443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\",\"flow\":\"xtls-rprx-vision\","
    "  \"encryption\":\"mlkem768x25519plus.native.0rtt.AAAA\","
    "  \"tls\":{\"enabled\":true,\"server_name\":\"r.example\",\"reality\":{\"enabled\":true,"
    "          \"public_key\":\"PBK\",\"short_id\":\"ab\"}}},"
    " {\"type\":\"vless\",\"tag\":\"w\",\"server\":\"10.0.0.3\",\"server_port\":443,"
    "  \"uuid\":\"11111111-2222-3333-4444-555555555555\","
    "  \"tls\":{\"enabled\":true,\"server_name\":\"w.example\"},"
    "  \"transport\":{\"type\":\"ws\",\"path\":\"/ws\",\"headers\":{\"Host\":\"w.example\"}}},"
    " {\"type\":\"direct\",\"tag\":\"direct-out\"}],"
    " \"route\":{\"rules\":["
    "  {\"domain\":[\"x.example\"],\"outbound\":\"x\"},"
    "  {\"domain\":[\"e.example\"],\"outbound\":\"e\"},"
    "  {\"domain\":[\"w.example\"],\"outbound\":\"w\"}],"
    "  \"final\":\"direct-out\"}}";

/* Текст файла подписки выхода по тегу sing-box. */
static char *sub_of(const struct tr_result *r, const char *tag) {
    const char *name = jgets(jget(jget(r->map, "outbounds"), tag), "name");
    const char *path = name ? jgets(jget(jget(r->spec, "outputs"), name), "subscription") : NULL;
    if (!path) return NULL;
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *s = calloc(1, 8192);
    if (s && fread(s, 1, 8191, f) == 0) s[0] = 0;
    fclose(f);
    return s;
}

static int has(const char *s, const char *needle) {
    if (s && strstr(s, needle)) return 1;
    fprintf(stderr, "нет «%s» в: %s\n", needle, s ? s : "(нет файла)");
    return 0;
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

    char *x = sub_of(&res, "x");
    CHECK(x && !strncmp(x, "vless://11111111-2222-3333-4444-555555555555@10.0.0.1:443?", 58));
    CHECK(has(x, "type=xhttp"));
    CHECK(has(x, "path=%2Fxh%2Fp"));
    CHECK(has(x, "host=cdn.example"));
    CHECK(has(x, "mode=packet-up"));
    CHECK(has(x, "security=tls"));
    CHECK(has(x, "sni=cdn.example"));
    CHECK(has(x, "fp=chrome"));
    CHECK(has(x, "encryption=none"));
    CHECK(has(x, "extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D"));
    CHECK(has(x, "#x"));

    char *e = sub_of(&res, "e");
    CHECK(e && !strncmp(e, "vless://", 8));
    CHECK(has(e, "encryption=mlkem768x25519plus.native.0rtt.AAAA"));
    CHECK(has(e, "flow=xtls-rprx-vision"));
    CHECK(has(e, "security=reality"));
    CHECK(has(e, "pbk=PBK"));
    CHECK(has(e, "sid=ab"));

    char *w = sub_of(&res, "w");
    CHECK(w && strstr(w, "\"outbounds\"") && strstr(w, "\"ws\""));

    free(x); free(e); free(w);
    box_translate_free(&res);
    json_free(cfg);
    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
