/* Перевод (translate.c): ничего не теряется молча. Порты правила и server_ports hysteria2 без
 * предела длины (раньше 1024 и 512 знаков: правило снималось, mport обрезался), пароль ss любой
 * длины, поля узлов, которых нет в ссылке подписки (ip_version, udp_over_tcp ss, path и headers
 * http, network hysteria2, xhttp не по умолчанию), перевод строки в домене, инверсия в правиле
 * DNS — каждое называется в отчёте. */
// deps: src/sbconf.c src/json.c tests/stub_log.c
#include "../src/translate.c"
#include "check.h"
#include <stdlib.h>

static int has_where(const struct jval *items, const char *w, const char *field) {
    for (size_t i = 0; i < jlen(items); i++) {
        const char *x = jgets(jat(items, i), "where"), *y = jgets(jat(items, i), "why");
        if (x && !strcmp(x, w) && (!field || (y && strstr(y, field)))) return 1;
    }
    return 0;
}

static char *read_all(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    char *s = calloc(1, 1 << 20);
    if (s && fread(s, 1, (1 << 20) - 1, f) == 0) s[0] = 0;
    fclose(f);
    return s;
}

static char *sub_of(const struct tr_result *r, const char *tag) {
    const char *name = jgets(jget(jget(r->map, "outbounds"), tag), "name");
    const char *path = name ? jgets(jget(jget(r->spec, "outputs"), name), "subscription") : NULL;
    return path ? read_all(path) : NULL;
}

int main(void) {
    char dir[] = "/tmp/t_translate_f.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char err[300];
    /* 600 портов в одном правиле (больше 1024 знаков), 300 диапазонов server_ports, пароль ss
     * в 3000 знаков. */
    size_t cap = 1 << 20;
    char *cfgs = malloc(cap), *c = cfgs;
    char pw[3001];
    memset(pw, 'p', 3000), pw[3000] = 0;
    c += sprintf(c, "{\"outbounds\":["
        "{\"type\":\"hysteria2\",\"tag\":\"h\",\"server\":\"10.0.0.1\",\"server_port\":443,\"password\":\"x\",\"network\":\"tcp\",\"server_ports\":[");
    for (int i = 0; i < 300; i++) c += sprintf(c, "%s\"%d:%d\"", i ? "," : "", 10000 + i * 10, 10005 + i * 10);
    c += sprintf(c, "]},"
        "{\"type\":\"shadowsocks\",\"tag\":\"s\",\"server\":\"10.0.0.2\",\"server_port\":8388,\"method\":\"aes-128-gcm\",\"udp_over_tcp\":true,\"password\":\"%s\"},"
        "{\"type\":\"http\",\"tag\":\"p\",\"server\":\"10.0.0.3\",\"server_port\":3128,\"path\":\"/x\",\"headers\":{\"A\":\"b\"}},"
        "{\"type\":\"vless\",\"tag\":\"x\",\"server\":\"10.0.0.4\",\"server_port\":443,\"uuid\":\"11111111-2222-3333-4444-555555555555\","
        " \"tls\":{\"enabled\":true,\"server_name\":\"a.example\"},"
        " \"transport\":{\"type\":\"xhttp\",\"mode\":\"auto\",\"path\":\"/p\",\"no_grpc_header\":true,\"sc_max_each_post_bytes\":5,\"xmux\":{\"max_concurrency\":\"1\"}}},"
        "{\"type\":\"direct\",\"tag\":\"direct-out\"}],"
        "\"route\":{\"rules\":[{\"port\":[", pw);
    for (int i = 0; i < 600; i++) c += sprintf(c, "%s%d", i ? "," : "", 1000 + i);
    c += sprintf(c, "],\"domain\":[\"a.example\"],\"outbound\":\"h\"},"
        "{\"ip_version\":4,\"domain\":[\"b.example\"],\"outbound\":\"s\"},"
        "{\"domain\":[\"c.example\\nevil.example\"],\"outbound\":\"p\"},"
        "{\"domain\":[\"d.example\"],\"outbound\":\"x\"}],\"final\":\"direct-out\"}}");
    struct jval *cfg = json_parse(cfgs, strlen(cfgs), err, sizeof err);
    CHECK(cfg != NULL);
    struct tr_opts o = { .dir = dir, .ruleset_dir = dir };
    struct tr_result res;
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));

    /* порты: правило осталось и несёт все 600 */
    const struct jval *lists = jget(res.spec, "lists");
    const struct jval *l = NULL;
    for (size_t i = 0; i < jlen(lists); i++)
        if (jget(lists->o[i].val, "ports")) l = lists->o[i].val;
    CHECK(l != NULL && jlen(jget(l, "ports")) == 600);

    char *h = sub_of(&res, "h");
    CHECK(h && strstr(h, "mport=") != NULL);
    CHECK(h && strstr(h, "12990-12995") != NULL);   /* последний диапазон не обрезан */
    char *s = sub_of(&res, "s");
    CHECK(s && strlen(s) > 4000);

    CHECK(has_where(res.report, "outbounds[tag=h]", "network"));
    CHECK(has_where(res.report, "outbounds[tag=s]", "udp_over_tcp"));
    CHECK(has_where(res.report, "outbounds[tag=p]", "path"));
    CHECK(has_where(res.report, "outbounds[tag=p]", "headers"));
    CHECK(has_where(res.report, "outbounds[tag=x]", "no_grpc_header"));
    CHECK(has_where(res.report, "outbounds[tag=x]", "sc_max_each_post_bytes"));
    CHECK(has_where(res.report, "outbounds[tag=x]", "xmux"));
    CHECK(has_where(res.report, "route.rules[1]", "ip_version"));
    CHECK(has_where(res.report, "route.rules[2]", "перевод"));
    free(h); free(s);
    box_translate_free(&res);
    json_free(cfg);
    free(cfgs);

    /* инверсия в правиле DNS с набором, у которого уже есть канал из маршрута */
    static const char DNS[] =
        "{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"direct-out\"}],"
        " \"dns\":{\"servers\":[{\"type\":\"udp\",\"tag\":\"d1\",\"server\":\"1.1.1.1\"}],"
        "  \"rules\":[{\"domain\":[\"z.example\"],\"invert\":true,\"server\":\"d1\"}]},"
        " \"route\":{\"final\":\"direct-out\"}}";
    cfg = json_parse(DNS, strlen(DNS), err, sizeof err);
    CHECK(cfg != NULL);
    CHECK(!box_translate(cfg, &o, &res, err, sizeof err));
    CHECK(has_where(res.report, "dns.rules[0]", "инверс"));
    box_translate_free(&res);
    json_free(cfg);

    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
