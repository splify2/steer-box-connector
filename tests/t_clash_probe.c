/* Clash API (clash.c): задержка спящего узла hysteria2. Его сервер слушает только UDP (QUIC), и
 * прежний замер соединением TCP показывал живой узел мёртвым. Теперь замер — проба ядра steer
 * (`steerd hysteria2-probe <файл подписки> --node 0 --timeout С`), а у TCP-узлов — по-прежнему
 * соединение с сервером. Ядро здесь — заглушка: печатает ответ пробы и сверяет аргументы. */
// deps: src/json.c src/evloop.c src/net.c src/sbconf.c src/translate.c tests/stub_log.c
#include "../src/clash.c"
#include "check.h"
#include <sys/stat.h>

struct box_rt *g_rt;

static const char *fake(const char *dir, const char *name, const char *body) {
    static char path[300];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return NULL;
    fputs(body, f);
    fclose(f);
    chmod(path, 0755);
    return path;
}

int main(void) {
    char dir[] = "/tmp/t_clash_probe.XXXXXX";
    if (!mkdtemp(dir)) return 2;
    char err[256];

    /* Узел hysteria2 из конфига — строка подписки hysteria2:// с паролем, sni и obfs. */
    static const char OB[] =
        "{\"type\":\"hysteria2\",\"tag\":\"hy\",\"server\":\"10.0.0.9\",\"server_port\":8443,"
        "\"password\":\"pw\",\"tls\":{\"enabled\":true,\"server_name\":\"h.example\"},"
        "\"obfs\":{\"type\":\"salamander\",\"password\":\"op\"}}";
    struct jval *ob = json_parse(OB, strlen(OB), err, sizeof err);
    char *txt = box_node_text(ob, err, sizeof err);
    CHECK(txt && !strncmp(txt, "hysteria2://pw@10.0.0.9:8443/?sni=h.example", 43));
    CHECK(txt && strstr(txt, "obfs=salamander"));

    /* Проба ответила: задержка — мс рукопожатия; аргументы — файл с узлом, --node 0, срок в с. */
    char body[1200];
    snprintf(body, sizeof body,
        "#!/bin/sh\n"
        "[ \"$1\" = hysteria2-probe ] && [ \"$3 $4 $5 $6\" = \"--node 0 --timeout 3\" ] || exit 7\n"
        "grep -q '^hysteria2://pw@10.0.0.9:8443/' \"$2\" || exit 8\n"
        "echo '{\"output\":\"\",\"sub_file\":\"'$2'\",\"results\":[{\"index\":0,\"name\":\"\","
        "\"type\":\"hysteria2\",\"ok\":true,\"handshake_ms\":42,\"ttfb_ms\":-1,\"why\":\"\"}],\"working\":0}'\n");
    const char *ok = fake(dir, "steerd-ok", body);
    CHECK(measure_probe(ok, txt ? txt : "", 2500, err, sizeof err) == 42);

    /* Узел не ответил — отказ с причиной пробы. */
    const char *bad = fake(dir, "steerd-bad",
        "#!/bin/sh\necho '{\"results\":[{\"index\":0,\"ok\":false,\"handshake_ms\":-1,"
        "\"why\":\"таймаут рукопожатия\"}],\"working\":-1}'\nexit 1\n");
    err[0] = 0;
    CHECK(measure_probe(bad, txt ? txt : "", 2500, err, sizeof err) == -1);
    CHECK(strstr(err, "таймаут") != NULL);

    /* Ядра нет (нет пакета) — отказ, а не зависание. */
    CHECK(measure_probe("/nonexistent/steerd", txt ? txt : "", 1000, err, sizeof err) == -1);

    free(txt);
    json_free(ob);
    char cmd[100];
    snprintf(cmd, sizeof cmd, "rm -rf %s", dir);
    if (system(cmd)) {}
    return T_DONE();
}
