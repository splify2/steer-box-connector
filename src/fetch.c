/* sing-box tools fetch <url> [-o выход]: тело ответа — в stdout.
 *
 * Кто зовёт: podkop (`tools fetch ifconfig.me -D /etc/sing-box`) и forkop (`… -c <dir>/config.json
 * -D <dir> --disable-color [-o <тег>]`) — узнать внешний адрес через выход. Без -o — выход по
 * умолчанию (route.final, как у sing-box). Схемы нет — http.
 *
 * Работает при запущенном основном экземпляре и без него: соединение идёт привязкой к устройству
 * выхода из status своего экземпляра steer, если он поднят (туннели живут только в нём), иначе
 * напрямую — так же, как отвечал бы sing-box без поднятого выхода: ошибкой. */
#define _GNU_SOURCE
#include "box.h"
#include "sbconf.h"
#include "bconn.h"
#include "steerctl.h"
#include "json.h"
#include "dnsup.h"
#include "dnsmsg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Устройство выхода tag по status экземпляра коннектора. */
static int egress_for(const struct jval *cfg, const char *tag, struct egress *eg, char *err, size_t errn) {
    memset(eg, 0, sizeof *eg);
    const struct jval *route = jget(cfg, "route");
    const struct jval *m = jget(route, "default_mark");
    if (m) eg->mark = m->t == J_NUM ? (uint32_t)m->i : (uint32_t)strtoul(m->s, NULL, 0);
    if (!tag) tag = jgets(route, "final");
    const struct jval *ob = tag ? sb_outbound(cfg, tag) : NULL;
    if (!ob) return 0;
    enum sb_okind k = sb_outbound_kind(ob);
    if (k == SBO_DIRECT) {
        const char *di = jgets(route, "default_interface");
        if (di) snprintf(eg->dev, sizeof eg->dev, "%s", di);
        return 0;
    }
    if (k == SBO_INTERFACE) {
        snprintf(eg->dev, sizeof eg->dev, "%s", jgets(ob, "bind_interface"));
        return 0;
    }
    if (k == SBO_REMARK) {
        const struct jval *rm = jget(ob, "routing_mark");
        eg->mark = rm->t == J_NUM ? (uint32_t)rm->i : (uint32_t)strtoul(rm->s, NULL, 0);
        return 0;
    }
    struct box_settings s;
    box_settings_load(&s);
    char sock[300], mappath[300];
    snprintf(sock, sizeof sock, "%s/steer/steer.sock", s.state_dir);
    snprintf(mappath, sizeof mappath, "%s/steer/box-map.json", s.state_dir);
    char e2[256];
    struct jval *map = json_parse_file(mappath, e2, sizeof e2);
    const char *name = jgets(jget(jget(map, "outbounds"), tag), "name");
    if (!name || !*name) {
        snprintf(err, errn, "выход %s не поднят коннектором (sing-box run не запущен или выход без вида в steer)", tag);
        json_free(map);
        return -1;
    }
    struct jval *st = steerctl_json(sock, "status", 15000, e2, sizeof e2);
    const char *dev = jgets(jget(jget(st, "outputs"), name), "device");
    if (!dev) {
        snprintf(err, errn, "у выхода %s сейчас нет устройства (%s)", tag, st ? "нет живого члена" : e2);
        json_free(st);
        json_free(map);
        return -1;
    }
    snprintf(eg->dev, sizeof eg->dev, "%s", dev);
    json_free(st);
    json_free(map);
    return 0;
}

/* Резолвер отдельного процесса tools fetch: сервер DNS конфига (route.default_domain_resolver,
 * иначе dns.final), блокирующим вопросом. Системный резолвер ходит через dnsmasq в коннектор, и
 * имя из канала получило бы fake-IP, по которому сокет самого роутера никуда не придёт. */
static struct dnsup *g_fetch_up;

static int fetch_resolver(const char *host, struct sockaddr_storage *out, socklen_t *lens, int max) {
    int n = 0;
    for (int fam = 0; fam < 2 && n < max && g_fetch_up; fam++) {
        uint8_t q[512], r[4096];
        size_t qn = dns_build_query(host, fam ? 28 : 1, (uint16_t)(rand() & 0xffff), q, sizeof q);
        long rn = qn ? dnsup_ask_blocking(g_fetch_up, q, qn, r, sizeof r, DNSUP_TIMEOUT_MS) : -1;
        if (rn <= 0) continue;
        struct dns_ip ips[8];
        int ni = 0;
        dns_walk(r, (size_t)rn, -1, 0, ips, 8, &ni);
        for (int i = 0; i < ni && n < max; i++) {
            memset(&out[n], 0, sizeof out[n]);
            if (ips[i].family == 4) {
                struct sockaddr_in *s4 = (struct sockaddr_in *)&out[n];
                s4->sin_family = AF_INET;
                memcpy(&s4->sin_addr, ips[i].a, 4);
                lens[n++] = sizeof *s4;
            } else {
                struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&out[n];
                s6->sin6_family = AF_INET6;
                memcpy(&s6->sin6_addr, ips[i].a, 16);
                lens[n++] = sizeof *s6;
            }
        }
    }
    return n;
}

/* Сервер DNS tag конфига как клиент; его domain_resolver — тоже (одна ступень, как у podkop и
 * forkop: DoH через bootstrap). */
static struct dnsup *fetch_up(const struct jval *cfg, const char *tag, int depth) {
    const struct jval *sv = sb_dns_server(cfg, tag);
    if (!sv || depth > 3) return NULL;
    const char *type = jgets(sv, "type");
    if (!type || !strcmp(type, "fakeip")) return NULL;
    const struct jval *dr = jget(sv, "domain_resolver");
    const char *rtag = dr ? (dr->t == J_STR ? dr->s : jgets(dr, "server")) : NULL;
    struct dnsup *res = rtag && strcmp(rtag, tag) ? fetch_up(cfg, rtag, depth + 1) : NULL;
    struct egress eg = { .dev = "", .mark = 0 };
    const struct jval *m = jget(jget(cfg, "route"), "default_mark");
    if (m) eg.mark = m->t == J_NUM ? (uint32_t)m->i : (uint32_t)strtoul(m->s, NULL, 0);
    return dnsup_new(NULL, sv, &eg, res);
}

static int tools_fetch(const struct box_opts *o, int argc, char **argv) {
    const char *url = NULL, *out = NULL;
    for (int i = 0; i < argc; i++) {
        if ((!strcmp(argv[i], "-o") || !strcmp(argv[i], "--outbound")) && i + 1 < argc) out = argv[++i];
        else if (!url) url = argv[i];
    }
    if (!url) { fprintf(stderr, "Error: accepts 1 arg(s), received 0\n"); return 1; }
    char err[512];
    struct jval *cfg = box_load_config(o, err, sizeof err);
    struct egress eg;
    if (cfg && egress_for(cfg, out, &eg, err, sizeof err)) {
        fprintf(stderr, "FATAL[0000] %s\n", err);
        json_free(cfg);
        return 1;
    }
    if (!cfg) memset(&eg, 0, sizeof eg);
    if (cfg) {
        const struct jval *ddr = jget(jget(cfg, "route"), "default_domain_resolver");
        const char *rtag = ddr ? (ddr->t == J_STR ? ddr->s : jgets(ddr, "server")) : NULL;
        if (!rtag) rtag = jgets(jget(cfg, "dns"), "final");
        if (rtag) g_fetch_up = fetch_up(cfg, rtag, 0);
        if (g_fetch_up) net_set_resolver(fetch_resolver);
    }
    json_free(cfg);
    http_set_user_agent("curl/7.88.0");
    unsigned char *body;
    size_t n;
    int status;
    if (http_get(url, &eg, 15000, 64u << 20, &body, &n, &status, err, sizeof err)) {
        fprintf(stderr, "FATAL[0000] fetch %s: %s\n", url, err);
        return 1;
    }
    fwrite(body, 1, n, stdout);
    free(body);
    return status >= 200 && status < 400 ? 0 : 1;
}

int cmd_tools(const struct box_opts *o, int argc, char **argv) {
    if (argc < 1) {
        puts("Usage:\n  sing-box tools [command]\n\nAvailable Commands:\n  fetch       Fetch an URL");
        return 0;
    }
    if (!strcmp(argv[0], "fetch")) return tools_fetch(o, argc - 1, argv + 1);
    fprintf(stderr, "Error: unknown command \"%s\" for \"sing-box tools\"\n", argv[0]);
    return 1;
}
