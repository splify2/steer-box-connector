/* Проверка конфига sing-box (sbconf.h) и помощники чтения. */
#define _GNU_SOURCE
#include "sbconf.h"
#include "box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <arpa/inet.h>

/* ---- помощники чтения ------------------------------------------------------------------- */

static struct jval *find_tag(const struct jval *arr, const char *tag) {
    for (size_t i = 0; i < jlen(arr); i++) {
        const char *t = jgets(jat(arr, i), "tag");
        if (t && !strcmp(t, tag)) return jat(arr, i);
    }
    return NULL;
}

struct jval *sb_outbound(const struct jval *cfg, const char *tag) {
    struct jval *v = find_tag(jget(cfg, "outbounds"), tag);
    return v ? v : find_tag(jget(cfg, "endpoints"), tag);
}

struct jval *sb_inbound(const struct jval *cfg, const char *tag) {
    return find_tag(jget(cfg, "inbounds"), tag);
}

struct jval *sb_dns_server(const struct jval *cfg, const char *tag) {
    return find_tag(jget(jget(cfg, "dns"), "servers"), tag);
}

struct jval *sb_rule_set(const struct jval *cfg, const char *tag) {
    return find_tag(jget(jget(cfg, "route"), "rule_set"), tag);
}

long long sb_duration_ms(const char *s) {
    if (!s || !*s) return -1;
    long long total = 0;
    const char *p = s;
    while (*p) {
        char *end;
        double v = strtod(p, &end);
        if (end == p) return -1;
        p = end;
        double mul;
        if (!strncmp(p, "ms", 2)) { mul = 1; p += 2; }
        else if (!strncmp(p, "us", 2) || !strncmp(p, "µs", 3)) { mul = 0.001; p += (*p == 'u') ? 2 : 3; }
        else if (!strncmp(p, "ns", 2)) { mul = 0.000001; p += 2; }
        else if (*p == 's') { mul = 1000; p++; }
        else if (*p == 'm') { mul = 60000; p++; }
        else if (*p == 'h') { mul = 3600000; p++; }
        else if (*p == 'd') { mul = 86400000; p++; }   /* sing-box принимает «d» в своих длительностях */
        else if (!*p && v == 0) { mul = 0; }
        else return -1;
        total += (long long)(v * mul);
    }
    return total;
}

enum sb_okind sb_outbound_kind(const struct jval *ob) {
    const char *t = jgets(ob, "type");
    if (!t) return SBO_UNKNOWN;
    if (!strcmp(t, "direct")) {
        if (jgets(ob, "bind_interface")) return SBO_INTERFACE;
        if (jget(ob, "routing_mark")) return SBO_REMARK;
        return SBO_DIRECT;
    }
    if (!strcmp(t, "block")) return SBO_BLOCK;
    if (!strcmp(t, "dns")) return SBO_DNS;
    if (!strcmp(t, "selector") || !strcmp(t, "urltest")) return SBO_GROUP;
    static const char *tun[] = { "vless", "vmess", "trojan", "shadowsocks", "socks", "http",
                                 "hysteria2", NULL };
    for (int i = 0; tun[i]; i++)
        if (!strcmp(t, tun[i])) return SBO_TUNNEL;
    return SBO_UNKNOWN;
}

/* ---- проверка --------------------------------------------------------------------------- */

struct ck {
    struct sbcheck *r;
    const struct jval *cfg;
};

static void ck_err(struct ck *c, const struct jval *at, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void ck_err(struct ck *c, const struct jval *at, const char *fmt, ...) {
    char buf[480];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (!c->r->errors)
        snprintf(c->r->first, sizeof c->r->first, "%s", buf);
    c->r->errors++;
    if (at && at->line) LOGE("%s (строка %u)", buf, at->line);
    else LOGE("%s", buf);
}

static void ck_warn(struct ck *c, const struct jval *at, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void ck_warn(struct ck *c, const struct jval *at, const char *fmt, ...) {
    char buf[480];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    c->r->warnings++;
    if (at && at->line) LOGW("%s (строка %u)", buf, at->line);
    else LOGW("%s", buf);
}

/* Ключи объекта сверяются со списком; незнакомый — предупреждение (см. sbconf.h). Список — через
 * пробел: «tag type server server_port». */
static void ck_keys(struct ck *c, const struct jval *obj, const char *where, const char *allowed) {
    if (!obj || obj->t != J_OBJ) return;
    for (size_t i = 0; i < obj->len; i++) {
        const char *k = obj->o[i].key;
        size_t kl = strlen(k);
        const char *p = allowed;
        int ok = 0;
        while (*p) {
            while (*p == ' ') p++;
            const char *e = p;
            while (*e && *e != ' ') e++;
            if ((size_t)(e - p) == kl && !memcmp(p, k, kl)) { ok = 1; break; }
            p = e;
        }
        if (!ok) ck_warn(c, obj->o[i].val, "%s: незнакомый ключ «%s» — пропущен", where, k);
    }
}

static int is_type(const struct jval *v, enum jtype t) { return v && v->t == t; }

static void ck_type(struct ck *c, const struct jval *obj, const char *key, enum jtype t,
                    const char *where) {
    struct jval *v = jget(obj, key);
    if (!v || v->t == t) return;
    static const char *names[] = { "null", "логическое", "число", "строка", "массив", "объект" };
    ck_err(c, v, "%s.%s: ожидалось %s", where, key, names[t]);
}

static void ck_strlist(struct ck *c, const struct jval *obj, const char *key, const char *where) {
    struct jval *v = jget(obj, key);
    if (v && jstrlist(v, NULL, 0) < 0) ck_err(c, v, "%s.%s: ожидалась строка или массив строк", where, key);
}

static void ck_port(struct ck *c, const struct jval *obj, const char *key, const char *where, int required) {
    struct jval *v = jget(obj, key);
    if (!v) {
        if (required) ck_err(c, obj, "%s: нет %s", where, key);
        return;
    }
    if (v->t != J_NUM || !v->is_int || v->i < 0 || v->i > 65535)
        ck_err(c, v, "%s.%s: порт должен быть числом 0..65535", where, key);
}

static int valid_cidr(const char *s) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", s);
    char *slash = strchr(buf, '/');
    int plen = -1;
    if (slash) {
        *slash = 0;
        char *e;
        long l = strtol(slash + 1, &e, 10);
        if (*e || l < 0) return 0;
        plen = (int)l;
    }
    unsigned char a[16];
    if (inet_pton(AF_INET, buf, a) == 1) return plen <= 32;
    if (inet_pton(AF_INET6, buf, a) == 1) return plen <= 128;
    return 0;
}

static void ck_cidrs(struct ck *c, const struct jval *obj, const char *key, const char *where) {
    struct jval *v = jget(obj, key);
    if (!v) return;
    long n = jstrlist(v, NULL, 0);
    if (n < 0) { ck_err(c, v, "%s.%s: ожидалась строка или массив строк", where, key); return; }
    const char **list = calloc((size_t)n + 1, sizeof *list);
    if (!list) return;
    jstrlist(v, list, (size_t)n);
    for (long i = 0; i < n; i++)
        if (!valid_cidr(list[i])) ck_err(c, v, "%s.%s: «%s» — не адрес и не подсеть", where, key, list[i]);
    free(list);
}

static void ck_duration(struct ck *c, const struct jval *obj, const char *key, const char *where) {
    struct jval *v = jget(obj, key);
    if (!v) return;
    if (v->t != J_STR || sb_duration_ms(v->s) < 0)
        ck_err(c, v, "%s.%s: длительность вида 30s, 3m, 1h", where, key);
}

/* Ссылка на тег выхода: есть ли такой. */
static void ck_outref(struct ck *c, const struct jval *at, const char *tag, const char *where) {
    if (!sb_outbound(c->cfg, tag)) ck_err(c, at, "%s: выхода «%s» нет", where, tag);
}

static void ck_dnsref(struct ck *c, const struct jval *at, const char *tag, const char *where) {
    if (!sb_dns_server(c->cfg, tag)) ck_err(c, at, "%s: сервера DNS «%s» нет", where, tag);
}

/* domain_resolver бывает строкой (тег сервера) и объектом { server, strategy, … }. */
static void ck_resolver(struct ck *c, const struct jval *obj, const char *where) {
    struct jval *v = jget(obj, "domain_resolver");
    if (!v) return;
    if (v->t == J_STR) ck_dnsref(c, v, v->s, where);
    else if (v->t == J_OBJ) {
        const char *s = jgets(v, "server");
        if (!s) ck_err(c, v, "%s.domain_resolver: нет server", where);
        else ck_dnsref(c, v, s, where);
    } else ck_err(c, v, "%s.domain_resolver: строка или объект", where);
}

#define DIAL_KEYS " detour bind_interface inet4_bind_address inet6_bind_address bind_address_no_port" \
    " protect_path routing_mark reuse_addr netns connect_timeout tcp_fast_open tcp_multi_path" \
    " disable_tcp_keep_alive tcp_keep_alive tcp_keep_alive_interval udp_fragment domain_resolver" \
    " network_strategy network_type fallback_network_type fallback_delay domain_strategy"

static void ck_dial(struct ck *c, const struct jval *obj, const char *where) {
    ck_type(c, obj, "bind_interface", J_STR, where);
    ck_type(c, obj, "detour", J_STR, where);
    struct jval *m = jget(obj, "routing_mark");
    if (m && !(m->t == J_NUM && m->is_int) && m->t != J_STR)
        ck_err(c, m, "%s.routing_mark: число или строка 0x…", where);
    const char *d = jgets(obj, "detour");
    if (d) ck_outref(c, jget(obj, "detour"), d, where);
    ck_resolver(c, obj, where);
}

static void ck_tls(struct ck *c, const struct jval *tls, const char *where, int server) {
    if (!tls) return;
    if (tls->t != J_OBJ) { ck_err(c, tls, "%s.tls: ожидался объект", where); return; }
    char w[256];
    snprintf(w, sizeof w, "%s.tls", where);
    ck_keys(c, tls, w, "enabled disable_sni server_name insecure alpn min_version max_version"
            " cipher_suites curve_preferences certificate certificate_path certificate_public_key_sha256"
            " key key_path client_certificate client_certificate_path client_key client_key_path"
            " ech utls reality fragment fragment_fallback_delay record_fragment kernel_tx kernel_rx"
            " acme handshake_timeout client_authentication client_certificate_public_key_sha256");
    ck_type(c, tls, "enabled", J_BOOL, w);
    ck_type(c, tls, "server_name", J_STR, w);
    ck_type(c, tls, "insecure", J_BOOL, w);
    ck_strlist(c, tls, "alpn", w);
    struct jval *r = jget(tls, "reality");
    if (r && jgetb(r, "enabled", 0)) {
        if (!server && !jgets(r, "public_key")) ck_err(c, r, "%s.reality: нет public_key", w);
        if (server && !jgets(r, "private_key")) ck_err(c, r, "%s.reality: нет private_key", w);
    }
    struct jval *u = jget(tls, "utls");
    if (u) ck_type(c, u, "fingerprint", J_STR, w);
}

static void ck_transport(struct ck *c, const struct jval *tr, const char *where) {
    if (!tr) return;
    if (tr->t != J_OBJ) { ck_err(c, tr, "%s.transport: ожидался объект", where); return; }
    const char *t = jgets(tr, "type");
    char w[256];
    snprintf(w, sizeof w, "%s.transport", where);
    if (!t) { ck_err(c, tr, "%s: нет type", w); return; }
    if (!strcmp(t, "ws"))
        ck_keys(c, tr, w, "type path headers max_early_data early_data_header_name");
    else if (!strcmp(t, "grpc"))
        ck_keys(c, tr, w, "type service_name idle_timeout ping_timeout permit_without_stream");
    else if (!strcmp(t, "httpupgrade"))
        ck_keys(c, tr, w, "type host path headers");
    else if (!strcmp(t, "http"))
        ck_keys(c, tr, w, "type host path method headers idle_timeout ping_timeout");
    else if (!strcmp(t, "xhttp"))
        ck_keys(c, tr, w, "type mode path host headers x_padding_bytes no_grpc_header no_sse_header"
                " sc_max_each_post_bytes sc_min_posts_interval_ms sc_max_buffered_posts"
                " sc_stream_up_server_secs server_max_header_bytes xmux download");
    else if (!strcmp(t, "quic"))
        ck_err(c, tr, "%s: транспорт quic (V2Ray) коннектор не поддерживает", w);
    else
        ck_err(c, tr, "%s: неизвестный транспорт «%s»", w, t);
}

static void ck_outbound(struct ck *c, const struct jval *ob, size_t idx) {
    char where[160];
    const char *tag = jgets(ob, "tag");
    const char *type = jgets(ob, "type");
    snprintf(where, sizeof where, "outbounds[%zu]%s%s", idx, tag ? " " : "", tag ? tag : "");
    if (ob->t != J_OBJ) { ck_err(c, ob, "%s: ожидался объект", where); return; }
    if (!type) { ck_err(c, ob, "%s: нет type", where); return; }
    if (!tag) ck_err(c, ob, "%s: нет tag", where);
    ck_dial(c, ob, where);
    const char *srv_keys = " type tag server server_port network" DIAL_KEYS;
    enum sb_okind k = sb_outbound_kind(ob);
    if (!strcmp(type, "direct")) {
        ck_keys(c, ob, where, "type tag override_address override_port proxy_protocol" DIAL_KEYS);
    } else if (!strcmp(type, "block") || !strcmp(type, "dns")) {
        ck_keys(c, ob, where, "type tag");
    } else if (k == SBO_GROUP) {
        ck_keys(c, ob, where, "type tag outbounds default url interval tolerance idle_timeout"
                " interrupt_exist_connections");
        struct jval *m = jget(ob, "outbounds");
        if (!is_type(m, J_ARR) || !m->len) ck_err(c, ob, "%s: нужен непустой outbounds", where);
        for (size_t i = 0; i < jlen(m); i++) {
            struct jval *e = jat(m, i);
            if (e->t != J_STR) ck_err(c, e, "%s.outbounds: ожидались теги", where);
            else ck_outref(c, e, e->s, where);
        }
        const char *def = jgets(ob, "default");
        if (def) {
            int found = 0;
            for (size_t i = 0; i < jlen(m); i++)
                if (jat(m, i)->t == J_STR && !strcmp(jat(m, i)->s, def)) found = 1;
            if (!found) ck_err(c, jget(ob, "default"), "%s: default «%s» не из outbounds", where, def);
        }
        ck_duration(c, ob, "interval", where);
        ck_duration(c, ob, "idle_timeout", where);
        ck_type(c, ob, "url", J_STR, where);
        ck_type(c, ob, "tolerance", J_NUM, where);
    } else if (!strcmp(type, "vless")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s uuid flow tls packet_encoding multiplex transport encryption", srv_keys);
        ck_keys(c, ob, where, keys);
        if (!jgets(ob, "uuid")) ck_err(c, ob, "%s: нет uuid", where);
    } else if (!strcmp(type, "vmess")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s uuid security alter_id global_padding authenticated_length tls"
                 " packet_encoding multiplex transport", srv_keys);
        ck_keys(c, ob, where, keys);
        if (!jgets(ob, "uuid")) ck_err(c, ob, "%s: нет uuid", where);
    } else if (!strcmp(type, "trojan")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s password tls multiplex transport", srv_keys);
        ck_keys(c, ob, where, keys);
        if (!jgets(ob, "password")) ck_err(c, ob, "%s: нет password", where);
    } else if (!strcmp(type, "shadowsocks")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s method password plugin plugin_opts udp_over_tcp multiplex", srv_keys);
        ck_keys(c, ob, where, keys);
        if (!jgets(ob, "method")) ck_err(c, ob, "%s: нет method", where);
        if (jgets(ob, "plugin") && *jgets(ob, "plugin"))
            ck_err(c, jget(ob, "plugin"), "%s: плагины shadowsocks (%s) коннектор не поддерживает",
                   where, jgets(ob, "plugin"));
    } else if (!strcmp(type, "socks")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s version username password udp_over_tcp", srv_keys);
        ck_keys(c, ob, where, keys);
    } else if (!strcmp(type, "http")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s username password path headers tls", srv_keys);
        ck_keys(c, ob, where, keys);
    } else if (!strcmp(type, "hysteria2")) {
        char keys[512];
        snprintf(keys, sizeof keys, "%s server_ports hop_interval up_mbps down_mbps obfs password tls"
                 " brutal_debug", srv_keys);
        ck_keys(c, ob, where, keys);
        ck_duration(c, ob, "hop_interval", where);
    } else {
        ck_err(c, ob, "%s: выход типа «%s» коннектор пока не поддерживает", where, type);
        return;
    }
    if (k == SBO_TUNNEL) {
        if (!jgets(ob, "server")) ck_err(c, ob, "%s: нет server", where);
        ck_port(c, ob, "server_port", where, strcmp(type, "hysteria2") || !jget(ob, "server_ports"));
        ck_tls(c, jget(ob, "tls"), where, 0);
        ck_transport(c, jget(ob, "transport"), where);
        struct jval *mux = jget(ob, "multiplex");
        if (mux && jgetb(mux, "enabled", 0))
            ck_warn(c, mux, "%s: multiplex коннектор не ведёт — соединения пойдут без него", where);
    }
}

/* Круг detour: выход, через который идёт выход, через который идёт… первый. Глубина цепочки —
 * не больше числа выходов (иначе круг). */
static void ck_detour_cycles(struct ck *c) {
    const struct jval *obs = jget(c->cfg, "outbounds");
    size_t n = jlen(obs);
    for (size_t i = 0; i < n; i++) {
        const struct jval *cur = jat(obs, i);
        size_t steps = 0;
        while (cur && jgets(cur, "detour") && steps <= n) {
            cur = sb_outbound(c->cfg, jgets(cur, "detour"));
            steps++;
        }
        if (steps > n)
            ck_err(c, jat(obs, i), "outbounds: detour у «%s» ходит по кругу", jgets(jat(obs, i), "tag"));
    }
}

/* Ключи правил (route и dns) и логических правил. Список общий: у DNS и route он почти один, а
 * ключ не из своего раздела sing-box и так отвергает на разборе. */
#define RULE_MATCH_KEYS "type mode rules invert inbound ip_version network auth_user protocol client" \
    " domain domain_suffix domain_keyword domain_regex geosite source_geoip geoip source_ip_cidr" \
    " source_ip_is_private ip_cidr ip_is_private ip_accept_any source_port source_port_range port" \
    " port_range process_name process_path process_path_regex package_name user user_id clash_mode" \
    " network_type network_is_expensive network_is_constrained wifi_ssid wifi_bssid rule_set" \
    " rule_set_ip_cidr_match_source rule_set_ip_cidr_accept_empty query_type preferred_by" \
    " interface_address network_interface_address default_interface_address source_mac_address" \
    " source_hostname"

static void ck_match(struct ck *c, const struct jval *r, const char *where) {
    ck_strlist(c, r, "inbound", where);
    ck_strlist(c, r, "domain", where);
    ck_strlist(c, r, "domain_suffix", where);
    ck_strlist(c, r, "domain_keyword", where);
    ck_strlist(c, r, "domain_regex", where);
    ck_strlist(c, r, "protocol", where);
    ck_strlist(c, r, "network", where);
    ck_cidrs(c, r, "ip_cidr", where);
    ck_cidrs(c, r, "source_ip_cidr", where);
    struct jval *rs = jget(r, "rule_set");
    if (rs) {
        long n = jstrlist(rs, NULL, 0);
        if (n < 0) ck_err(c, rs, "%s.rule_set: ожидалась строка или массив строк", where);
        else {
            const char **l = calloc((size_t)n + 1, sizeof *l);
            if (l) {
                jstrlist(rs, l, (size_t)n);
                for (long i = 0; i < n; i++)
                    if (!sb_rule_set(c->cfg, l[i]))
                        ck_err(c, rs, "%s.rule_set: набора «%s» нет в route.rule_set", where, l[i]);
                free(l);
            }
        }
    }
    struct jval *in = jget(r, "inbound");
    if (in) {
        long n = jstrlist(in, NULL, 0);
        const char **l = n > 0 ? calloc((size_t)n, sizeof *l) : NULL;
        if (l) {
            jstrlist(in, l, (size_t)n);
            for (long i = 0; i < n; i++)
                if (!sb_inbound(c->cfg, l[i]))
                    ck_warn(c, in, "%s.inbound: входа «%s» нет — правило его не увидит", where, l[i]);
            free(l);
        }
    }
    const char *type = jgets(r, "type");
    if (type && !strcmp(type, "logical")) {
        const char *mode = jgets(r, "mode");
        if (!mode || (strcmp(mode, "and") && strcmp(mode, "or")))
            ck_err(c, r, "%s: у логического правила mode — and или or", where);
        struct jval *sub = jget(r, "rules");
        if (!is_type(sub, J_ARR) || !sub->len) ck_err(c, r, "%s: у логического правила нужен rules", where);
        for (size_t i = 0; i < jlen(sub); i++) {
            char w[200];
            snprintf(w, sizeof w, "%s.rules[%zu]", where, i);
            ck_match(c, jat(sub, i), w);
        }
    }
}

static void ck_route(struct ck *c, const struct jval *route) {
    if (!route) return;
    if (route->t != J_OBJ) { ck_err(c, route, "route: ожидался объект"); return; }
    ck_keys(c, route, "route", "rules rule_set final auto_detect_interface override_android_vpn"
            " default_interface default_mark default_domain_resolver default_network_strategy"
            " default_network_type default_fallback_network_type default_fallback_delay find_process"
            " geoip geosite");
    const char *fin = jgets(route, "final");
    if (fin) ck_outref(c, jget(route, "final"), fin, "route.final");
    struct jval *dr = jget(route, "default_domain_resolver");
    if (dr) {
        const char *s = dr->t == J_STR ? dr->s : jgets(dr, "server");
        if (s) ck_dnsref(c, dr, s, "route.default_domain_resolver");
    }
    struct jval *sets = jget(route, "rule_set");
    for (size_t i = 0; i < jlen(sets); i++) {
        struct jval *s = jat(sets, i);
        char w[256];
        const char *tag = jgets(s, "tag");
        snprintf(w, sizeof w, "route.rule_set[%zu]%s%s", i, tag ? " " : "", tag ? tag : "");
        const char *type = jgets(s, "type");
        if (!tag) ck_err(c, s, "%s: нет tag", w);
        if (!type) { ck_err(c, s, "%s: нет type", w); continue; }
        if (!strcmp(type, "local")) {
            ck_keys(c, s, w, "type tag format path");
            if (!jgets(s, "path")) ck_err(c, s, "%s: нет path", w);
        } else if (!strcmp(type, "remote")) {
            ck_keys(c, s, w, "type tag format url download_detour update_interval http_client");
            if (!jgets(s, "url")) ck_err(c, s, "%s: нет url", w);
            const char *dd = jgets(s, "download_detour");
            if (dd) ck_outref(c, jget(s, "download_detour"), dd, w);
            ck_duration(c, s, "update_interval", w);
        } else if (!strcmp(type, "inline")) {
            ck_keys(c, s, w, "type tag rules");
            struct jval *rules = jget(s, "rules");
            for (size_t k = 0; k < jlen(rules); k++) {
                char w2[200];
                snprintf(w2, sizeof w2, "%s.rules[%zu]", w, k);
                ck_keys(c, jat(rules, k), w2, RULE_MATCH_KEYS);
                ck_match(c, jat(rules, k), w2);
            }
        } else ck_err(c, s, "%s: неизвестный type «%s»", w, type);
        const char *fmt = jgets(s, "format");
        if (fmt && strcmp(fmt, "binary") && strcmp(fmt, "source"))
            ck_err(c, s, "%s: format — binary или source", w);
        for (size_t k = 0; k < i; k++)
            if (tag && jgets(jat(sets, k), "tag") && !strcmp(tag, jgets(jat(sets, k), "tag")))
                ck_err(c, s, "%s: тег набора повторяется", w);
    }
    struct jval *rules = jget(route, "rules");
    for (size_t i = 0; i < jlen(rules); i++) {
        struct jval *r = jat(rules, i);
        char w[64];
        snprintf(w, sizeof w, "route.rules[%zu]", i);
        ck_keys(c, r, w, RULE_MATCH_KEYS " action outbound override_address override_port"
                " network_strategy network_type fallback_network_type fallback_delay"
                " udp_disable_domain_unmapping udp_connect udp_timeout tls_fragment"
                " tls_fragment_fallback_delay tls_record_fragment method no_drop sniffer timeout"
                " strategy server disable_cache rewrite_ttl client_subnet");
        ck_match(c, r, w);
        const char *act = jgets(r, "action");
        if (!act) act = "route";
        if (!strcmp(act, "route")) {
            const char *o = jgets(r, "outbound");
            if (!o) ck_err(c, r, "%s: у route нужен outbound", w);
            else ck_outref(c, jget(r, "outbound"), o, w);
        } else if (!strcmp(act, "resolve")) {
            const char *s = jgets(r, "server");
            if (s) ck_dnsref(c, jget(r, "server"), s, w);
        } else if (strcmp(act, "sniff") && strcmp(act, "hijack-dns") && strcmp(act, "reject") &&
                   strcmp(act, "route-options") && strcmp(act, "bypass")) {
            ck_err(c, r, "%s: неизвестное действие «%s»", w, act);
        }
    }
}

static void ck_dns(struct ck *c, const struct jval *dns) {
    if (!dns) return;
    if (dns->t != J_OBJ) { ck_err(c, dns, "dns: ожидался объект"); return; }
    ck_keys(c, dns, "dns", "servers rules final strategy disable_cache disable_expire independent_cache"
            " cache_capacity reverse_mapping client_subnet fakeip");
    struct jval *servers = jget(dns, "servers");
    for (size_t i = 0; i < jlen(servers); i++) {
        struct jval *s = jat(servers, i);
        const char *tag = jgets(s, "tag");
        const char *type = jgets(s, "type");
        char w[256];
        snprintf(w, sizeof w, "dns.servers[%zu]%s%s", i, tag ? " " : "", tag ? tag : "");
        if (!tag) ck_err(c, s, "%s: нет tag", w);
        if (!type) {
            /* Прежний вид записи (address: "https://…") sing-box 1.12 ещё читает, но podkop и
             * forkop его не пишут — переводить его коннектор не берётся. */
            if (jgets(s, "address"))
                ck_err(c, s, "%s: прежняя запись сервера DNS (address) не поддерживается — нужен type", w);
            else ck_err(c, s, "%s: нет type", w);
            continue;
        }
        if (!strcmp(type, "udp") || !strcmp(type, "tcp") || !strcmp(type, "tls") ||
            !strcmp(type, "quic") || !strcmp(type, "https") || !strcmp(type, "h3")) {
            ck_keys(c, s, w, "type tag server server_port path headers tls" DIAL_KEYS);
            if (!jgets(s, "server")) ck_err(c, s, "%s: нет server", w);
            ck_port(c, s, "server_port", w, 0);
            ck_dial(c, s, w);
            ck_tls(c, jget(s, "tls"), w, 0);
        } else if (!strcmp(type, "fakeip")) {
            ck_keys(c, s, w, "type tag inet4_range inet6_range");
            ck_cidrs(c, s, "inet4_range", w);
            ck_cidrs(c, s, "inet6_range", w);
        } else if (!strcmp(type, "local") || !strcmp(type, "hosts")) {
            ck_keys(c, s, w, "type tag prefer_go path predefined" DIAL_KEYS);
        } else if (!strcmp(type, "tailscale")) {
            ck_err(c, s, "%s: tailscale коннектор не поддерживает", w);
        } else ck_err(c, s, "%s: сервер DNS типа «%s» коннектор не поддерживает", w, type);
        for (size_t k = 0; k < i; k++)
            if (tag && jgets(jat(servers, k), "tag") && !strcmp(tag, jgets(jat(servers, k), "tag")))
                ck_err(c, s, "%s: тег сервера повторяется", w);
    }
    const char *fin = jgets(dns, "final");
    if (fin) ck_dnsref(c, jget(dns, "final"), fin, "dns.final");
    const char *strat = jgets(dns, "strategy");
    if (strat && strcmp(strat, "prefer_ipv4") && strcmp(strat, "prefer_ipv6") &&
        strcmp(strat, "ipv4_only") && strcmp(strat, "ipv6_only"))
        ck_err(c, jget(dns, "strategy"), "dns.strategy: неизвестное значение «%s»", strat);
    struct jval *rules = jget(dns, "rules");
    for (size_t i = 0; i < jlen(rules); i++) {
        struct jval *r = jat(rules, i);
        char w[64];
        snprintf(w, sizeof w, "dns.rules[%zu]", i);
        ck_keys(c, r, w, RULE_MATCH_KEYS " action server outbound strategy disable_cache rewrite_ttl"
                " client_subnet method no_drop rcode answer ns extra");
        ck_match(c, r, w);
        const char *act = jgets(r, "action");
        if (!act) act = "route";
        if (!strcmp(act, "route")) {
            const char *s = jgets(r, "server");
            if (!s) ck_err(c, r, "%s: у route нужен server", w);
            else ck_dnsref(c, jget(r, "server"), s, w);
        } else if (strcmp(act, "reject") && strcmp(act, "route-options") && strcmp(act, "predefined")) {
            ck_err(c, r, "%s: неизвестное действие «%s»", w, act);
        }
    }
}

static void ck_inbounds(struct ck *c, const struct jval *ins) {
    for (size_t i = 0; i < jlen(ins); i++) {
        struct jval *in = jat(ins, i);
        const char *tag = jgets(in, "tag");
        const char *type = jgets(in, "type");
        char w[256];
        snprintf(w, sizeof w, "inbounds[%zu]%s%s", i, tag ? " " : "", tag ? tag : "");
        if (!type) { ck_err(c, in, "%s: нет type", w); continue; }
        const char *listen_keys = " type tag listen listen_port bind_interface routing_mark reuse_addr"
            " netns tcp_fast_open tcp_multi_path udp_fragment udp_timeout detour sniff"
            " sniff_override_destination sniff_timeout domain_strategy udp_disable_domain_unmapping";
        char keys[768];
        if (!strcmp(type, "tproxy")) {
            snprintf(keys, sizeof keys, "%s network", listen_keys);
            ck_keys(c, in, w, keys);
        } else if (!strcmp(type, "direct")) {
            snprintf(keys, sizeof keys, "%s network override_address override_port", listen_keys);
            ck_keys(c, in, w, keys);
        } else if (!strcmp(type, "mixed") || !strcmp(type, "socks") || !strcmp(type, "http")) {
            snprintf(keys, sizeof keys, "%s users set_system_proxy tls", listen_keys);
            ck_keys(c, in, w, keys);
        } else {
            ck_err(c, in, "%s: вход типа «%s» коннектор пока не поддерживает", w, type);
            continue;
        }
        ck_port(c, in, "listen_port", w, 1);
        ck_type(c, in, "listen", J_STR, w);
        for (size_t k = 0; k < i; k++)
            if (tag && jgets(jat(ins, k), "tag") && !strcmp(tag, jgets(jat(ins, k), "tag")))
                ck_err(c, in, "%s: тег входа повторяется", w);
    }
}

int sb_check(const struct jval *cfg, struct sbcheck *res) {
    memset(res, 0, sizeof *res);
    struct ck c = { res, cfg };
    if (!cfg || cfg->t != J_OBJ) {
        ck_err(&c, cfg, "конфиг должен быть объектом JSON");
        return -1;
    }
    ck_keys(&c, cfg, "конфиг", "log dns ntp certificate endpoints inbounds outbounds route services"
            " experimental $schema");
    struct jval *log = jget(cfg, "log");
    if (log) {
        ck_keys(&c, log, "log", "disabled level output timestamp");
        enum box_level lv;
        const char *l = jgets(log, "level");
        if (l && box_level_parse(l, &lv)) ck_err(&c, jget(log, "level"), "log.level: неизвестный уровень «%s»", l);
    }
    struct jval *eps = jget(cfg, "endpoints");
    for (size_t i = 0; i < jlen(eps); i++) {
        const char *t = jgets(jat(eps, i), "type");
        ck_err(&c, jat(eps, i), "endpoints[%zu]: %s коннектор не поддерживает", i, t ? t : "без типа");
    }
    struct jval *svcs = jget(cfg, "services");
    for (size_t i = 0; i < jlen(svcs); i++) {
        const char *t = jgets(jat(svcs, i), "type");
        ck_err(&c, jat(svcs, i), "services[%zu]: служба %s коннектором не поддерживается", i, t ? t : "без типа");
    }
    struct jval *obs = jget(cfg, "outbounds");
    if (obs && obs->t != J_ARR) ck_err(&c, obs, "outbounds: ожидался массив");
    for (size_t i = 0; i < jlen(obs); i++) {
        ck_outbound(&c, jat(obs, i), i);
        const char *tag = jgets(jat(obs, i), "tag");
        for (size_t k = 0; tag && k < i; k++)
            if (jgets(jat(obs, k), "tag") && !strcmp(tag, jgets(jat(obs, k), "tag")))
                ck_err(&c, jat(obs, i), "outbounds[%zu]: тег «%s» повторяется", i, tag);
    }
    ck_detour_cycles(&c);
    struct jval *ins = jget(cfg, "inbounds");
    if (ins && ins->t != J_ARR) ck_err(&c, ins, "inbounds: ожидался массив");
    ck_inbounds(&c, ins);
    ck_dns(&c, jget(cfg, "dns"));
    ck_route(&c, jget(cfg, "route"));
    struct jval *exp = jget(cfg, "experimental");
    if (exp) {
        ck_keys(&c, exp, "experimental", "cache_file clash_api v2ray_api debug");
        struct jval *api = jget(exp, "clash_api");
        if (api) {
            ck_keys(&c, api, "experimental.clash_api", "external_controller external_ui"
                    " external_ui_download_url external_ui_download_detour secret default_mode"
                    " access_control_allow_origin access_control_allow_private_network");
            ck_type(&c, api, "external_controller", J_STR, "experimental.clash_api");
        }
        struct jval *cf = jget(exp, "cache_file");
        if (cf) ck_keys(&c, cf, "experimental.cache_file", "enabled path cache_id store_fakeip store_rdrc rdrc_timeout");
        if (jget(exp, "v2ray_api")) ck_warn(&c, jget(exp, "v2ray_api"), "experimental.v2ray_api коннектор не ведёт");
    }
    return res->errors ? -1 : 0;
}

/* ---- sing-box check --------------------------------------------------------------------- */

#include "translate.h"
#include <unistd.h>
#include <sys/stat.h>
int box_validate_spec(const struct box_settings *set, const char *spec, const char *state, char *err, size_t errn);

/* Конфиг, годный для sing-box, ещё не значит годный для steer: перевод может дать спеку, которой
 * движок этой версии не примет. Поэтому check переводит конфиг во временный каталог и проверяет
 * спеку движком (`apply --dry-run`) — forkop и podkop увидят причину при старте, а не тишину.
 * Движка нет — проверка только по sing-box (её хватает `version`, `generate`, `rule-set`). */
static int check_with_steer(const struct jval *cfg) {
    struct box_settings set;
    box_settings_load(&set);
    if (!set.mark_mask) set.mark_mask = 0x000000ff;
    if (!set.rule_pref) set.rule_pref = 100;
    if (access(set.steerd, X_OK)) return 0;
    char dir[] = "/tmp/sing-box-check.XXXXXX";
    if (!mkdtemp(dir)) return 0;
    char rs[128], st[128], spec[128], err[600];
    snprintf(rs, sizeof rs, "%s/rulesets", set.state_dir);
    snprintf(st, sizeof st, "%s/state", dir);
    snprintf(spec, sizeof spec, "%s/spec.json", dir);
    mkdir(st, 0700);
    struct tr_opts to = { .dir = dir, .ruleset_dir = rs, .router_self = 1 };
    struct tr_result res;
    box_log_level(BL_ERROR);
    int rc = box_translate(cfg, &to, &res, err, sizeof err);
    if (rc) fprintf(stderr, "FATAL[0000] перевод в спеку steer: %s\n", err);
    else {
        box_translate_free(&res);
        rc = box_validate_spec(&set, spec, st, err, sizeof err);
        if (rc) fprintf(stderr, "FATAL[0000] steer не принимает переведённую спеку: %s\n", err);
    }
    char cmd[200];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    if (system(cmd)) {}
    return rc ? -1 : 0;
}

int cmd_check(const struct box_opts *o) {
    char err[512];
    box_log_level(BL_WARN);
    struct jval *cfg = box_load_config(o, err, sizeof err);
    if (!cfg) {
        fprintf(stderr, "FATAL[0000] decode config: %s\n", err);
        return 1;
    }
    /* Первая непустая строка вывода — то, что forkop кладёт в журнал причиной отказа. Поэтому
     * первый проход молчит и только находит первую ошибку, она печатается строкой FATAL, а
     * подробности (все ошибки и предупреждения) — вторым проходом, уже после неё. */
    struct sbcheck r;
    box_log_level(BL_FATAL);
    int rc = sb_check(cfg, &r);
    if (rc) fprintf(stderr, "FATAL[0000] %s\n", r.first);
    box_log_level(BL_WARN);
    sb_check(cfg, &r);
    if (!rc) rc = check_with_steer(cfg);
    json_free(cfg);
    return rc ? 1 : 0;
}
