/* Сообщения DNS — см. dnsmsg.h. */
#include "dnsmsg.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <strings.h>

static int skip_name(const uint8_t *p, size_t n, size_t *off) {
    size_t o = *off;
    for (int guard = 0; guard < 128; guard++) {
        if (o >= n) return -1;
        uint8_t l = p[o];
        if (l == 0) { *off = o + 1; return 0; }
        if ((l & 0xC0) == 0xC0) { if (o + 2 > n) return -1; *off = o + 2; return 0; }
        if (l & 0xC0) return -1;
        o += 1u + l;
    }
    return -1;
}

int dnsq_parse(const uint8_t *p, size_t n, struct dnsq *q) {
    memset(q, 0, sizeof *q);
    if (n < 12) return -1;
    if (p[2] & 0x80) return -1;
    if (((p[4] << 8) | p[5]) != 1) return -1;
    q->id = (uint16_t)((p[0] << 8) | p[1]);
    size_t o = 12, j = 0;
    for (int guard = 0; guard < 128; guard++) {
        if (o >= n) return -1;
        uint8_t l = p[o++];
        if (!l) break;
        if (l & 0xC0) return -1;            /* в вопросе сжатия не бывает */
        if (o + l > n || j + l + 1 >= sizeof q->name) return -1;
        if (j) q->name[j++] = '.';
        for (uint8_t i = 0; i < l; i++) q->name[j++] = (char)tolower(p[o + i]);
        o += l;
    }
    q->name[j] = 0;
    if (o + 4 > n) return -1;
    q->qtype = (uint16_t)((p[o] << 8) | p[o + 1]);
    q->qclass = (uint16_t)((p[o + 2] << 8) | p[o + 3]);
    q->qend = o + 4;
    q->udp_size = 512;
    unsigned an = (unsigned)((p[6] << 8) | p[7]), ns = (unsigned)((p[8] << 8) | p[9]),
             ar = (unsigned)((p[10] << 8) | p[11]);
    o = q->qend;
    for (unsigned i = 0; i < an + ns + ar; i++) {
        if (skip_name(p, n, &o) || o + 10 > n) break;
        uint16_t type = (uint16_t)((p[o] << 8) | p[o + 1]);
        uint16_t cls = (uint16_t)((p[o + 2] << 8) | p[o + 3]);
        uint16_t rdl = (uint16_t)((p[o + 8] << 8) | p[o + 9]);
        if (type == 41) { q->edns = 1; q->udp_size = cls < 512 ? 512 : cls; }
        o += 10u + rdl;
    }
    return 0;
}

size_t dns_empty_reply(const uint8_t *p, const struct dnsq *q, int rcode, uint8_t *out, size_t cap) {
    if (q->qend > cap) return 0;
    memcpy(out, p, q->qend);
    out[2] = (uint8_t)(0x80 | (p[2] & 0x79));      /* QR, opcode и RD из запроса */
    out[3] = (uint8_t)(0x80 | (rcode & 0x0F));     /* RA */
    out[6] = out[7] = out[8] = out[9] = out[10] = out[11] = 0;
    return q->qend;
}

size_t dns_add_opt(const uint8_t *p, size_t n, const struct dnsq *q, uint16_t code, uint8_t *out, size_t cap) {
    /* Запрос без своих записей OPT: вопрос и новая OPT. Чужие записи дополнительной секции
     * (OPT клиента с ECS, cookie) отбрасываются — резолверу steer они ни к чему. */
    (void)n;
    if (q->qend + 15 > cap) return 0;
    memcpy(out, p, q->qend);
    out[6] = out[7] = out[8] = out[9] = 0;
    out[10] = 0;
    out[11] = 1;
    size_t o = q->qend;
    out[o++] = 0;                                   /* имя — корень */
    out[o++] = 0; out[o++] = 41;                    /* OPT */
    out[o++] = 0x04; out[o++] = 0xD0;               /* UDP 1232 */
    out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;
    out[o++] = 0; out[o++] = 4;                     /* rdlen */
    out[o++] = (uint8_t)(code >> 8); out[o++] = (uint8_t)code;
    out[o++] = 0; out[o++] = 0;
    return o;
}

int dns_rcode(const uint8_t *p, size_t n) { return n >= 4 ? (p[3] & 0x0F) : -1; }

unsigned dns_ancount(const uint8_t *p, size_t n) { return n >= 8 ? (unsigned)((p[6] << 8) | p[7]) : 0; }

long dns_walk(uint8_t *p, size_t n, long rewrite, long dec, struct dns_ip *ips, int max_ips, int *nips) {
    if (nips) *nips = 0;
    if (n < 12) return -1;
    unsigned qd = (unsigned)((p[4] << 8) | p[5]), an = (unsigned)((p[6] << 8) | p[7]),
             ns = (unsigned)((p[8] << 8) | p[9]), ar = (unsigned)((p[10] << 8) | p[11]);
    size_t o = 12;
    for (unsigned i = 0; i < qd; i++) {
        if (skip_name(p, n, &o) || o + 4 > n) return -1;
        o += 4;
    }
    long min = -1;
    for (unsigned i = 0; i < an + ns + ar; i++) {
        if (skip_name(p, n, &o) || o + 10 > n) return -1;
        uint16_t type = (uint16_t)((p[o] << 8) | p[o + 1]);
        uint32_t ttl = (uint32_t)p[o + 4] << 24 | (uint32_t)p[o + 5] << 16 | (uint32_t)p[o + 6] << 8 | p[o + 7];
        uint16_t rdl = (uint16_t)((p[o + 8] << 8) | p[o + 9]);
        if (o + 10 + rdl > n) return -1;
        if (type != 41) {
            if (rewrite >= 0) ttl = (uint32_t)rewrite;
            else if (dec > 0) ttl = ttl > (uint32_t)dec ? ttl - (uint32_t)dec : 1;
            p[o + 4] = (uint8_t)(ttl >> 24); p[o + 5] = (uint8_t)(ttl >> 16);
            p[o + 6] = (uint8_t)(ttl >> 8); p[o + 7] = (uint8_t)ttl;
            if (i < an && (min < 0 || (long)ttl < min)) min = (long)ttl;
            if (i < an && ips && nips && *nips < max_ips) {
                if (type == 1 && rdl == 4) { ips[*nips].family = 4; memcpy(ips[*nips].a, p + o + 10, 4); (*nips)++; }
                else if (type == 28 && rdl == 16) { ips[*nips].family = 6; memcpy(ips[*nips].a, p + o + 10, 16); (*nips)++; }
            }
        }
        o += 10u + rdl;
    }
    return min;
}

size_t dns_build_query(const char *name, uint16_t qtype, uint16_t id, uint8_t *out, size_t cap) {
    size_t nl = strlen(name);
    if (12 + nl + 2 + 4 + 11 > cap) return 0;
    memset(out, 0, 12);
    out[0] = (uint8_t)(id >> 8);
    out[1] = (uint8_t)id;
    out[2] = 0x01;                                  /* RD */
    out[5] = 1;
    out[11] = 1;
    size_t o = 12;
    const char *s = name;
    while (*s) {
        const char *d = strchr(s, '.');
        size_t l = d ? (size_t)(d - s) : strlen(s);
        if (!l || l > 63) return 0;
        out[o++] = (uint8_t)l;
        memcpy(out + o, s, l);
        o += l;
        s += l;
        if (*s == '.') s++;
    }
    out[o++] = 0;
    out[o++] = (uint8_t)(qtype >> 8); out[o++] = (uint8_t)qtype;
    out[o++] = 0; out[o++] = 1;
    out[o++] = 0; out[o++] = 0; out[o++] = 41;
    out[o++] = 0x04; out[o++] = 0xD0;
    out[o++] = 0; out[o++] = 0; out[o++] = 0; out[o++] = 0;
    out[o++] = 0; out[o++] = 0;
    return o;
}

uint16_t dns_type_num(const char *s) {
    static const struct { const char *n; uint16_t v; } t[] = {
        { "A", 1 }, { "NS", 2 }, { "CNAME", 5 }, { "SOA", 6 }, { "PTR", 12 }, { "MX", 15 },
        { "TXT", 16 }, { "AAAA", 28 }, { "SRV", 33 }, { "NAPTR", 35 }, { "OPT", 41 },
        { "DS", 43 }, { "RRSIG", 46 }, { "DNSKEY", 48 }, { "SVCB", 64 }, { "HTTPS", 65 },
        { "ANY", 255 }, { "CAA", 257 },
    };
    if (!s) return 0;
    if (*s >= '0' && *s <= '9') return (uint16_t)atoi(s);
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (!strcasecmp(t[i].n, s)) return t[i].v;
    return 0;
}
