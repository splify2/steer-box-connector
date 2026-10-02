/* Сообщения DNS для коннектора: разбор вопроса, ответы-заготовки, TTL, адреса ответа. */
#ifndef BOX_DNSMSG_H
#define BOX_DNSMSG_H
#include <stdint.h>
#include <stddef.h>

#define DNS_MAX 65535

struct dnsq {
    uint16_t id;
    char name[256];             /* нижним регистром, без точки в конце; корень — "" */
    uint16_t qtype, qclass;
    size_t qend;                /* конец секции вопроса */
    int edns;                   /* в запросе есть OPT */
    uint16_t udp_size;          /* из OPT; 512 без него */
};

/* 0 — это запрос с одним вопросом. */
int dnsq_parse(const uint8_t *p, size_t n, struct dnsq *q);

/* Ответ без записей с кодом rcode на вопрос p[0..q->qend). Возвращает длину. */
size_t dns_empty_reply(const uint8_t *p, const struct dnsq *q, int rcode, uint8_t *out, size_t cap);

/* Добавить к запросу запись OPT с опцией code (пустой) — запрос копируется в out. 0 — не влезло. */
size_t dns_add_opt(const uint8_t *p, size_t n, const struct dnsq *q, uint16_t code, uint8_t *out, size_t cap);

/* Код ответа и число ответов. */
int dns_rcode(const uint8_t *p, size_t n);
unsigned dns_ancount(const uint8_t *p, size_t n);

/* Пройти записи ответа: поменять TTL (rewrite >= 0 — поставить это значение; dec > 0 — вычесть
 * секунды, не опускаясь ниже 1) и/или собрать адреса A/AAAA. Возвращает наименьший TTL ответа
 * (-1 — записей нет или пакет испорчен). */
struct dns_ip { int family; uint8_t a[16]; };
long dns_walk(uint8_t *p, size_t n, long rewrite, long dec, struct dns_ip *ips, int max_ips, int *nips);

/* Собрать запрос name/qtype с номером id и опцией EDNS (UDP 1232). */
size_t dns_build_query(const char *name, uint16_t qtype, uint16_t id, uint8_t *out, size_t cap);

/* Имя типа (A, AAAA, HTTPS…) → номер; 0 — не знаю. Число строкой тоже принимается. */
uint16_t dns_type_num(const char *s);

#endif
