/* sing-box generate: uuid, rand, reality-keypair, wg-keypair, tls-keypair.
 *
 * Кто зовёт и что разбирает — forkop, server/service.uc:613-712: первая непустая строка у uuid
 * и rand; строки «PrivateKey: …» и «PublicKey: …» у reality-keypair (ключи base64url без
 * набивки, как у sing-box и Xray); у tls-keypair — блоки PEM «PRIVATE KEY» и «CERTIFICATE» в
 * любом порядке. Криптография — только через слой примитивов steer (scrypto.h), как у всех
 * модулей. */
#include "box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "scrypto.h"

static void b64(const unsigned char *in, size_t n, int url, char *out) {
    const char *tab = url ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                          : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t j = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16 | (i + 1 < n ? in[i + 1] : 0) << 8 | (i + 2 < n ? in[i + 2] : 0);
        out[j++] = tab[v >> 18 & 63];
        out[j++] = tab[v >> 12 & 63];
        if (i + 1 < n) out[j++] = tab[v >> 6 & 63];
        else if (!url) out[j++] = '=';
        if (i + 2 < n) out[j++] = tab[v & 63];
        else if (!url) out[j++] = '=';
    }
    out[j] = 0;
}

static int gen_uuid(void) {
    unsigned char u[16];
    if (box_random(u, sizeof u)) return 1;
    u[6] = (u[6] & 0x0F) | 0x40;    /* версия 4 */
    u[8] = (u[8] & 0x3F) | 0x80;    /* вариант RFC 4122 */
    printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
           u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13],
           u[14], u[15]);
    return 0;
}

static int gen_rand(int argc, char **argv) {
    long n = -1;
    int base64 = 0, hex = 0;
    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i], "--base64")) base64 = 1;
        else if (!strcmp(argv[i], "--hex")) hex = 1;
        else if (n < 0) n = strtol(argv[i], NULL, 10);
    }
    if (n <= 0) {
        fprintf(stderr, "Error: accepts 1 arg(s), received 0\n");
        return 1;
    }
    unsigned char *buf = malloc((size_t)n);
    char *out = malloc((size_t)n * 2 + 8);
    if (!buf || !out || box_random(buf, (size_t)n)) { free(buf); free(out); return 1; }
    if (base64) {
        b64(buf, (size_t)n, 0, out);
        puts(out);
    } else if (hex) {
        for (long i = 0; i < n; i++) printf("%02x", buf[i]);
        putchar('\n');
    } else {
        fwrite(buf, 1, (size_t)n, stdout);
    }
    free(buf);
    free(out);
    return 0;
}

/* Пара X25519: закрытый ключ — 32 случайных байта с прижатием по RFC 7748 (так его хранят
 * sing-box и Xray), открытый — его образ на базовой точке. */
static int x25519_pair(unsigned char priv[32], unsigned char pub[32]) {
    if (box_random(priv, 32)) return -1;
    priv[0] &= 248;
    priv[31] &= 127;
    priv[31] |= 64;
    return sc_x25519_base(pub, priv) ? -1 : 0;
}

static int gen_x25519(int url) {
    unsigned char priv[32], pub[32];
    char a[64], b[64];
    if (x25519_pair(priv, pub)) {
        fprintf(stderr, "FATAL[0000] не удалось получить пару X25519\n");
        return 1;
    }
    b64(priv, 32, url, a);
    b64(pub, 32, url, b);
    printf("PrivateKey: %s\nPublicKey: %s\n", a, b);
    return 0;
}

/* Самоподписанный сертификат ECDSA P-256 на имя name, как `sing-box generate tls-keypair`:
 * CN и dNSName — это имя, срок — months месяцев. Ключ и подпись — scrypto (sc_ecdsa_p256_*),
 * сам сертификат (DER) собирает box/x509.c. */
/* Выпуск сертификата нужен серверному режиму forkop (`generate tls-keypair <имя>`), а подписи
 * ECDSA в слое примитивов steer пока нет: проверка у клиента есть, выпуска нет. До тех пор —
 * отказ словами, а не пустой вывод, который forkop принял бы за ключ. */
static int box_tls_selfsigned(const char *name, int months, FILE *out) {
    (void)name; (void)months; (void)out;
    fprintf(stderr, "FATAL[0000] generate tls-keypair коннектор пока не умеет: в steer нет подписи "
                    "ECDSA для выпуска сертификата\n");
    return 1;
}

static int gen_tls(const char *name, int months) {
    return box_tls_selfsigned(name, months, stdout);
}

int cmd_generate(int argc, char **argv) {
    if (argc < 1) {
        puts("Usage:\n  sing-box generate [command]\n\nAvailable Commands:\n"
             "  rand            Generate random bytes\n"
             "  reality-keypair Generate reality key pair\n"
             "  tls-keypair     Generate TLS self sign key pair\n"
             "  uuid            Generate UUID string\n"
             "  wg-keypair      Generate WireGuard key pair");
        return 0;
    }
    if (!strcmp(argv[0], "uuid")) return gen_uuid();
    if (!strcmp(argv[0], "rand")) return gen_rand(argc - 1, argv + 1);
    if (!strcmp(argv[0], "reality-keypair")) return gen_x25519(1);
    if (!strcmp(argv[0], "wg-keypair")) return gen_x25519(0);
    if (!strcmp(argv[0], "tls-keypair")) {
        const char *name = NULL;
        int months = 1;
        for (int i = 1; i < argc; i++) {
            if ((!strcmp(argv[i], "-m") || !strcmp(argv[i], "--months")) && i + 1 < argc)
                months = atoi(argv[++i]);
            else if (!name) name = argv[i];
        }
        if (!name) {
            fprintf(stderr, "Error: accepts 1 arg(s), received 0\n");
            return 1;
        }
        return gen_tls(name, months);
    }
    fprintf(stderr, "Error: unknown command \"%s\" for \"sing-box generate\"\n", argv[0]);
    return 1;
}
