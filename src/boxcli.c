/* Подкоманды без движка: version, format, merge. */
#define _GNU_SOURCE
#include "box.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

/* Строка версии решает, что включат podkop и forkop (BOX_CONNECTOR.md, раздел 3б):
 *   - первая строка «sing-box version X» — X берут последним полем (forkop) или третьим
 *     (podkop), значит, в X не должно быть пробелов;
 *   - X ≥ 1.12.4, иначе podkop не стартует (диагностика хочет 1.12.4);
 *   - «extended» в X — forkop включает XHTTP и mtproxy; без него узлы xhttp он пропускает;
 *   - строка Tags: forkop разбирает её на слова; with_tailscale там нет нарочно — tailscale
 *     коннектор не умеет, и пусть forkop узнаёт это из Tags, а не из отказа check.
 * Ответ обязан прийти быстрее секунды (forkop убивает `version` через секунду), поэтому здесь
 * нет ни сети, ни запуска движка. */
int cmd_version(void) {
    struct box_settings s;
    box_settings_load(&s);
    struct utsname u;
    const char *arch = "unknown";
    if (!uname(&u)) arch = u.machine;
    const char *goarch = !strcmp(arch, "x86_64") ? "amd64"
                       : !strcmp(arch, "aarch64") ? "arm64"
                       : !strncmp(arch, "arm", 3) ? "arm"
                       : !strncmp(arch, "mips", 4) ? arch : arch;
    int ext = !strcmp(s.variant, "extended");
    printf("sing-box version %s%s\n\n", s.sb_version, ext ? "-extended" : "");
    printf("Environment: steer-box-connector %s linux/%s\n", BOX_VERSION, goarch);
    printf("Tags: with_quic,with_utls,with_clash_api,with_gvisor,with_wireguard\n");
    printf("Revision: steer-box-connector-%s\n", BOX_VERSION);
    printf("CGO: disabled\n");
    return 0;
}

/* format: напечатать конфиг с отступом в два пробела; `-w` — переписать файл на месте. Как у
 * sing-box, формат применяется к каждому -c отдельно. */
int cmd_format(const struct box_opts *o, int argc, char **argv) {
    int write_back = 0;
    for (int i = 0; i < argc; i++)
        if (!strcmp(argv[i], "-w") || !strcmp(argv[i], "--write")) write_back = 1;
    if (!o->nconfigs) {
        fprintf(stderr, "FATAL[0000] нужен -c <файл>\n");
        return 1;
    }
    for (size_t i = 0; i < o->nconfigs; i++) {
        char err[512];
        struct jval *v = json_parse_file(o->configs[i], err, sizeof err);
        if (!v) { fprintf(stderr, "FATAL[0000] %s\n", err); return 1; }
        if (write_back) {
            char tmp[1024];
            snprintf(tmp, sizeof tmp, "%s.tmp", o->configs[i]);
            FILE *f = fopen(tmp, "w");
            if (!f || json_write(f, v, 2) || fputc('\n', f) == EOF || fclose(f)) {
                fprintf(stderr, "FATAL[0000] %s: не записался\n", tmp);
                json_free(v);
                return 1;
            }
            if (rename(tmp, o->configs[i])) {
                fprintf(stderr, "FATAL[0000] %s: не переименовался\n", tmp);
                json_free(v);
                return 1;
            }
            fprintf(stderr, "%s\n", o->configs[i]);
        } else {
            json_write(stdout, v, 2);
            putchar('\n');
        }
        json_free(v);
    }
    return 0;
}

/* merge <выход>: слить все -c и -C в один файл. */
int cmd_merge(const struct box_opts *o, int argc, char **argv) {
    if (argc < 1) {
        fprintf(stderr, "FATAL[0000] merge: нужен путь выходного файла\n");
        return 1;
    }
    char err[512];
    struct jval *v = box_load_config(o, err, sizeof err);
    if (!v) { fprintf(stderr, "FATAL[0000] %s\n", err); return 1; }
    FILE *f = !strcmp(argv[0], "stdout") ? stdout : fopen(argv[0], "w");
    if (!f) { fprintf(stderr, "FATAL[0000] %s: не открывается\n", argv[0]); json_free(v); return 1; }
    json_write(f, v, 2);
    fputc('\n', f);
    if (f != stdout) fclose(f);
    json_free(v);
    return 0;
}
