/* boxrun.c: метки tproxy соседа (neutralize_family) и разбор строк. Два дефекта:
 *  - g_neut на 16 меток: лишние молча пропускались; теперь 17-я метка остаётся без правила, но
 *    об этом один раз сказано в журнале (g_neut_full), и счёт `ip rule add` — ровно 16;
 *  - strtok держит одно состояние на процесс: neut_tick в цикле событий и lan_devices в рабочем
 *    потоке (sel_work → translate_run) резали строки друг у друга. Теперь strtok_r.
 * Гонку ASan/UBSan детерминированно не ловят: второй сценарий проверяет результат разбора в
 * двух потоках на многих итерациях, а не отсутствие гонки. ip и uci — заглушки в PATH. */
// deps: src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/boxrun.c"
#include "check.h"
#include <pthread.h>
#include <sys/stat.h>

static char g_dir[64];

static void fake(const char *name, const char *body) {
    char path[300];
    snprintf(path, sizeof path, "%s/%s", g_dir, name);
    FILE *f = fopen(path, "w");
    if (!f) return;
    fputs(body, f);
    fclose(f);
    chmod(path, 0755);
}

static int count_adds(void) {
    char path[300], line[64];
    int n = 0;
    snprintf(path, sizeof path, "%s/adds", g_dir);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) n++;
    fclose(f);
    return n;
}

static struct box_rt t_rt;

#define ITER 300

static void *neut_thread(void *arg) {
    (void)arg;
    for (int i = 0; i < 40; i++) neutralize_family(&t_rt, 0);
    return NULL;
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/t_boxrun_neut.XXXXXX");
    if (!mkdtemp(g_dir)) return 2;
    char path[400];
    snprintf(path, sizeof path, "%s:%s", g_dir, getenv("PATH") ? getenv("PATH") : "/usr/bin:/bin");
    setenv("PATH", path, 1);

    char body[1500];
    snprintf(body, sizeof body,
        "#!/bin/sh\n"
        "case \"$2 $3\" in\n"
        "  \"rule show\") i=1; while [ $i -le 17 ]; do echo \"$((100+i)):\\tfrom all fwmark 0x$i lookup t$i\"; i=$((i+1)); done ;;\n"
        "  \"rule add\") echo \"$*\" >>%s/adds ;;\n"
        "  \"route show\") echo 'local default dev lo scope host' ;;\n"
        "esac\n"
        "exit 0\n", g_dir);
    fake("ip", body);
    fake("uci", "#!/bin/sh\necho 'br-a br-b br-c'\n");

    /* 1: 17 меток — правил ровно 16, о переполнении сказано. */
    neutralize_family(&t_rt, 0);
    CHECK(count_adds() == 16);
    CHECK(g_neut_n == 16);
    CHECK(g_neut_full == 1);
    neutralize_family(&t_rt, 0);                 /* повтор: новых правил нет */
    CHECK(count_adds() == 16);
    neutralize_undo();
    CHECK(g_neut_n == 0 && g_neut_full == 0);

    /* 2: lan_devices в этом потоке, neutralize_family в другом — разбор строк не мешает друг другу. */
    pthread_t th;
    pthread_create(&th, NULL, neut_thread, NULL);
    for (int i = 0; i < ITER; i++) {
        const char *dev[8];
        int n = lan_devices(dev, 8);
        CHECK(n == 3);
        if (n == 3) CHECK(!strcmp(dev[0], "br-a") && !strcmp(dev[1], "br-b") && !strcmp(dev[2], "br-c"));
        if (t_fails) break;
    }
    pthread_join(th, NULL);
    return T_DONE();
}
