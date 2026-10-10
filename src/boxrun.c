/* sing-box run: перевод конфига, свой экземпляр steer, плоскость управления.
 *
 * Порядок старта (BOX_CONNECTOR.md, раздел 3в):
 *   1. конфиг: загрузить, проверить (как check), перевести в спеку;
 *   2. правила «метка tproxy соседа → main» (ниже, «Нейтрализатор»);
 *   3. steerd ребёнком: свои --spec, --state-dir, --socket; поле метки и приоритет правил — из
 *      окружения (STEER_MARK_FIELD, STEER_RULE_PREF), таблица nft — своя (STEER_NFT_TABLE);
 *   4. части: DNS, Clash API, mixed, наборы правил, слушатели-заглушки tproxy.
 * SIGHUP — перечитать конфиг и применить; SIGTERM/SIGINT — снять всё и выйти. */
#define _GNU_SOURCE
#include "runtime.h"
#include "sbconf.h"
#include "translate.h"
#include "steerctl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>
#include <sys/epoll.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

struct box_rt *g_rt;

/* ---- соответствия и задержки ------------------------------------------------------------ */

const char *rt_steer_name(struct box_rt *rt, const char *tag) {
    const char *n = jgets(jget(jget(rt->map, "outbounds"), tag), "name");
    return n && *n ? n : NULL;
}

const char *rt_tag_of(struct box_rt *rt, const char *steer_name) {
    const struct jval *obs = jget(rt->map, "outbounds");
    for (size_t i = 0; i < jlen(obs); i++) {
        const char *n = jgets(obs->o[i].val, "name");
        if (n && !strcmp(n, steer_name)) return obs->o[i].key;
    }
    return NULL;
}

const char *rt_clash_type(struct box_rt *rt, const char *tag) {
    const char *t = jgets(jget(jget(rt->map, "outbounds"), tag), "type");
    return t ? t : "Unknown";
}

void rt_delay_put(struct box_rt *rt, const char *tag, int delay) {
    struct delay_rec *d = NULL;
    for (size_t i = 0; i < rt->delays_n; i++)
        if (!strcmp(rt->delays[i].tag, tag)) d = &rt->delays[i];
    if (!d) {
        if (rt->delays_n == rt->delays_cap) {
            size_t nc = rt->delays_cap ? rt->delays_cap * 2 : 16;
            struct delay_rec *nd = realloc(rt->delays, nc * sizeof *nd);
            if (!nd) return;
            rt->delays = nd;
            rt->delays_cap = nc;
        }
        d = &rt->delays[rt->delays_n++];
        snprintf(d->tag, sizeof d->tag, "%s", tag);
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    d->time_ms = (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    d->delay = delay;
}

const struct delay_rec *rt_delay_get(struct box_rt *rt, const char *tag) {
    for (size_t i = 0; i < rt->delays_n; i++)
        if (!strcmp(rt->delays[i].tag, tag)) return &rt->delays[i];
    return NULL;
}

/* ---- куда идут свои соединения ---------------------------------------------------------- */

/* Устройство маршрута по умолчанию (IPv4) — как auto_detect_interface sing-box. */
static void default_route_dev(char *out, size_t n) {
    out[0] = 0;
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return;
    char line[256], dev[32];
    unsigned long dst, mask;
    unsigned flags;
    int metric, best = 1 << 30;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%31s %lx %*x %x %*d %*d %d %lx", dev, &dst, &flags, &metric, &mask) != 5) continue;
        if (dst || mask || !(flags & 1)) continue;
        if (metric < best) { best = metric; snprintf(out, n, "%s", dev); }
    }
    fclose(f);
}

int rt_egress(struct box_rt *rt, const char *tag, struct egress *eg, char *err, size_t errn) {
    memset(eg, 0, sizeof *eg);
    /* Метка своих сокетов: route.default_mark (forkop ждёт 0x08000000) и всё поле метки steer —
     * значение «сам движок»: правило `self` (трафик самого роутера) такие сокеты не берёт. */
    eg->mark = rt->default_mark | rt->set.mark_mask;
    const struct jval *ob = tag ? sb_outbound(rt->cfg, tag) : NULL;
    enum sb_okind k = ob ? sb_outbound_kind(ob) : SBO_DIRECT;
    if (!tag || !ob || k == SBO_DIRECT) {
        /* Напрямую — привязкой к устройству WAN, как sing-box с auto_detect_interface: метка
         * соседа (podkop, forkop) не уведёт такой сокет ни в его tproxy, ни в наш туннель. */
        if (rt->default_dev[0]) snprintf(eg->dev, sizeof eg->dev, "%s", rt->default_dev);
        else default_route_dev(eg->dev, sizeof eg->dev);
        return 0;
    }
    if (k == SBO_INTERFACE) {
        snprintf(eg->dev, sizeof eg->dev, "%s", jgets(ob, "bind_interface"));
        return 0;
    }
    if (k == SBO_REMARK) {
        const struct jval *m = jget(ob, "routing_mark");
        eg->mark = m->t == J_NUM ? (uint32_t)m->i : (uint32_t)strtoul(m->s, NULL, 0);
        return 0;
    }
    const char *name = rt_steer_name(rt, tag);
    if (!name) { snprintf(err, errn, "у выхода %s нет вида в steer", tag); return -1; }
    /* Устройство — по последнему status: у группы это лист выбранного члена. */
    const struct jval *o = jget(jget(rt->status, "outputs"), name);
    const char *dev = jgets(o, "device");
    if (o && jget(o, "group")) {
        const char *sel = jgets(jget(o, "group"), "selected");
        if (!sel) { snprintf(err, errn, "группа %s сейчас без живого члена", tag); return -1; }
    }
    if (!dev) {
        /* status ещё не пришёл — устройство туннеля известно из спеки. */
        const char *sp = jgets(jget(jget(jget(rt->map, "_spec_outputs"), name), "device"), NULL);
        (void)sp;
        snprintf(err, errn, "устройство выхода %s пока неизвестно", tag);
        return -1;
    }
    snprintf(eg->dev, sizeof eg->dev, "%s", dev);
    return 0;
}

/* ---- status ----------------------------------------------------------------------------- */

struct status_job {
    struct box_rt *rt;
    char sock[600];
    struct jval *res;
};

static void status_work(void *p) {
    struct status_job *j = p;
    char err[256];
    j->res = steerctl_json(j->sock, "status", 15000, err, sizeof err);
    if (!j->res) LOGD("status: %s", err);
}

static void status_done(void *p) {
    struct status_job *j = p;
    j->rt->status_busy = 0;
    if (j->res) {
        json_free(j->rt->status);
        j->rt->status = j->res;
        j->rt->status_at = ev_now_ms();
    }
    free(j);
}

void rt_status_refresh(struct box_rt *rt) {
    if (rt->status_busy || !rt->steerd) return;
    struct status_job *j = calloc(1, sizeof *j);
    if (!j) return;
    j->rt = rt;
    snprintf(j->sock, sizeof j->sock, "%s", rt->sock);
    rt->status_busy = 1;
    if (ev_spawn(rt->ev, status_work, status_done, j)) { rt->status_busy = 0; free(j); }
}

static void status_tick(struct ev *ev, void *arg) {
    struct box_rt *rt = arg;
    rt_status_refresh(rt);
    ev_timer(ev, 3000, status_tick, rt);
}

/* ---- нейтрализатор -----------------------------------------------------------------------
 *
 * podkop и forkop ставят `ip rule fwmark M/M lookup <своя таблица>` (105) и в ней
 * `local default dev lo` — так помеченный их nft пакет доставляется сокету tproxy sing-box.
 * Прозрачного сокета у нас нет, и такой пакет ушёл бы локальному стеку в никуда (RST). Поэтому
 * перед их правилом встаёт наше: та же метка — в main, то есть ровно то, что sing-box сделал бы
 * трафику, не попавшему ни в одно правило (direct-out). Пакеты, которые забрал steer, до этого
 * правила не доходят: правила steer стоят ещё выше (STEER_RULE_PREF). Правила соседа не
 * трогаются; находятся они по своей таблице, а не по имени, — поэтому одинаково и для podkop, и
 * для forkop, и для будущих форков. */

struct neut { int v6; char mark[48]; unsigned pref; };
static struct neut g_neut[16];
static size_t g_neut_n;

static int run_cmd(const char *const argv[], char *out, size_t outn) {
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC)) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); return -1; }
    if (!pid) {
        dup2(pfd[1], 1);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, 2);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    size_t got = 0;
    ssize_t r;
    while (out && got + 1 < outn && (r = read(pfd[0], out + got, outn - got - 1)) > 0) got += (size_t)r;
    char sink[512];
    while (read(pfd[0], sink, sizeof sink) > 0) {}
    close(pfd[0]);
    if (out) out[got] = 0;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void neutralize_family(struct box_rt *rt, int v6) {
    static char buf[16384], rbuf[4096];
    const char *fam = v6 ? "-6" : "-4";
    const char *list[] = { "ip", fam, "rule", "show", NULL };
    if (run_cmd(list, buf, sizeof buf)) return;
    for (char *line = strtok(buf, "\n"); line; line = strtok(NULL, "\n")) {
        unsigned pref;
        char mark[48], table[64];
        const char *fm = strstr(line, "fwmark ");
        const char *lk = strstr(line, "lookup ");
        if (!fm || !lk || sscanf(line, "%u:", &pref) != 1) continue;
        if (sscanf(fm + 7, "%47s", mark) != 1 || sscanf(lk + 7, "%63s", table) != 1) continue;
        if (!strcmp(table, "main") || !strcmp(table, "local") || !strcmp(table, "default")) continue;
        if (pref <= rt->set.rule_pref + 1) continue;      /* наши и steer */
        char tb[64];
        snprintf(tb, sizeof tb, "%s", table);
        const char *rl[] = { "ip", fam, "route", "show", "table", tb, NULL };
        if (run_cmd(rl, rbuf, sizeof rbuf)) continue;
        if (!strstr(rbuf, "local default dev lo") && !strstr(rbuf, "local ::/0 dev lo")) continue;
        int have = 0;
        for (size_t i = 0; i < g_neut_n; i++)
            if (g_neut[i].v6 == v6 && !strcmp(g_neut[i].mark, mark)) have = 1;
        if (have || g_neut_n >= sizeof g_neut / sizeof g_neut[0]) continue;
        char p[16];
        snprintf(p, sizeof p, "%u", rt->set.rule_pref + 1);
        const char *add[] = { "ip", fam, "rule", "add", "fwmark", mark, "lookup", "main", "pref", p, NULL };
        if (run_cmd(add, NULL, 0) == 0) {
            g_neut[g_neut_n].v6 = v6;
            snprintf(g_neut[g_neut_n].mark, sizeof g_neut[g_neut_n].mark, "%s", mark);
            g_neut[g_neut_n].pref = rt->set.rule_pref + 1;
            g_neut_n++;
            LOGI("метка tproxy %s (таблица %s, приоритет %u) идёт в main: прозрачного сокета у коннектора нет",
                 mark, table, pref);
        }
    }
}

static void neutralize(struct box_rt *rt) {
    neutralize_family(rt, 0);
    neutralize_family(rt, 1);
}

static void neutralize_undo(void) {
    for (size_t i = 0; i < g_neut_n; i++) {
        char p[16];
        snprintf(p, sizeof p, "%u", g_neut[i].pref);
        const char *del[] = { "ip", g_neut[i].v6 ? "-6" : "-4", "rule", "del", "fwmark", g_neut[i].mark,
                              "lookup", "main", "pref", p, NULL };
        run_cmd(del, NULL, 0);
    }
    g_neut_n = 0;
}

static void neut_tick(struct ev *ev, void *arg) {
    /* Сосед перезапускается (podkop restart — новые правила 105): сверяемся раз в 15 с. */
    neutralize(arg);
    ev_timer(ev, 15000, neut_tick, arg);
}

/* ---- steerd ----------------------------------------------------------------------------- */

static void child_env_set(const struct box_settings *set) {
    char v[32];
    snprintf(v, sizeof v, "0x%08x", set->mark_mask ? set->mark_mask : 0x000000ffu);
    setenv("STEER_MARK_FIELD", v, 1);
    snprintf(v, sizeof v, "%u", set->rule_pref ? set->rule_pref : 100);
    setenv("STEER_RULE_PREF", v, 1);
    setenv("STEER_NFT_TABLE", "sbox", 1);
    /* Решение steer — обратно, если цепочка podkop/forkop переписала метку целиком
     * (generate.c, build_mark_restore). */
    setenv("STEER_MARK_RESTORE", "1", 1);
    /* Трафик самого роутера к адресам из списков — по тем же правилам (platform.c). */
    setenv("STEER_ROUTER_SELF", "1", 1);
}

static void child_env(struct box_rt *rt) { child_env_set(&rt->set); }

int box_validate_spec(const struct box_settings *set, const char *spec, const char *state, char *err, size_t errn) {
    if (access(set->steerd, X_OK)) { snprintf(err, errn, "нет ядра steer %s", set->steerd); return -1; }
    int pfd[2];
    if (pipe2(pfd, O_CLOEXEC)) { snprintf(err, errn, "pipe: %s", strerror(errno)); return -1; }
    pid_t pid = fork();
    if (pid < 0) { close(pfd[0]); close(pfd[1]); snprintf(err, errn, "fork: %s", strerror(errno)); return -1; }
    if (!pid) {
        child_env_set(set);
        dup2(pfd[1], 2);
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, 1);
        const char *argv[] = { set->steerd, "apply", "--dry-run", "--spec", spec, "--state-dir", state, NULL };
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    char buf[4096];
    size_t got = 0;
    ssize_t r;
    while (got + 1 < sizeof buf && (r = read(pfd[0], buf + got, sizeof buf - got - 1)) > 0) got += (size_t)r;
    char sink[512];
    while (read(pfd[0], sink, sizeof sink) > 0) {}
    close(pfd[0]);
    buf[got] = 0;
    int st = 0;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    if (WIFEXITED(st) && WEXITSTATUS(st) == 0) return 0;
    /* Первая строка отказа — она и есть причина («…: clients.router.self: …»). */
    char *line = buf;
    for (char *p = strtok(buf, "\n"); p; p = strtok(NULL, "\n"))
        if (strstr(p, "steer") || strstr(p, ":")) { line = p; break; }
    snprintf(err, errn, "%s", *line ? line : "apply --dry-run завершился отказом");
    return -1;
}

static pid_t spawn_steerd(struct box_rt *rt) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        child_env(rt);
        sigset_t s;
        sigemptyset(&s);
        sigprocmask(SIG_SETMASK, &s, NULL);
        /* Движок живёт не дольше коннектора. procd, не дождавшись выхода, добивает sing-box
         * SIGKILL — и steerd без этого оставался сиротой с нашим сокетом: каждый следующий запуск
         * натыкался на «уже отвечает другой сервер» и выходил, а DNS и маршрутизация стояли. */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1) _exit(1);       /* родитель умер раньше, чем мы успели попросить */
        const char *argv[] = { rt->set.steerd, "daemon", "--watch", "--supervise", "--apply",
                               "--spec", rt->spec, "--state-dir", rt->state, "--socket", rt->sock, NULL };
        execv(argv[0], (char *const *)argv);
        fprintf(stderr, "ERROR[0000] не запускается %s: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    return pid;
}

static int wait_socket(struct box_rt *rt, int ms) {
    long long until = ev_now_ms() + ms;
    while (ev_now_ms() < until) {
        char err[256];
        struct jval *v = steerctl_call(rt->sock, "version", NULL, 0, 2000, err, sizeof err);
        if (v) { json_free(v); return 0; }
        int st;
        if (waitpid(rt->steerd, &st, WNOHANG) == rt->steerd) { rt->steerd = 0; return -1; }
        usleep(100 * 1000);
    }
    return -1;
}

/* Процесс pid — демон steer (argv[0] — steerd или steer, argv[1] — daemon)? В spec — значение
 * его --spec или "". По словам argv, а не подстрокой: подстроку «steerd daemon» содержит и
 * командная строка оболочки, которая про него спрашивает (pgrep -f в ssh). */
static int steer_daemon_proc(const char *pid, char *spec, size_t specn) {
    char path[64], cmd[2048];
    snprintf(path, sizeof path, "/proc/%s/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, cmd, sizeof cmd - 1);
    close(fd);
    if (n <= 0) return 0;
    cmd[n] = 0;
    const char *argv[64];
    int argc = 0;
    for (ssize_t i = 0; i < n && argc < 64; i += (ssize_t)strlen(cmd + i) + 1) argv[argc++] = cmd + i;
    if (argc < 2 || strcmp(argv[1], "daemon")) return 0;
    const char *b = strrchr(argv[0], '/');
    b = b ? b + 1 : argv[0];
    if (strcmp(b, "steerd") && strcmp(b, "steer")) return 0;
    spec[0] = 0;
    for (int i = 2; i + 1 < argc; i++)
        if (!strcmp(argv[i], "--spec")) snprintf(spec, specn, "%s", argv[i + 1]);
    return 1;
}

/* Свой ли это steerd: другой экземпляр (служба steer владельца) держал бы таблицу маршрутизации
 * 300+ и поле метки там же, где наш, — делить их steer пока не умеет. */
static int foreign_steerd(struct box_rt *rt) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    int found = 0;
    while (!found && (de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char spec[512];
        if (steer_daemon_proc(de->d_name, spec, sizeof spec) && strcmp(spec, rt->spec))
            found = atoi(de->d_name);
    }
    closedir(d);
    return found;
}

/* steerd нашего экземпляра (с нашей спекой), оставшийся от прежнего запуска: родителя убили
 * раньше, чем он погасил движок (SIGKILL от procd, OOM). Его сокет занят, и новый steerd не
 * поднялся бы. Гасим его, как погасили бы свой: SIGTERM, потом SIGKILL. 1 — нашёлся. */
static int reap_orphans(struct box_rt *rt) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    pid_t pids[16];
    int n = 0;
    while (n < 16 && (de = readdir(d))) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        char spec[512];
        if (steer_daemon_proc(de->d_name, spec, sizeof spec) && !strcmp(spec, rt->spec))
            pids[n++] = (pid_t)atoi(de->d_name);
    }
    closedir(d);
    for (int i = 0; i < n; i++) {
        LOGW("ядро steer прежнего запуска (pid %d) ещё работает — гашу его", (int)pids[i]);
        kill(pids[i], SIGTERM);
    }
    for (int t = 0; t < 100 && n; t++) {
        int alive = 0;
        for (int i = 0; i < n; i++) if (!kill(pids[i], 0)) alive++;
        if (!alive) break;
        usleep(100 * 1000);
    }
    for (int i = 0; i < n; i++) kill(pids[i], SIGKILL);
    return n > 0;
}

/* ---- перевод и применение --------------------------------------------------------------- */

static int lan_devices(const char **out, int max) {
    /* Устройства раздачи: что podkop или forkop назвали источниками (их UCI читается, не
     * правится), иначе br-lan. */
    static char buf[1024];
    int n = 0;
    const char *cmds[][6] = {
        { "uci", "-q", "get", "podkop.settings.source_network_interfaces", NULL },
        { "uci", "-q", "get", "forkop.settings.source_network_interfaces", NULL },
    };
    for (size_t c = 0; c < 2 && !n; c++) {
        if (run_cmd(cmds[c], buf, sizeof buf)) continue;
        for (char *t = strtok(buf, " \n"); t && n < max; t = strtok(NULL, " \n")) out[n++] = t;
    }
    return n;
}

/* Проверить переведённую спеку тем движком, который её поведёт: `apply --dry-run` с тем же
 * окружением. Без этого отказ steer (ключ, которого движок этой версии не знает) превращался в
 * «steer поднят, применять нечего» — sing-box работал, а маршрутизации не было вовсе. 0 — годна;
 * иначе первая строка отказа в err. */
int box_validate_spec(const struct box_settings *set, const char *spec, const char *state, char *err, size_t errn);

/* Перевод и, кроме первого раза, reload. Состояние коннектора не трогает — новую карту отдаёт в
 * *map, — поэтому годится и для рабочего потока (rt_select). */
static int translate_run(struct box_rt *rt, struct jval *cfg, int first, struct jval **map,
                         char *err, size_t errn) {
    const char *devs[16];
    int nd = lan_devices(devs, 16);
    struct tr_opts to = { .dir = rt->inst, .ruleset_dir = rt->rsdir, .lan_devices = devs,
                          .lan_n = (size_t)nd, .egress_mark = rt->default_mark, .router_self = 1,
                          .selected = rt->selected };
    struct tr_result res;
    *map = NULL;
    char e1[512];
    if (box_translate(cfg, &to, &res, e1, sizeof e1)) {
        snprintf(err, errn, "перевод конфига: %s", e1);
        return -1;
    }
    {
        char e2[600];
        if (box_validate_spec(&rt->set, rt->spec, rt->state, e2, sizeof e2)) {
            snprintf(err, errn, "steer не принимает переведённую спеку: %s", e2);
            box_translate_free(&res);
            return -1;
        }
    }
    *map = res.map;
    res.map = NULL;
    /* Спеку box_translate уже записал атомарно в <inst>/spec.json. */
    if (res.warnings) LOGW("перевод: %u предупреждений (строки выше)", res.warnings);
    box_translate_free(&res);
    if (!first) {
        char e2[512];
        if (steerctl_run(rt->sock, "reload", 450000, e2, sizeof e2)) {
            snprintf(err, errn, "steer reload: %s", e2);
            return -1;      /* спека уже новая: карта — тоже */
        }
    }
    return 0;
}

static int translate_apply(struct box_rt *rt, struct jval *cfg, int first) {
    struct jval *map;
    char err[700];
    int rc = translate_run(rt, cfg, first, &map, err, sizeof err);
    if (map) { json_free(rt->map); rt->map = map; }
    if (rc) LOGE("%s", err);
    return rc;
}

/* ---- выбор селекторов ------------------------------------------------------------------- */

static void selected_save(struct box_rt *rt);

static void sel_path(const struct box_rt *rt, char *p, size_t n) {
    snprintf(p, n, "%s/selected.json", rt->set.state_dir);
}

/* Выбор, сделанный прежним коннектором: тогда селектор был группой steer `pick: manual`, и выбор
 * лежал у движка (<inst>/select, строки «группа член» именами steer). Имена переводятся в теги по
 * карте прежнего перевода (<inst>/box-map.json ещё прежняя — новый перевод её перепишет). Без
 * этого обновление молча возвращало селектор на первый член. */
static void selected_from_engine(struct box_rt *rt) {
    char p[700], e[200], line[512];
    snprintf(p, sizeof p, "%s/box-map.json", rt->inst);
    struct jval *map = json_parse_file(p, e, sizeof e);
    snprintf(p, sizeof p, "%s/select", rt->inst);
    FILE *f = map ? fopen(p, "r") : NULL;
    const struct jval *obs = jget(map, "outbounds");
    while (f && fgets(line, sizeof line, f)) {
        char g[256], m[256];
        if (sscanf(line, "%255s %255s", g, m) != 2) continue;
        const char *gt = NULL, *mt = NULL;
        for (size_t i = 0; i < jlen(obs); i++) {
            const struct jval *v = obs->o[i].val;
            const char *n = jgets(v, "name"), *ty = jgets(v, "type");
            if (!n || !ty) continue;
            if (!gt && !strcmp(n, g) && !strcmp(ty, "Selector")) gt = obs->o[i].key;
            if (!mt && !strcmp(n, m) && strcmp(ty, "Selector") && strcmp(ty, "URLTest")) mt = obs->o[i].key;
        }
        if (gt && mt && !jget(rt->selected, gt)) {
            jobj_set(rt->selected, gt, jstr(mt));
            LOGI("селектор %s: выбор %s перенесён от прежнего коннектора", gt, mt);
        }
    }
    if (f) fclose(f);
    json_free(map);
    if (rt->selected->len) selected_save(rt);
}

static void selected_load(struct box_rt *rt) {
    char p[700], e[200];
    sel_path(rt, p, sizeof p);
    rt->selected = json_parse_file(p, e, sizeof e);
    if (!rt->selected || rt->selected->t != J_OBJ) {
        json_free(rt->selected);
        rt->selected = jnew(J_OBJ);
        selected_from_engine(rt);
    }
}

static void selected_save(struct box_rt *rt) {
    char p[700], tmp[720];
    sel_path(rt, p, sizeof p);
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    char *s = json_to_str(rt->selected, -1, NULL);
    FILE *f = s ? fopen(tmp, "w") : NULL;
    if (f) {
        fputs(s, f);
        if (fclose(f) == 0) rename(tmp, p);
    }
    free(s);
}

struct seljob {
    struct box_rt *rt;
    void (*done)(void *, int, const char *);
    void *arg;
    struct jval *map;
    int rc;
    char err[700];
};

static void sel_work(void *p) {
    struct seljob *j = p;
    j->rc = translate_run(j->rt, j->rt->cfg, 0, &j->map, j->err, sizeof j->err);
}

static void sel_done(void *p) {
    struct seljob *j = p;
    struct box_rt *rt = j->rt;
    if (j->map) { json_free(rt->map); rt->map = j->map; }
    rt->reloading = 0;
    if (j->rc) LOGE("смена выбора: %s", j->err);
    rt_status_refresh(rt);
    if (j->done) j->done(j->arg, j->rc, j->err);
    free(j);
    if (rt->pending_reload) {
        rt->pending_reload = 0;
        rt_reload(rt, "отложено до конца смены выбора");
    } else if (rt->pending_retranslate) {
        rt->pending_retranslate = 0;
        rt_retranslate(rt, "отложено до конца смены выбора");
    }
}

int rt_select(struct box_rt *rt, const char *selector, const char *member,
              void (*done)(void *arg, int rc, const char *err), void *arg) {
    if (rt->reloading) return -1;
    struct seljob *j = calloc(1, sizeof *j);
    if (!j) return -1;
    jobj_set(rt->selected, selector, jstr(member));
    selected_save(rt);
    LOGI("селектор %s: выбран %s", selector, member);
    j->rt = rt;
    j->done = done;
    j->arg = arg;
    rt->reloading = 1;
    if (ev_spawn(rt->ev, sel_work, sel_done, j)) {
        rt->reloading = 0;
        free(j);
        return -1;
    }
    return 0;
}

static void apply_cfg_globals(struct box_rt *rt, const struct jval *cfg) {
    const struct jval *route = jget(cfg, "route");
    const struct jval *m = jget(route, "default_mark");
    rt->default_mark = !m ? 0 : m->t == J_NUM ? (uint32_t)m->i : (uint32_t)strtoul(m->s, NULL, 0);
    const char *di = jgets(route, "default_interface");
    snprintf(rt->default_dev, sizeof rt->default_dev, "%s", di ? di : "");
    enum box_level lv;
    const char *lvl = rt->set.log_level[0] ? rt->set.log_level : jgets(jget(cfg, "log"), "level");
    if (lvl && !box_level_parse(lvl, &lv)) box_log_level(lv);
    if (jgetb(jget(cfg, "log"), "disabled", 0)) box_log_level(BL_FATAL);
}

static void restart_parts(struct box_rt *rt) {
    dns_stop(rt);
    mixed_stop(rt);
    clash_stop(rt);
    dns_start(rt);
    mixed_start(rt);
    clash_start(rt);
}

void rt_retranslate(struct box_rt *rt, const char *why) {
    if (rt->reloading) { rt->pending_retranslate = 1; return; }
    LOGI("перевожу заново: %s", why);
    if (!translate_apply(rt, rt->cfg, 0)) rt_status_refresh(rt);
}

void rt_reload(struct box_rt *rt, const char *why) {
    if (rt->reloading) { rt->pending_reload = 1; return; }
    char err[512];
    struct jval *cfg = box_load_config(rt->opts, err, sizeof err);
    if (!cfg) { LOGE("перечитать конфиг (%s): %s — работаю по прежнему", why, err); return; }
    struct sbcheck ck;
    if (sb_check(cfg, &ck)) {
        LOGE("перечитать конфиг (%s): %s — работаю по прежнему", why, ck.first);
        json_free(cfg);
        return;
    }
    LOGI("перечитываю конфиг: %s", why);
    if (translate_apply(rt, cfg, 0)) { json_free(cfg); return; }
    json_free(rt->cfg);
    rt->cfg = cfg;
    apply_cfg_globals(rt, cfg);
    restart_parts(rt);
    rs_stop(rt);
    rs_start(rt);
    rt_status_refresh(rt);
}

/* ---- слушатели-заглушки tproxy ------------------------------------------------------------
 *
 * podkop и forkop проверяют netstat: есть ли слушатель на 127.0.0.1:1602 (forkop — ещё на
 * [::1]:1602). Это обычные слушающие сокеты TCP без IP_TRANSPARENT: правило tproxy их не видит
 * (ему нужен прозрачный сокет), трафик в них не приходит, а соединение с ними самими отбивается
 * сразу же. */
static void dummy_accept(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)ev; (void)e; (void)arg;
    int c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (c >= 0) close(c);
}

static void dummies_start(struct box_rt *rt) {
    const struct jval *ins = jget(rt->cfg, "inbounds");
    for (size_t i = 0; i < jlen(ins); i++) {
        const struct jval *in = jat(ins, i);
        const char *type = jgets(in, "type");
        if (!type || (strcmp(type, "tproxy") && strcmp(type, "redirect"))) continue;
        struct sockaddr_storage a;
        socklen_t l;
        const char *listen = jgets(in, "listen");
        if (net_parse_ip(listen ? listen : "0.0.0.0", (uint16_t)jgeti(in, "listen_port", 0), &a, &l)) continue;
        for (int udp = 0; udp < 2; udp++) {
            int fd = net_listen(&a, l, udp);
            if (fd < 0) {
                LOGW("вход %s: заглушка на %s:%lld не встала: %s", jgets(in, "tag") ? jgets(in, "tag") : "?", listen ? listen : "0.0.0.0",
                     (long long)jgeti(in, "listen_port", 0), strerror(errno));
                continue;
            }
            int *nf = realloc(rt->dummy_fds, (rt->dummy_n + 1) * sizeof *nf);
            if (!nf) { close(fd); continue; }
            rt->dummy_fds = nf;
            rt->dummy_fds[rt->dummy_n++] = fd;
            if (!udp) ev_add(rt->ev, fd, EPOLLIN, dummy_accept, rt);
        }
    }
}

static void dummies_stop(struct box_rt *rt) {
    for (size_t i = 0; i < rt->dummy_n; i++) {
        ev_del(rt->ev, rt->dummy_fds[i]);
        close(rt->dummy_fds[i]);
    }
    free(rt->dummy_fds);
    rt->dummy_fds = NULL;
    rt->dummy_n = 0;
}

/* ---- сигналы ---------------------------------------------------------------------------- */

static void stop_all(struct box_rt *rt) {
    rs_stop(rt);
    clash_stop(rt);
    mixed_stop(rt);
    dns_stop(rt);
    dummies_stop(rt);
    if (rt->steerd > 0) {
        kill(rt->steerd, SIGTERM);
        /* До 10 с, шагом 10 мс: steerd гасится за десятки миллисекунд, и шаг в 100 мс добавлял
         * к каждой остановке (и к каждому перезапуску) почти столько же ожидания. */
        for (int i = 0; i < 1000; i++) {
            int st;
            if (waitpid(rt->steerd, &st, WNOHANG) == rt->steerd) { rt->steerd = 0; break; }
            usleep(10 * 1000);
        }
        if (rt->steerd > 0) { kill(rt->steerd, SIGKILL); waitpid(rt->steerd, NULL, 0); }
        rt->steerd = 0;
    }
    /* Снять набор правил и маршруты своего экземпляра. */
    pid_t pid = fork();
    if (!pid) {
        child_env(rt);
        const char *argv[] = { rt->set.steerd, "down", "--state-dir", rt->state, NULL };
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) dup2(dn, 1);
        execv(argv[0], (char *const *)argv);
        _exit(127);
    }
    if (pid > 0) waitpid(pid, NULL, 0);
    neutralize_undo();
}

static void sig_cb(struct ev *ev, int fd, uint32_t e, void *arg) {
    (void)e;
    struct box_rt *rt = arg;
    struct signalfd_siginfo si;
    while (read(fd, &si, sizeof si) == sizeof si) {
        if (si.ssi_signo == SIGHUP) {
            rt_reload(rt, "SIGHUP");
        } else if (si.ssi_signo == SIGCHLD) {
            /* Только steerd: прочих детей (apply --dry-run, conntrack, ip) ждут те, кто их
             * запустил, в том числе рабочие потоки, — waitpid(-1) отнимал бы у них код выхода. */
            int st;
            if (rt->steerd > 0 && waitpid(rt->steerd, &st, WNOHANG) == rt->steerd) {
                LOGE("steerd завершился (%s %d) — выхожу, procd поднимет заново",
                     WIFEXITED(st) ? "код" : "сигнал", WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
                rt->steerd = 0;
                ev_stop(ev);
            }
        } else {
            LOGI("сигнал %u — останавливаюсь", si.ssi_signo);
            ev_stop(ev);
        }
    }
}

/* ---- точка входа ------------------------------------------------------------------------ */

static int mkdir_p(const char *path) {
    char buf[600];
    snprintf(buf, sizeof buf, "%s", path);
    for (char *p = buf + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(buf, 0755);
            *p = '/';
        }
    return mkdir(buf, 0755) && errno != EEXIST ? -1 : 0;
}

int cmd_run(const struct box_opts *o) {
    static struct box_rt rt;
    g_rt = &rt;
    rt.opts = o;
    box_settings_load(&rt.set);
    if (!rt.set.mark_mask) rt.set.mark_mask = 0x000000ff;
    if (!rt.set.rule_pref) rt.set.rule_pref = 100;
    char err[512];
    rt.cfg = box_load_config(o, err, sizeof err);
    if (!rt.cfg) { fprintf(stderr, "FATAL[0000] decode config: %s\n", err); return 1; }
    struct sbcheck ck;
    if (sb_check(rt.cfg, &ck)) { fprintf(stderr, "FATAL[0000] %s\n", ck.first); return 1; }
    apply_cfg_globals(&rt, rt.cfg);
    if (access(rt.set.steerd, X_OK)) {
        fprintf(stderr, "FATAL[0000] нет ядра steer %s — поставьте steer-core (страница Services → Steer Connector)\n",
                rt.set.steerd);
        return 1;
    }
    snprintf(rt.inst, sizeof rt.inst, "%s/steer", rt.set.state_dir);
    snprintf(rt.spec, sizeof rt.spec, "%s/spec.json", rt.inst);
    snprintf(rt.state, sizeof rt.state, "%s/state", rt.inst);
    snprintf(rt.sock, sizeof rt.sock, "%s/steer.sock", rt.inst);
    snprintf(rt.rsdir, sizeof rt.rsdir, "%s/rulesets", rt.set.state_dir);
    if (mkdir_p(rt.inst) || mkdir_p(rt.state) || mkdir_p(rt.rsdir)) {
        fprintf(stderr, "FATAL[0000] %s: %s\n", rt.inst, strerror(errno));
        return 1;
    }
    int other = foreign_steerd(&rt);
    if (other && access("/etc/steer/spec.json", F_OK) && access("/etc/steer/spec.yaml", F_OK)) {
        /* Служба steer без своей спеки: её включил пакет steer-core при установке или обновлении
         * (раньше, чем узнал о коннекторе). Ей нечего вести, а таблицы маршрутизации у неё те же,
         * что у нашего экземпляра, — останавливаем и выключаем её, как это сделала бы страница
         * коннектора. */
        LOGW("служба steer (pid %d) работает без своей спеки — останавливаю: ядро ведёт коннектор", other);
        const char *stop[] = { "/etc/init.d/steer", "stop", NULL };
        const char *dis[] = { "/etc/init.d/steer", "disable", NULL };
        run_cmd(stop, NULL, 0);
        run_cmd(dis, NULL, 0);
        other = foreign_steerd(&rt);
    }
    if (other) {
        fprintf(stderr, "FATAL[0000] работает служба steer со своей спекой (pid %d) — коннектор ведёт "
                        "свой экземпляр ядра, и делить с ней таблицы он не может; остановите её "
                        "(/etc/init.d/steer stop && /etc/init.d/steer disable) или уберите /etc/steer/spec.*\n", other);
        return 1;
    }
    reap_orphans(&rt);
    rt.ev = ev_new();
    if (!rt.ev) { fprintf(stderr, "FATAL[0000] цикл событий не завёлся\n"); return 1; }
    rt.started_ms = ev_now_ms();
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGHUP);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGCHLD);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    signal(SIGPIPE, SIG_IGN);
    int sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);
    ev_add(rt.ev, sfd, EPOLLIN, sig_cb, &rt);

    selected_load(&rt);
    if (translate_apply(&rt, rt.cfg, 1)) return 1;
    neutralize(&rt);
    rt.steerd = spawn_steerd(&rt);
    if (rt.steerd < 0 || wait_socket(&rt, 60000)) {
        fprintf(stderr, "FATAL[0000] steerd не поднялся (сокет %s)\n", rt.sock);
        stop_all(&rt);
        return 1;
    }
    LOGI("steer поднят: спека %s", rt.spec);
    dummies_start(&rt);
    dns_start(&rt);
    dns_install_resolver();
    mixed_start(&rt);
    clash_start(&rt);
    rs_start(&rt);
    rt_status_refresh(&rt);
    ev_timer(rt.ev, 3000, status_tick, &rt);
    ev_timer(rt.ev, 15000, neut_tick, &rt);
    LOGI("sing-box started (steer-box-connector %s)", BOX_VERSION);
    ev_run(rt.ev);
    stop_all(&rt);
    LOGI("sing-box stopped");
    return 0;
}
