/* sing-box run (boxrun.c): обработчик SIGCHLD забирает только steerd. Прочих детей коннектора
 * ждут те, кто их запустил, — и часть из них в рабочих потоках: `apply --dry-run` смены выбора
 * (sel_work → box_validate_spec), conntrack -D (kill_work). waitpid(-1) в цикле событий забирал
 * такого ребёнка раньше, и его waitpid(pid) получал ECHILD при st = 0 — box_validate_spec
 * принимала это за «спека годна», и reload шёл со спекой, от которой steer отказался. */
// deps: src/json.c src/evloop.c src/net.c tests/stub_log.c
#include "../src/boxrun.c"
#include "check.h"

int main(void) {
    static struct box_rt rt;
    rt.ev = ev_new();
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGCHLD);
    sigprocmask(SIG_BLOCK, &ss, NULL);
    int sfd = signalfd(-1, &ss, SFD_NONBLOCK | SFD_CLOEXEC);

    /* steerd — долгий ребёнок; «проверка спеки» — ребёнок рабочего потока, вышел с отказом. */
    rt.steerd = fork();
    if (!rt.steerd) { pause(); _exit(0); }
    pid_t check = fork();
    if (!check) _exit(3);
    siginfo_t si;
    waitid(P_PID, (id_t)check, &si, WEXITED | WNOWAIT);     /* он уже зомби, SIGCHLD ждёт */

    sig_cb(rt.ev, sfd, EPOLLIN, &rt);

    int st = 0;
    pid_t got = waitpid(check, &st, 0);
    CHECK(got == check);
    CHECK(got == check && WIFEXITED(st) && WEXITSTATUS(st) == 3);
    CHECK(rt.steerd > 0);                     /* steerd жив — его не трогали */

    /* А выход самого steerd обработчик видит. */
    kill(rt.steerd, SIGKILL);
    waitid(P_PID, (id_t)rt.steerd, &si, WEXITED | WNOWAIT);
    sig_cb(rt.ev, sfd, EPOLLIN, &rt);
    CHECK(rt.steerd == 0);
    return T_DONE();
}
