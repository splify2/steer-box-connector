/* Клиент сокета управления steer — см. steerctl.h и docs/ctl.md. */
#define _GNU_SOURCE
#include "steerctl.h"
#include "net.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

struct jval *steerctl_call(const char *sock, const char *line, const char *body, size_t bodyn,
                           int timeout_ms, char *err, size_t errn) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { snprintf(err, errn, "socket: %s", strerror(errno)); return NULL; }
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    snprintf(a.sun_path, sizeof a.sun_path, "%s", sock);
    if (connect(fd, (struct sockaddr *)&a, sizeof a)) {
        snprintf(err, errn, "steer (%s): %s", sock, strerror(errno));
        close(fd);
        return NULL;
    }
    char req[600];
    int n = body ? snprintf(req, sizeof req, "%s %zu\n", line, bodyn) : snprintf(req, sizeof req, "%s\n", line);
    if (n < 0 || (size_t)n >= sizeof req || write_all(fd, req, (size_t)n) ||
        (body && bodyn && write_all(fd, body, bodyn))) {
        snprintf(err, errn, "steer: запрос не ушёл");
        close(fd);
        return NULL;
    }
    size_t cap = 65536, got = 0;
    char *buf = malloc(cap);
    long long deadline_left = timeout_ms;
    while (buf) {
        struct pollfd pf = { fd, POLLIN, 0 };
        int pr = poll(&pf, 1, (int)deadline_left);
        if (pr <= 0) { snprintf(err, errn, "steer: нет ответа за %d мс на «%s»", timeout_ms, line); free(buf); buf = NULL; break; }
        if (got + 1 >= cap) {
            char *nb = realloc(buf, cap *= 2);
            if (!nb) { free(buf); buf = NULL; break; }
            buf = nb;
        }
        ssize_t r = read(fd, buf + got, cap - got - 1);
        if (r <= 0) break;
        got += (size_t)r;
        if (memchr(buf + got - (size_t)r, '\n', (size_t)r)) break;
    }
    close(fd);
    if (!buf) return NULL;
    buf[got] = 0;
    char e2[256];
    struct jval *v = json_parse(buf, got, e2, sizeof e2);
    free(buf);
    if (!v) { snprintf(err, errn, "steer: ответ не JSON (%s)", e2); return NULL; }
    if (jgets(v, "error")) {
        snprintf(err, errn, "steer: %s: %s", jgets(v, "error"), jgets(v, "message") ? jgets(v, "message") : "");
        json_free(v);
        return NULL;
    }
    return v;
}

static void stderr_text(const struct jval *v, char *err, size_t errn) {
    const struct jval *se = jget(v, "stderr");
    if (se && se->t == J_STR) snprintf(err, errn, "%s", se->s);
    else if (se && se->t == J_ARR) {
        size_t j = 0;
        err[0] = 0;
        for (size_t i = 0; i < se->len && j < errn; i++)
            if (se->a[i]->t == J_STR) j += (size_t)snprintf(err + j, errn - j, "%s%s", i ? " " : "", se->a[i]->s);
    } else snprintf(err, errn, "код %lld", (long long)jgeti(v, "code", -1));
}

/* stdout у протокола — строка или массив строк (docs/ctl.md: «её вывод строками»). */
static char *stdout_text(const struct jval *v) {
    const struct jval *so = jget(v, "stdout");
    if (!so) return strdup("");
    if (so->t == J_STR) return strdup(so->s);
    if (so->t != J_ARR) return strdup("");
    size_t n = 1;
    for (size_t i = 0; i < so->len; i++) if (so->a[i]->t == J_STR) n += so->a[i]->len + 1;
    char *s = malloc(n), *p = s;
    if (!s) return NULL;
    for (size_t i = 0; i < so->len; i++)
        if (so->a[i]->t == J_STR) { memcpy(p, so->a[i]->s, so->a[i]->len); p += so->a[i]->len; *p++ = '\n'; }
    *p = 0;
    return s;
}

struct jval *steerctl_json(const char *sock, const char *line, int timeout_ms, char *err, size_t errn) {
    struct jval *v = steerctl_call(sock, line, NULL, 0, timeout_ms, err, errn);
    if (!v) return NULL;
    if (jgeti(v, "code", -1) != 0) {
        stderr_text(v, err, errn);
        json_free(v);
        return NULL;
    }
    char *s = stdout_text(v);
    json_free(v);
    if (!s) { snprintf(err, errn, "нет памяти"); return NULL; }
    char e2[256];
    struct jval *r = json_parse(s, strlen(s), e2, sizeof e2);
    if (!r) snprintf(err, errn, "steer %s: вывод не JSON (%s)", line, e2);
    free(s);
    return r;
}

int steerctl_run(const char *sock, const char *line, int timeout_ms, char *err, size_t errn) {
    struct jval *v = steerctl_call(sock, line, NULL, 0, timeout_ms, err, errn);
    if (!v) return -1;
    int rc = jgeti(v, "code", -1) == 0 ? 0 : -1;
    if (rc) stderr_text(v, err, errn);
    json_free(v);
    return rc;
}
