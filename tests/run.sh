#!/bin/sh
# Стенды коннектора на машине разработки: каждая проверка tests/t_*.c собирается cc хоста с
# ASan и UBSan и запускается. Проверка берёт часть коннектора целиком (#include "../src/x.c" —
# чтобы видеть её статические функции) и строкой «// deps:» называет остальные исходники, с
# которыми линкуется (строкой «// ldflags:» — ключи компоновщика); то, до чего проверка не
# доходит (TLS, Reality из steer), остаётся неразрешённым.
#
#   sh tests/run.sh            все проверки
#   sh tests/run.sh t_json     одна (по имени файла без .c)
#   sh tests/run.sh releases   стенд rpcd на shell (tests/releases.sh) — он идёт и в общем прогоне
set -u
cd "$(dirname "$0")/.."
shfail=0
if [ $# -eq 0 ] || case " $* " in *" releases "*) true ;; *) false ;; esac; then
    if sh tests/releases.sh >build-releases.log 2>&1; then echo "ok   releases"
    else echo "FAIL releases"; sed 's/^/    /' build-releases.log | grep -v '^    ok ' | head -40; shfail=1; fi
    rm -f build-releases.log
    [ "$*" = releases ] && exit $shfail
fi
[ -d steer/src ] || { echo "нет подмодуля steer — git submodule update --init" >&2; exit 1; }
CC=${CC:-cc}
INC="-Isrc $(find steer/src -type d | sed 's/^/-I/' | tr '\n' ' ')"
OUT=build/tests
mkdir -p "$OUT"
fail=$shfail
for t in tests/t_*.c; do
    n=$(basename "$t" .c)
    [ $# -gt 0 ] && { case " $* " in *" $n "*) ;; *) continue ;; esac; }
    deps=$(sed -n 's|^// deps: ||p' "$t")
    ldflags=$(sed -n 's|^// ldflags: ||p' "$t")
    # shellcheck disable=SC2086
    if ! $CC -g -O1 -D_GNU_SOURCE -fsanitize=address,undefined -fno-omit-frame-pointer \
            -Wno-macro-redefined -Wno-builtin-macro-redefined $INC -o "$OUT/$n" "$t" $deps \
            -lpthread -lm -Wl,--unresolved-symbols=ignore-all $ldflags 2>"$OUT/$n.cc"; then
        echo "FAIL $n (сборка: $OUT/$n.cc)"
        fail=1
        continue
    fi
    if ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/$n" >"$OUT/$n.log" 2>&1; then
        echo "ok   $n"
    else
        echo "FAIL $n"
        sed 's/^/    /' "$OUT/$n.log" | head -40
        fail=1
    fi
done
exit $fail
