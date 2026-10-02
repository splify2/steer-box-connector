#!/bin/sh
# Пакет коннектора объявляет свои настройки (/etc/config/steer-box и /etc/config/sing-box):
#   - ipk — в conffiles: opkg при обновлении не затирает правленый файл (иначе страница LuCI
#     теряла настройки, а enabled podkop/forkop в sing-box сбрасывался в 0 — и postinst
#     перезапускал sing-box, который уже не стартовал);
#   - оба формата — в /lib/upgrade/keep.d: sysupgrade «с сохранением настроек» их сохраняет.
# Собирает одну архитектуру (docker), как sh build.sh; ARCH=<арх> — другая.
set -eu
cd "$(dirname "$0")/.."
ARCH=${ARCH:-x86_64}
VER=$(cat steer/VERSION)
STEER_ARCH=$ARCH sh build.sh >/dev/null
ipk="out/steer-box-connector-$VER-1_$ARCH.ipk"
apk="out/steer-box-connector-$VER-1_$ARCH.apk"
[ -f "$ipk" ] && [ -f "$apk" ] || { echo "FAIL: пакеты не собрались"; exit 1; }
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
tar -xzf "$ipk" -C "$t"
mkdir "$t/c" "$t/d"
tar -xzf "$t/control.tar.gz" -C "$t/c"
tar -xzf "$t/data.tar.gz" -C "$t/d"
fail=0
for f in /etc/config/steer-box /etc/config/sing-box; do
    grep -qx "$f" "$t/c/conffiles" 2>/dev/null || { echo "FAIL: ipk: $f нет в conffiles"; fail=1; }
    grep -qx "$f" "$t/d/lib/upgrade/keep.d/steer-box-connector" 2>/dev/null ||
        { echo "FAIL: ipk: $f нет в lib/upgrade/keep.d/steer-box-connector"; fail=1; }
done
# apk (adb) — список путей через apk adbdump в alpine, как собирает его build.sh.
docker run --rm -v "$PWD/out":/o alpine:latest sh -c \
    "apk add --no-cache apk-tools >/dev/null 2>&1; apk adbdump /o/$(basename "$apk")" 2>/dev/null |
    grep -A7 'name: lib/upgrade/keep.d$' | grep -q 'name: steer-box-connector$' ||
    { echo "FAIL: apk: нет lib/upgrade/keep.d/steer-box-connector"; fail=1; }
[ "$fail" = 0 ] && echo "ok   pkg ($ARCH)"
exit $fail
