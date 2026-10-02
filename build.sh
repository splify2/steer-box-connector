#!/bin/sh
# Сборка steer-box-connector: бинарник sing-box для каждой архитектуры OpenWrt и пакет в двух
# форматах (.apk и .ipk).
#
#   sh build.sh            все архитектуры steer (STEER_ARCH=<арх> — одна)
#   sh build.sh --bundle   ещё и тестовый набор out/steer-box-connector-test-<версия>.tar.gz:
#                          пакеты steer той же версии собираются подмодулем (steer/build.sh)
#
# Коннектор — модуль steer вне его дерева: связан с libsteer и требует пакет steer-core ТОЙ ЖЕ
# версии. Поэтому версия коннектора — версия steer в подмодуле (steer/VERSION), а собирается он
# сборкой steer (steer/build/ext-build.sh: тот же образ, те же цели zig и загрузчики musl). Своих
# флагов компиляции и своего списка архитектур здесь нет — два места разъехались бы.
set -eu
cd "$(dirname "$0")"
ROOT="$PWD"
BUNDLE=0
[ "${1:-}" = "--bundle" ] && BUNDLE=1

[ -f steer/VERSION ] || { echo "нет подмодуля steer — git submodule update --init" >&2; exit 1; }
VERSION="$(cat steer/VERSION)"
OUT="$ROOT/out"
mkdir -p "$OUT" build

. steer/build/arches.sh
if [ -n "${STEER_ARCH:-}" ]; then
    ISAS="$(printf '%s\n' "$ISAS" | grep "^${STEER_ARCH}:")"
    [ -n "$ISAS" ] || { echo "неизвестная архитектура: $STEER_ARCH" >&2; exit 1; }
fi

# ipkg-build — родной скрипт OpenWrt (тот же, что берёт steer): два источника, потому что
# raw.githubusercontent.com у части провайдеров закрыт.
IPKG=build/ipkg-build
if [ ! -x "$IPKG" ]; then
    if [ -x steer/build/ipkg-build ]; then
        cp steer/build/ipkg-build "$IPKG"
    else
        RAW=https://raw.githubusercontent.com/openwrt/openwrt/master/scripts/ipkg-build
        API='https://api.github.com/repos/openwrt/openwrt/contents/scripts/ipkg-build?ref=master'
        curl -fsSL "$RAW" -o "$IPKG" ||
            curl -fsSL -H 'Accept: application/vnd.github.raw' "$API" -o "$IPKG" ||
            { echo "не удалось скачать ipkg-build" >&2; exit 1; }
    fi
    chmod +x "$IPKG"
fi

NAME=steer-box-connector
DESC="steer-box-connector: sing-box для podkop и forkop на ядре steer (вместо пакета sing-box)"
# Ставится ВМЕСТО пакетов sing-box (их бинарник /usr/bin/sing-box и служба /etc/init.d/sing-box —
# то, что зовут podkop и forkop): конфликтует с ними и берёт на себя их имя.
CONFLICTS="sing-box sing-box-tiny sing-box-extended"
REPLACES="sing-box"

# Дерево пакета для архитектуры: бинарник, служба, настройки, rpcd, правило fw4 и страница LuCI.
tree() {  # АРХ БИНАРНИК -> каталог дерева
    _r="build/pkg/$1"
    rm -rf "$_r"
    mkdir -p "$_r/usr/bin" "$_r/www"
    cp "$2" "$_r/usr/bin/sing-box"
    cp -a files/. "$_r/"
    cp -a luci/htdocs/. "$_r/www/"
    cp -a luci/root/. "$_r/"
    find "$_r" -type d -exec chmod 0755 {} +
    find "$_r" -type f -exec chmod 0644 {} +
    chmod 0755 "$_r/usr/bin/sing-box" "$_r/etc/init.d/sing-box" "$_r/usr/libexec/rpcd/steer-box"
    echo "$_r"
}

pack_apk() {  # АРХ ДЕРЕВО
    _deps="steer-core=$VERSION-r1"
    for _c in $CONFLICTS; do _deps="$_deps !$_c"; done
    docker run --rm -v "$ROOT":/w -w /w alpine:latest sh -c \
        "apk add --no-cache apk-tools >/dev/null 2>&1; apk mkpkg \
           --info name:$NAME --info version:$VERSION-r1 --info description:'$DESC' \
           --info arch:$1 --info depends:'$_deps' \
           --info replaces:'$REPLACES' --info provides:'sing-box=$VERSION-r1' \
           --script post-install:scripts/postinst --script post-upgrade:scripts/postinst \
           --script pre-deinstall:scripts/prerm --script post-deinstall:scripts/postrm \
           -F $2 -o out/$NAME-$VERSION-1_$1.apk" >/dev/null 2>&1 \
        || { echo "    (apk не собрался: $1)"; return 1; }
}

pack_ipk() {  # АРХ ДЕРЕВО
    mkdir -p "$2/CONTROL"
    {
        echo "Package: $NAME"
        echo "Version: $VERSION-1"
        echo "Depends: steer-core (= $VERSION-1)"
        echo "Architecture: $1"
        echo "Maintainer: splify2"
        echo "Section: net"
        echo "Conflicts: $(echo $CONFLICTS | sed 's/ /, /g')"
        echo "Replaces: $REPLACES"
        echo "Provides: sing-box"
        echo "Description: $DESC"
    } > "$2/CONTROL/control"
    for _h in postinst prerm postrm; do cp "scripts/$_h" "$2/CONTROL/$_h"; chmod 0755 "$2/CONTROL/$_h"; done
    if "$ROOT/$IPKG" "$2" "$OUT" >/dev/null 2>&1; then
        mv "$OUT/${NAME}_${VERSION}-1_$1.ipk" "$OUT/$NAME-$VERSION-1_$1.ipk" 2>/dev/null || true
    else
        echo "    (ipk не собрался: $1)"
    fi
    rm -rf "$2/CONTROL"
}

echo "$NAME $VERSION (steer $(git -C steer describe --tags --always 2>/dev/null || echo ?))"
for spec in $ISAS; do
    arch=${spec%%:*}
    printf '  %-26s ' "$arch"
    libs="build/libs/$arch"
    rm -rf "$libs"
    if sh steer/build/ext-build.sh "$arch" "$ROOT/$libs" "sing-box:$ROOT/src" \
            >"build/$arch.log" 2>"build/$arch.err" && [ -s "$libs/sing-box" ]; then
        r="$(tree "$arch" "$libs/sing-box")"
        pack_apk "$arch" "$r" && pack_ipk "$arch" "$r" &&
            echo "$(stat -c %s "$libs/sing-box") bytes"
    else
        echo "FAILED — $(grep -m1 -iE "error|undefined" "build/$arch.err" "build/$arch.log" 2>/dev/null || tail -1 "build/$arch.err")"
    fi
done

[ "$BUNDLE" = 1 ] || exit 0

# ---- тестовый набор: только наши пакеты, по каталогу на архитектуру -------------------------
# steer-core и модули протоколов sing-box (vless, hysteria2, proxy) — из сборки подмодуля той же
# версии. Пакетов из фидов OpenWrt в наборе нет: их ставит менеджер пакетов.
echo "steer $VERSION — пакеты для набора (steer/build.sh)"
(cd steer && sh build.sh >"$ROOT/build/steer.log" 2>&1) || { echo "сборка steer не прошла — build/steer.log" >&2; exit 1; }
PKGS="steer-core steer-vless steer-hysteria2 steer-proxy"
name="$NAME-test-$VERSION"
stage="build/pkg/$name"
rm -rf "$stage"
mkdir -p "$stage/packages"
arches=""
for spec in $ISAS; do
    a=${spec%%:*}
    ok=1
    for ext in apk ipk; do
        [ -f "out/$NAME-$VERSION-1_$a.$ext" ] || ok=0
        for p in $PKGS; do [ -f "steer/out/$p-$VERSION-1_$a.$ext" ] || ok=0; done
    done
    [ "$ok" = 1 ] || { echo "  $a: не все пакеты собраны — архитектура пропущена" >&2; continue; }
    mkdir -p "$stage/packages/$a"
    for p in $PKGS; do cp "steer/out/$p-$VERSION-1_$a.apk" "steer/out/$p-$VERSION-1_$a.ipk" "$stage/packages/$a/"; done
    cp "out/$NAME-$VERSION-1_$a.apk" "out/$NAME-$VERSION-1_$a.ipk" "$stage/packages/$a/"
    arches="$arches${arches:+, }$a"
done
[ -n "$arches" ] || { echo "нет ни одной полной архитектуры" >&2; exit 1; }
sed "s/@VERSION@/$VERSION/g" bundle/install.sh > "$stage/install.sh"
chmod 0755 "$stage/install.sh"
sed "s/@VERSION@/$VERSION/g; s/@ARCHES@/$arches/" bundle/README.txt > "$stage/README.txt"
(cd "$stage/packages" && find . -type f | sort | xargs sha256sum) > "$stage/SHA256SUMS"
tar -C build/pkg -czf "out/$name.tar.gz" "$name"
echo "out/$name.tar.gz: $(stat -c %s "out/$name.tar.gz") байт; архитектуры: $arches"
