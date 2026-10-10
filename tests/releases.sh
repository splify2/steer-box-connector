#!/bin/sh
# Стенд rpcd коннектора (files/usr/libexec/rpcd/steer-box): откуда берутся версии steer и пакеты.
#
# Решение владельца: версии и адреса файлов — СНАЧАЛА из version.json репозитория splify2/releases
# (raw.githubusercontent.com → cdn.jsdelivr.net → splify2.github.io), api.github.com и прямая
# ссылка выпуска steer — запасной путь. Пакет качается по urls из version.json по порядку со
# сверкой sha256 (если есть sha256sum), потом — прежней ссылкой выпуска.
#
# Как устроено. Сеть — заглушка curl: адрес отображается в файл песочницы `www/<хост>/<путь>`
# (`?` в пути — `_`), нет файла — отказ, как у закрытого адреса; каждый адрес пишется в журнал.
# apk, jsonfilter, uci, pgrep — заглушки; jshn — tests/stub/jshn.sh. Сам скрипт rpcd —
# настоящий, швы у него два: JSHN_SH и OPENWRT_RELEASE.
#
# Запуск: sh tests/releases.sh (нужен python3 — для заглушек jsonfilter и jshn).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RPCD="$ROOT/files/usr/libexec/rpcd/steer-box"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT INT TERM
mkdir -p "$T/bin" "$T/www"

fails=0
check() {  # ОПИСАНИЕ ОЖИДАЕМОЕ ПОЛУЧЕННОЕ
    if [ "$2" = "$3" ]; then
        printf 'ok   %s\n' "$1"
    else
        printf 'FAIL %s\n     ожидалось: %s\n     получено:  %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

cat > "$T/bin/curl" <<'EOF'
#!/bin/sh
out=""; url=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -m) shift 2 ;;
        http*) url="$1"; shift ;;
        *) shift ;;
    esac
done
echo "$url" >> "$T/curl.log"
f="$T/www/$(printf '%s' "${url#*://}" | tr '?' '_')"
[ -f "$f" ] || exit 22
cp "$f" "$out"
EOF
# Стоящие пакеты — строки «имя версия» в $T/installed.
cat > "$T/bin/apk" <<'EOF'
#!/bin/sh
case "$1" in
    add) shift; for a in "$@"; do case "$a" in -*) ;; *) printf '%s %s\n' "${a##*/}" "$(cat "$a")" >> "$T/apk.log" ;; esac; done
         [ -f "$T/apk.rc" ] && exit "$(cat "$T/apk.rc")" ;;
    --print-arch) echo x86_64 ;;
    info) grep -q "^$3 " "$T/installed" 2>/dev/null || exit 1 ;;
    list) awk -v p="$3" '$1 == p { print p "-" $2 "-r1 x86_64 {" p "} (GPL-3.0) [installed]" }' "$T/installed" 2>/dev/null ;;
esac
exit 0
EOF
# Коннектор этой сборки — 2.0.0 (так его видит rpcd по `sing-box version`).
cat > "$T/bin/sing-box" <<'EOF'
#!/bin/sh
case "$*" in
    *version*) printf 'sing-box version 1.13.21-extended\n\nEnvironment: steer-box-connector 2.0.0 linux/amd64\n' ;;
    *) exit 1 ;;
esac
EOF
printf '#!/bin/sh\nexit 1\n' > "$T/bin/uci"
printf '#!/bin/sh\nexit 1\n' > "$T/bin/pgrep"
# jsonfilter: пути вида @.a['b'].c[*].d[0] — ровно то, что встречается в скрипте.
cat > "$T/bin/jsonfilter" <<'EOF'
#!/bin/sh
src=""; mode=stdin; exprs=""
while [ $# -gt 0 ]; do
    case "$1" in
        -i) src="$2"; mode=file; shift 2 ;;
        -s) src="$2"; mode=str; shift 2 ;;
        -e) exprs="$exprs$2
"; shift 2 ;;
        *) shift ;;
    esac
done
[ "$mode" = stdin ] && src="$(cat)"
MODE="$mode" EXPRS="$exprs" python3 - "$src" <<'PY'
import json, os, re, sys
try:
    d = json.load(open(sys.argv[1])) if os.environ["MODE"] == "file" else json.loads(sys.argv[1])
except Exception:
    sys.exit(1)
def walk(cur, parts):
    if not parts:
        if cur is not None: yield cur
        return
    p, rest = parts[0], parts[1:]
    if p == "*":
        for it in (cur if isinstance(cur, list) else list(cur.values()) if isinstance(cur, dict) else []):
            yield from walk(it, rest)
    elif isinstance(cur, list) and p.isdigit():
        if int(p) < len(cur): yield from walk(cur[int(p)], rest)
    elif isinstance(cur, dict) and p in cur:
        yield from walk(cur[p], rest)
hit = False
for e in os.environ["EXPRS"].splitlines():
    if not e: continue
    parts = re.findall(r"\['([^']*)'\]|\[(\*|\d+)\]|\.([A-Za-z_][A-Za-z0-9_]*)", e[1:])
    for v in walk(d, [a or b or c for a, b, c in parts]):
        hit = True
        print(("true" if v else "false") if isinstance(v, bool) else json.dumps(v) if isinstance(v, (dict, list)) else v)
sys.exit(0 if hit else 1)
PY
EOF
chmod +x "$T/bin"/*
printf "DISTRIB_ARCH='x86_64'\n" > "$T/openwrt_release"

rpcd() {  # МЕТОД [ВХОД]
    printf '%s\n' "${2:-}" | env T="$T" PATH="$T/bin:$PATH" JSHN_SH="$ROOT/tests/stub/jshn.sh" \
        OPENWRT_RELEASE="$T/openwrt_release" APK_WORLD="$T/apk.world" APK_DB="$T/apk.db" ${SHA256SUM:+SHA256SUM="$SHA256SUM"} SING_BOX="$T/bin/sing-box" sh "$RPCD" call "$1" 2>"$T/stderr"
}
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin); v=d.get(sys.argv[1])
print("" if v is None else json.dumps(v, ensure_ascii=False) if isinstance(v,(list,dict,bool)) else v)' "$1"; }
reset() { rm -rf "$T/www" "$T/curl.log" "$T/apk.log" "$T/installed"; mkdir -p "$T/www"; : > "$T/curl.log"; : > "$T/apk.log"; }
put() {  # URL ФАЙЛ_ИЛИ_ТЕКСТ
    f="$T/www/$(printf '%s' "${1#*://}" | tr '?' '_')"; mkdir -p "${f%/*}"
    if [ -f "$2" ]; then cp "$2" "$f"; else printf '%s\n' "$2" > "$f"; fi
}
sum() { printf '%s\n' "$1" | sha256sum | cut -d' ' -f1; }

RAW=https://raw.githubusercontent.com/splify2/releases/main/version.json
CDN=https://cdn.jsdelivr.net/gh/splify2/releases@main/version.json
PAGES=https://splify2.github.io/releases/version.json
API=https://api.github.com/repos/splify2/steer/releases?per_page=10
REL=https://github.com/splify2/releases/releases/download
SRC=https://github.com/splify2/steer/releases/download

# version.json в том виде, в каком его пишет scripts/publish.py splify2/releases. У steer 2.0.0 —
# предварительный (поле prerelease), у файлов — sha256 содержимого «GOOD-<имя>».
mkrel() {  # ФАЙЛ
    python3 - "$1" <<'PY'
import hashlib, json, sys
def a(tag, ver, n, repo="steer"):
    return {"name": n, "size": 10, "sha256": hashlib.sha256(f"GOOD-{n}\n".encode()).hexdigest(),
            "urls": [f"https://github.com/splify2/releases/releases/download/{tag}/{n}",
                     f"https://github.com/splify2/{repo}/releases/download/v{ver}/{n}"]}
def v(ver, ch, names, prod="steer"):
    tag = f"{prod}-v{ver}"
    return {"version": ver, "channel": ch, "date": "2026-10-02", "tag": tag,
            "source": f"https://github.com/splify2/{prod}/releases/tag/v{ver}",
            "changelog": f"changelogs/{prod}/{ver}.md", "assets": [a(tag, ver, n, prod) for n in names]}
X = "x86_64"
doc = {"schema": 1, "updated": "2026-10-02T12:00:00Z", "products": {"steer": {
    "title": "Ядро steer", "repo": "splify2/steer", "stable": "1.5.9", "prerelease": "2.0.0",
    "versions": [v("2.0.0", "prerelease", [f"steer-core-2.0.0-1_{X}.apk", f"steer-vless-2.0.0-1_{X}.apk"]),
                 v("1.5.9", "stable", [f"steer-1.5.9-1_{X}.apk", f"steer-extended-1.5.9-1_{X}.apk"]),
                 v("1.5.8-rc1", "stable", [f"steer-1.5.8-rc1-1_{X}.apk"])]},
    "steer-box-connector": {"title": "steer-box-connector", "repo": "splify2/steer-box-connector",
    "stable": "2.1.0", "prerelease": None,
    "versions": [v("2.1.0", "stable", [f"steer-box-connector-2.1.0-1_{X}.apk"], "steer-box-connector")]}}}
json.dump(doc, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
PY
}
mkrel "$T/version.json"

# ---- releases: version.json первым -------------------------------------------------------
reset
put "$RAW" "$T/version.json"
put "$API" '[{"tag_name":"v1.2.0"}]'
out="$(rpcd releases)"
check "версии steer — из version.json (без «-rc»)" '["2.0.0", "1.5.9"]' "$(printf '%s' "$out" | jget versions)"
check "предварительная названа полем prerelease" "2.0.0" "$(printf '%s' "$out" | jget prerelease)"
check "version.json спрошен первым — на raw.githubusercontent.com" "$RAW" "$(head -1 "$T/curl.log")"
check "к api.github.com при живом version.json не ходили" "0" "$(grep -c api.github.com "$T/curl.log")"

reset
put "$PAGES" "$T/version.json"
out="$(rpcd releases)"
check "raw и jsDelivr молчат — version.json с splify2.github.io" '["2.0.0", "1.5.9"]' \
      "$(printf '%s' "$out" | jget versions)"
check "адреса version.json — по порядку" "$RAW $CDN $PAGES" "$(head -3 "$T/curl.log" | tr '\n' ' ' | sed 's/ $//')"

# ---- releases: откат на api.github.com --------------------------------------------------
reset
put "$API" '[{"tag_name":"v1.2.0"},{"tag_name":"v1.1.0"}]'
out="$(rpcd releases)"
check "version.json недоступен — версии из api.github.com" '["1.2.0", "1.1.0"]' "$(printf '%s' "$out" | jget versions)"
check "на запасном пути поля prerelease нет" "" "$(printf '%s' "$out" | jget prerelease)"
reset
put "$RAW" '<html>не json</html>'
put "$CDN" '{"schema": 2, "products": {}}'
put "$PAGES" '{"schema": 1, "products": {"xsteer": {"stable": "1.4.3", "prerelease": null, "versions": []}}}'
put "$API" '[{"tag_name":"v1.2.0"}]'
out="$(rpcd releases)"
check "битый, чужой схемы, без steer — версии из api.github.com" '["1.2.0"]' "$(printf '%s' "$out" | jget versions)"

# ---- install: адреса из version.json, сверка sha256 ---------------------------------------
CORE=steer-core-2.0.0-1_x86_64.apk
VLESS=steer-vless-2.0.0-1_x86_64.apk
reset
put "$RAW" "$T/version.json"
put "$REL/steer-v2.0.0/$CORE" "GOOD-$CORE"; put "$REL/steer-v2.0.0/$VLESS" "GOOD-$VLESS"
put "$SRC/v2.0.0/$CORE" "SRC-$CORE"; put "$SRC/v2.0.0/$VLESS" "SRC-$VLESS"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core","steer-vless"]}')"
check "предварительная ставится: пакеты с первого адреса version.json" "true" "$(printf '%s' "$out" | jget ok)"
check "первый адрес пакета — выпуск в splify2/releases" "$REL/steer-v2.0.0/$CORE" \
      "$(grep "$CORE" "$T/curl.log" | head -1)"
check "сумма сошлась — второй адрес не спрашивали" "1" "$(grep -c "$CORE" "$T/curl.log")"
check "apk получил оба пакета из выпуска splify2/releases" "$CORE GOOD-$CORE;$VLESS GOOD-$VLESS" \
      "$(tr '\n' ';' < "$T/apk.log" | sed 's/;$//')"

reset
put "$RAW" "$T/version.json"
put "$REL/steer-v2.0.0/$CORE" "BAD"; put "$SRC/v2.0.0/$CORE" "GOOD-$CORE"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "сумма первого не сошлась — взят второй адрес" "true;$CORE GOOD-$CORE" \
      "$(printf '%s' "$out" | jget ok);$(cat "$T/apk.log")"

reset
put "$RAW" "$T/version.json"
put "$REL/steer-v2.0.0/$CORE" "BAD"; put "$SRC/v2.0.0/$CORE" "BAD"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "сумма не сошлась нигде — не ставится" "false;" "$(printf '%s' "$out" | jget ok);$(cat "$T/apk.log")"

# Сумма в перечне есть, а сверить её нечем (нет sha256sum) — не ставить непроверенное.
reset
put "$RAW" "$T/version.json"
put "$REL/steer-v2.0.0/$CORE" "GOOD-$CORE"; put "$SRC/v2.0.0/$CORE" "GOOD-$CORE"
out="$(SHA256SUM=/nonexistent/sha256sum rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "сумма известна, sha256sum нет — не ставится" "false;" "$(printf '%s' "$out" | jget ok);$(cat "$T/apk.log")"
check "отказ называет причину" "1" "$(printf '%s' "$out" | jget error | grep -c sha256sum)"

# Файла нет в version.json — прежняя ссылка выпуска steer.
PROXY=steer-proxy-2.0.0-1_x86_64.apk
reset
put "$RAW" "$T/version.json"
put "$SRC/v2.0.0/$PROXY" "OLD"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-proxy"]}')"
check "файла нет в version.json — прежняя ссылка выпуска" "true;$SRC/v2.0.0/$PROXY" \
      "$(printf '%s' "$out" | jget ok);$(grep 'steer-proxy' "$T/curl.log" | head -1)"
check "суммы для файла нет — вывод говорит: без проверки суммы" "1" "$(printf '%s' "$out" | jget output | grep -c 'без проверки суммы')"

# ---- install другой версии: steer и коннектор — вместе ------------------------------------
# Пакеты зависят друг от друга с точной версией: другая версия steer — это каждый стоящий пакет
# steer той же версией и коннектор той же версии с его выпуска; иначе менеджер пакетов отказывает
# всей транзакции (apk) или оставляет модуль и коннектор старыми при новом ядре (opkg).
BOX=https://github.com/splify2/steer-box-connector/releases/download
reset
put "$RAW" "$T/version.json"
printf 'steer-core 2.0.0\nsteer-hysteria2 2.0.0\nsteer-box-connector 2.0.0\n' > "$T/installed"
for p in steer-core steer-hysteria2; do put "$SRC/v2.1.0/$p-2.1.0-1_x86_64.apk" "NEW-$p"; done
SBC=steer-box-connector-2.1.0-1_x86_64.apk
put "$REL/steer-box-connector-v2.1.0/$SBC" "GOOD-$SBC"
put "$BOX/v2.1.0/$SBC" "SRC-box"
out="$(rpcd install '{"version":"2.1.0","packages":["steer-core"]}')"
check "другая версия: стоящие модули и коннектор — той же версией" \
      "true;steer-core-2.1.0-1_x86_64.apk NEW-steer-core;steer-hysteria2-2.1.0-1_x86_64.apk NEW-steer-hysteria2;$SBC GOOD-$SBC" \
      "$(printf '%s' "$out" | jget ok);$(tr '\n' ';' < "$T/apk.log" | sed 's/;$//')"
check "коннектор — с первого адреса продукта steer-box-connector в version.json" \
      "$REL/steer-box-connector-v2.1.0/$SBC" "$(grep "$SBC" "$T/curl.log" | head -1)"

reset
printf 'steer-core 2.0.0\n' > "$T/installed"
put "$SRC/v2.1.0/steer-core-2.1.0-1_x86_64.apk" "NEW-steer-core"
put "$BOX/v2.1.0/$SBC" "SRC-box"
out="$(rpcd install '{"version":"2.1.0","packages":["steer-core"]}')"
check "version.json недоступен — коннектор прежней ссылкой его выпуска" "true;$SBC SRC-box" \
      "$(printf '%s' "$out" | jget ok);$(grep "$SBC" "$T/apk.log")"

reset
put "$RAW" "$T/version.json"
printf 'steer-core 2.0.0\n' > "$T/installed"
put "$SRC/v2.1.0/steer-core-2.1.0-1_x86_64.apk" "NEW-steer-core"
out="$(rpcd install '{"version":"2.1.0","packages":["steer-core"]}')"
check "другая версия без выпуска коннектора — не ставится ничего" "false;" \
      "$(printf '%s' "$out" | jget ok);$(cat "$T/apk.log")"

reset
put "$RAW" "$T/version.json"
printf 'steer-core 2.0.0\nsteer-box-connector 2.0.0\n' > "$T/installed"
put "$REL/steer-v2.0.0/$CORE" "GOOD-$CORE"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core","steer-box-connector"]}')"
check "та же версия — коннектор не качается и с выпуска steer не берётся" "true;0;$CORE GOOD-$CORE" \
      "$(printf '%s' "$out" | jget ok);$(grep -c 'steer-box-connector' "$T/curl.log");$(cat "$T/apk.log")"

# version.json недоступен — пакет прежней ссылкой, без сверки.
reset
put "$SRC/v2.0.0/$CORE" "SRC-$CORE"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "version.json недоступен — пакет прежней ссылкой" "true;$CORE SRC-$CORE" \
      "$(printf '%s' "$out" | jget ok);$(cat "$T/apk.log")"

# Версия с недопустимыми знаками отвергается до сети.
reset
out="$(rpcd install '{"version":"2.0.0;rm","packages":["steer-core"]}')"
check "версия не из цифр и точек отвергается до сети" "false;0" \
      "$(printf '%s' "$out" | jget ok);$(grep -c . "$T/curl.log")"

# Имя пакета — только знаки имён пакетов: «/» и «..» в путь файла и в адрес не попадают.
reset
put "$RAW" "$T/version.json"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-../../etc/x"]}')"
check "имя пакета с «/» не качается" "0" "$(grep -c 'etc/x' "$T/curl.log")"

# ---- закрепления в /etc/apk/world после оборванной установки ---------------------------------
# `apk add ФАЙЛ` (apk 3) пишет в world «имя><хеш файла»; транзакция, оборванная на середине
# (кончилось место при распаковке второго пакета), оставляет хеши новых файлов при прежних пакетах в
# базе, и дальше любая команда apk отвечает «unable to select packages: breaks:
# world[steer-core><Q1…]» — не ставится даже чужой zapret. Воспроизведено на apk 3.0.5.
reset
put "$SRC/v2.0.0/$CORE" "SRC-$CORE"
printf '%s\n' 'steer-core><QnEWcoreNEWcoreNEWcoreNEWcor=' 'steer-vless><QnEWvlessNEWvlessNEWvlessNEW=' \
    'zapret><QgoodZapretGoodZapretGoodZapretG=' '!libsteer' > "$T/apk.world"
printf '%s\n' 'C:QoLdcoreOLDcoreOLDcoreOLDcoreO=' 'P:steer-core' 'V:2.0.0-r1' '' \
    'C:QgoodZapretGoodZapretGoodZapretG=' 'P:zapret' 'V:72-r1' '' > "$T/apk.db"
printf '1\n' > "$T/apk.rc"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "обрыв install: отказ отдан как есть" "false" "$(printf '%s' "$out" | jget ok)"
check "  закрепление стоящего ядра стало «именем»" "steer-core" "$(grep '^steer-core' "$T/apk.world")"
check "  закрепление за пакетом, которого в базе нет, убрано" "0" "$(grep -c '^steer-vless' "$T/apk.world")"
check "  чужое закрепление с верным хешом и запись !имя целы" \
      "zapret><QgoodZapretGoodZapretGoodZapretG= !libsteer" \
      "$(grep -e '^zapret' -e '^!' "$T/apk.world" | tr '\n' ' ' | sed 's/ $//')"
rm -f "$T/apk.rc"
printf '%s\n' 'steer-core><QnEWcoreNEWcoreNEWcoreNEWcor=' 'zapret><QgoodZapretGoodZapretGoodZapretG=' > "$T/apk.world"
out="$(rpcd install '{"version":"2.0.0","packages":["steer-core"]}')"
check "успешный install: закрепление нашего пакета за файлом снято" "steer-core" "$(grep '^steer-core' "$T/apk.world")"
check "  чужое закрепление осталось" "zapret><QgoodZapretGoodZapretGoodZapretG=" "$(grep '^zapret' "$T/apk.world")"
rm -f "$T/apk.world" "$T/apk.db"

# Тот же помощник — в установщике набора (bundle/install.sh): достаётся текстом, как у стендов steer.
eval "$(sed -n '/^PKG_OURS=/p; /^pkg_world_heal() {/,/^}/p' "$ROOT/bundle/install.sh")"
printf '%s\n' 'steer-core><QnEWcoreNEWcoreNEWcoreNEWcor=' 'steer-box-connector><QnEWboxNEWboxNEWboxNEWboxNEWb=' \
    'zapret><QgoodZapretGoodZapretGoodZapretG=' > "$T/apk.world"
printf '%s\n' 'C:QoLdcoreOLDcoreOLDcoreOLDcoreO=' 'P:steer-core' 'V:2.0.0-r1' '' \
    'C:QgoodZapretGoodZapretGoodZapretG=' 'P:zapret' 'V:72-r1' '' > "$T/apk.db"
PATH="$T/bin:$PATH" APK_WORLD="$T/apk.world" APK_DB="$T/apk.db" pkg_world_heal "$PKG_OURS"
check "bundle/install.sh: лечение world — ядро «именем», коннектор без пакета убран, чужое цело" \
      "steer-core zapret><QgoodZapretGoodZapretGoodZapretG=" "$(tr '\n' ' ' < "$T/apk.world" | sed 's/ $//')"
rm -f "$T/apk.world" "$T/apk.db"

[ "$fails" -eq 0 ] && echo "все проверки прошли" || echo "ПРОВАЛОВ: $fails"
[ "$fails" -eq 0 ]
