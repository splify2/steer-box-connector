#!/bin/sh
# Установка тестового набора steer-box-connector на роутер: steer-core, модули протоколов
# (vless, hysteria2, proxy) и сам коннектор — sing-box для podkop и forkop на ядре steer.
# Запуск на роутере из распакованного каталога: sh install.sh
#
# Из фидов OpenWrt здесь ничего нет: то, что пакетам нужно оттуда, менеджер пакетов скачает сам
# (поэтому сначала apk update / opkg update).
set -e
cd "$(dirname "$0")"
VER=@VERSION@
PKGS="steer-core steer-vless steer-hysteria2 steer-proxy steer-box-connector"

[ "$(id -u)" = 0 ] || { echo "Нужен root."; exit 1; }
[ -f /etc/openwrt_release ] || { echo "Это не OpenWrt."; exit 1; }
. /etc/openwrt_release
ARCH="$DISTRIB_ARCH"
dir="packages/$ARCH"
if [ ! -d "$dir" ]; then
	echo "Архитектуры $ARCH в наборе нет. Есть: $(ls packages | tr '\n' ' ')"
	exit 1
fi
if command -v apk >/dev/null 2>&1; then fmt=apk; else fmt=ipk; fi
files=""
for p in $PKGS; do
	f="$dir/$p-$VER-1_$ARCH.$fmt"
	[ -f "$f" ] || { echo "Нет файла $f."; exit 1; }
	files="$files ./$f"
done

# Работающие forkop и podkop — остановить на время установки и запустить обратно после неё.
# Менеджер пакетов качает зависимости из фидов по ходу транзакции, а как только он снимает
# sing-box из фида, правила forkop или podkop оставляют сам роутер без сети: следующие пакеты
# не скачиваются, и установка обрывается на полпути. Остановленный forkop (podkop) свои правила
# снимает; при запуске он заново пишет конфиг и поднимает sing-box — уже коннектор.
stopped=""
for svc in forkop podkop; do
	if [ -x /etc/init.d/$svc ] && /etc/init.d/$svc enabled 2>/dev/null &&
	   nft list table inet "$( [ $svc = forkop ] && echo ForkopTable || echo PodkopTable )" >/dev/null 2>&1; then
		echo "Останавливаю $svc на время установки."
		/etc/init.d/$svc stop >/dev/null 2>&1 || true
		stopped="$stopped $svc"
	fi
done
# sing-box без forkop и podkop (свой конфиг) — запустить коннектор после установки.
was_running=0
[ -z "$stopped" ] && [ -x /etc/init.d/sing-box ] && /etc/init.d/sing-box running 2>/dev/null && was_running=1

# Метка для скриптов ядра и модулей: в этой транзакции ядро встаёт раньше коннектора, и без неё
# оно включило бы службу steer — а движок ведёт коннектор своим экземпляром.
mkdir -p /var/run
touch /var/run/steer-box-installing
restore() {
	rm -f /var/run/steer-box-installing
	for svc in $stopped; do
		echo "Запускаю $svc."
		/etc/init.d/$svc start >/dev/null 2>&1 || echo "$svc не запустился — /etc/init.d/$svc start"
	done
	stopped=""
}
trap restore EXIT

# Закрепления в /etc/apk/world, которые ни на что не указывают.
#
# `apk add ФАЙЛ` (apk 3) записывает в world не «имя», а «имя><хеш файла» — закрепление за этой
# сборкой. Если транзакция оборвалась на середине (на роутере с малым флешем — «No space left on
# device» при распаковке второго пакета набора), world уже записан с хешами НОВЫХ файлов, а в базе
# остались прежние пакеты или не появилось вовсе нового. С этой минуты ЛЮБАЯ команда apk — и наша,
# и чужая, хоть установка zapret — не решается: «unable to select packages: breaks:
# world[steer-core><Q1…]». Воспроизведено на apk 3.0.5 (как на OpenWrt 25.12.5) с tmpfs на 4–5 МБ.
#
# Чиним правкой самого файла, без apk: решатель в таком состоянии отказывает и на `apk add имя`.
# Что делаем с каждой записью «имя><хеш»:
#   - пакета с таким именем нет в базе — запись убирается: она ничего не держит;
#   - пакет стоит, но с другим хешом — становится просто «имя»;
#   - наше имя (аргумент — регулярное выражение имён) — становится «имя» всегда: закрепление за
#     файлом нужно только самой транзакции, дальше оно лишь не даёт apk увидеть пакет в фиде и
#     ломает следующую установку той же версии другой сборки.
# Записи без «><» (в том числе `!имя`) и закрепления чужих пакетов с верным хешом не трогаются.
# Пути — APK_WORLD и APK_DB: стенды подставляют свои.
PKG_OURS='^(steer|steer-.*|libsteer.*|steer-box-connector|luci-app-steer-box-connector)$'
pkg_world_heal() {  # [ИМЕНА-ERE]
	command -v apk >/dev/null 2>&1 || return 0
	_wh_w="${APK_WORLD:-/etc/apk/world}"; _wh_d="${APK_DB:-/lib/apk/db/installed}"
	[ -s "$_wh_w" ] && [ -s "$_wh_d" ] || return 0
	grep -q '><' "$_wh_w" 2>/dev/null || return 0
	grep -q '^P:' "$_wh_d" 2>/dev/null || return 0
	_wh_t="$_wh_w.heal.$$"
	if awk -v ours="${1:-^$}" '
		FILENAME == ARGV[1] {
			if ($0 ~ /^C:/) { c = substr($0, 3); if (p != "") id[p] = c }
			else if ($0 ~ /^P:/) { p = substr($0, 3); if (c != "") id[p] = c }
			if ($0 == "") { c = ""; p = "" }
			next
		}
		{
			i = index($0, "><")
			if (i == 0) { print; next }
			n = substr($0, 1, i - 1); q = substr($0, i + 2)
			if (!(n in id)) next
			if (n ~ ours || id[n] != q) print n; else print
		}' "$_wh_d" "$_wh_w" > "$_wh_t" 2>/dev/null; then
		cmp -s "$_wh_t" "$_wh_w" || mv "$_wh_t" "$_wh_w"
	fi
	rm -f "$_wh_t"
	return 0
}

echo "Ставлю steer-box-connector $VER ($ARCH, .$fmt)."
if [ "$fmt" = apk ]; then
	apk update >/dev/null 2>&1 || echo "apk update не прошёл — ставлю с тем списком пакетов, что есть."
	# Коннектор объявляет себя пакетом sing-box, и apk сам заменяет им sing-box из фида.
	pkg_world_heal
	rc=0
	apk add --allow-untrusted $files || rc=$?
	# При любом исходе: оборванная установка оставляет в world закрепления за файлами, которых в
	# базе нет, — после неё не ставится ничто (см. pkg_world_heal). Закрепления за файлами нам и
	# не нужны.
	pkg_world_heal "$PKG_OURS"
	[ "$rc" = 0 ] || exit "$rc"
else
	opkg update >/dev/null 2>&1 || echo "opkg update не прошёл — ставлю с тем списком пакетов, что есть."
	# opkg сам пакет sing-box не заменяет — снимаем его (настройки в /etc/config/sing-box остаются).
	for p in sing-box sing-box-tiny sing-box-extended; do
		if opkg list-installed | grep -q "^$p "; then
			[ -x /etc/init.d/sing-box ] && /etc/init.d/sing-box stop 2>/dev/null || true
			opkg remove --force-depends "$p"
		fi
	done
	# --force-reinstall: предварительный выпуск и выпуск одной версии — пакеты с одним номером, и без
	# флага opkg считает стоящий пакет той же версии новым и ничего не ставит (apk файл с тем же
	# номером, но другим содержимым заменяет сам).
	opkg install --force-reinstall $files
fi

restore
if [ "$was_running" = 1 ] && ! /etc/init.d/sing-box running 2>/dev/null; then
	/etc/init.d/sing-box start 2>/dev/null || true
fi

echo
sing-box version | head -1
echo "Готово. Страница: LuCI → Services → Steer Connector."
