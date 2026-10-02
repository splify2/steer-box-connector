#!/bin/sh
# Установка тестового набора steer-box-connector на роутер: steer-core, модули протоколов
# (vless, hysteria2, proxy) и сам коннектор — sing-box для podkop и forkop на движке steer.
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

echo "Ставлю steer-box-connector $VER ($ARCH, .$fmt)."
if [ "$fmt" = apk ]; then
	apk update >/dev/null 2>&1 || echo "apk update не прошёл — ставлю с тем списком пакетов, что есть."
	# Коннектор объявляет себя пакетом sing-box, и apk сам заменяет им sing-box из фида.
	apk add --allow-untrusted $files
else
	opkg update >/dev/null 2>&1 || echo "opkg update не прошёл — ставлю с тем списком пакетов, что есть."
	# opkg сам пакет sing-box не заменяет — снимаем его (настройки в /etc/config/sing-box остаются).
	for p in sing-box sing-box-tiny sing-box-extended; do
		if opkg list-installed | grep -q "^$p "; then
			[ -x /etc/init.d/sing-box ] && /etc/init.d/sing-box stop 2>/dev/null || true
			opkg remove --force-depends "$p"
		fi
	done
	opkg install $files
fi

restore
if [ "$was_running" = 1 ] && ! /etc/init.d/sing-box running 2>/dev/null; then
	/etc/init.d/sing-box start 2>/dev/null || true
fi

echo
sing-box version | head -1
echo "Готово. Страница: LuCI → Services → Steer Connector."
