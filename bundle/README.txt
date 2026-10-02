steer-box-connector @VERSION@ — тестовый набор
=============================================

Что это. Замена пакета sing-box для podkop и forkop. Команда `sing-box run` переводит конфиг,
который пишут podkop или forkop, в спеку steer, и маршрутизацию ведёт ядро steer средствами ядра Linux —
без TPROXY и без прокси в пространстве пользователя для простых выходов. Сами podkop и forkop
не меняются: ставятся отдельно, из своих выпусков, как обычно.

Что внутри. Только наши пакеты, по каталогу на архитектуру (packages/<архитектура>), в двух
форматах — .apk (OpenWrt 25.12, apk) и .ipk (OpenWrt на opkg):
  steer-core           ядро steer
  steer-vless          VLESS / Reality
  steer-hysteria2      hysteria2
  steer-proxy          trojan, shadowsocks, socks, http, vmess
  steer-box-connector  сам коннектор (/usr/bin/sing-box, служба sing-box) и страница LuCI
Пакетов из фидов OpenWrt в наборе нет: что нужно оттуда, менеджер пакетов скачает сам.

Архитектуры: @ARCHES@.
Своя — в /etc/openwrt_release, строка DISTRIB_ARCH.

Установка (на роутере):
  tar -xzf steer-box-connector-test-@VERSION@.tar.gz
  cd steer-box-connector-test-@VERSION@
  sh install.sh
Скрипт сам берёт нужную архитектуру и формат. Пакет sing-box из фида заменяется коннектором
(apk делает это сам, на opkg скрипт снимает sing-box перед установкой). Настройки
/etc/config/sing-box, podkop и forkop не трогаются. Если sing-box работал — после установки
работает коннектор.

Страница: LuCI → Services → Steer Connector. На ней — состояние, какие пакеты steer нужны
текущему конфигу (и их установка), каким sing-box представляться (вариант и версия: forkop
смотрит на extended, podkop требует не ниже 1.12.4), поле метки и приоритет правил.

Проверено (стенд QEMU с OpenWrt 25.12.5 x86_64 и роутер на aarch64_cortex-a53, оба на apk):
  - podkop 0.7.22 и forkop 2.0.0: списки доменов (fake-IP), подсети, прямой выход, DNS
    (udp, DoH с bootstrap, через выход), Clash API, mixed-вход, наборы правил;
  - трафик самого роутера к именам из списков идёт тем же выходом, что и трафик LAN;
  - 74 имени разом на холодном старте — все с ответом.
На opkg набор не проверялся.

Что знать заранее:
  - Селектор (у forkop — вся подписка в одном выходе): как у sing-box, трафик несёт только
    выбранный узел, и туннель поднят только к нему. Выбор на странице forkop (Clash API)
    переключает туннель за секунду-две и помнится до перезагрузки роутера. Задержка невыбранных
    узлов в замере — время соединения с их сервером, без похода через сам узел.
  - urltest (у podkop — режим URLTest) держит туннель к каждому своему узлу: так он их и
    сравнивает. Это около 2 МБ памяти на узел, на роутере с малой памятью узлов в urltest
    должно быть немного.
  - Диагностика forkop показывает два ⚠ — это не поломка:
      «Счётчики правил proxy» — счётчик forkop стоит за tproxy, а прозрачного сокета нет
      (коннектор работает без TPROXY), поэтому он всегда 0;
      «Найдены дополнительные правила маркировки» — это таблица inet sbox ядра steer.
  - Пока не переводится: действие reject и блокировка QUIC, выход через routing_mark zapret,
    серверный режим forkop (кроме сервера socks), `sing-box generate tls-keypair`. О первых двух
    коннектор предупреждает в журнале при запуске («… пока не переводится»). С сервером forkop
    vless, vmess, trojan, hysteria2, shadowsocks, mtproxy, tailscale или из JSON коннектор не
    запускается: sing-box check и run отказывают с причиной («вход типа … коннектор пока не
    поддерживает»), и forkop с таким сервером не стартует. Сервер socks принимает соединения
    (CONNECT, без UDP), но правила секций к ним не применяются — всё идёт в route.final. Подмена порта (route-options
    override_port — проверка FakeIP в браузере у podkop и forkop) переводится.
  - Без запущенного sing-box (коннектора) forkop и podkop оставляют свои правила, и у самого
    роутера пропадает DNS и часть сети — так же, как с обычным sing-box.

Вернуть обычный sing-box (apk):
  /etc/init.d/forkop stop        (или podkop)
  apk del steer-box-connector
  apk add sing-box
  /etc/init.d/forkop start
Сначала остановить forkop/podkop обязательно: без sing-box их правила оставляют роутер без
сети, и apk add не скачает пакет.

Если что-то не так — пришлите:
  sing-box version
  logread -e sing-box | tail -200
  /etc/init.d/forkop global_check   (или вывод диагностики podkop)
Ключи и адреса серверов из конфига перед отправкой уберите.
