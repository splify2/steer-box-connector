# steer-box-connector

Замена пакета `sing-box` для [podkop](https://github.com/itdoginfo/podkop) и
[forkop](https://github.com/ushan0v/forkop) на OpenWrt, работающая на ядре
[steer](https://github.com/splify2/steer).

podkop и forkop пишут конфиг sing-box и запускают службу `sing-box` как обычно. Коннектор
переводит этот конфиг в спеку steer, а маршрутизацию ведёт ядро steer средствами ядра Linux: списки доменов через
fake-IP, наборы nftables и таблицы маршрутизации. TPROXY и прокси в пространстве пользователя
для каждого соединения не нужны — через процесс идут только туннели с протоколами. Сами podkop и
forkop не меняются и ставятся из своих выпусков.

## Что умеет

- CLI sing-box, которым пользуются podkop и forkop: `version`, `check`, `format`, `merge`,
  `generate`, `rule-set`, `tools fetch`.
- Выходы: direct, интерфейс (WireGuard, AmneziaWG), VLESS/Reality, hysteria2, trojan,
  shadowsocks, socks, http, vmess; группы selector и urltest.
- Selector держит туннель только к выбранному узлу, как sing-box. Выбор со страницы forkop или
  podkop (Clash API) переключает туннель и сохраняется до перезагрузки.
- DNS: udp, tcp, DoT, DoH (HTTP/1.1 и HTTP/2), fake-IP, правила `dns.rules`, bootstrap.
- Clash API (выходы, задержки, соединения, трафик), вход mixed (SOCKS4/5, HTTP), наборы правил
  remote и local.
- Трафик самого роутера к именам из списков идёт тем же выходом, что трафик LAN.
- `route-options` с `override_port` — на нём держится проверка FakeIP в браузере у podkop и
  forkop.
- Страница LuCI **Services → Steer Connector**: состояние, нужные пакеты steer и их установка,
  каким sing-box представляться.

Перезапуск на роутере с aarch64 (сотня имён в fake-IP): DNS отвечает через ~0.9 с, трафик идёт
через ~1.2 с.

## Пока не умеет

- действие `reject` и блокировку QUIC;
- выход direct с `routing_mark` (zapret у forkop);
- серверный режим forkop, кроме сервера socks;
- `sing-box generate tls-keypair`.

О первых двух коннектор предупреждает в журнале при запуске, а правила с ними снимает. С сервером
forkop vless, vmess, trojan, hysteria2, shadowsocks, mtproxy, tailscale или из JSON коннектор не
запускается вовсе: `sing-box check` и `sing-box run` отказывают с причиной («вход типа «vless»
коннектор пока не поддерживает», «endpoints[0]: tailscale коннектор не поддерживает»), и forkop
с включённым сервером не стартует. Сервер socks принимает соединения (CONNECT, с паролем и без,
без UDP), но правила секций forkop к ним не применяются: всё уходит в `route.final`.

В диагностике forkop остаются два ⚠ — «Rules proxy counters» и «Additional marking rules found».
Это проверки механики TPROXY, которой коннектор не пользуется, а не поломка.

## Установка

Нужен пакет `steer-core` той же версии и модули протоколов, которые использует конфиг
(`steer-vless`, `steer-hysteria2`, `steer-proxy`). Проще всего — тестовый набор из выпуска:

```sh
tar -xzf steer-box-connector-test-<версия>.tar.gz
cd steer-box-connector-test-<версия>
sh install.sh
```

`install.sh` сам выбирает архитектуру (`DISTRIB_ARCH`) и формат (apk или opkg) и заменяет пакет
sing-box коннектором. Работающие forkop и podkop он на время установки останавливает, а потом
запускает снова. Подробности и обратный путь — в `README.txt` внутри набора.

Проверено на OpenWrt 25.12 (apk) с podkop 0.7.22 и forkop 2.0.0. На opkg не проверялось.

## Сборка

```sh
git clone --recursive https://github.com/splify2/steer-box-connector
cd steer-box-connector
sh build.sh              # пакеты коннектора под все архитектуры steer (STEER_ARCH=<арх> — одну)
sh build.sh --bundle     # плюс тестовый набор с пакетами steer той же версии
```

Нужен docker: сборка идёт в образе сборщика steer (`steer/build/ext-build.sh`) теми же целями
zig и загрузчиками musl, что пакеты steer. Версия коннектора — версия steer в подмодуле:
коннектор связан с libsteer и требует `steer-core` той же версии.

## Устройство

| Каталог | Что там |
|---|---|
| `src/` | `sing-box`: CLI, перевод конфига в спеку steer, DNS, Clash API, mixed, наборы правил |
| `files/` | служба `/etc/init.d/sing-box`, настройки, метод rpcd, правило fw4 для туннелей `sbx*` |
| `luci/` | страница Services → Steer Connector |
| `scripts/` | скрипты пакета |
| `bundle/` | `install.sh` и `README.txt` тестового набора |
| `steer/` | подмодуль ядра steer |

## Сообщить о проблеме

Приложите вывод `sing-box version`, `logread -e sing-box | tail -200` и архитектуру
(`DISTRIB_ARCH` из `/etc/openwrt_release`). Ключи и адреса серверов из конфига перед отправкой
уберите.

## Лицензия

GPL-3.0, как у steer.
