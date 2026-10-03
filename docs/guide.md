# steer-box-connector

Замена пакета `sing-box` для [podkop](https://github.com/itdoginfo/podkop) и
[forkop](https://github.com/ushan0v/forkop) на OpenWrt, работающая на ядре
[steer](https://github.com/splify2/steer).

podkop и forkop пишут конфиг sing-box и запускают службу `sing-box` как обычно. Коннектор
переводит этот конфиг в спеку steer, а маршрутизацию ведёт ядро steer средствами ядра Linux: списки доменов через
fake-IP, наборы nftables и таблицы маршрутизации. TPROXY и прокси в пространстве пользователя
для каждого соединения не нужны — через процессы идут только туннели с протоколами, DNS и входы
mixed. Сами podkop и forkop не меняются и ставятся из своих выпусков.

## Что умеет

- CLI sing-box, которым пользуются podkop и forkop: `run`, `version`, `check`, `format`, `merge`,
  `generate`, `rule-set`, `tools fetch`.
- Выходы: direct, интерфейс (WireGuard, AmneziaWG), VLESS/Reality (в том числе xhttp и шифрование
  VLESS `encryption`), hysteria2, trojan, shadowsocks, socks, http, vmess; группы selector и
  urltest.
- Selector держит туннель только к выбранному узлу, как sing-box. Выбор со страницы forkop или
  podkop (Clash API) переключает туннель и сохраняется до перезагрузки.
- DNS: udp, tcp, DoT, DoH (HTTP/1.1 и HTTP/2), fake-IP, правила `dns.rules`, bootstrap.
- Clash API (выходы, задержки, соединения, трафик), вход mixed (SOCKS4/5, HTTP), наборы правил
  remote и local.
- Трафик самого роутера к именам из списков идёт тем же выходом, что трафик LAN.
- `route-options` с `override_port` — на нём держится проверка FakeIP в браузере у podkop и
  forkop.
- Страница LuCI **Services → Steer Connector**: состояние, нужные пакеты steer и их установка,
  каким sing-box представляться, уровень журнала, поле метки и приоритет правил.

Перезапуск на роутере с aarch64 (сотня имён в fake-IP): DNS отвечает через ~0.9 с, трафик идёт
через ~1.2 с.

## Пока не умеет

- действие `reject` и блокировку QUIC;
- выход direct с `routing_mark` (zapret у forkop);
- `multiplex` у выходов;
- серверный режим forkop, кроме сервера socks;
- плагины shadowsocks, транспорт quic (V2Ray), выходы других типов (tuic, anytls, shadowtls,
  wireguard и прочие), прежнюю запись сервера DNS через `address`, серверы DNS `quic` и `h3`;
- `sing-box generate tls-keypair` и `sing-box rule-set compile`.

О первых трёх коннектор предупреждает в журнале при запуске: правила с reject и routing_mark он
снимает, а соединения multiplex идут без него. Конфиг с плагином shadowsocks, транспортом quic,
выходом другого типа или прежней записью DNS `sing-box check` не принимает — служба не стартует, и
forkop или podkop показывает причину. С сервером
forkop vless, vmess, trojan, hysteria2, shadowsocks, mtproxy, tailscale или из JSON коннектор не
запускается вовсе: `sing-box check` и `sing-box run` отказывают с причиной («вход типа «vless»
коннектор пока не поддерживает», «endpoints[0]: tailscale коннектор не поддерживает»), и forkop
с включённым сервером не стартует. Сервер socks принимает соединения (CONNECT, с паролем и без,
без UDP); правило с условиями по адресу назначения к ним не применяется: соединение идёт по
правилу, у которого из условий только этот вход, а нет такого — в `route.final`.

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
запускает снова.

Ядро steer коннектор ведёт своим экземпляром, поэтому при установке служба `steer` (например, от
splify2) останавливается и выключается; её спека в `/etc/steer` остаётся на месте. При удалении
коннектора пакеты `steer-*` остаются, а служба — выключенной: вернуть её —
`/etc/init.d/steer enable && /etc/init.d/steer start`.

Проверено на OpenWrt 25.12 (apk) с podkop 0.7.22 и forkop 2.0.0. На opkg не проверялось.

Со страницы **Services → Steer Connector** пакеты steer ставятся по сети. Версии берутся из
перечня выпусков [splify2/releases](https://github.com/splify2/releases) — `version.json` с
raw.githubusercontent.com, jsDelivr или splify2.github.io, по порядку; предварительная версия
помечена в списке. Пакет качается по адресам из перечня (сначала выпуск в splify2/releases, потом
выпуск steer) и сверяется с его `sha256`, если на роутере есть `sha256sum`: не сошлось — следующий
адрес. Перечень не ответил — список версий из выпусков GitHub `splify2/steer`; файла нет в
перечне — пакет по ссылке выпуска steer.

Пакеты steer и коннектор зависят друг от друга с точной версией. Поэтому версия, отличная от версии
коннектора, ставится целиком: каждый установленный пакет steer этой версией и коннектор той же
версии с его выпуска. Выпуска коннектора этой версии нет — не ставится ничего.

## Вернуть обычный sing-box (apk)

```sh
/etc/init.d/forkop stop        # или podkop
apk del steer-box-connector
apk add sing-box
/etc/init.d/forkop start
```

Сначала остановите forkop или podkop: без sing-box их правила оставляют роутер без сети, и пакет
sing-box не скачается.

## Сборка

```sh
git clone --recursive https://github.com/splify2/steer-box-connector
cd steer-box-connector
sh build.sh              # пакеты коннектора под все архитектуры steer (STEER_ARCH=<арх> — одну)
sh build.sh --bundle     # плюс тестовый набор с пакетами steer той же версии
```

Нужен docker: сборка идёт в образе сборщика steer (`steer/build/ext-build.sh`) теми же целями
zig и загрузчиками musl, что пакеты steer. Версия коннектора — версия steer в подмодуле:
коннектор связан с libsteer и требует `steer-core` той же версии. Предварительные выпуски одной
версии различаются коммитом steer — он в строке `Revision:` вывода `sing-box version`; ставить
коннектор нужно с `steer-core` той же сборки, из того же набора.

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
