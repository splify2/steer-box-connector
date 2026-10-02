<div align="center">

<img src="https://splify2.github.io/assets/img/logo.svg" width="96" alt="">

# steer-box-connector

**sing-box для [podkop](https://github.com/itdoginfo/podkop) и [forkop](https://github.com/ushan0v/forkop) на ядре [steer](https://github.com/splify2/steer)**

[![Выпуск](https://img.shields.io/github/v/release/splify2/steer-box-connector?include_prereleases&label=выпуск&color=6d5ce7)](https://github.com/splify2/steer-box-connector/releases)
[![Лицензия](https://img.shields.io/github/license/splify2/steer-box-connector?label=лицензия&color=6d5ce7)](LICENSE)
[![Документация](https://img.shields.io/badge/документация-splify2.github.io-a897ff)](https://splify2.github.io/docs/connector/)
[![Telegram](https://img.shields.io/badge/Telegram-чат-2CA5E0?logo=telegram&logoColor=white)](https://t.me/ssplify)

</div>

Пакет встаёт на место `sing-box`. podkop и forkop пишут свой конфиг и запускают службу как обычно, а
коннектор переводит конфиг в спеку steer: маршрутизация идёт средствами ядра Linux (nftables,
таблицы маршрутизации, домены через fake-IP), без TPROXY и без прокси на каждое соединение.

## Возможности

- CLI sing-box, которым пользуются podkop и forkop: `version`, `check`, `format`, `merge`, `generate`, `rule-set`, `tools fetch`
- выходы direct, интерфейс, VLESS/Reality, hysteria2, trojan, shadowsocks, socks, http, vmess; группы selector и urltest
- selector держит туннель только к выбранному узлу; выбор через Clash API
- DNS: udp, tcp, DoT, DoH (HTTP/1.1 и HTTP/2), fake-IP, `dns.rules`
- Clash API, вход mixed, наборы правил remote и local, `override_port` для проверки FakeIP
- страница LuCI **Services → Steer Connector**
- перезапуск на роутере — около секунды

## Установка

```sh
tar -xzf steer-box-connector-test-<версия>.tar.gz
cd steer-box-connector-test-<версия>
sh install.sh
```

Набор берётся из [выпусков](https://github.com/splify2/steer-box-connector/releases): в нём пакеты коннектора и
ядра steer той же версии под все архитектуры. Подробности, ограничения и обратный путь —
в [документации](https://splify2.github.io/docs/connector/).

## Сборка

```sh
git clone --recursive https://github.com/splify2/steer-box-connector
cd steer-box-connector
sh build.sh              # пакеты под все архитектуры (STEER_ARCH=<арх> — одну)
sh build.sh --bundle     # плюс тестовый набор
```

Нужен docker. Версия коннектора — версия steer в подмодуле: пакет требует `steer-core` той же версии.

## Лицензия

[GPL-3.0](LICENSE)
