# tgproxy-server

Прокси для Telegram Bot API. `server` принимает запросы ботов, `agent` (в другом сегменте сети или за NAT) ходит в `api.telegram.org`. Один бинарь `tgproxy`, связь server ↔ agent по mTLS.

![tgproxy server + agent](docs/tgproxy-server-agent.svg)

## Архитектура (кратко)

- Клиенты меняют только base URL: `{base}/bot<token>/<method>` или `{base}/k/<key>/bot<token>/<method>`. Доступ — правила (сети CIDR и/или скрытый ключ), токены ботов сервер не хранит.
- Сервер балансирует запросы по агентам (P2C по inflight×EWMA, circuit breaker); небезопасные методы (`send*`) не ретраятся после записи.
- Два режима связи: `dial` (сервер ходит к агенту на `:8443`) и `reverse` (агент за NAT сам дозванивается до `agent_gateway` сервера `:8444`).
- Встроенный CA (ключ шифруется KEK) выпускает сертификаты; SQLite — единственное обязательное хранилище; админка — Web-UI + `/api/v1` с паролем и TOTP.
- Обновления подписаны minisign; агент сам проверяет подпись встроенными ключами. Подробности: [docs/architecture.md](docs/architecture.md).

## Быстрый старт сервера (Debian 12, amd64)

Релизные deb — в GitHub Releases (`tgproxy_<версия>_amd64.deb`).

```sh
sudo dpkg -i tgproxy_<версия>_amd64.deb      # автозапуск не включается
sudo editor /etc/tgproxy/server.yaml          # public_base_url, tls, access_rules
tgproxy config validate --mode server -c /etc/tgproxy/server.yaml
```

Бутстрап (один раз; сервер без CA не стартует):

```sh
# 1. KEK — ключ шифрования секретов. Сразу сохраните копию в офлайн-хранилище (docs/operations.md)
sudo tgproxy pki kek-init --out /etc/tgproxy/kek && sudo chown tgproxy:tgproxy /etc/tgproxy/kek
# 2. CA в БД
sudo runuser -u tgproxy -- tgproxy pki init -c /etc/tgproxy/server.yaml
# 3. Хеш пароля админа (запросит пароль без эха)
tgproxy hashpw
# 4. /etc/tgproxy/users_database.yml (root:tgproxy, 0640), формат Authelia:
#    users:
#      admin:
#        displayname: Admin
#        password: '<хеш из hashpw>'
#        email: admin@example.com
#        telegram_id: 123456789     # получатель алертов, 0 — никому
# 5. TOTP обязателен: печатает QR и totp_secret_enc
sudo runuser -u tgproxy -- tgproxy totp enroll admin      # --users-file, --kek-file — если пути нестандартные
#    вставьте totp_secret_enc в users_database.yml под пользователем admin
# 6. Правило доступа (без правил прокси закрыт для всех)
sudo runuser -u tgproxy -- tgproxy access add --name office --cidr 203.0.113.0/24 -c /etc/tgproxy/server.yaml
sudo runuser -u tgproxy -- tgproxy access add --name ci --with-key --rps 5 -c /etc/tgproxy/server.yaml   # ключ печатается один раз
# 7. Запуск и самообновление
sudo systemctl enable --now tgproxy-server tgproxy-update-server.path
```

Правила `access_rules` из `server.yaml` засеваются в БД только при пустой таблице; дальше источник правды — БД (UI «Доступ» или `tgproxy access add|list|delete`).

Правило «сеть + ключ» требует **оба** условия: запрос из этой сети без ключа получает 403 (в UI чекбокс «Скрытый ключ в адресе» по умолчанию выключен, при заданных сетях показывается подсказка).

### Отказы, баны и страны

Каждый отказ доступа виден в логе (`client_ip`, `reason`, `country`), в метрике `tgp_denied_total{reason}`, на графике «Обзор» (серия «Отказы») и в «Ошибках» (фаза `access`). Причины: `no_rule`, `key_required`, `bad_key`, `rate_limited`, `banned`.

Встроенный fail2ban (`ban:` в `server.yaml`, включён по умолчанию): 20 отказов `no_rule|key_required|bad_key` за 10 минут — бан на 1 ч, повторные — 24 ч, затем 7 д. Свои адреса (trusted_proxies, агенты, сети правил, приватные) не банятся. Ручное управление — экран «Баны», иконка бана в «Ошибках», `tgproxy ban add|list|delete -c /etc/tgproxy/server.yaml`, API `/api/v1/bans`. Алерт `ip_autoban` приходит админам одним сообщением на пачку.

Флаги стран (`geoip.file`) — по локальной базе, deb кладёт её в `/usr/share/tgproxy/geoip/`; нет файла — флаги не показываются. Для локальной сборки пакета: `make geoip` (скачивает базу в `build/geoip/`).

IP Geolocation by [DB-IP](https://db-ip.com) — база «IP to Country Lite» распространяется под лицензией [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

### TLS на входе (`tls.mode`)

| Режим | Что делать |
|---|---|
| `files` | `tls.cert_file` + `tls.key_file` (0600/0640 `root:tgproxy`); подмена файла подхватывается без рестарта (или `systemctl reload`/SIGHUP) |
| `acme` | `tls.domains`, `tls.acme.email`; нужен входящий `:443` (или `tls.acme.http01_listen: ":80"`) и исходящий доступ к ACME CA; кэш `tls.cache_dir` |
| `off` | TLS терминирует внешний reverse proxy; обязателен `trusted_proxies` |

Порт `:443` непривилегированному юниту: drop-in `AmbientCapabilities=CAP_NET_BIND_SERVICE` и `CapabilityBoundingSet=CAP_NET_BIND_SERVICE` (`systemctl edit tgproxy-server`).

## Агенты

Установка агента — в UI «Агенты → Добавить».

- **Агент доступен по SSH (`dial`)**: мастер по SSH ставит deb из кэша сервера, выпускает сертификат и запускает агента. Ключ хоста закрепляется при первом подключении (TOFU, отпечаток подтверждаете вы).
- **Агент за NAT (`reverse`)**: токен из UI «Агент за NAT» или CLI
  ```sh
  sudo runuser -u tgproxy -- tgproxy agents enroll-token --name nat1 -c /etc/tgproxy/server.yaml
  ```
  Токен одноразовый (TTL 1 ч, максимум `--ttl 24h`). Команда на выходе — одна копируемая целиком, для чистого Debian/Ubuntu amd64, под root (без sudo) или обычным пользователем с `sudo`; при отсутствии `curl` доустанавливает `curl` и `ca-certificates`; скачивает deb **с самого сервера** (`GET https://<сервер>:8444/enroll/package/<deb>`, GitHub не нужен), сверяет sha256 из подписанного `checksums.txt`, ставит через `apt-get install` (с зависимостями), выполняет `tgproxy agent enroll` и `systemctl enable --now tgproxy-agent`. Токен в argv/`ps` не попадает (`printf` — builtin шелла, заголовок в curl идёт через stdin), TLS — `--cacert` с CA сервера, TLS 1.3, без `-k`.

  Требования: на сервере в кэше загрузок (`update.downloads_dir`, UI «Система → Обновления») должен лежать **подписанный релиз той же версии, что и сервер** (`tgproxy_<версия>_amd64.deb` + `checksums.txt` + `.minisig`); иначе токен не выдаётся — «загрузите релиз X в Система → Обновления». Хост gateway входит в SAN серверного сертификата — после обновления сервера до этой версии перезапустите его, чтобы сертификат перевыпустился.

  После выпуска токена экран сам отслеживает подключение (опрос htmx каждые 3 с, пока страница открыта): «Ожидаем подключения» → «зарегистрирован» → «подключился» (тост и через 2 с переход на «Агенты» с подсветкой строки); истёкший или отозванный токен останавливает опрос и предлагает выпустить новый.

  Утёкший или ненужный токен отзывается до использования: в UI «Агенты → Агент за NAT → Ожидающие подключения» (иконка «Отозвать», подтверждение модалкой), через `DELETE /api/v1/enrollments/{id}?confirm=yes` или CLI `tgproxy agents enroll-token -c /etc/tgproxy/server.yaml --list` / `--revoke <id|имя>`. После отзыва `/enroll` и `/enroll/package/*` отвечают `401`, действие пишется в аудит (`enrollment.revoke`). `tgproxy agent enroll` в конфиге `reverse`-агента не пишет `listen.api` (входящих нет); для перехода в `dial`/`both` адрес `listen.api` задаётся вручную.

  Если tgproxy на хосте уже установлен, там же показана короткая команда (`printf %s '<токен>' | sudo tgproxy agent enroll --token-stdin --server https://<сервер>:8444 --ca-fingerprint SHA256:...`; в CLI — `agents enroll-token --installed`, пакет в кэше не нужен), затем `systemctl enable --now tgproxy-agent`. Отпечаток CA: `tgproxy pki fingerprint -c /etc/tgproxy/server.yaml`.

## Порты

| Процесс | Порт | Назначение |
|---|---|---|
| server | `:8443` (шаблон `/etc/tgproxy/server.yaml`; дефолт конфига `:8080`) | прокси для ботов, TLS по `tls.mode` |
| server | `127.0.0.1:8090` | Web-UI, `/api/v1`, `/healthz`, `/readyz` (наружу — через reverse proxy) |
| server | `127.0.0.1:9090` | `/metrics` |
| server | `:8444` | `agent_gateway`: reverse-соединения агентов (mTLS), `/enroll`, раздача пакетов |
| server | `mtproto.listen` (по умолчанию `shared` — порт `listen.proxy`) | MTProto-прокси для клиентов Telegram (FakeTLS), только при `mtproto.enabled`; отдельный порт — режим dedicated |
| agent | `:8443` | mTLS: `/tg/*`, `/_agent/*` (только для `dial`) |
| agent | `127.0.0.1:9443` | `/metrics` |

Для `reverse` на агенте входящих портов не нужно; на сервере должен быть открыт `:8444` из сетей агентов. Агентам для MTProto нужен исходящий TCP 443 к сетям Telegram.

## MTProto для клиентов Telegram (beta)

Те же агенты умеют проксировать обычные клиенты Telegram: пользователь открывает ссылку `tg://proxy?…` с FakeTLS-секретом (`ee…`), сервер принимает соединение и ведёт его к дата-центрам Telegram через агента. Невалидные соединения (зонды, чужие секреты) получают обычный TLS-сайт с настоящим сертификатом. По умолчанию выключено.

```yaml
# server.yaml: нужны pki.kek_file и tls.mode files|acme
mtproto:
  enabled: true
  listen: shared                       # или "203.0.113.10:443" — отдельный IP (рекомендуется для прода)
  fronting_domain: tgproxy.example.com # домен из сертификата входа
```

Секреты и ссылки — UI «MTProto» либо `tgproxy mtproto secret add|list|link|rotate|delete`; проверка — `tgproxy mtproto probe`. Ограничения beta: нет ad-tag/спонсорского канала, ServerHello FakeTLS отличается по отпечатку от `crypto/tls`. Подготовка хостов (NTP, sysctl, фаервол), диагностика, ротация, переход на dedicated IP — [docs/operations.md](docs/operations.md) («MTProto»); дизайн — [docs/mtproto.md](docs/mtproto.md).

## Метрики

Префикс `tgp_`, `bot_id` в метках нет. `/metrics` на не-loopback адресе требует `metrics.bearer_file` (Bearer-токен, `openssl rand -hex 24 > файл`, права 0640 `root:tgproxy`). Метрики агентов сервер отдаёт федеративно: `/api/v1/agents/{id}/metrics`. Список — [docs/architecture.md](docs/architecture.md) §10 (MTProto — `tgp_mtproto_*`, [docs/mtproto.md](docs/mtproto.md) §13).

## Обновления

- Источник по умолчанию — GitHub Releases (`update.repo`), `update.source`: `github | proxy | agent | upload`. Сервер скачивает релиз, проверяет minisign и ставит его юнитом `tgproxy-update-server.path`; при провале `/healthz` за 30 с — откат на предыдущий deb.
- Агентов обновляет сервер (UI «Система → Обновления», канарейка → батчи): пакет проверяется подписью на самом агенте. Путь `tgproxy-update-agent.path` на агенте включается установщиком и `agent enroll`.
- Деплой вашего форка на прод: `deploy/.env.example` → `deploy/.env`, затем `make deploy` (`DEPLOY_DRY_RUN=1` — только план; `DEPLOY_MODE=release DEPLOY_TAG=vX.Y.Z` — релиз с проверкой подписи). Скрипт не делает бутстрап и не трогает агентов.
- Выпуск релиза и ключ minisign: [docs/release.md](docs/release.md).

## Эксплуатация

[docs/operations.md](docs/operations.md): бэкап и восстановление, потеря KEK, ротация ключей и сертификатов, lockout, MTProto, troubleshooting.

## Разработка и локальный запуск (macOS)

```sh
make build && ./bin/tgproxy version
make dev-setup && make run-server     # + make run-agent в соседнем терминале
```

Подробности (агент за NAT, SSH-стенд в docker, TOTP, метрики, алерты) — [dev/README.md](dev/README.md). `dev/users.yml` (`admin` / `dev-password`) и ключи в `dev/` — только для разработки. `make help` — список целей.

## Документация

- [docs/architecture.md](docs/architecture.md) — архитектура (источник правды)
- [docs/operations.md](docs/operations.md) — эксплуатация
- [docs/mtproto.md](docs/mtproto.md) — MTProto-прокси для клиентов Telegram
- [docs/release.md](docs/release.md) — релизы и ключ подписи
- [docs/plan.md](docs/plan.md) — план реализации по вехам
