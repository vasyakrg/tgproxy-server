# dev-окружение

## Запуск (сквозной путь бот → server → agent → api.telegram.org)

```sh
make dev-setup          # один раз: KEK dev/data/kek, CA в dev/data/tgproxy.db (`pki init`), сертификаты агентов local, local2 в dev/tls, chmod 0640 dev/users.yml
make run-agent          # терминал 1: агент local,  mTLS на 127.0.0.1:8443
make run-agent2         # терминал 2: агент local2, mTLS на 127.0.0.1:8445 (:8444 занят agent_gateway)
make run-server         # терминал 3: прокси 127.0.0.1:8080, admin 127.0.0.1:8090, agent_gateway 127.0.0.1:8444
```

`dev-setup` идемпотентен: CA, KEK и действующие сертификаты агентов не перевыпускаются. Сервер не создаёт CA сам —
без `pki init` он не стартует (`CA is not initialized`). Чтобы начать с чистого CA: остановить сервер, удалить
`dev/data/tgproxy.db*` и `dev/tls`, повторить `make dev-setup`. В `dev/server.yaml` нет `agent_tls`: сервер берёт CA из БД
и сам выпускает себе mTLS-сертификат (статические `agent_tls`-файлы остаются поддержанным режимом без reverse и enrollment).

Один агент можно не запускать: сервер работает с тем, что `up` (опрос статуса каждые 5 с,
3 неудачи подряд — down, один успех — снова up). Запросы к упавшему агенту уходят на второй.

## Агент за NAT (reverse + enrollment) и SSH-установка

`agent_gateway` (`127.0.0.1:8444`, TLS 1.3) принимает reverse-соединения агентов и `POST /enroll`. Токен подключения:
в UI (ветка «Агент за NAT») или из CLI:

```sh
./bin/tgproxy agents enroll-token -c dev/server.yaml --name nat1     # печатает команду `tgproxy agent enroll ...` (токен один раз)
```

Публичный URL gateway в команде = хост `server.public_base_url` + порт `listen.agent_gateway` (`https://127.0.0.1:8444`).
Агент на хосте: выполнить команду (без `sudo`, с `-c <agent.yaml>`), затем `./bin/tgproxy agent -c <agent.yaml>` — он появится
в реестре в режиме `reverse`, а `tgp_agent_reverse_conns{agent="nat1"}` на сервере станет 2.

Docker-стенд (`make dev-target-up`; нужен запущенный `make run-server`):

- `nat-agent` — агент в reverse-режиме без опубликованных портов. Достаёт сервер на хосте по `https://host.docker.internal:8444`
  (в команде из UI/CLI замените хост `127.0.0.1` на `host.docker.internal`). Enrollment внутри контейнера:
  `docker compose -f dev/docker-compose.yml exec -e TGP_ENROLL_TOKEN=<токен> nat-agent tgproxy agent enroll --server https://host.docker.internal:8444 --ca-fingerprint <SHA256:...>` —
  контейнер ждёт `/etc/tgproxy/agent.yaml` и сам запускает агента. Либо передать `TGP_ENROLL_TOKEN`/`TGP_CA_FINGERPRINT` окружением при `make dev-target-up`.
- `sshd-debian` — цель SSH-установки (образ из `internal/server/installer/testdata/Dockerfile.sshd-systemd`: debian:12, systemd, sshd,
  пользователь `admin`/`adminpw` с sudo по паролю). В UI: хост `127.0.0.1`, SSH-порт `2222`, порт агента `18443`.
  Локальный deb для установщика — `make dev-packages` (snapshot под архитектуру docker-хоста → `dev/data/packages`; на Apple Silicon — arm64, только для dev).
  После пересоздания контейнера ключ хоста меняется, и мастер отвечает «Ключ хоста отличается от закреплённого». Сброс пина (только CLI на сервере, не UI):
  `tgproxy hostkeys list -c dev/server.yaml`, затем `tgproxy hostkeys forget 127.0.0.1:2222 -c dev/server.yaml` (без `--yes` покажет отпечаток и спросит y/N;
  пишет аудит `hostkey.forget`, actor `cli:<$USER>`). При следующей установке отпечаток нужно подтвердить заново.
- `make dev-target-down` останавливает оба сервиса.

## Веб-UI

После `make run-server` админка на `http://127.0.0.1:8090` (вход: `admin` / `dev-password`).
Пока в `dev/users.yml` нет `totp_secret_enc`, вход только по паролю: для этого в `dev/server.yaml`
стоит `auth.allow_password_only: true` — **только dev; в проде TOTP обязателен**.

Включить TOTP для `admin`:

```sh
./bin/tgproxy totp enroll admin --users-file dev/users.yml --kek-file dev/data/kek   # печатает QR и totp_secret_enc
# вставьте totp_secret_enc в dev/users.yml под пользователем admin (сессии админа сбросятся сами)
# затем уберите auth.allow_password_only из dev/server.yaml (или поставьте false) и перезапустите сервер
```

`SIGHUP` перечитывает `dev/users.yml`; изменения файла подхватываются автоматически.
`server.public_base_url` (`dev/server.yaml`) попадает в UI «Доступ» как base URL для ботов.

## Метрики и алерты

`/metrics` слушает `127.0.0.1:9090` и на loopback открыт без bearer:

```sh
curl -s 127.0.0.1:9090/metrics | grep tgp_requests_total      # bot_id в метках нет
```

Чтобы включить bearer: `openssl rand -hex 24 > dev/data/metrics-bearer && chmod 600 dev/data/metrics-bearer`,
раскомментировать `metrics.bearer_file` в `dev/server.yaml`, затем
`curl -H "Authorization: Bearer $(cat dev/data/metrics-bearer)" 127.0.0.1:9090/metrics`.

Алерты (`notify`) выключены по умолчанию. Включение: создать файл токена (в git нет, `dev/data/` в `.gitignore`)
и раскомментировать секцию `notify` в `dev/server.yaml`:

```sh
mkdir -p dev/data && printf '%s' '<токен от @BotFather>' > dev/data/notify-token && chmod 600 dev/data/notify-token
```

Получатели — `telegram_id` пользователей в `dev/users.yml` (по умолчанию `0` → никому не отправляется;
подставьте свой id). Алерт `agent_down` приходит, когда агент недоступен, через оставшиеся агенты.
Секция `notify` закомментирована намеренно: при включённой секции без файла токена конфиг не грузится (в т.ч. для CLI).
SIGHUP перечитывает и получателей.

## БД, правила доступа и агенты

Состояние сервера — SQLite `dev/data/tgproxy.db`. Правила доступа и агенты из `server.yaml`
(`access_rules`, `agents`) засеваются в БД **только при пустых таблицах** (первый старт);
дальше источник правды — БД. Чтобы пересеять — остановить сервер и удалить `dev/data/tgproxy.db*`.

CLI работает напрямую с БД по конфигу сервера, в том числе при запущенном сервере
(WAL; сервер подхватывает изменения в течение ~2 с, рестарт не нужен):

```sh
./bin/tgproxy access add --name ext --with-key --rps 5 -c dev/server.yaml   # ключ печатается ОДИН раз
./bin/tgproxy access add --name lan --cidr 10.0.0.0/8 --cidr 192.168.0.0/16 -c dev/server.yaml
./bin/tgproxy access list -c dev/server.yaml                                # только префикс ключа
./bin/tgproxy access delete --name ext -c dev/server.yaml                   # или --id N
./bin/tgproxy agents list -c dev/server.yaml
```

Ограничение `--rps`: сверх лимита сервер отвечает `429` с `retry_after`, не обращаясь к агенту.

## Окна 429 (flood)

`scripts/dev/flood.sh [N] [PROXY]` шлёт N `sendMessage` в один чат (токен и `TGP_DEV_CHAT_ID` — из
`dev/.env`, токен не печатается) и показывает, на каком запросе Telegram вернул 429 через агента
и с какого сервер отвечает 429 сам (окно `(bot, chat)`), без похода к агенту.

Токен бота — в `dev/.env` (не коммитится, шаблон — `dev/.env.example`):

```sh
set -a; . dev/.env; set +a      # переменная TGP_DEV_BOT_TOKEN
TOKEN=$TGP_DEV_BOT_TOKEN

curl -s http://127.0.0.1:8080/bot$TOKEN/getMe                              # правило localhost (сеть)
curl -s http://127.0.0.1:8080/k/tgp_devkey_local_only/bot$TOKEN/getMe      # правило dev-key (ключ)

curl -s http://127.0.0.1:8090/healthz     # 200
curl -s http://127.0.0.1:8090/readyz      # 200, если хотя бы один агент up
```

Сигналы: `SIGTERM`/`SIGINT` — graceful shutdown (до 30 с на inflight);
`SIGHUP` — перечитать конфиг (уровень логов и параметры обработчика; правила доступа
перечитываются из БД; `kill -HUP <pid>`). Некорректный конфиг при SIGHUP отвергается, остаётся прежний.

Все ключи и пароли в этой папке — **только для локальной разработки**. В прод не переносить.

## Ключ клиента `dev-key`

Правило доступа `dev-key` в `server.yaml` (засеивается в БД при первом старте) хранит только SHA-256 ключа (`key_sha256`).
Сам ключ — строка `tgp_devkey_local_only`. Хеш считается так:

```sh
printf 'tgp_devkey_local_only' | shasum -a 256
# 5d920d4d62626d92a41b29c61d704f31857190681e0f521e08d22ce671082be7
```

(`printf`, а не `echo`: перевод строки изменит хеш.)

Клиент вне доверенных сетей обращается так:

```sh
curl http://127.0.0.1:8080/k/tgp_devkey_local_only/bot$TOKEN/getMe
curl -H 'X-Proxy-Key: tgp_devkey_local_only' http://127.0.0.1:8080/bot$TOKEN/getMe
```

Правило `localhost` (CIDR `127.0.0.0/8`) пускает без ключа: `http://127.0.0.1:8080/bot$TOKEN/getMe`.

В боевой конфигурации вместо `key_sha256` можно указать `key_file` (файл с ключом, права 0600/0640,
ключ хешируется при загрузке). Правило без сетей и без ключа, а также `0.0.0.0/0` без ключа
отвергаются валидацией (открытый relay к Bot API).

## Прочее

- `users.yml` — пользователь `admin`, пароль `dev-password`.
- `tls/` — сертификаты dev-агентов, выпущенные CA из БД (`make dev-certs` → `tgproxy pki dev-agents`); в git не коммитятся. Выпуск агентам из `dev-agents` — только dev; в проде агент получает сертификат по CSR/enrollment, отпечаток CA: `tgproxy pki fingerprint -c server.yaml`.
- `data/` — рабочие данные dev-процессов (БД сервера `tgproxy.db`, KEK `kek`, данные агентов).
- Конфиги проверяются командой `tgproxy config validate --mode server|agent -c <file>`.
