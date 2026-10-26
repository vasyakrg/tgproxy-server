# dev-окружение

## Запуск (сквозной путь бот → server → agent → api.telegram.org)

```sh
make dev-setup          # один раз: dev-certs (CA + server + агенты local, local2 в dev/tls) + KEK dev/data/kek + chmod 0640 dev/users.yml
make run-agent          # терминал 1: агент local,  mTLS на 127.0.0.1:8443
make run-agent2         # терминал 2: агент local2, mTLS на 127.0.0.1:8445 (:8444 занят agent_gateway)
make run-server         # терминал 3: прокси 127.0.0.1:8080, admin 127.0.0.1:8090
```

`dev-certs` идемпотентен: если `dev/tls/ca.crt` уже есть (создан до появления `local2`),
удалите `dev/tls` и повторите `make dev-certs`.

Один агент можно не запускать: сервер работает с тем, что `up` (опрос статуса каждые 5 с,
3 неудачи подряд — down, один успех — снова up). Запросы к упавшему агенту уходят на второй.

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
- `tls/` — dev-сертификаты (`make dev-certs` → `tgproxy pki dev-init`); в git не коммитятся.
- `data/` — рабочие данные dev-процессов (БД сервера `tgproxy.db`, KEK `kek`, данные агентов).
- Конфиги проверяются командой `tgproxy config validate --mode server|agent -c <file>`.
