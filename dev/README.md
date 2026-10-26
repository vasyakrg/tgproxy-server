# dev-окружение

## Запуск (сквозной путь бот → server → agent → api.telegram.org)

```sh
make dev-certs          # один раз: CA + сертификаты server/agent в dev/tls
make run-agent          # терминал 1: mTLS на 127.0.0.1:8443
make run-server         # терминал 2: прокси 127.0.0.1:8080, admin 127.0.0.1:8090
```

Токен бота — в `dev/.env` (не коммитится, шаблон — `dev/.env.example`):

```sh
set -a; . dev/.env; set +a      # переменная TGP_DEV_BOT_TOKEN
TOKEN=$TGP_DEV_BOT_TOKEN

curl -s http://127.0.0.1:8080/bot$TOKEN/getMe                              # правило localhost (сеть)
curl -s http://127.0.0.1:8080/k/tgp_devkey_local_only/bot$TOKEN/getMe      # правило dev-key (ключ)

curl -s http://127.0.0.1:8090/healthz     # 200
curl -s http://127.0.0.1:8090/readyz      # 200, если агент отвечает
```

Сигналы: `SIGTERM`/`SIGINT` — graceful shutdown (до 30 с на inflight);
`SIGHUP` — перечитать конфиг (правила доступа и уровень логов применяются без рестарта;
`kill -HUP <pid>`). Некорректный конфиг при SIGHUP отвергается, остаётся прежний.

Все ключи и пароли в этой папке — **только для локальной разработки**. В прод не переносить.

## Ключ клиента `dev-key`

Правило доступа `dev-key` в `server.yaml` хранит только SHA-256 ключа (`key_sha256`).
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
- `data/` — рабочие данные dev-процессов.
- Конфиги проверяются командой `tgproxy config validate --mode server|agent -c <file>`.
