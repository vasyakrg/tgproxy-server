# AGENTS.md — tgproxy-server

Прокси для Telegram Bot API: один бинарь `tgproxy` (режимы `server` и `agent`), связь server ↔ agent по mTLS в режимах `dial` (сервер звонит агенту) и `reverse` (агент за NAT сам подключается к `agent_gateway`). Плюс beta-режим MTProto-прокси для клиентов Telegram (FakeTLS). Состояние — SQLite, админка — templ + htmx, поставка — deb + подписанные minisign релизы с самообновлением.

Версия — из тега (`git describe --tags`), релизы публикуются в GitHub Releases. Статус: MTProto beta и по умолчанию выключен (`mtproto.enabled: false`).

## Источник правды

| Документ | Что там |
|---|---|
| `docs/architecture.md` | архитектура. **Правки архитектуры — только здесь**; расхождение кода и документа = ошибка кода |
| `docs/plan.md`, `docs/plan-mtproto.md` | план по вехам и статус задач |
| `docs/operations.md` | эксплуатация: бэкап, KEK, ротация, lockout, MTProto, troubleshooting |
| `docs/mtproto.md` | дизайн MTProto, §13 — метрики |
| `docs/release.md` | релиз, ключ minisign, environment `release` |
| `dev/README.md` | локальный стенд: dev-сервер, агенты, reverse/enrollment, SSH-стенд |
| `docs/design/*.dc.html` | макеты UI |

## Команды

```sh
make build          # bin/tgproxy (CGO_ENABLED=0, trimpath, ldflags из git describe)
make generate       # go tool templ generate  (обязательно после правки *.templ)
make test           # go test ./...
make test-race      # go test -race ./...   — обязателен локально перед тегом
make lint           # golangci-lint run (конфиг .golangci.yml, version: 2)
make vuln           # go tool govulncheck ./...
make gosec          # gosec v2.30.0 через go run
make fuzz           # фаззеры, FUZZTIME=60s на таргет; список таргетов — в Makefile
make snapshot|deb   # goreleaser snapshot / только deb (нужен goreleaser v2)
make release-dry    # полный dry-run + smoke deb (нужен docker)
make dev-setup      # KEK, CA в dev/data/tgproxy.db, сертификаты агентов, chmod dev/users.yml
make run-server     # ./bin/tgproxy server -c dev/server.yaml  (admin 127.0.0.1:8090)
make run-agent      # агент local :8443; make run-agent2 — агент local2 :8445
make bench|bench-mtproto  # нагрузочные smoke (vegeta)
make vendor-verify  # sha256 вендорных ассетов web/static/vendor
```

CLI: `go run ./cmd/tgproxy …` или собранный `bin/tgproxy`. Проверка конфига — `tgproxy config validate --mode server|agent -c <file>`.

## Проверки перед сдачей

```sh
make generate && git diff --exit-code   # сгенерированный templ не разошёлся
go test ./...                           # гоняй без конкурирующей нагрузки
make lint && make vuln && make gosec
make vendor-verify                      # если трогал web/static
```

Правишь MTProto — дополнительно `go test ./internal/mtproto/...` (контракт-тесты mtg).
Перед тегом — `make test-race` (CI его не делает).

## Окружение

- **Go.** `go.mod`: `go 1.26.9` + `toolchain go1.27.4`. CI ставит Go по `go-version-file: go.mod`, поэтому фактическая версия сборки и `govulncheck` — из `toolchain`, а не локальная: поднимать версию Go = править `toolchain` (и при необходимости `go`) в `go.mod`.
- **templ** — tool-зависимость: только `go tool templ generate` (или `make generate`). Глобальный `templ` из `$PATH` не нужен и может дать другой вывод.
- **golangci-lint** v2.15.0 (совпадает с CI). Версия другой мажорной ветки конфиг `version: "2"` не прочитает.
- **gosec** пинится `v2.30.0` в `Makefile` и `ci.yml` — менять только синхронно в обоих местах.
- **goreleaser** и **docker** локально нужны для `snapshot`/`deb`/`release-dry` и smoke deb (debian:12 + systemd, `--privileged`).

## Карта репозитория

| Путь | Что там |
|---|---|
| `cmd/tgproxy` | cobra-CLI: server, agent, pki, totp, access, agents, ban, mtproto, update, deploy-helper |
| `internal/app` | wiring процессов server/agent + e2e-тесты (в т.ч. `tokenleak_e2e_test.go`) |
| `internal/server/{proxy,router,balancer,access,ban,agents,enroll,gateway,installer,notify,rollout,updater,history}` | серверная часть |
| `internal/server/web` | UI: `screens/*.templ` (templ + htmx), `views/`, `api/` (`/api/v1`), `auth/` |
| `internal/agent` | агент: mTLS-сервер, релей, метрики, обновление |
| `internal/store/{sqlite,redis}` + `storetest`, `memtest` | хранилище; контрактные наборы тестов |
| `internal/store/sqlite/migrations` | миграции goose (embed), нумерованные `NNNN_*.sql` |
| `internal/mtproto` (+ `faketls`, `mux`, `link`, `probe`, `trace`, `upstream`) | адаптер mtg, FakeTLS-разводка, пробы DC |
| `internal/transport` | `AgentTransport` (Bot API) и `StreamTransport` (MTProto) |
| `internal/tgapi` | разбор путей Bot API, таблица DC |
| `internal/{pki,config,redact,release,selfupdate,deployhelper,tlsin,geoip,metrics,history}` | PKI/KEK, конфиг, редакция секретов, minisign-проверка, самообновление, root-хелпер, TLS/ACME, GeoIP |
| `web/static` | вендоренные htmx 2.x, uPlot, шрифты + `SHA256SUMS` (CDN нет) |
| `packaging` | systemd-юниты, `etc/*.yaml`, maintainer-скрипты, `ci/smoke.sh` |
| `deploy`, `scripts/deploy.sh` | деплой сервера на прод (`deploy/.env`) |
| `dev` | dev-конфиги, стенд docker (sshd-debian, nat-agent) |
| `swarm-report/` | отчёты задач, **в .gitignore** |

## Жёсткие правила

1. **Сгенерированное не править руками.** `*_templ.go` — только через `make generate`; CI-job `generate` делает `templ generate` + `git diff --exit-code`.
2. **Логи — только `slog`.** В `internal/` запрещены `fmt.Print*` и пакет `log` (линтер `forbidigo`), вне `internal/` (CLI в `cmd/`) — можно.
3. **Секреты не логируются.** Токены ботов, ключи, пароли, ee-секреты — через `internal/redact`; в логах/метриках допустим только `bot_id` (часть до `:`), в метках метрик ботов нет вовсе.
4. **Подавление линтеров — только с обоснованием.** gosec: `// #nosec Gxxx -- причина`. golangci: `//nolint:<linter> // причина`. Без обоснования — красный CI.
5. **Секреты вне репозитория и вне argv.** `*.key`, KEK, `users_database.yml`, `deploy/.env`, `dev/.env` в git не попадают; enrollment-токен передаётся через stdin (`--token-stdin`), а не аргументом.
6. **GitHub Actions — только по полному SHA** с комментарием версии (Dependabot обновляет их сам).
7. **Вендорные ассеты** обновлять вместе с `web/static/vendor/SHA256SUMS`. htmx — 2.x, не 4.x (архитектура закрепляет 2).
8. **Миграции только добавлять.** Применённые `internal/store/sqlite/migrations/NNNN_*.sql` не редактируются — новая миграция новым номером.
9. **Не коммитить артефакты:** `bin/`, `dist/`, `dev/data/`, `dev/tls/`, `*.db*`, `build/`, `swarm-report/`.

## Тесты

- **CI юнит-тесты не запускает** (осознанное решение владельца, см. комментарий в `ci.yml`). Перед тегом обязателен локальный `make test-race` (см. `docs/release.md`).
- `go test ./...` — быстрый прогон; гонки видит только `-race`. Хелперы `race_on_test.go`/`race_off_test.go` в `internal/store/sqlite` учитывают режим.
- Интеграционные тесты — за тегом `integration`: `go test -tags integration ./internal/store/redis/ ./internal/server/installer/ ./internal/selfupdate/`. Нужны docker (debian:12, настоящие root/dpkg/systemd) и `make redis-up`.
- Контракт стора: новый метод добавляется в `internal/store/storetest` (и `memtest`) и прогоняется на sqlite и redis — иначе поведение бэкендов разъедется.
- e2e живут в `internal/app`; `tokenleak_e2e_test.go` проверяет, что токен не всплывает в логах, метриках, дампе SQLite, ответах админки, SSE и алертах. Ломать этот тест нельзя — он часть security-контракта.
- Фаззеры: список таргетов в `Makefile` (`FUZZ_TARGETS`), nightly в CI. Новый парсер ввода — новый таргет рядом.
- Тесты пишутся таблично, с `t.Parallel()` где безопасно; `goleak` (`go.uber.org/goleak`) используется для проверки утечек горутин в долгоживущих компонентах.

## CI (GitHub Actions)

`.github/workflows/ci.yml` — на push/PR/schedule/manual: `lint`, `vuln`, `gosec`, `generate`, `goreleaser-check`, `deb-smoke`, `vendor`; `fuzz` — только `schedule` (cron `17 2 * * *`) и `workflow_dispatch`.

- **Nightly падает на `vuln`**, если `govulncheck` нашёл уязвимость в стандартной библиотеке Go. Лечится подъёмом `toolchain` в `go.mod` (и, при необходимости, `go`), а не правкой кода.
- `deb-smoke` собирает snapshot через goreleaser и гоняет `packaging/ci/smoke.sh`: debian:12 + systemd, install → start → `/healthz` → upgrade (конфиг сохранён) → remove → purge → `systemd-analyze security ≤ 2.0`.
- `.github/workflows/release.yml` — по тегу `v*`, environment `release` (аппрув + `MINISIGN_SECRET_KEY`/`MINISIGN_PASSWORD`): сборка, подпись, проверка подписи и sha256, smoke deb, публикация через `gh release create`.

## Коммиты и язык

- Conventional Commits, заголовок по-русски: `feat(mtproto): …`, `fix(ci): …`, `fix(enroll): …`. Типы в истории: `feat`, `fix`, `docs`, `test`, `build`, `chore`, `deploy`, `release`.
- Документация, комментарии в коде, UI-строки, сообщения об ошибках и алерты — **русский**. Идентификаторы, имена пакетов, JSON-поля — английский.
- Один коммит — одна тема; рефакторинг не смешивать с фичей. Не менять версии зависимостей в коммите про фичу (это делает Dependabot).

## Архитектурные инварианты (не нарушать)

- **Открытого relay быть не может.** Правило доступа без сетей и без ключа, а также `0.0.0.0/0` без ключа отвергаются валидацией: прокси к Bot API без ограничений = бан IP агентов.
- **Секреты ботов не хранятся** и не пишутся в логи; разбор пути — `internal/tgapi`.
- **Агент не знает секретов.** Для MTProto агенту передаётся только номер DC (отрицательный/неизвестный отвергается), IP — из вшитой таблицы, dial-control разрешает только сети Telegram.
- **Компрометация сервера ≠ RCE на агентах.** Агент сам проверяет minisign вшитыми ключами; можно поставить только подписанный релиз не ниже `min_version`; есть откат на `prev.deb` при провале health-проверки. Не «оптимизировать» эту проверку.
- **KEK — корень доверия.** Без KEK нет CA и не включается MTProto; ключ CA и секреты MTProto шифруются KEK (AAD привязан к id).
- **Небезопасные методы (`send*`) не ретраятся после записи** — иначе дубли сообщений. Окна 429 ведутся по `(bot, chat)`.
- **SQLite — единственное обязательное хранилище.** Redis опционален, только `rediss://` + ACL и только для эфемерного состояния; при отказе конфигурации сервер не стартует.
- **Админка.** Пароль argon2id + **обязательный TOTP** в проде (`auth.allow_password_only` — только dev), cookie `__Host-sid`, CSRF через `http.CrossOriginProtection`, lockout по паре (user, подсеть).
- **Два транспорта не сливать:** `AgentTransport` (Bot API) и `StreamTransport` (MTProto) разделены, чтобы медиа не создавало HOL для Bot API.

## Частые грабли

- `make run-server` без `make dev-setup` падает с `CA is not initialized`.
- Правила доступа и агенты из `dev/server.yaml` сеются в БД **только при пустых таблицах**; пересев — остановить сервер и удалить `dev/data/tgproxy.db*`.
- Забытый `make generate` после правки `.templ` — красный job `generate` в CI.
- `govulncheck` смотрит на версию Go из `go.mod`, а не на локальную: локально «зелено» на 1.28 ничего не значит для CI.
- `mtproto` стартует только с `pki.kek_file` и `tls.mode ∈ {files, acme}`; `fronting_domain` обязан входить в SAN входного сертификата, иначе отказ старта.
- Порт по умолчанию: прокси `:8080`, админка `127.0.0.1:8090`, метрики `:9090`, `agent_gateway` `:8444`; в шаблоне `/etc/tgproxy/server.yaml` прокси на `:8443`.
- `go tool govulncheck` / `go tool templ` — через tool-директиву `go.mod`, не `go install`.
- `make dev-packages` собирает deb под архитектуру docker-хоста (на Apple Silicon — arm64): такой пакет только для dev-стенда.

## Отчёты

Отчёт по задаче — `swarm-report/<slug>-<YYYY-MM-DD>.md` (каталог в `.gitignore`, в релиз не попадает).
