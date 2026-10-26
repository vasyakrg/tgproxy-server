# tgproxy — план реализации

Статус: v1 (2026-10-26). Источник правды по архитектуре — `docs/architecture.md`, схема — `docs/diagrams/architecture.html`, UI — `docs/design/*.dc.html`.
Расхождение плана и архитектуры = ошибка плана; изменения архитектуры — только через правку `architecture.md`.

## 0. Базовые решения для реализации

### 0.1 Версии (сверено с proxy.golang.org / npm / context7, 2026-10-26)

| Компонент | Версия | Примечание (context7) |
|---|---|---|
| Go toolchain | `go 1.26.0` в `go.mod`, `toolchain go1.27.3`; CI — матрица 1.26.x / 1.27.x | `http.CrossOriginProtection` ≥1.25, `go tool` ≥1.24 |
| github.com/a-h/templ | v0.3.1100 | ставится как `go get -tool github.com/a-h/templ/cmd/templ@v0.3.1100`, запуск `go tool templ generate`; рендер — `templ.Handler(c)` / `c.Render(ctx, w)` |
| modernc.org/sqlite | v1.61.0 | DSN `file:/var/lib/tgproxy/tgproxy.db?_busy_timeout=5000&_journal_mode=WAL&_synchronous=NORMAL&_foreign_keys=on&_time_format=sqlite`; `sqlite.StrictPragmas(true)` при старте (DSN частично из конфига) |
| github.com/pressly/goose/v3 | v3.29.0 | миграции через `embed.FS` |
| golang.org/x/crypto | v0.58.0 | `ssh.FixedHostKey`, `ssh.FingerprintSHA256`, `ssh.ParsePrivateKeyWithPassphrase`, `*ssh.PassphraseMissingError`, `argon2.IDKey` |
| github.com/pkg/sftp | v1.13.12 | |
| github.com/prometheus/client_golang | v1.25.0 | `prometheus.NewRegistry()` (раздельные реестры), `collectors.NewGoCollector()`, `collectors.NewProcessCollector(...)`, `promhttp.HandlerFor(reg, opts)`, тесты — `testutil.CollectAndCompare`, `promlint` |
| github.com/redis/go-redis/v9 | v9.23.0 | |
| github.com/spf13/cobra | v1.10.2 | |
| go.yaml.in/yaml/v3 | v3.0.5 | `KnownFields(true)` |
| github.com/pquerna/otp | v1.5.0 | |
| golang.org/x/time | v0.16.0 | `rate.Limiter` |
| github.com/oklog/ulid/v2 | v2.1.2 | `X-Request-ID` |
| github.com/fsnotify/fsnotify | v1.10.1 | перечитывание users-файла |
| aead.dev/minisign | v0.3.0 | проверка `checksums.txt.minisig` |
| htmx.org | **2.0.11** (НЕ 4.x: `latest` на GitHub = v4.0.0, архитектура закрепляет htmx 2) | вендорится в `web/static/vendor/` |
| uPlot | 1.6.32 | вендорится |
| goreleaser | v2.19.0 (nfpm v2.48.0 внутри) | `version: 2`; `nfpms.contents[].type: "config\|noreplace"`; `scripts.{preinstall,postinstall,preremove,postremove}` |
| golangci-lint | v2.15.0 | |

Все внешние JS/шрифты — в репозитории с sha256 в `web/static/vendor/SHA256SUMS`; `make vendor-verify` в CI.

### 0.2 Раскладка портов (дефолты конфига)

| Процесс | Порт | Назначение |
|---|---|---|
| server | `:8080` | прокси для ботов (`/k/...`, `/bot...`), TLS по `tls.mode` = `acme` | `files` | `off` (§3.1 архитектуры) |
| server | `127.0.0.1:8090` | Web-UI + `/api/v1` + `/healthz` + `/readyz` (отдельный listener — админка не торчит туда, куда ходят боты) |
| server | `:9090` | `/metrics` (bearer) |
| server | `:8444` | `agent_gateway`: входящие reverse-соединения агентов (mTLS), `/enroll`, раздача пакетов агентам |
| agent | `:8443` | mTLS: `/tg/*`, `/_agent/*` |
| agent | `:9443` | `/metrics` (bearer) |

### 0.3 Скоупы exec-агентов (непересекающиеся файлы)

| Скоуп | Файлы | Содержание |
|---|---|---|
| **S-core** | `internal/config/**`, `internal/redact/**`, `internal/tgapi/**`, `internal/pki/**`, `internal/store/**` | фундамент, без сетевой логики |
| **S-agent** | `internal/agent/**`, `internal/transport/**` | агент + mTLS-транспорт сервера |
| **S-proxy** | `internal/server/{proxy,access,router,balancer,agents}/**` | путь запроса бота |
| **S-obs** | `internal/metrics/**`, `internal/server/{history,notify}/**` | метрики, история, алерты |
| **S-ops** | `internal/server/{installer,updater}/**`, `internal/selfupdate/**` | SSH-установка, релизы, `update apply` |
| **S-web** | `internal/server/web/**`, `web/**` | auth, сессии, templ, htmx, API `/api/v1` |
| **S-pkg** | `packaging/**`, `.goreleaser.yaml`, `.github/**`, `Makefile`, `dev/**`, `scripts/**`, `deploy/**` | сборка, CI, dev-окружение, деплой |
| **S-wire** | `cmd/tgproxy/**`, `internal/app/**` | composition root, cobra-команды; правит только ведущий (оркестратор/лид) в конце каждой фазы |

Правило: межскоуповые зависимости — только через интерфейсы, объявленные в пакете-потребителе (consumer-side interfaces); общие типы — в `internal/tgapi` (протокол Telegram) и `internal/store` (модели хранения).

### 0.4 Общие правила реализации

- TDD: в каждой задаче сначала коммитятся тесты из блока «Тесты первыми» (красные), затем реализация.
- `go test -race ./...` зелёный на каждой задаче; покрытие пакетов `router`, `balancer`, `access`, `web/auth`, `pki`, `redact`, `tgapi` ≥ 85%.
- Никакого `log.Printf` — только `slog` через `redact.Handler`.
- Локальная проверка каждой вехи: `make dev-certs && make run-agent` + `make run-server` на `127.0.0.1`, реальные запросы в `api.telegram.org` через агента тестовым ботом (`TGP_DEV_BOT_TOKEN` в `dev/.env`, не коммитится).

---

## M0 — Скелет, dev-окружение, CI · объём **S**

Цель: репозиторий собирается, линтится и тестируется в CI; `tgproxy version` работает на macOS и в linux/amd64.

- [x] **M0-T1 · Инициализация репозитория** (S-wire + S-pkg)
  - Создать: `go.mod` (module — `github.com/vasyakrg/tgproxy-server`), `.gitignore`, `.editorconfig`, `LICENSE`, `README.md` (минимум: назначение, `make` цели), `cmd/tgproxy/main.go`, `cmd/tgproxy/root.go`, `cmd/tgproxy/version.go`, `internal/buildinfo/buildinfo.go` (`Version`, `Commit`, `Date` через `-ldflags -X`).
  - `go get -tool github.com/a-h/templ/cmd/templ@v0.3.1100`, `go get -tool golang.org/x/vuln/cmd/govulncheck`.
  - Тесты первыми: `cmd/tgproxy/version_test.go` — вывод содержит version/commit/go-версию; `buildinfo` дефолт `dev`.
  - Приёмка: `go build ./cmd/tgproxy && ./tgproxy version`; `git init`, первый коммит.
- [x] **M0-T2 · Makefile и dev-окружение** (S-pkg)
  - Создать: `Makefile` (цели `build`, `generate` (= `go tool templ generate`), `test`, `test-race`, `lint`, `vuln`, `snapshot`, `dev-certs`, `run-server`, `run-agent`, `redis-up`, `vendor-verify`, `deploy`(заглушка до M7)), `dev/server.yaml`, `dev/agent.yaml`, `dev/users.yml` (пример, хеш тестового пароля), `dev/.env.example` (`TGP_DEV_BOT_TOKEN=`), `dev/docker-compose.yml` (redis с TLS+ACL, `sshd-debian` для M5).
  - Приёмка: `make build test lint` проходит локально.
- [x] **M0-T3 · CI** (CI зелёный: run 40338806616) (S-pkg)
  - Создать: `.github/workflows/ci.yml` (golangci-lint v2.15.0, `go test -race`, govulncheck, `templ generate` + `git diff --exit-code`, `goreleaser check`, `make vendor-verify`), `.github/dependabot.yml` (gomod, github-actions), `.golangci.yml` (v2: `errcheck, govet, staticcheck, gosec, revive, bodyclose, noctx, contextcheck, forbidigo` — запрет `fmt.Print*`/`log.*` в `internal/`).
  - Actions закреплены по SHA.
  - Приёмка: зелёный CI на первом PR.
- [x] **M0-T4 · Ассеты бренда** (S-web)
  - Из `docs/logo.jpg` сделать `web/static/img/logo.svg|png` (32/64/192), `favicon.ico`; `docs/tgproxy-server-agent.svg` — диаграмма, использовать в `README.md`, не в UI.
  - Вшить IBM Plex Sans (400/500/600) и IBM Plex Mono (400/500) woff2, subset latin+cyrillic → `web/static/fonts/`, `web/static/fonts/OFL.txt`.
  - Завендорить `htmx.min.js` 2.0.11, `uPlot.iife.min.js` + `uPlot.min.css` 1.6.32 → `web/static/vendor/`, `SHA256SUMS`.
  - Создать `web/embed.go` (`//go:embed static` → `var Static embed.FS`).
  - Приёмка: `make vendor-verify` зелёный; размер ассетов < 1.5 МБ.

**Срез M0:** `./tgproxy version` на macOS; CI зелёный.

---

## M1 — Сквозной путь бот → server → agent → Telegram · объём **M**

Цель: реальный `getMe`/`sendMessage` тестового бота проходит через сервер и агента по mTLS с dev-сертификатами; агенты и client-key — статически в конфиге.

- [x] **M1-T1 · `internal/config`** (S-core)
  - Файлы: `config.go` (`ServerConfig`, `AgentConfig`, `ListenConfig`, `TLSFiles`, `RouterConfig{MaxAttempts=3, Budget=25s, LongPollExtra=15s, MaxLongPoll=65s}`, `BufferConfig{RAMMax=1MiB, DiskMax=10MiB, BodyMax=51MB}`, `StoreConfig`, `UpdateConfig`, `NotifyConfig`), `load.go` (`Load(path) (*T, error)`: YAML `KnownFields(true)` → env `TGPROXY_*` → `*_file` секреты), `validate.go`, `defaults.go`.
  - Команда `tgproxy config validate --mode server|agent -c file` (S-wire).
  - Тесты первыми: неизвестное поле → ошибка с путём; приоритет env > yaml; `token_file` читается, права файла шире 0600 → ошибка; `redis.url` не `rediss://` → ошибка старта; дефолты; `webhook_policy` ∈ {deny,passthrough}; отрицательные таймауты.
  - Приёмка: `dev/*.yaml` валидны; покрытие ≥ 85%.
- [x] **M1-T2 · `internal/redact`** (S-core)
  - Файлы: `redact.go` (`Token(s string) string` → `bot123456:***`, `String(s)` заменяет все вхождения regex `\d{5,}:[A-Za-z0-9_-]{30,}`), `slog.go` (`NewHandler(h slog.Handler) slog.Handler` — маскирует атрибуты и сообщение), `url.go` (`URL(u *url.URL) string`, маска client-key `tgp_xxxx…`).
  - Тесты первыми: таблица токенов (в пути, query, JSON-ошибке, multipart-имени файла, `url.Error`); client-key маскируется до префикса; **fuzz** `FuzzRedactNeverLeaks` — для любого входа с вставленным токеном выход не матчит regex токена; slog-группы и вложенные `error`.
  - Приёмка: fuzz 60s без находок в CI (короткий прогон 10s).
- [x] **M1-T3 · `internal/tgapi`** (S-core)
  - Файлы: `methods.go` (`type Class int {Safe, Semi, Unsafe}`; `Classify(method string) Class` — точная таблица + префиксы из §6 архитектуры; неизвестный метод → `Unsafe`; `setWebhook` отдельно), `path.go` (`ParsePath(p string) (Route{ClientKey, Token, BotID int64, Method, IsFile, FilePath}, error)` для `/k/<key>/bot<token>/<method>`, `/k/<key>/file/bot<token>/<path>`, `/bot<token>/...`), `response.go` (`Envelope{OK bool; ErrorCode int; Description string; Parameters{RetryAfter int; MigrateToChatID int64}}`, `ParseEnvelope(io.Reader, limit)`), `errors.go` (`WriteError(w, code, desc)` в формате Telegram), `methodlabel.go` (нормализация `method` для метрик: известные ~150 + `other`).
  - Тесты первыми: classify-таблица на каждый метод из §6 + регистр (`SendMessage` ≡ `sendMessage`); неизвестный → Unsafe; путь с `..`/`%2F` → ошибка; извлечение `bot_id` из токена; `editMessageText` с «message is not modified» распознаётся `IsNotModified(env)`; envelope > лимита не читается целиком.
- [x] **M1-T4 · Dev-PKI** (S-core)
  - Файлы: `internal/pki/ca.go` (`NewCA(subject) (*CA, error)`, ECDSA P-256), `internal/pki/issue.go` (`IssueServerClient(ca)`, `IssueAgent(ca, csr, agentID, ttl)`), `internal/pki/verify.go` (`VerifyAgentPeer(id)`, `VerifyServerPeer()` — проверка SAN `spiffe://tgproxy/agent/<id>` / `tgproxy-server`); команда `tgproxy pki dev-init --out dev/certs` (S-wire) → `make dev-certs`.
  - Тесты первыми: выпущенный сертификат агента проходит `VerifyAgentPeer(id)` и падает для другого id; клиент без SAN `tgproxy-server` отклоняется; TTL 90 дней; ключи P-256; CSR с чужой подписью отклоняется.
  - Полная PKI (KEK, ротация, denylist) — M5.
- [x] **M1-T5 · Агент** (S-agent)
  - Файлы: `internal/agent/server.go` (`New(cfg, reg) *Agent`, `Run(ctx)`; TLS 1.3, `ClientAuth: RequireAndVerifyClientCert`, `VerifyPeerCertificate` = `pki.VerifyServerPeer`), `proxy.go` (`httputil.ReverseProxy` на жёстко `https://api.telegram.org`, `Rewrite` (не `Director`), `FlushInterval: -1`, чистка hop-by-hop/`X-Forwarded-*`/`Forwarded`/`Via`/`Cookie`/`Authorization`, `X-TGP-*` не уходят в Telegram), `phase.go` (разметка фаз через `httptrace.ClientTrace`: `dial`, `tls`, `pre-send` (до `WroteHeaders`), `write`, `read`, `timeout`; `ErrorHandler` пишет 502 + `X-TGP-Source: agent`, `X-TGP-Error-Phase`), `timeout.go` (`X-TGP-Timeout-Ms` → `context.WithTimeout`), `health.go` (`/_agent/healthz` с кэшем TLS-пробы 10s), `status.go` (`/_agent/status` JSON: `version, commit, uptime_s, inflight, rps_1m, errors_by_phase, upstream_rtt_ms, draining, cert_not_after`), `drain.go` (`POST /_agent/drain` → `atomic.Bool`, новые `/tg/*` → 503 `X-TGP-Error-Phase: pre-send`).
  - Тесты первыми (через `httptest.NewTLSServer` вместо Telegram, upstream подменяется только в тестах через неэкспортируемое поле): фазы — сервер Telegram недоступен → `dial`; плохой сертификат → `tls`; закрытие соединения до заголовков ответа после отправки тела → `read`; дедлайн → `timeout`; заголовки чистятся в обе стороны; клиент без mTLS-серта → handshake error; клиент с сертом агента (не сервера) → отказ; drain → 503 pre-send; стриминг: ответ 5 МБ отдаётся без буферизации (проверка первого байта до конца апстрима).
  - Приёмка: `make run-agent`; `curl --cert dev/certs/server.pem ... https://127.0.0.1:8443/tg/bot$TOKEN/getMe` → `{"ok":true}`.
- [x] **M1-T6 · `internal/transport`** (S-agent)
  - Файлы: `client.go` (`type AgentTransport interface{ RoundTrip(ctx, agent AgentRef, req *http.Request) (*http.Response, error); Status(ctx, agent) (*AgentStatus, error) }`; реализация `dial.go`: `http.Transport` с `ForceAttemptHTTP2`, TLS 1.3, клиентский серт сервера, пиннинг SAN агента; пул на агента; `registry.go` — `AgentRef.Mode` (`dial`|`reverse`) выбирает реализацию, reverse добавляется в M5-T8 без изменения интерфейса), `errors.go` (`type PhaseError struct{ Phase Phase; Source Source; Err error }`; `Phase` = `dial|tls|pre_send|write|read|timeout`; `Classify(resp, err) (Outcome)` — объединяет ошибку соединения server→agent и `X-TGP-Error-Phase` от агента; ошибка server→agent после записи тела в агента = `write` (агент мог отправить в Telegram)).
  - Тесты первыми: таблица «что случилось» → `Phase`: refused к агенту → `dial`; handshake fail → `tls`; агент ответил 502 + `X-TGP-Error-Phase: dial` → `dial/agent`; RST после отправки тела агенту → `write`; таймаут чтения ответа агента → `timeout`; 5xx от Telegram (`X-TGP-Source: telegram`) → не транспортная ошибка.
- [x] **M1-T7 · Минимальный прокси сервера** (S-proxy)
  - Файлы: `internal/server/proxy/handler.go` (`Handler{Access, Router}`; `ServeHTTP`: `MaxBytesReader(51MB)` → 413 в формате Telegram, `X-Request-ID` ULID, `webhook_policy`), `internal/server/proxy/headers.go`, `internal/server/access/static.go` (временные правила доступа из конфига: CIDR и/или ключ, SHA-256 сравнение constant-time; ботов не проверяем), `internal/server/router/router.go` — пока одна попытка, один агент из конфига.
  - Тесты первыми: `/bot<token>/getMe` из сети правила → проходит без ключа; из чужой сети без ключа → 403 Telegram-формат; `/k/<key>/bot...` с верным ключом из любой сети → проходит; ключ не тот → 403; `X-Proxy-Key` для `/bot...`; правило без сети и ключа → отказ старта; `setWebhook` при `deny` → 403 с описанием из §3; тело 52 МБ → 413; ответ содержит `X-Request-ID`; токен не попадает в логи (проверка через захват slog-буфера + regex).
- [x] **M1-T8 · Wiring `server`/`agent`** (S-wire)
  - Файлы: `internal/app/server.go`, `internal/app/agent.go`, `cmd/tgproxy/server.go`, `cmd/tgproxy/agent.go`; graceful shutdown по SIGTERM (drain inflight до 30s), SIGHUP — reload.
  - Приёмка среза: `make run-agent`, `make run-server`; `curl http://127.0.0.1:8080/bot$TOKEN/getMe` (правило `127.0.0.0/8`) и `curl http://127.0.0.1:8080/k/$KEY/bot$TOKEN/getMe` → `ok:true`; `sendMessage` в тестовый чат доходит; `getFile` + `/file/...` скачивает файл; в логах нет токена.

**Срез M1:** реальный бот работает через `127.0.0.1:8080`. Статус: сквозной путь до api.telegram.org подтверждён (getMe с фейковым токеном → 401 от Telegram по обоим правилам доступа); проверка `sendMessage`/`getFile` с реальным ботом — ждёт `TGP_DEV_BOT_TOKEN` в `dev/.env`.

---

## M2 — Надёжность: хранилище, ключи, ретраи, балансировка, 429 · объём **L**

Цель: несколько агентов, отказ одного не виден ботам для safe/semi-методов; unsafe не дублируются; client-keys в SQLite.

- [x] **M2-T1 · `internal/store` + SQLite + миграции** (S-core)
  - Файлы: `store.go` (`type Store interface{ Agents() AgentRepo; AccessRules() AccessRuleRepo; Sessions() SessionRepo; Outbox() OutboxRepo; RateState() RateStateRepo; History() HistoryRepo; Audit() AuditRepo; HostKeys() HostKeyRepo; Certs() CertRepo; Close() error }`), `models.go`, `sqlite/open.go` (DSN из §0.1, `StrictPragmas(true)`, `SetMaxOpenConns`: 1 writer-пул + reader-пул), `sqlite/migrations/0001_init.sql` … (goose, `embed.FS`), `sqlite/*_repo.go`, `memtest/` (in-memory реализация для unit-тестов потребителей).
  - Таблицы: `agents`, `agent_hostkeys`, `certs`, `cert_denylist`, `access_rules` (`name`, `cidrs` JSON, `key_hash` NULL, `key_prefix` NULL, `rps`, `enabled`, `revoked_at`; CHECK: есть `cidrs` или `key_hash`), `sessions`, `rate_windows`, `outbox`, `audit_log`, `samples_10s`, `samples_5m`, `error_events`, `install_jobs`, `install_job_events`, `releases`.
  - Тесты первыми: миграции up на пустой БД и повторно (идемпотентно); WAL включён (`PRAGMA journal_mode`); конкурентные записи 50 горутин без `SQLITE_BUSY`; contract-тесты `storetest.Run(t, factory)` общие для sqlite и memtest (и redis в M2-T7).
- [x] **M2-T2 · `access`: правила доступа из БД (сеть и/или ключ), rate-limit** (S-proxy) · зависит от M2-T1
  - Файлы: `internal/server/access/rules.go` (`Checker.Check(r *http.Request, route tgapi.Route) (RuleInfo, error)`: ключ из `/k/<key>` или `X-Proxy-Key` → правила с этим ключом (+CIDR, если задан); без ключа → правила только-сеть; кэш правил в памяти с инвалидацией по версии), `cidr.go`, `ratelimit.go` (`rate.Limiter` на правило; при `store.redis` — через `RateStateRepo`), `generate.go` (`NewKey() (plain, hash, prefix)` — `tgp_` + 24 символа base62 из `crypto/rand`).
  - Тесты первыми: отозванный ключ → 403; IP вне CIDR → 403; правило «сеть+ключ» требует оба; несколько подходящих правил → берётся первое по специфичности (ключ+сеть > ключ > сеть) для учёта rps; превышение rps → 429 с `retry_after` в формате Telegram; `X-Forwarded-For` **не** учитывается (только `RemoteAddr`, если не задан `trusted_proxies`); хеш в БД, plain не сохраняется нигде.
- [x] **M2-T3 · `RetryBuffer`** (S-proxy)
  - Файлы: `internal/server/router/buffer.go` (`type Replayable interface{ NewReader() (io.ReadCloser, error); Size() int64; Replayable() bool; Close() error }`; `Wrap(req, cfg) (Replayable, error)`: ≤1 МиБ — RAM; multipart ≤10 МиБ — tmp-файл в `/var/lib/tgproxy/tmp` (0600) с AES-256-GCM поблочно, ключ — случайный на запрос, только в памяти (KEK не нужен); при старте tmp-каталог очищается; больше — `nonReplayable` с счётчиком прочитанных байт), `buffer_crypto.go`.
  - Тесты первыми: 3 чтения подряд байт-в-байт равны оригиналу (RAM и disk); tmp-файл удаляется после `Close` и при панике хендлера; на диске нет открытого текста (поиск маркера в файле); >10 МиБ → `Replayable()==false`, но `BytesConsumed()==0` до первого чтения; метрика `inflight_buffered_bytes` растёт/падает.
- [x] **M2-T4 · `balancer`: P2C + EWMA + circuit breaker** (S-proxy)
  - Файлы: `internal/server/balancer/balancer.go` (`type Balancer interface{ Pick(ctx, key string, exclude []AgentID) (Agent, func(Result), error) }`; P2C, score = `(inflight+1) × EWMA(latency, α=0.3) / weight`), `ewma.go`, `breaker.go` (`closed → open` после 5 подряд транспортных ошибок, open 30s → `half-open` с одной пробной попыткой), `health.go` (кандидаты: up, не draining, breaker не open).
  - Тесты первыми: детерминированный `rand` — из двух выбирается меньший score; `exclude` соблюдается; при всех исключённых → `ErrNoHealthyAgents`; вес 0 → агент не выбирается; long-poll (`release(Result{LongPoll:true})`) не меняет EWMA; breaker: 4 ошибки + успех → closed; 5 ошибок → open; через 30s (fake clock) half-open пропускает ровно одну попытку; ответы Telegram 4xx/5xx/429 **не** считаются транспортной ошибкой агента; распределение на 10k выборов при равных агентах — отклонение < 5%; race-тест конкурентных `Pick/release`.
- [x] **M2-T5 · `router`: ретраи, бюджет, 429-окна** (S-proxy) · зависит от M1-T3, M1-T6, M2-T3, M2-T4
  - Файлы: `internal/server/router/router.go` (`Router.Do(ctx, route, req, body Replayable) (*http.Response, error)`), `policy.go` (`Decide(class tgapi.Class, outcome transport.Outcome, attempt int) Decision{Retry bool; Backoff time.Duration; Final *FinalResponse}` — чистая функция), `deadline.go` (бюджет 25s; `getUpdates`: `timeout+15s`, ≤65s; `X-TGP-Timeout-Ms` = остаток), `ratewindow.go` (`Windows.Check(botID, chatID) (retryAfter, bool)`, `Windows.Observe(botID, chatID, env)`; `chat_id` из JSON/form/multipart-поля без полного разбора тела > 1 МиБ), `nohealthy.go` (ожидание агента до дедлайна, затем 502 `tgproxy: no healthy agents`).
  - Тесты первыми — **ретрай-матрица** (`policy_test.go`, table-driven, полное декартово произведение):
    - классы `safe | semi | unsafe` × исходы `dial, tls, pre-send, write, read, timeout, tg-5xx, tg-429, tg-4xx, tg-400-not-modified, ok` × попытка `1, 3`;
    - ожидание: `dial/tls/pre-send` → retry для всех классов; `write/read/timeout` → retry для safe/semi, для unsafe → final 502 `{"ok":false,"error_code":502,"description":"tgproxy: delivery unknown"}`; `tg-5xx` → retry safe/semi с backoff 0.5/1/2s, unsafe → passthrough; `tg-429` → passthrough всегда; `not modified` для semi → успех; попытка 3 → final во всех случаях.
  - Интеграционные (`router_test.go`, 3 фейковых агента на `httptest`): агент-1 рвёт на `dial` → `sendMessage` уходит на агент-2, тело байт-в-байт; агент-1 рвёт после записи → `sendMessage` 502, агент-2 **не** получил запрос; `getUpdates?timeout=50` — дедлайн 65s, не 25s; бюджет 25s исчерпан → финальный ответ до дедлайна клиента; агенты прошлых попыток исключены; 429 c `retry_after=7` на `(bot,chat)` → следующий `sendMessage` в тот же чат за 7s отвечает 429 сам (агент не вызван), в другой чат — проходит; `/file/*` — ретрай только до первого отданного байта; запрос боту отменён (`ctx.Done`) → ретраев нет; nonReplayable тело + `pre-send` → retry только если `BytesConsumed()==0`.
- [x] **M2-T6 · Реестр агентов и poller** (S-proxy) · зависит от M1-T6, M2-T1
  - Файлы: `internal/server/agents/registry.go` (`Registry{List, Get, SetWeight, SetDraining, Subscribe() <-chan Event}`), `poller.go` (опрос `/_agent/status` каждые 5s, jitter 10%, 3 неудачи → down), `passive.go` (health по реальному трафику от балансировщика).
  - Тесты первыми: fake clock; down после 3 пропусков; up после 1 успеха; событие `agent_down`/`agent_up` публикуется один раз; draining снимает агента из кандидатов немедленно.
- [x] **M2-T7 · Redis-бэкенд (опционально)** (S-core) · зависит от M2-T1
  - Файлы: `internal/store/redis/{sessions,ratestate}.go`; отказ старта без `rediss://` и ACL-пользователя.
  - Тесты: contract-тесты `storetest` под тегом `integration` против `make redis-up`.
- [x] **M2-T8 · Wiring + CLI** (S-wire)
  - `tgproxy access add|list|delete` (правила доступа локально к БД — для бутстрапа до UI; `--cidr`, `--with-key`, `--rps`; ключ печатается один раз); `access_rules` из конфига → таблица при первом старте; конфиг агентов → таблица `agents` при первом старте (`agents.seed`).
  - Приёмка среза: 2 агента на `127.0.0.1:8443/8445` (`:8444` занят `agent_gateway`); `kill` одного во время цикла `getMe` ×1000 → 0 ошибок у бота; `sendMessage` при обрыве после записи → 502 `delivery unknown`, в чате нет дубля; 429-окно воспроизводится скриптом `scripts/dev/flood.sh`.

**Срез M2:** отказоустойчивый прокси без UI. Статус: 2 агента, `kill -9` одного под нагрузкой → 0 ошибок у клиента; rate-limit правила и 429-окна работают. Не проверено: `flood.sh` и «нет дубля в чате» с реальным ботом (нужен `dev/.env`), Redis-интеграционные тесты (`-tags integration`).

---

## M3 — Метрики, история, алерты · объём **M**

- [x] **M3-T1 · `internal/metrics`** (S-obs)
  - Файлы: `server.go` (`NewServerRegistry() (*prometheus.Registry, *ServerMetrics)` — все метрики §10 с префиксом `tgp_`), `agent.go` (`NewAgentRegistry()`), `common.go` (`build_info`, `collectors.NewGoCollector()`, `collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})`), `handler.go` (`Handler(reg, bearer)` — `promhttp.HandlerFor`, `subtle.ConstantTimeCompare`), `labels.go` (фиксированные наборы `code`, `method` через `tgapi.MethodLabel`, `rule` — имя правила доступа; `bot_id` в метках запрещён), `topbots.go` (in-memory top-K `bot_id` за окно для UI).
  - Тесты первыми: `promlint` без проблем; `testutil.CollectAndCompare` для `requests_total`; нет `bot_id` ни в одной метрике (рефлексия по `Desc`); неверный bearer → 401, пустой bearer в конфиге → отказ старта; кардинальность: 10k случайных методов → ≤ 151 значений метки.
- [x] **M3-T2 · Инструментирование** (S-proxy, S-agent — параллельно, разные файлы)
  - S-proxy: `internal/server/router/metrics.go`, `internal/server/proxy/metrics.go` (интерфейс `Recorder`, реализация передаётся из wiring).
  - S-agent: `internal/agent/metrics.go`.
  - Тесты: после фейкового запроса нужные счётчики +1 с правильными метками.
- [x] **M3-T3 · `history`** (S-obs) · зависит от M2-T1
  - Файлы: `internal/server/history/sampler.go` (каждые 10s снимок: rps ok/err/429, p95, inflight по агентам → `samples_10s`), `rollup.go` (5m агрегаты, ретенция 24h / 30d), `errors.go` (кольцевой журнал `error_events`: время, request_id, bot_id, method, agent, phase, code, outcome ∈ {retried, failed_to_bot, passed_to_bot}, описание через `redact`), `query.go` (`Timeseries(range 1h|6h|24h|7d)`, `Errors(cursor, filters)`).
  - Тесты первыми: rollup правильно агрегирует p95 (по гистограмме, не среднее p95); ретенция удаляет старое; курсорная пагинация стабильна при вставках; описание ошибки не содержит токен.
- [x] **M3-T4 · `notify`** (S-obs) · зависит от M2-T1, M2-T5
  - Файлы: `internal/server/notify/notifier.go` (`Notifier{Fire(ctx, Alert), Resolve(ctx, AlertKey)}`; типы из §9), `outbox.go` (дедуп `(agent_id,type)`, firing ≤1/ч, resolved однократно, глобально ≤20/мин со склейкой в одно сообщение), `deliver.go` (`sendMessage` через `Router` с меткой `internal`, получатели — `telegram_id` из users-файла), `rules.go` (`agent_degraded`: err>5%/5m, `overload`: inflight>порог, `cert_expiring`: <14 дней, `version_mismatch`, `all_agents_down`).
  - Тесты первыми: fake clock — повтор firing через 59 мин подавлен, через 61 — отправлен; resolved без firing не шлётся; 25 алертов за минуту → ≤20 сообщений, последнее — склейка; нет агентов → outbox копится, `alerts_undeliverable` растёт, при появлении агента доставляется; текст алерта без токенов.
- [x] **M3-T5 · Wiring** (S-wire): листенеры `:9090`/`:9443`, `/healthz`, `/readyz` (≥1 агент up).
  - Приёмка среза: `curl -H "Authorization: Bearer …" 127.0.0.1:9090/metrics` показывает `tgp_*`; остановка агента → алерт `agent_down` приходит в Telegram админу через второй агент.
  - Статус: `/metrics` и отсутствие `bot_id` проверены вживую; доставка `agent_down`/resolved через второй агент — e2e с фейковым Telegram. Живой алерт в настоящий Telegram ждёт токен бота уведомлений.

---

## M4 — Web-auth и UI (обзор, ошибки, доступ) · объём **L**

Цель: вход по users-файлу (argon2id + TOTP), экраны Login, Main, Errors, Доступ, JSON `/api/v1` для них.

- [x] **M4-T1 · Users-файл и argon2id (формат Authelia)** (S-web)
  - Файлы: `internal/server/web/auth/users.go` (`UsersFile{Users map[string]User}`; `User{DisplayName, Password, Email, Groups, Disabled, TelegramID int64, TOTPSecretEnc string}`; загрузка + fsnotify + SIGHUP, атомарная подмена), `argon2id.go` (`ParsePHC(s) (Params{M,T,P uint32; Salt, Key []byte}, error)`, `Verify(password, phc) bool` — `argon2.IDKey` + `subtle.ConstantTimeCompare`), `dummy.go` (фиктивный хеш с параметрами по умолчанию для несуществующих юзеров), `hashpw.go` + команда `tgproxy hashpw` (S-wire; параметры Authelia по умолчанию `m=65536,t=3,p=4`, salt 16, key 32), `totp.go` (`tgproxy totp enroll <user>` — генерирует секрет, печатает otpauth URI/QR в терминал, пишет `totp_secret_enc` под KEK).
  - Тесты первыми: эталонный хеш из документации Authelia (`$argon2id$v=19$m=65536,t=3,p=4$…`) верифицируется; хеш от `tgproxy hashpw` верифицируется; отказ: `v=16`, `$argon2i$`, `$argon2d$`, отсутствует `m|t|p`, `p=0`, неверный base64, salt < 8 байт; **DoS-защита**: `m > 1 GiB` или `t > 10` → отказ без вычисления; base64 RawStd и Std (с паддингом) — оба принимаются; disabled-юзер не входит; время ответа для несуществующего юзера сопоставимо с существующим (±30%, бенч-тест); перечитывание файла применяется без рестарта, битый файл → остаётся старая версия + лог.
- [x] **M4-T2 · Сессии, login-флоу, CSRF, lockout** (S-web) · зависит от M2-T1, M4-T1
  - Файлы: `auth/session.go` (`__Host-sid`, 32 байта `crypto/rand`, в БД — SHA-256; idle 30m / abs 12h; ротация id после логина), `auth/login.go` (двухшаговый: пароль → `pending` (5 мин) → TOTP; лимит 5/мин на IP+user; lockout 15m после 10 неудач + алерт `login_lockout`), `auth/middleware.go` (`RequireAuth`, `http.CrossOriginProtection`, CSP `default-src 'self'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`), `audit.go`.
  - Тесты первыми: успешный вход → cookie с `Secure; HttpOnly; SameSite=Strict; Path=/`; TOTP вне окна ±1 → отказ; повтор того же TOTP-кода → отказ (anti-replay); 6-я попытка в минуту → 429; 10 неудач → lockout + `Notifier.Fire` вызван; idle 31m → 401; abs 12h → 401; cross-origin POST → 403; logout инвалидирует в БД; аудит пишет логин/логаут/неудачи без пароля.
- [x] **M4-T3 · UI-каркас и дизайн-токены** (S-web) · зависит от M0-T4
  - Файлы: `web/static/css/app.css` (CSS-переменные: `--bg:#0F1115; --surface:#171A21; --border:#262B36; --text:#E6E8EE; --muted:#9AA3B2; --accent:#2DD4BF; --ok:#34D399; --warn:#FBBF24; --err:#F87171; --tg:#A78BFA`; ссылки `#5EEAD4`/hover `#99F6E4`; inputs `#2F3542`; `@font-face` на вшитые Plex), `internal/server/web/views/layout.templ` (сайдбар: Обзор, Агенты, Доступ, Ошибки, Система; логотип + версия; пользователь + «Выйти»), `views/components.templ` (StatusPill, KPI, Table, Modal, Toast, EmptyState), `internal/server/web/static.go` (раздача `web.Static` с `Cache-Control: immutable` + хеш в имени), `router.go`.
  - Сайдбар по `Sidebar.dc.html`: логотип из `docs/logo.jpg` + «tgproxy» + версия; клик по заголовку/логотипу сворачивает меню до иконок (232px ↔ 68px), состояние в `localStorage['tgproxy.sidebar.collapsed']` (чтение/запись в try/catch, применяется до первой отрисовки через inline-скрипт в `<head>`, чтобы не мигало); иконки разделов — inline SVG (Обзор — пульс, Агенты — серверы, Доступ — щит, Ошибки — треугольник, Система — шестерёнка, Выйти — иконка слева от логина, без отдельной строки); в свёрнутом виде у ссылок `title` + `aria-label`, у кнопки `aria-expanded`. Favicon: `favicon.ico` (16/32/48) + `icon-192.png` + `apple-touch-icon.png` из `docs/logo.jpg`, `<link rel="icon">` в `layout.templ`.
  - Тесты: golden-тесты рендера templ-компонентов (`testdata/*.golden.html`); все ссылки на статику резолвятся из embed; нет внешних URL в HTML (regex `https?://` кроме `api.telegram.org` в текстах).
- [x] **M4-T4 · Экран Login** (S-web) — по `Login.dc.html`: шаг «Пользователь/Пароль → Продолжить», шаг «Код TOTP → Войти», «← Другой пользователь», ошибка «Осталось попыток: N», пояснение про блокировку 15 мин. API: `POST /api/v1/auth/login`, `POST /api/v1/auth/totp`, `POST /api/v1/auth/logout`, `GET /api/v1/auth/me`.
  - Тесты: htmx-фрагменты (`HX-Request`) и полная страница; ошибка не раскрывает, что именно неверно.
- [x] **M4-T5 · Экран Обзор (Main)** (S-web) · зависит от M3-T3
  - По `Main.dc.html`: переключатель диапазона `1ч/6ч/24ч/7д`; KPI «Запросов в секунду», «Ошибки прокси», «Ответов 429», «Агенты в работе», «In-flight сейчас»; график uPlot «Запросы и ошибки, rps» (серии: успешные, ошибки прокси, 429 Telegram) — живой: опрос `GET /api/v1/stats/timeseries?since=<last_ts>` раз в 2–5 с (настраивается), новые точки дописываются справа со сдвигом окна и плавной анимацией, переключатель «Live / Пауза» с пульсирующим индикатором и «обновлено N с назад», подсказка значений при наведении (курсор uPlot), опрос приостанавливается при скрытой вкладке (`visibilitychange`), анимации отключаются при `prefers-reduced-motion`; KPI обновляются тем же опросом; таблица агентов (Агент/Статус/rps/p95/Ошибки/In-flight/Версия) + «Все агенты →»; лента «События» (уведомления, отправленные в Telegram).
  - API: `GET /api/v1/stats/summary`, `GET /api/v1/stats/timeseries?range=`; автообновление htmx `hx-trigger="every 10s"`; `web/static/js/charts.js` (инициализация uPlot из `data-*`/JSON, без inline-скриптов — CSP).
  - Тесты: хендлеры на memtest-store; JSON-схема ответа; пустое состояние (нет агентов).
- [x] **M4-T6 · Экран Ошибки** (S-web) · зависит от M3-T3
  - По `Errors.dc.html`: KPI по фазам (`dial / tls`, `pre-send`, `timeout / read`, 429), фильтры Агент/bot_id/Фаза/Код/Request ID, таблица (Время, Request ID, bot_id, Метод, Агент, Фаза, Код, Итог ∈ переотправлен/отказ боту/передан боту, Описание), «Показать ещё» (курсор). API: `GET /api/v1/errors?cursor=&agent=&bot_id=&phase=&code=&request_id=`.
  - Тесты: фильтры комбинируются; курсор; описание проходит `redact`.
- [x] **M4-T7 · Экран Доступ** (S-web) · зависит от M2-T2
  - По `ClientKeys.dc.html` (экран «Доступ»): таблица правил (Правило, Тип: сеть / ключ / сеть+ключ, Сети, Ключ-префикс, Лимит, Запросов 24ч, Последнее использование, Изменить/Удалить); панель «Новое правило» (название, сети CIDR построчно, переключатель «скрытый ключ», лимит rps); после создания — ключ показан один раз, Base URL: `{public_base_url}` для правил только-сеть, `{public_base_url}/k/<key>` для правил с ключом; подсказка про `X-Proxy-Key` и вебхуки. API: `access-rules` CRUD.
  - Тесты: plain-ключ возвращается только в ответе создания; невалидный CIDR → 422 с полем; правило без сети и без ключа → 422; `0.0.0.0/0` без ключа → 422 (тот же открытый relay); отзыв мгновенно применяется в `access` (инвалидация кэша).
- [x] **M4-T9 · TLS входа: `acme` / `files` / `off`** (S-core) · параллельно с M4-T1…T7
  - Файлы: `internal/tlsin/tlsin.go` (`type Provider interface{ GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error); Info() CertInfo }`, `New(cfg) (Provider, error)`), `files.go` (загрузка PEM, `tls.X509KeyPair` + проверка срока и цепочки, атомарная подмена `atomic.Pointer[tls.Certificate]`, fsnotify + SIGHUP + mtime-тикер 60s, при ошибке — старый серт + событие), `acme.go` (`autocert.Manager` с `DirCache("/var/lib/tgproxy/acme")`, `HostPolicy` из `tls.domains`, опц. `Client.HTTPClient` через `/_agent/egress`; HTTP-01 хендлер на `:80` по флагу), `off.go` (требует `trusted_proxies`), `metrics.go` (`tgp_ingress_cert_not_after_seconds`). Конфиг: `tls.mode`, `tls.cert_file`, `tls.key_file`, `tls.domains`, `tls.acme.email`, `tls.acme.directory_url`, `tls.acme.via_agent_egress`.
  - Тесты первыми: `files` — подмена файлов на диске → новый серт отдаётся следующему хендшейку без рестарта; ключ от другого серта → остаётся старый + событие `ingress_cert_invalid`; истёкший серт → отказ подмены; права ключа шире 0640 → отказ старта; `acme` — против `pebble` в тесте (или фейкового ACME-сервера), кеш переживает рестарт; `off` без `trusted_proxies` → отказ старта; `ingress_cert_expiring` за 14 дней.
  - UI: карточка «Сертификат входа» на экране «Система» (M6-T5): режим, CN/SAN, издатель, `not_after`, последняя перезагрузка/продление, кнопка «Перечитать файлы» (`POST /api/v1/system/tls/reload`).
- [x] **M4-T8 · Wiring** (S-wire): листенер `127.0.0.1:8090`, `public_base_url` в конфиге.
  - Приёмка среза: в браузере `http://localhost:8090` вход по `dev/users.yml` + TOTP; создаются правило-сеть и правило-ключ, бот работает по обоим base URL; на Обзоре виден трафик, на Ошибках — ошибка после `kill` агента.
  - Статус: проверено во встроенном браузере (вход, Обзор с живым графиком, Доступ, Ошибки после kill агента, сворачивание сайдбара). Вход в dev — паролем (`allow_password_only`); TOTP покрыт тестами, живой вход с TOTP — после `tgproxy totp enroll`. ACME проверен без реального CA (pebble недоступен).

---

## M5 — PKI, SSH-установщик, экраны Агенты и Мастер · объём **L**

Цель: агент ставится из UI по SSH на чистый Debian (локально — контейнер `sshd-debian` из `dev/docker-compose.yml`), сертификаты ротируются.

- [x] **M5-T1 · PKI полностью** (S-core)
  - Файлы: `internal/pki/kek.go` (KEK из `/etc/tgproxy/kek`, права 0400, иначе отказ старта; `Seal/Open` AES-256-GCM с AAD = назначение), `store.go` (CA-ключ в БД зашифрован KEK), `csr.go` (`SignAgentCSR(csr, agentID) (certPEM, serial)`: только P-256, только SAN `spiffe://tgproxy/agent/<id>`, KU/EKU clientAuth+serverAuth, TTL 90д), `denylist.go`, `rotation.go` (`DueForRotation(cert, now)` — на 2/3 срока); команда `tgproxy pki init`.
  - Тесты первыми: CSR с RSA / P-384 / лишними SAN / CA:true → отказ; серийник из denylist отклоняется в `VerifyAgentPeer`; KEK с правами 0644 → ошибка; неверный KEK → ошибка расшифровки CA, а не паника; `DueForRotation` на границах 59/60/61 дня.
- [x] **M5-T2 · CSR-флоу агента** (S-agent) · зависит от M5-T1
  - Файлы: `internal/agent/csr.go` (`POST /_agent/csr` — агент генерирует ключ P-256 локально (0600), возвращает CSR; `PUT /_agent/cert` — принимает подписанный, проверяет соответствие ключу, атомарно меняет `tls.Config.GetCertificate`), `internal/agent/bootstrap.go` (одноразовый bootstrap-токен для первой выдачи по mTLS с временным сертом — см. M5-T3).
  - Тесты: серт не к тому ключу → 400; горячая замена без обрыва активных соединений; ключ агента никогда не покидает процесс (нет в ответах).
- [x] **M5-T3 · `installer`** (S-ops) · зависит от M5-T1, M5-T2
  - Файлы: `internal/server/installer/ssh.go` (`Dial(ctx, Target, Auth, HostKeyPolicy)`: TOFU — первое подключение возвращает `ErrHostKeyUnknown{Fingerprint: ssh.FingerprintSHA256(key)}`; после подтверждения — `ssh.FixedHostKey(pinned)`; несовпадение → `ErrHostKeyMismatch` + алерт `hostkey_mismatch`; `ParsePrivateKeyWithPassphrase` при `*ssh.PassphraseMissingError`), `job.go` (`Installer{Install, Upgrade, Rollback, Uninstall}`; `Job` с шагами и событиями), `steps.go` (шаги мастера: SSH-подключение (ключ хоста закреплён) → Загрузка deb (SFTP в `/var/lib/tgproxy/packages/`) → Установка пакета и пользователей (`dpkg -i`, `tgproxy-deploy` + ed25519-ключ сервера + sudoers из §8) → Выпуск сертификата агента (CSR-флоу) → Запуск `tgproxy-agent` → Проверка mTLS и доступа к Telegram → Включение в балансировку), `sudoers.tmpl`, `remote.go` (шелл-экранирование, только фиксированные команды).
  - Креды админа: только в памяти `Job`, обнуляются после шага 3; не логируются, не пишутся в БД (проверка тестом).
  - Тесты первыми: in-process SSH-сервер (`ssh.NewServerConn` в тесте) — TOFU/FixedHostKey/mismatch; ключ с passphrase без passphrase → понятная ошибка; запись команд фейкового сервера — ровно ожидаемый список; sudoers проходит `visudo -c` (интеграционный тест в контейнере, тег `integration`); падение на шаге N → откат шагов N-1..1 по описанию; события джобы пишутся в `install_job_events` без секретов.
- [x] **M5-T4 · Ротация сертификатов и отзыв** (S-proxy) · зависит от M5-T1, M5-T2
  - Файлы: `internal/server/agents/certrotate.go` (по `cert_not_after` из статуса: 2/3 срока → CSR → подпись → PUT), `remove.go` (удаление агента → серийник в denylist, drain, отзыв доступа).
  - Тесты: fake clock — ротация вызывается один раз; denylist-агент отклоняется транспортом.
- [x] **M5-T5 · Экран Агенты** (S-web) · зависит от M2-T6, M5-T4
  - По `Agents.dc.html`: заголовок «N агентов · M в работе · версия сервера», «Обновить отстающие до vX» (в M6), «+ Добавить агента»; фильтры Поиск/Статус (Все, В работе, Деградация, Недоступен, Drain); таблица (Агент, Связь: «→ агент» / «агент →» (reverse, число соединений), Статус, Вес, rps, p95, Ошибки 5м, In-flight, Версия, Сертификат, Опрос, Drain/Обновить/⋯); меню «⋯»: Изменить вес, Перевыпустить сертификат, Откатить на предыдущую версию, Метрики агента, Удалить (сертификат в denylist); блок «Пороги алертов». API: `agents` CRUD, `agents/{id}/{drain,metrics}`.
  - Тесты: подтверждение для деструктивных действий (htmx `hx-confirm` + серверная проверка); федерация `/api/v1/agents/{id}/metrics`.
- [x] **M5-T6 · Мастер «Новый агент»** (S-web) · зависит от M5-T3
  - По `AgentAdd.dc.html`, 3 шага: (1) Хост и доступ — Имя, Хост/IP, SSH-порт, Пользователь (sudo), Порт агента (mTLS), Вес; Аутентификация: Приватный ключ (+Passphrase) | Пароль; предупреждение «используются один раз…»; (2) Проверьте ключ хоста — `ED25519 · SHA256:…`, «Отклонить» / «Отпечаток совпадает, установить»; (3) Установка — чеклист шагов + лог в реальном времени по SSE `GET /api/v1/install-jobs/{id}/events` (htmx `sse`-расширение вендорится вместе с htmx 2.0.11). API: `POST /api/v1/ssh/hostkey`, `POST /api/v1/install-jobs`.
  - Тесты: секреты из формы не попадают в логи/БД/SSE; SSE переподключение (`Last-Event-ID`) отдаёт пропущенные события.
- [x] **M5-T7 · Wiring + dev-стенд** (S-wire, S-pkg)
  - `dev/docker-compose.yml`: сервис `sshd-debian` (debian:12 + openssh-server + systemd), `make dev-target-up`; локальный deb — `make snapshot` (goreleaser `--snapshot`).
  - Приёмка среза: из UI на macOS ставится агент в контейнер, он появляется в балансировке, `getMe` через него проходит; повторное подключение с подменённым host key → отказ + алерт.

---

- [x] **M5-T8 · Режим `reverse`: агент дозванивается до сервера** (S-agent + S-proxy, разные файлы — параллельно) · зависит от M1-T6, M5-T1
  - S-proxy: `internal/server/gateway/gateway.go` (listener `agent_gateway` `:8444`, TLS 1.3, `ClientAuth: VerifyClientCertIfGiven` — без серта пускается только на `/enroll`; после хендшейка сверка SAN `agent/<id>` с БД и denylist), `internal/transport/reverse.go` (`ReversePool`: на агента до 2 `*http2.ClientConn` из `(&http2.Transport{}).NewClientConn(conn)`, выбор живого, вытеснение старого соединения при повторном подключении, `RoundTrip`/`Status` через тот же `AgentTransport`), `internal/transport/ping.go` (h2 PING 15s, 2 пропуска → `down`).
  - S-agent: `internal/agent/connector.go` (держит 2 исходящих TLS-соединения к `server_url`, на каждом `http2.Server.ServeConn(conn, &http2.ServeConnOpts{Handler: agentMux})`; backoff 1s→60s + jitter; при `PUT /_agent/config` — переключение режима без рестарта процесса), `internal/agent/listener.go` (выделить текущий `dial`-листенер, режим `both` для миграции).
  - Тесты первыми: интеграционный — агент за «NAT» (у агента нет листенера) получает `sendMessage` через reverse-канал, тело байт-в-байт, стрим 20 МБ файла без буферизации; обрыв одного из 2 соединений → запросы идут по второму, 0 ошибок для safe-методов; убить оба → агент `down` за ≤35s, переподключение → `up`; чужой сертификат / серт из denylist → соединение закрыто до первого запроса; второе подключение с тем же id и валидным сертом вытесняет первое; фазы ошибок (`dial`/`write`/…) классифицируются так же, как в `dial`-режиме (общий table-test на обе реализации `AgentTransport`).
- [x] **M5-T9 · Enrollment агента за NAT** (S-proxy + S-agent + S-web) · зависит от M5-T8
  - Файлы: `internal/server/gateway/enroll.go` (`POST /enroll {token, csr}`: токен — SHA-256 в таблице `enrollments` (TTL 1ч, одно использование, `name`, `weight`), rate-limit 5/мин на IP, подпись CSR через `pki`, аудит, алерт `agent_enrolled`), `internal/agent/enroll.go` + `cmd/tgproxy/agent_enroll.go` (`tgproxy agent enroll --server --token --ca-fingerprint`: pinning CA по отпечатку, ключ генерируется локально 0600, пишет `/etc/tgproxy/agent.yaml` с `mode: reverse`, `systemctl enable --now tgproxy-agent`), миграция `enrollments`. UI — вторая ветка мастера `AgentAdd.dc.html` («Агент за NAT»: имя, вес → команда установки с токеном и отпечатком CA, ожидание подключения через SSE). API: `POST/DELETE /api/v1/enrollments`.
  - Тесты первыми: токен повторно → 403; просрочен → 403; неверный отпечаток CA на агенте → отказ до отправки CSR; CSR с чужим CN/SAN → сервер выставляет SAN сам; 6-я попытка в минуту → 429; токен не попадает в логи (`redact`).
  - Приёмка среза: агент в docker-сети без проброса портов (`dev/docker-compose.yml`, сервис `nat-agent`) подключается командой из UI и обслуживает трафик.

**Срез M5:** агент `ssh1` поставлен из UI по SSH в контейнер `sshd-debian` (7/7 шагов, лог по SSE, откат проверен на отсутствии пакета и на падении юнита), `nat1` подключён через enrollment в docker без проброса портов; трафик распределяется по весам между dial, reverse и SSH-агентами. Подмена host key → отказ; сброс пина — только CLI `tgproxy hostkeys forget`. Отклонения от §8: sudo у `tgproxy-deploy` — только `tgproxy deploy-helper` (шаблоны `dpkg`/`systemctl` из исходной редакции давали root). Не проверено: установка на amd64 под Rosetta (hardening юнита скрывает `/proc/sys` — ограничение эмуляции, dev-стенд работает в нативной архитектуре).
В M7: токен enrollment виден в `ps` во время `sudo TGP_ENROLL_TOKEN=…` (читать из stdin); подтверждение `hostkeys forget` без проверки tty.

## M6 — Пакет, самообновление сервера, раскатка агентов, экран Система · объём **L**

- [x] **M6-T1 · goreleaser + nfpm** (сделано в рамках M5: deb, юниты с hardening 1.2, smoke, CI `deb-smoke`) (S-pkg)
  - Файлы: `.goreleaser.yaml` (`version: 2`; builds linux/amd64, darwin/arm64, darwin/amd64, `CGO_ENABLED=0`, `-trimpath`, ldflags buildinfo; archives tar.gz; `nfpms` deb: `contents` — бинарь `/usr/bin/tgproxy`, юниты `/lib/systemd/system/`, `/etc/tgproxy/server.yaml` и `agent.yaml` с `type: "config|noreplace"`, `/var/lib/tgproxy` (dir, owner tgproxy, 0750); `scripts` preinstall/postinstall/preremove/postremove; `checksum`; `signs` — minisign), `packaging/systemd/{tgproxy-server.service,tgproxy-agent.service,tgproxy-update.path,tgproxy-update.service}` (hardening из §8), `packaging/scripts/{preinst,postinst,prerm,postrm}.sh`, `packaging/etc/{server,agent}.yaml`.
  - Тесты: `goreleaser check`; CI-джоба smoke в `debian:12` (systemd-контейнер): install → `systemctl start tgproxy-server` → `/healthz`; upgrade поверх → изменённый конфиг сохранён; `remove` → юниты остановлены; `purge` → данные и юзер удалены; `systemd-analyze security tgproxy-server.service` ≤ 2.0 (парсинг вывода).
- [x] **M6-T2 · `updater`: источники релизов и minisign** (S-ops)
  - Файлы: `internal/server/updater/source.go` (`type Source interface{ Latest(ctx) (Release, error); Fetch(ctx, asset) (io.ReadCloser, error) }`: `GitHubSource`, `ProxySource` (`update.http_proxy`), `AgentEgressSource` (через агента — **только** GET на allowlist `github.com`/`objects.githubusercontent.com` через отдельный `/_agent/egress` с жёстким allowlist хостов; добавить в контракт агента и `architecture.md`), `UploadSource`), `verify.go` (`Verify(checksums, sig, pubkeys [2]minisign.PublicKey)`, sha256 deb, `min_version`), `cache.go` (`/var/lib/tgproxy/packages/tgproxy_<v>_amd64.deb`, `prev.deb`), `stage.go` (`updates/staged` + файл `request`).
  - Тесты первыми: подпись вторым (ротационным) ключом принимается; чужим — отказ; изменённый 1 байт deb → отказ; даунгрейд ниже `min_version` → отказ; `AgentEgressSource` не ходит на хост вне allowlist (тест на агенте); частичная загрузка не попадает в `staged` (атомарный rename).
- [x] **M6-T3 · `tgproxy update apply` (root oneshot)** (S-ops)
  - Файлы: `internal/selfupdate/apply.go` (повторная проверка подписи → бэкап текущего deb → `dpkg -i` → `systemctl restart tgproxy-server` → опрос `/healthz` 30s → при провале `dpkg -i prev.deb` + restart + запись результата в `updates/result.json`), `cmd/tgproxy/update.go` (S-wire).
  - Тесты: `Executor`-интерфейс для `dpkg/systemctl` с фейком — успешный путь, провал health → откат, провал подписи → ничего не выполняется; интеграционный — в `debian:12` CI.
- [x] **M6-T4 · Раскатка агентов** (S-ops) · зависит от M5-T3, M6-T2
  - Файлы: `internal/server/installer/rollout.go` (`Rollout{Canary: 1, BatchSize: N}`; на каждом агенте, независимо от режима связи: drain → `POST /_agent/update {version}` → агент сам качает пакет с `agent_gateway`/GitHub, проверяет minisign встроенными ключами и `min_version`, ставит через свой root-oneshot `tgproxy-update.service` → health 60s → иначе `prev.deb`; стоп раскатки при провале канарейки; «Остановить»), `internal/agent/selfupdate.go` (S-agent), `GET /_agent_gw/packages/<v>` в gateway (S-proxy). SSH (`tgproxy-deploy`) — только аварийный путь для `dial`-агентов.
  - Тесты: агент отвергает пакет с чужой подписью и версию ниже `min_version` даже по команде сервера; провал канарейки → остальные не трогаются; провал в батче 2 → откат именно этого агента, раскатка стоп, алерт; повторный запуск идемпотентен (агенты уже на версии пропускаются).
- [x] **M6-T5 · Экран Система + раскатка в Агентах** (S-web)
  - По `System.dc.html`: карточка «Обновление сервера» (Установлено/Доступно/Проверено; «Откуда скачать»: GitHub Releases — напрямую, Через HTTP-прокси — `update.http_proxy`, Через агента — <агент>, Загрузить файл — deb + .minisig; чеклист проверки deb/minisign/sha256; пояснение про откат через 30 с; «Установить vX», «Что нового»); карточка «Уведомления в Telegram» (статус бота, «Отправить тест», таблица администраторов: telegram_id, 2FA, последний вход; источник `/etc/tgproxy/users.yml`); «Какие события отправлять» (переключатели типов §9). В Агентах — баннер раскатки «канарейка → батчи по N», шаги, «Остановить».
  - API: `system/{version,releases,update,upload}`, `notifications` + `test`, `agents/{id}/{update,rollback}`; upload — лимит 100 МБ, проверка подписи до сохранения в кэш.
  - Тесты: upload без `.minisig` → 422; повторное нажатие «Установить» не создаёт второй `request`.
- [x] **M6-T6 · Release-workflow** (S-pkg)
  - `.github/workflows/release.yml`: по тегу `v*`, environment `release` с minisign-ключом (см. ОВ-4), goreleaser release, smoke deb в `debian:12`, публикация в GitHub Releases.
  - Приёмка среза: на macOS сервер обнаруживает релиз (тестовый тег в форк-репо или локальный `ProxySource` на `httptest`-сервере с подписанными артефактами), проверяет подпись, стейджит; `update apply` и раскатка агентов проверяются в контейнере `sshd-debian`.

**Срез M6:** в контейнере `sshd-debian` (systemd) агент ssh1 поставлен версией 0.0.2, обновлён командой сервера до 0.0.3 (подпись dev-ключом minisign, `tgproxy-update-agent.path` → `update apply`), релиз 0.0.4 с падающим бинарём откатан на 0.0.3 (`rolled_back=true`, агент up). Чужая подпись и даунгрейд → 422. Сервер на macOS проверяет релизы (GitHub: 0 релизов — корректно). Каталоги: непривилегированный кэш `updates/downloads`, доверенный `/var/cache/tgproxy/packages` (root). Не проверено: раскатка канарейка→батчи на нескольких systemd-агентах (стенд: один systemd-агент), реальная подпись minisign в release.yml (нужен ключ, ОВ-4).
В M7: аварийное обновление dial-агента по SSH (`Installer.EmergencyUpdate`, нужен SSH-порт агента в БД).

---

## M7 — Hardening, документация, деплой-скрипт, релиз v0.1.0 · объём **M**

- [ ] **M7-T1 · Security-проход** (все скоупы, параллельно по своим файлам)
  - Фаззеры: `tgapi.ParsePath`, `tgapi.ParseEnvelope`, `argon2id.ParsePHC`, `router.chat_id`-экстрактор, `redact` (60s в nightly).
  - Сквозной тест «токен нигде»: прогон сценария M2-приёмки с захватом всех логов, ответов API, SSE, метрик, БД-дампа → regex токена не найден.
  - `gosec` без игнорирований без комментария; `govulncheck` чист.
- [ ] **M7-T2 · Нагрузочный smoke** (S-pkg): `scripts/bench/` (vegeta/hey против фейкового Telegram на агенте): 500 rps `getMe`, p95 overhead сервера < 10 мс, RSS сервера < 200 МБ, без утечек горутин (`goleak` в тестах).
- [ ] **M7-T3 · Деплой-скрипт** (S-pkg)
  - Файлы: `scripts/deploy.sh`, `deploy/.env.example` (`PROD_SERVER_HOST`, `PROD_SERVER_SSH_USER`, `PROD_AGENT_HOSTS`, `PROD_PUBLIC_URL`, `PROD_ADMIN_URL`), цель `make deploy`:
    1. `make snapshot` (или тег) → `dist/tgproxy_*_amd64.deb`;
    2. `scp` deb на сервер → `sudo dpkg -i` → `systemctl restart tgproxy-server`;
    3. копирование того же deb в `/var/lib/tgproxy/packages/` сервера (для раскатки агентов);
    4. на хостах из `PROD_AGENT_HOSTS`, где агент уже установлен, — `sudo dpkg -i` + restart (первичная установка агента — только через UI, это часть E2E);
    5. health check: `curl -fsS $PROD_ADMIN_URL/healthz` (до 30s), `/readyz` ≥1 агент, `systemctl is-active` на агентах; ненулевой код при провале.
  - Тест: `shellcheck`; dry-run режим `DEPLOY_DRY_RUN=1` печатает план.
- [ ] **M7-T4 · Документация** (S-pkg): `README.md` (быстрый старт, конфиг, порты, бутстрап: `pki init`, `hashpw`, `totp enroll`), `docs/operations.md` (бэкап БД/KEK, ротация minisign-ключа, восстановление после потери KEK). Правка `architecture.md`: `/_agent/egress`, порты §0.2.
- [ ] **M7-T5 · Релиз v0.1.0**: тег, release-workflow зелёный, deb в GitHub Releases.

---

## M8 — Validation (по глобальным правилам) · объём **M**

Порядок строго по правилам пользователя; файл сценария — источник правды, перечитывается перед каждым действием.

- [ ] **V-1** · Оркестратор спрашивает платформы (`AskUserQuestion`, multiSelect). Варианты, применимые к проекту: **Backend**, **Web**. (Android/iOS/Desktop — неприменимы.)
- [ ] **V-2** · Создать `./swarm-report/tgproxy-e2e-scenario.md` (один раз). Каркас шагов:
  - Backend: `curl $PROD_ADMIN_URL/healthz` = 200; `/readyz` ≥1 агент; `/metrics` без bearer → 401, с bearer → `tgp_build_info`; `getMe` через `/bot<token>/getMe` из сети правила → `ok:true`; через `/k/<key>/bot<token>/getMe` из внешней сети → `ok:true`; без ключа из внешней сети → 403; неверный ключ → 403; `setWebhook` → 403; тело 52 МБ → 413; `sendMessage` доходит в тестовый чат; `getUpdates?timeout=30` отвечает ≤45s; остановка одного агента (`systemctl stop tgproxy-agent`) во время 100× `getMe` → 0 ошибок; reverse-агент за NAT подключён enrollment-командой и обслуживает `sendMessage`; разрыв его соединений → `agent_down`, восстановление → resolved; алерт `agent_down` пришёл в Telegram админу; агент поднят → алерт resolved; 429-окно: флуд в один чат → следующий ответ 429 от сервера (заголовок `X-TGP-Source` отсутствует / агент не вызван — по метрике); токен не встречается в `journalctl -u tgproxy-server`.
  - Web (`playwright-cli -s=tgproxy`): вход (пароль → TOTP); неверный пароль показывает «Осталось попыток»; Обзор: KPI, график, таблица агентов, переключение 1ч/24ч; Ключи: создать ключ, ключ показан один раз, Base URL корректный, отозвать → бот получает 401; Ошибки: фильтр по фазе, «Показать ещё»; Агенты: drain/undrain, изменение веса; Мастер: добавить агента на чистый хост (шаги 1–3, подтверждение отпечатка, лог SSE до «Включение в балансировку»); Система: проверка релизов, «Отправить тест» уведомления, список админов; выход.
- [ ] **V-3** · Деплой на прод-стенд: `make deploy` → дождаться успешного health check. Без успешного деплоя проверки не начинаются.
- [ ] **V-4** · Unit-тесты: `make test-race` (+ `go test -tags integration ./...` при доступном Docker).
- [ ] **V-5** · Web-проверки через `playwright-cli`: `playwright-cli list` → если `tgproxy` `open` — использовать; если `closed` — `snapshot` всех открытых сессий в поисках `$PROD_ADMIN_URL`; не найдено — спросить пользователя. Каждая команда с `-s=tgproxy`; `screenshot` ключевых экранов в `./swarm-report/`. Окно на передний план не выводить.
- [ ] **V-6** · Backend-проверки — `curl` по сценарию.
- [ ] **V-7** · После каждого шага — отметить `[x]` в файле сценария. При ошибках — откат в соответствующую фазу с описанием; невыполненные шаги остаются.
- [ ] **V-8** · Отчёт `./swarm-report/tgproxy-<YYYY-MM-DD>.md`.

---

## Зависимости и параллельность

| Задача | Зависит от | Скоуп | Параллельно с |
|---|---|---|---|
| M0-T1 | — | S-wire/S-pkg | — |
| M0-T2, M0-T3 | M0-T1 | S-pkg | M0-T4 |
| M0-T4 | M0-T1 | S-web | M0-T2, M0-T3 |
| M1-T1, M1-T2, M1-T3, M1-T4 | M0-T1 | S-core | друг с другом (разные пакеты) и с M1-T5 (заглушки интерфейсов) |
| M1-T5 | M1-T4 (dev-PKI), M1-T2 | S-agent | M1-T6, M1-T7 |
| M1-T6 | M1-T4 | S-agent | M1-T7 |
| M1-T7 | M1-T1..T3 | S-proxy | M1-T5, M1-T6 |
| M1-T8 | M1-T1..T7 | S-wire | — |
| M2-T1 | M1-T1 | S-core | M2-T3, M2-T4 |
| M2-T2 | M2-T1 | S-proxy | M2-T7 |
| M2-T3, M2-T4 | M1-T3 | S-proxy (разные файлы) | друг с другом, M2-T1 |
| M2-T5 | M1-T6, M2-T3, M2-T4 | S-proxy | M2-T7 |
| M2-T6 | M1-T6, M2-T1 | S-proxy | M2-T5 (разные пакеты) |
| M2-T7 | M2-T1 | S-core | M2-T2, M2-T5, M2-T6 |
| M3-T1 | M1-T3 | S-obs | вся M2 |
| M3-T2 | M3-T1, M2-T5 | S-proxy + S-agent | друг с другом |
| M3-T3, M3-T4 | M2-T1 (T4 ещё M2-T5) | S-obs | M4-T1..T3 |
| M4-T1 | M1-T1 | S-web | M2, M3 |
| M4-T2 | M2-T1, M4-T1 | S-web | M3-T3 |
| M4-T3 | M0-T4 | S-web | M4-T1 |
| M4-T4..T7 | M4-T2, M4-T3 (+M3-T3 для T5/T6, M2-T2 для T7) | S-web | M5-T1, M5-T2 |
| M4-T9 | M1-T8 | S-core | M4-T1…T7 |
| M5-T1 | M1-T4 | S-core | M4 целиком |
| M5-T2 | M5-T1 | S-agent | M5-T3 (контракт CSR фиксируется в T1) |
| M5-T3 | M5-T1, M5-T2 | S-ops | M5-T4, M5-T5 |
| M5-T4 | M5-T1, M5-T2 | S-proxy | M5-T3 |
| M5-T5, M5-T6 | M5-T4 / M5-T3 | S-web | M6-T1 |
| M5-T8 | M1-T6, M5-T1 | S-agent ∥ S-proxy | M5-T3…T6 |
| M5-T9 | M5-T8 | S-proxy, S-agent, S-web | M5-T5 |
| M6-T1 | M0-T3 | S-pkg | M5 целиком |
| M6-T2 | M2-T1 | S-ops | M6-T1, M5-T5 |
| M6-T3 | M6-T2 | S-ops | M6-T5 |
| M6-T4 | M5-T3, M6-T2 | S-ops | M6-T5 |
| M6-T5 | M6-T2, M6-T4 (API) | S-web | M6-T3 |
| M6-T6 | M6-T1 | S-pkg | M6-T2..T5 |
| M7-T1 | M6 | все | M7-T2, M7-T3, M7-T4 |
| M7-T3 | M6-T1 | S-pkg | M7-T1 |
| M7-T5 | M7-T1..T4 | S-pkg | — |
| M8 | M7-T3 (деплой), M7-T5 | оркестратор | — |

Критический путь: M0-T1 → M1-T4 → M1-T6 → M2-T4/T3 → M2-T5 → M3-T4 → M5-T1 → M5-T3 → M6-T4 → M7-T3 → M8.
Максимальная параллельность: 3–4 exec-агента (S-core/S-agent/S-proxy в M1–M2; S-web/S-obs/S-core в M3–M5; S-ops/S-pkg/S-web в M6).

## Оценка объёма

| Фаза | Объём | Задач |
|---|---|---|
| M0 Скелет + CI | S | 4 |
| M1 Сквозной путь | M | 8 |
| M2 Надёжность | L | 8 |
| M3 Наблюдаемость | M | 5 |
| M4 Auth + UI | L | 8 |
| M5 PKI + SSH + Агенты | L | 7 |
| M6 Пакет + обновления | L | 6 |
| M7 Hardening + релиз | M | 5 |
| M8 Validation | M | 8 |
| **Итого** | | **59** |

## Риски и меры

| Риск | Мера |
|---|---|
| Дубли `send*` при ретраях | ретрай unsafe только на `dial/tls/pre-send`; полная матрица в `policy_test.go`; интеграционный тест «агент-2 не получил запрос» |
| Неверная разметка фазы (например, `write` спутан с `pre-send`) → дубли | фаза `pre-send` только до `WroteHeaders` в `httptrace`; ошибка server→agent после записи тела = `write`; тесты на каждую фазу с реальным TCP-обрывом |
| Утечка токенов (логи, ошибки `url.Error`, UI, метрики) | `redact.Handler` для slog, ботов в метриках нет, fuzz + сквозной тест «токен нигде» |
| DoS через argon2-параметры в users-файле | верхние границы `m/t/p`, отказ без вычисления |
| Компрометация админки → SSH на любые хосты | TOTP обязателен, lockout, аудит, админ-листенер на `127.0.0.1` по умолчанию, креды SSH только в памяти |
| Self-update ломает сервер | root-oneshot отдельно от процесса, подпись проверяется дважды, health 30s + откат на `prev.deb`, smoke в `debian:12` |
| Канал «через агента» для обновлений = SSRF/egress-прокси | отдельный `/_agent/egress`: только GET, жёсткий allowlist хостов, лимит размера, только с SAN `tgproxy-server` |
| SQLite-конкуренция под нагрузкой | WAL + `busy_timeout`, один writer-пул, история пишется батчами раз в 10s; горячий путь запроса в БД не пишет (rate-окна в памяти) |
| htmx 4.x несовместим с кодом под 2.x | вендорится 2.0.11, Dependabot для вендора не используется, обновление вручную |
| `__Host-` cookie требует HTTPS | в dev — `localhost` (secure context); в проде — TLS на админ-листенере или reverse proxy; при `http` не-localhost — отказ старта |
| Расхождение UI с макетами | golden-тесты компонентов; скриншоты в Validation сравниваются с `docs/design/*.dc.html` |
| Локальная проверка SSH/dpkg на macOS невозможна нативно | контейнер `sshd-debian` (systemd) в `dev/docker-compose.yml` |

## Открытые вопросы (с дефолтами)

| # | Вопрос | Дефолт до ответа |
|---|---|---|
| ОВ-1 | Go module path | ✅ `github.com/vasyakrg/tgproxy-server` |
| ОВ-2 | Домен/хост прод-стенда сервера и хосты агентов | `PROD_SERVER_HOST`, `PROD_AGENT_HOSTS` в `deploy/.env` — нужны до M7-T3 |
| ОВ-3 | GitHub-репо для релизов | ✅ публичный `vasyakrg/tgproxy-server`, `GitHubSource` без токена |
| ОВ-4 | Где хранить minisign-ключ (секретный) | GitHub environment `release` (secret + required reviewers); резервная копия второго ключа — офлайн у владельца |
| ОВ-5 | Нужен ли HA / Redis сейчас | нет: один инстанс, Redis-бэкенд пишется (M2-T7), но не включается |
| ОВ-6 | TLS на входе сервера | ✅ `tls.mode`: `acme` (сервер сам получает/продлевает) или `files` (купленный серт, горячая перезагрузка); `off` — за reverse proxy |
| ОВ-7 | Users-файл | ✅ свой `/etc/tgproxy/users.yml`, формат хешей Authelia + `telegram_id`, `totp_secret_enc` |
| ОВ-8 | Тестовый бот и чат для E2E/алертов на стенде | токен в `deploy/.env` / `dev/.env`, не в репозитории |
| ОВ-9 | Автоматизация Admin API (токены для скриптов) | не делаем в v0.1; деплой — по SSH (`make deploy`) |
