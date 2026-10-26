# tgproxy — архитектура

Статус: черновик v1 (2026-10-26), итог консилиума architect / security / devops / api.

## 1. Назначение и контекст

Один Go-бинарник `tgproxy` с режимами `server` и `agent`.

- **server** — стоит в контуре, где `api.telegram.org` недоступен/нестабилен. Drop-in замена base URL для ботов. Балансирует запросы по агентам, ставит/обновляет агентов по SSH, веб-UI для 2–3 админов, Prometheus, алерты в Telegram.
- **agent** — стоит там, где Telegram доступен. Получает запросы сервера по mTLS (входящее соединение от сервера или собственное исходящее, если агент за NAT) и проксирует в `api.telegram.org`. Свои Prometheus-метрики, статус для сервера. UI нет.

Принятые решения (пользователь):
| Вопрос | Решение |
|---|---|
| Канал server↔agent | **оба режима**, задаётся на агента: `dial` — сервер ходит к агенту (агент слушает `:8443`); `reverse` — агент сам дозванивается до сервера (агент за NAT / без входящих портов) |
| Хранилище | встроенное (SQLite pure-Go) по умолчанию + опциональный Redis |
| Дистрибуция | GitHub Releases (deb); агенты обновляются по команде сервера, пакет проверяется подписью на самом агенте |

## 2. Компоненты

```
cmd/tgproxy                     cobra: server | agent | hashpw | pki | update apply | version | config validate
internal/config                 YAML + env (TGPROXY_*) + *_file секреты; users_database.yml (формат Authelia)
internal/server/proxy           вход /bot<token>/<method>, /file/bot<token>/<path>, те же пути с префиксом /k/<key>
internal/server/access          правила доступа: сети (CIDR) и/или скрытый ключ, rate-limit
internal/server/router          классификация методов, синхронные ретраи, бюджет, 429-окна
internal/server/balancer        P2C по (inflight+1)×EWMA(latency), circuit breaker
internal/server/agents          реестр, poller /_agent/status (5s), drain
internal/server/installer       SSH/SFTP: install / upgrade / rollback / uninstall, TOFU host keys
internal/server/updater         загрузка релизов (GitHub | proxy | через агента | ручной upload), minisign
internal/server/notify          outbox алертов, дедуп, лимиты, доставка через собственный пул агентов
internal/server/history         samples_10s (24h) + samples_5m (30d)
internal/server/web             templ + htmx + uPlot (embed), сессии, TOTP, CSRF, JSON API /api/v1
internal/agent                  ReverseProxy → api.telegram.org, /_agent/*, upstream TLS-проба; listener (dial) или connector (reverse), enroll, self-update
internal/transport              AgentTransport: dial (h2-клиент → agent:8443) | reverse (h2 поверх входящего от агента соединения), разметка фаз ошибок
internal/server/gateway         agent_gateway :8444 — приём reverse-соединений агентов, /enroll, раздача пакетов агентам
internal/pki                    встроенный CA (ECDSA P-256), CSR-флоу, denylist серийников
internal/store                  Store: sqlite | redis (только эфемерное)
internal/tgapi                  таблица методов safe/semi/unsafe, парсинг {ok,error_code,parameters}
internal/metrics                раздельные реестры server/agent
internal/redact                 маскирование токенов везде
```

Ключевые интерфейсы: `Balancer.Pick(ctx, key, exclude) (Agent, release, error)`, `AgentTransport.RoundTrip/Status`, `Store{Agents,Sessions,Outbox,RateState,History}`, `RetryBuffer.Wrap(req) Replayable`, `Notifier.Fire/Resolve`, `Installer.Install/Upgrade/Rollback`.

## 3. Публичный прокси-контракт

| Путь | Поведение |
|---|---|
| `/bot<token>/<method>` (GET/POST) | сквозная передача, клиент меняет только base URL; json / urlencoded / multipart как есть; лимит 51 МБ → 413 в формате Telegram |
| `/file/bot<token>/<path>` (GET/HEAD) | стримом, ретрай только до первого отданного байта |
| `/k/<key>/bot<token>/...`, `/k/<key>/file/bot<token>/...` | то же, со скрытым ключом в base URL — для клиентов вне доверенных сетей |
| заголовок `X-Proxy-Key` | необязательная альтернатива ключу в пути |
| `setWebhook` | по умолчанию 403 `tgproxy: webhooks unsupported, use getUpdates` (`webhook_policy: deny|passthrough`) |
| нет здоровых агентов | ждём до дедлайна (30s) → 502 `{"ok":false,"error_code":502,"description":"tgproxy: no healthy agents"}` |

**Доступ — правила, а не учёт ботов.** Токены и `bot_id` клиентов сервер не хранит и не проверяет: запрос уходит в `api.telegram.org` как есть. Правило доступа = имя + сети (CIDR, опц.) + скрытый ключ (опц., в БД — SHA-256) + лимит rps. Запрос пропускается, если подходит хотя бы одно правило:

| Правило | Как клиент обращается | Условие |
|---|---|---|
| только сеть | `{base}/bot<token>/sendMessage` | `RemoteAddr` ∈ CIDR |
| только ключ | `{base}/k/<key>/bot<token>/sendMessage` | ключ совпал |
| сеть + ключ | `{base}/k/<key>/bot<token>/sendMessage` | оба условия |

Правило без сети и без ключа запрещено валидацией: это открытый relay к Bot API → бан IP агентов. `X-Forwarded-For` учитывается только от `trusted_proxies`. Нет подходящего правила → 403 в формате Telegram. Upstream жёстко `api.telegram.org`.

Заголовки: вычищаются hop-by-hop, `X-Forwarded-*`, `Forwarded`, `Via`, `Cookie`, `Authorization`; в ответ добавляется `X-Request-ID`.

### 3.1 TLS на входе сервера

Один механизм для обоих листенеров (прокси ботов и админка), `tls.mode`:

| Режим | Как работает |
|---|---|
| `acme` | сервер сам получает и продлевает сертификат (`golang.org/x/crypto/acme/autocert`, TLS-ALPN-01 / HTTP-01; кеш в `/var/lib/tgproxy/acme`, 0700). Нужен входящий доступ из интернета к `:443` (или `:80`) и исходящий к ACME CA. Если контур не выпускает наружу — ACME-клиент ходит через `/_agent/egress` (хост CA в allowlist). |
| `files` | администратор кладёт купленный сертификат: `cert_file` (цепочка PEM) + `key_file` (0600/0640 `root:tgproxy`). Горячая перезагрузка без рестарта: fsnotify + `SIGHUP` + проверка mtime раз в минуту; новый сертификат подменяется атомарно через `tls.Config.GetCertificate`. Перед подменой — валидация: ключ соответствует сертификату, срок не истёк, цепочка собирается; при ошибке остаётся старый сертификат + алерт `ingress_cert_invalid`. |
| `off` | TLS терминирует внешний reverse proxy; `trusted_proxies` обязателен. |

Для любого режима: алерт `ingress_cert_expiring` (< 14 дней), метрика `tgp_ingress_cert_not_after_seconds`, карточка в UI «Система → Сертификат входа» (источник, CN/SAN, издатель, срок, последняя перезагрузка/продление, кнопка «Перечитать файлы» для `files`). Ключ сертификата входа не загружается и не показывается через UI.

## 4. Server ↔ agent

HTTP/2 reverse proxy поверх mTLS 1.3 (не gRPC — multipart и файлы идут байт-в-байт стримом, без перекодирования).

| Эндпоинт агента (порт 8443) | Назначение |
|---|---|
| `ANY /tg/{rest}` | прозрачно в `https://api.telegram.org/{rest}` (`FlushInterval:-1`) |
| `GET /_agent/healthz` | 200/503 + кэш TLS-пробы до Telegram (10s) |
| `GET /_agent/status` | version, commit, uptime, inflight, rps, ошибки по фазам, upstream_rtt, draining, cert_not_after |
| `POST /_agent/drain` | не принимать новые запросы (перед обновлением) |
| `POST /_agent/csr` → `PUT /_agent/cert` | ротация сертификата: агент генерирует ключ+CSR, сервер подписывает |
| `PUT /_agent/config` | смена режима связи, адреса сервера, весов/лимитов агента |
| `POST /_agent/update {version}` | агент сам скачивает и ставит подписанный пакет (см. §12) |
| `GET /metrics` (отдельный порт, bearer) | Prometheus агента; сервер федерирует как `/api/v1/agents/{id}/metrics` |

Запрос: `X-Request-ID` (ULID), `X-TGP-Timeout-Ms`, `X-TGP-Attempt`, `X-TGP-Bot-ID`.
Ответ: `X-TGP-Source: telegram|agent`, `X-TGP-Error-Phase: dial|tls|pre-send|write|read|timeout`, `X-TGP-Upstream-Ms`.

### 4.1 Режимы связи server ↔ agent

Над обоими режимами — один интерфейс `AgentTransport`; балансировщик, ретраи, опрос статуса и метрики не знают, как агент подключён. Внутри канала — тот же HTTP/2 и те же эндпоинты `/tg/*`, `/_agent/*`.

| | `dial` (по умолчанию) | `reverse` (агент за NAT) |
|---|---|---|
| Кто открывает TCP | сервер → `agent:8443` | агент → `server:8444` (`agent_gateway`) |
| Роли TLS | агент — TLS-сервер, сервер — клиент с сертификатом `tgproxy-server` | сервер — TLS-сервер, агент — клиент с сертификатом `agent/<id>`; оба проверяют CA проекта |
| HTTP/2 поверх соединения | сервер — h2-клиент | **роли разворачиваются**: агент запускает `http2.Server.ServeConn(conn)`, сервер делает `http2.Transport.NewClientConn(conn)` (`golang.org/x/net/http2`) и шлёт запросы в агента |
| Сколько соединений | пул `http.Transport` | агент держит 2 параллельных соединения (отказоустойчивость), переподключение с экспоненциальным backoff + jitter (1s…60s), h2 PING каждые 15s, разрыв = агент `down` через 2 пропущенных PING |
| Что открыть в сети | входящий `:8443` на агенте | входящий `:8444` на сервере (из сетей агентов); на агенте ничего |
| Идентификация | SAN агента сверяется с записью в БД | то же; повторное подключение с тем же id вытесняет старое только после проверки сертификата |

Режим можно переключить у существующего агента (UI → «Связь»): сервер выдаёт агенту новый конфиг через `/_agent/config`, агент переподключается.

**Подключение агента за NAT (enrollment).** SSH с сервера до такого агента обычно недоступен, поэтому есть второй способ установки:
1. В UI «Добавить агента → Агент за NAT» сервер создаёт одноразовый токен (32 байта, в БД — SHA-256, TTL 1 ч, одно использование) и показывает команду: `curl -fsSLO …/tgproxy_<v>_amd64.deb && sudo dpkg -i … && sudo tgproxy agent enroll --server https://<server>:8444 --token <t> --ca-fingerprint SHA256:<…>`.
2. Агент проверяет сертификат `agent_gateway` по отпечатку CA из команды (pinning без TOFU), генерирует ключ, шлёт CSR + токен на `POST /enroll`.
3. Сервер гасит токен, подписывает сертификат, агент сохраняет его и стартует в режиме `reverse`.
`/enroll` — единственный эндпоинт `agent_gateway` без клиентского сертификата: rate-limit 5/мин на IP, отказ без валидного токена, аудит + алерт админам о новом агенте.

Отчётность агента — **pull**: сервер опрашивает `/_agent/status` каждые 5s + пассивный health по реальному трафику. Канал данных **не умеет исполнять код**: команда `/_agent/update` передаёт только версию; агент сам скачивает пакет и ставит его, только если подпись minisign сошлась с ключами, вшитыми в бинарь (см. §12).

Таймауты: входной сервер `ReadHeaderTimeout=10s`, `WriteTimeout=0`; дедлайн `getUpdates` = `timeout+15s` (≤65s), long-poll не учитывается в EWMA.

## 5. Балансировка

- Power-of-two-choices, score = `(inflight+1) × EWMA(latency, α=0.3)`, вес агента из UI.
- Кандидаты: health=up, не draining, circuit breaker закрыт (5 подряд транспортных ошибок → open 30s → half-open).
- Без sticky: лимиты Telegram на бота/чат, не на IP.
- 429: сервер запоминает `retry_after` по `(sha256(token), chat_id)` в памяти и до истечения окна отвечает 429 сам, не нагружая агентов. На health агента не влияет.

## 6. Ретраи и «кеш» сообщений

**Ретраи только синхронные, внутри жизни запроса бота.** Асинхронная доотправка после ответа боту запрещена: бот повторит сам → гарантированный дубль.

| Класс | Методы | dial / tls / pre-send | write / read / timeout | 5xx Telegram | 429 |
|---|---|---|---|---|---|
| safe | `get*`, `getUpdates`, `/file/*`, `set*`≠setWebhook, `delete*`, `pin/unpin`, `ban/restrict/promote` | ретрай | ретрай | ретрай (backoff 0.5/1/2s) | passthrough |
| semi | `edit*`, `answerCallbackQuery`, `answerInlineQuery`, `stopPoll`, `sendChatAction` | ретрай | ретрай (`not modified` = успех) | ретрай | passthrough |
| unsafe | `send*`, `forward*`, `copy*`, `sendMediaGroup`, `create*`, `refund*` | **ретрай** | **нет** → 502 `delivery unknown` | нет | passthrough |

Бюджет: ≤3 попыток, ≤25s, агенты прошлых попыток исключаются.

Буфер тела («кеш») на время запроса: ≤1 МиБ — RAM; multipart ≤10 МиБ — tmp-файл (удаляется по завершении); больше — без буфера, ретрай только если агент прочитал 0 байт. На диске — шифрование AES-256-GCM (DEK под KEK). Тела в SQLite/Redis не персистятся. В UI видны только метаданные in-flight.

## 7. Хранилище

| Данные | SQLite (всегда) | Redis (опц.) |
|---|---|---|
| агенты, host-key fingerprints, сертификаты, denylist | ✓ | — |
| история метрик (10s/24h, 5m/30d) | ✓ | — |
| outbox алертов, аудит-лог админов | ✓ | — |
| сессии, rate-limit/429-окна | ✓ по умолчанию | ✓ (для нескольких инстансов) |

SQLite: `modernc.org/sqlite`, WAL, миграции goose. Redis — только `rediss://` + ACL, иначе отказ старта.

## 8. Безопасность

- **PKI**: встроенный CA (ECDSA P-256), ключ CA зашифрован KEK (`/etc/tgproxy/kek`, 0400). Ключ агента генерируется на агенте, сервер подписывает CSR. Сертификаты 90 дней, ротация на 2/3 срока по mTLS. SAN `spiffe://tgproxy/agent/<id>` сверяется с БД; агент принимает только клиента с SAN `tgproxy-server`. Отзыв — denylist серийников + короткий TTL.
- **SSH**: первичная установка — креды админа (ключ/пароль) только в памяти задачи. На агенте создаётся `tgproxy-deploy` с серверным ed25519-ключом и sudoers только на `dpkg -i /var/lib/tgproxy/packages/tgproxy_*.deb` и `systemctl * tgproxy-agent`. Host key — TOFU с подтверждением fingerprint в UI, далее `FixedHostKey`; несовпадение → отказ + алерт.
- **Web-auth**: users_database.yml (Authelia), argon2id (параметры из хеша, constant-time), `__Host-sid` HttpOnly/Secure/SameSite=Strict, idle 30m / abs 12h, CSRF через `http.CrossOriginProtection`, 5 попыток/мин на IP+user, lockout 15m после 10 неудач + алерт, фиктивный хеш для несуществующих юзеров, перечитывание файла по fsnotify/SIGHUP. **TOTP обязателен** (секрет в том же файле, шифрован KEK).
- **Секреты**: `redact` для токенов в логах/UI/ошибках (виден только `bot_id` — часть до `:`), в метриках ботов нет вовсе; фаззер-тест на regex токена во всех выводах.
- **Обновления**: `checksums.txt` подписан minisign (ed25519), 2 публичных ключа вшиты в бинарь (ротация). Даунгрейд ниже `min_version` запрещён.
- **systemd hardening**: `ProtectSystem=strict`, `NoNewPrivileges`, пустой `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `UMask=0077`, цель `systemd-analyze security` ≤ 2.0.

## 9. Уведомления

- Отдельный notifier-бот-токен; `sendMessage` идёт через тот же Router/Balancer с меткой `internal` (сервер сам Telegram не видит).
- Получатели — `telegram_id` из users_database.yml.
- Типы: `agent_down`, `agent_degraded` (err>5%/5m), `overload` (inflight выше порога), `cert_expiring`, `ingress_cert_expiring`, `ingress_cert_invalid`, `version_mismatch`, `login_lockout`, `hostkey_mismatch`, `agent_enrolled`, `all_agents_down`.
- Outbox в SQLite, дедуп по `(agent_id,type)`, повтор firing ≤1/ч, resolved — один раз, глобально ≤20/мин со склейкой. Нет агентов → копится в outbox + метрика `tgp_alerts_undeliverable`.

## 10. Метрики (`tgp_`)

Server (отдельный порт, bearer, constant-time): `requests_total{rule,method,code}`, `request_duration_seconds{method_class,agent}`, `upstream_attempts_total{agent,result}`, `retries_total{class,reason}`, `telegram_429_total{rule}`, `agent_up{agent,mode}`, `agent_inflight{agent}`, `agent_reverse_conns{agent}`, `enroll_attempts_total{result}`, `no_healthy_agents_total`, `inflight_buffered_bytes`, `longpoll_active`, `webhook_blocked_total`, `install_jobs_total{result}`, `admin_logins_total{result}`, `alerts_undeliverable`, `build_info`.
Agent: `agent_requests_total{code_class,error_phase}`, `agent_upstream_duration_seconds`, `agent_inflight`, `agent_upstream_bytes_total{direction}`, `agent_dial_errors_total{kind}`, `build_info` + go/process.
Кардинальность: `method` ~150+`other`, `code` из фиксированного набора, `rule` = число правил доступа. `bot_id` в метки не попадает (ботов никто не регистрирует — множество неограниченно); «топ ботов» для UI — in-memory top-K по `bot_id` за окно, плюс фильтр по `bot_id` в журнале ошибок.

## 11. Admin API и UI

UI: **templ + htmx 2 + uPlot**, всё через `go:embed`, без CDN и node-тулчейна. Тот же сервисный слой отдаёт JSON `/api/v1`:

`auth/{login,logout,me,totp}` · `agents` CRUD, `agents/{id}/{drain,update,rollback,metrics,config}`, `enrollments` (создать/отозвать токен) · `ssh/hostkey` (TOFU) · `install-jobs` + SSE `install-jobs/{id}/events` · `stats/{summary,timeseries}` · `errors` (курсор) · `inflight` · `access-rules` CRUD · `notifications` + `test` · `system/{version,releases,update,upload}` · `audit`.

## 12. Поставка и обновление

- **Пакет**: один deb `tgproxy` (goreleaser v2 + nfpm), `CGO_ENABLED=0`, linux/amd64 deb + tar.gz, darwin/{arm64,amd64} tar.gz. Юниты `tgproxy-server.service`, `tgproxy-agent.service`, `tgproxy-update.path` + `tgproxy-update.service`. Конфиги `/etc/tgproxy/*.yaml` (`config|noreplace`), данные `/var/lib/tgproxy`, логи — journald (slog JSON).
- **Maintainer-скрипты**: preinst — системный юзер; postinst — daemon-reload, при upgrade `try-restart` активных юнитов; prerm(remove) — stop+disable; postrm(purge) — удалить данные и юзера.
- **Самообновление сервера**: процесс (непривилегированный) скачивает deb + checksums + minisig (GitHub → `update.http_proxy` → **через egress агента** → ручной upload в UI), проверяет, кладёт в `updates/staged` и создаёт `request`. `tgproxy-update.path` запускает root-oneshot `tgproxy update apply`: повторная проверка подписи → бэкап текущего deb → `dpkg -i` → рестарт → `/healthz` 30s → при провале откат.
- **Установка агентов**: `dial`-агент — по SSH (SFTP deb из кэша сервера → `dpkg -i` → конфиг + CSR-флоу → `enable --now` → проверка `/_agent/status`); `reverse`-агент — командой enrollment (§4.1), SSH не нужен.
- **Обновление агентов — единый путь для обоих режимов**: сервер шлёт `/_agent/update {version}` по уже открытому mTLS-каналу → агент скачивает deb + `checksums.txt` + `.minisig` с сервера (`GET /_agent_gw/packages/<v>` из кэша) или с GitHub → **сам проверяет подпись встроенными ключами** и `min_version` → кладёт в `updates/staged` → root-oneshot `tgproxy-update.service` ставит пакет → health 60s → откат на `prev.deb`. Компрометация сервера не даёт RCE на агентах: поставить можно только официально подписанный релиз не ниже `min_version`. Раскатка: канарейка (1 агент) → батчи по N, drain перед рестартом. SSH для `dial`-агентов остаётся аварийным путём (переустановка, откат вручную).
- **macOS dev**: `make build | dev-certs | run-server | run-agent | redis-up | lint | test | vuln | snapshot`, конфиги `./dev/*.yaml`, агент на `127.0.0.1:8443`.
- **CI** (GitHub Actions): golangci-lint v2, `go test -race`, govulncheck, `templ generate` + проверка диффа, `goreleaser check`; release по тегу `v*` с minisign-ключом в защищённом environment, smoke-тест deb в `debian:12`. Actions закреплены по SHA, Dependabot.

## 13. Стек

Go ≥1.25 (net/http h2, httputil.ReverseProxy, slog, embed, CrossOriginProtection) · modernc.org/sqlite · pressly/goose/v3 · golang.org/x/crypto (ssh, knownhosts, argon2) · pkg/sftp · prometheus/client_golang · redis/go-redis/v9 · spf13/cobra · go.yaml.in/yaml/v3 · golang.org/x/time/rate · a-h/templ · pquerna/otp · htmx 2 · uPlot · goreleaser v2 / nfpm · minisign.

## 14. Отклонения от исходного ТЗ (обоснование)

1. **«Кешировать сообщения для переотправки»** → синхронный буфер на время запроса. Отложенная доотправка `send*` даёт дубли сообщений.
2. **Redis** → опционален и только для эфемерного состояния; при одном инстансе сервера не нужен.
3. **Обновление агентов — по команде сервера, но с проверкой подписи на агенте** (пересмотрено после добавления `reverse`: до агента за NAT нет SSH). Канал данных передаёт только номер версии, исполнить можно лишь подписанный релиз → компрометация сервера ≠ RCE на агентах.
6. **Два режима связи server↔agent** (`dial` / `reverse`) за одним интерфейсом `AgentTransport`.
4. **TOTP** добавлен к паролю — админка умеет SSH на произвольные хосты и выпуск сертификатов.
5. **Правила доступа** по сети и/или скрытому ключу обязательны, учёта ботов нет — открытый прокси к Bot API = бан IP агентов.
