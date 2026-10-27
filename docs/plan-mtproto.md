# tgproxy — план: MTProto-прокси для клиентов Telegram

Статус: v1 (2026-10-27). Продолжение `docs/plan.md` (вехи M9…M13). Источник правды — `docs/mtproto.md` и `docs/architecture.md` §15; расхождение плана и дизайна = ошибка плана.

## 0. Базовые решения

### 0.1 Версии

| Компонент | Версия | Примечание |
|---|---|---|
| github.com/9seconds/mtg/v2 | **v2.2.8** (pin, без `@latest`) | MIT, `go 1.26` — совместимо с `go.mod`; импортируются только `mtglib`, `antireplay`, `ipblocklist`, `events`, `essentials`; пакет `network` — нет |
| транзитивные | `panjf2000/ants/v2`, `pires/go-proxyproto`, `OneOfOne/xxhash`, `tylertreat/BoomFilters` | лицензии и `govulncheck` — в M9-T0 |

Обновление mtg — только отдельной задачей с прогоном контракт-тестов M9-T0.

### 0.2 Новый скоуп

| Скоуп | Файлы | Содержание |
|---|---|---|
| **S-mtproto** | `internal/mtproto/**` | FakeTLS-разводка, muxListener, адаптер mtg, Network через агентов, link, probe |

Остальные скоупы — по `plan.md` §0.3. `internal/server/gateway/**` — как в M5-T8, скоуп **S-proxy**. Таблица DC — `internal/tgapi/dc.go` (**S-core**, общий тип протокола Telegram: её используют и агент, и сервер). Межскоуповые зависимости — только consumer-side интерфейсами (`docs/mtproto.md` §4.2).

### 0.3 Общие правила

Как `plan.md` §0.4: TDD (тесты из «Тесты первыми» коммитятся красными первыми), `go test -race ./...` зелёный на каждой задаче, покрытие `internal/mtproto/**`, `balancer`, `internal/agent/mtproto*` ≥ 85%, только `slog` через `redact.Handler`, `goleak` в пакетах с горутинами. Ключ секрета не появляется ни в одном логе/ошибке/метрике.

Локальная проверка вех: `make run-agent` + `make run-server`, `tgproxy mtproto probe --link …` против fake-DC (`TGP_DEV_FAKE_DC=1`) и против реального Telegram (dev-агент с доступом к DC).

---

## M9 — Основа: конфиг, секреты, агент-релей, StreamTransport (dial) · объём **M**

Цель: агент умеет отдать h2-стрим, соединённый с DC; сервер умеет его открыть; секреты хранятся зашифрованными. MTProto-листенера ещё нет.

- [x] **M9-T0 · Спайк и контракт-тесты mtg v2.2.8** (S-mtproto)
  - Файлы: `go.mod`/`go.sum` (`go get github.com/9seconds/mtg/v2@v2.2.8`), `internal/mtproto/mtgcontract_test.go`, `internal/mtproto/doc.go`, `NOTICE` (атрибуция MIT).
  - Тесты первыми (фиксируют поведение mtg, на которое опирается дизайн): `ServeConn` с conn, у которого `RemoteAddr` не `*net.TCPAddr`, паникует (наша обёртка обязана его давать); адреса в `Network.Dial` ∈ `essentials.TelegramCoreAddresses` и отображение addr→DC однозначно; `PreferIP: "only-ipv4"` → только `tcp4`; поведение на отрицательных DC и `AllowFallbackOnUnknownDC`; `AntiReplayCache.SeenBefore` вызывается ровно один раз на ClientHello; `Shutdown()` рвёт активный relay (если нет — пометить в `docs/mtproto.md` §4.3 «свой реестр conn»); `DomainFronting{ProxyProtocol:true}` шлёт PROXY v2 с исходным IP; события `EventStart/ConnectedToDC/Traffic/Finish/ReplayAttack/DomainFronting` приходят с ожидаемыми полями.
  - Приёмка: контракт-тесты зелёные; лицензии зависимостей в `NOTICE`; `govulncheck` чист; найденные расхождения внесены в `docs/mtproto.md` до старта M10.
- [x] **M9-T1 · Конфиг `mtproto:`** (S-core)
  - Файлы: `internal/config/config.go` (`MTProtoConfig`, `MTProtoAgentPool`, `AgentMTProtoConfig`; поле `MTProto` в `ServerConfig`/`AgentConfig`), `defaults.go`, `validate.go` (`ValidateServer`/`ValidateAgent`), неэкспортируемый тест-оверрайд таблицы DC по образцу `OverrideTelegramAPIURL` (`internal/config/defaults.go:123`), `packaging/etc/*.yaml` не трогать (M13).
  - Тесты первыми: дефолты из `docs/mtproto.md` §10; `enabled: true` без `pki.kek_file` → ошибка; `listen: shared` + `tls.mode: off` → ошибка; dedicated `listen` совпал с `listen.proxy|admin|metrics|agent_gateway` → ошибка; `fronting_domain` пустой/с портом/не FQDN → ошибка; `time_skew` ∉ [30s,10m], `replay_cache` ∉ [1MiB,256MiB], неположительные лимиты → ошибка; неизвестное поле → ошибка с путём; признак «требует рестарта» для `enabled|listen|fronting_domain` при reload.
  - Приёмка: `tgproxy config validate` на `dev/*.yaml` с `mtproto:`; покрытие ≥ 85%.
- [x] **M9-T2 · Таблица DC и сети Telegram** (S-core)
  - Файлы: `internal/tgapi/dc.go` (`DCAddrs(dc int, v6 bool) []netip.AddrPort`, `KnownDC(dc int) bool`, `TelegramPrefixes() []netip.Prefix`), `dc_test.go`.
  - Тесты первыми: все DC `1…5` и media (знак) имеют ≥1 IPv4; все адреса ∈ `TelegramPrefixes`; неизвестный DC → пусто; порт 443; совпадение IPv4-набора с `essentials.TelegramCoreAddresses` проверяется в `internal/mtproto` (M10-T4), чтобы `tgapi` не импортировал mtg.
- [x] **M9-T3 · Хранилище секретов и журнала** (S-core)
  - Файлы: `internal/store/sqlite/migrations/0009_mtproto.sql` (`mtproto_secrets`, `mtproto_sessions`, триггеры `versions('mtproto_secrets')` по образцу `0001_init.sql:95`), `internal/store/models.go` (`MTProtoSecret`, `MTProtoSession`), `internal/store/store.go` (`MTProtoSecrets() MTProtoSecretRepo`, `MTProtoSessions() MTProtoSessionRepo`), `internal/store/sqlite/mtproto.go`, `internal/store/memtest/`, `internal/store/storetest/` (contract).
  - Repo: `Create(ctx, name, sealed, prefix, cidrs, maxConns)`, `List`, `ListActive(ctx) ([]MTProtoSecret, version, error)`, `Update`, `Revoke(id, at)`, `Rotate(id, sealed, prefix, graceUntil)`, `Version`; сессии — `InsertBatch`, `List(cursor, filters)`, `Prune(before)`.
  - Тесты первыми: миграция up/down на копии прод-схемы; `secret_enc` хранится как есть (store не шифрует — шифрует сервисный слой KEK с `aad "mtproto/<id>"`); версия растёт на insert/update/revoke; `ListActive` не возвращает отозванные и с истёкшим `grace_until`; уникальность имени; batch 10k сессий < 200 мс.
  - Приёмка: contract-тесты общие для sqlite и memtest; Redis не затронут.
- [x] **M9-T4 · Агент: эндпоинт `/_agent/mtproto/dc/{dc}`** (S-agent)
  - Файлы: `internal/agent/mtproto.go` (handler, релей `r.Body` ↔ TCP ↔ `ResponseWriter` + `http.ResponseController.Flush`), `internal/agent/mtproto_dial.go` (dialer с `Control` по образцу `egressDialControl`, `internal/agent/egress.go:73`, + allowlist `tgapi.TelegramPrefixes`), регистрация в `internal/agent/server.go:11` (`Handler`), учёт в `drain.go`.
  - Тесты первыми (fake-DC — локальный TCP через тест-оверрайд таблицы): 200 приходит до первого байта от DC; байты идут в обе стороны без буферизации (эхо 5 МБ); `{dc}` ≠ `X-TGP-DC` → 400; неизвестный DC → 403; DC недоступен → 502 `X-TGP-Error-Phase: dial`, таймаут → `timeout`; `max_streams` → 503; drain → 503 для новых, живой стрим продолжается; `idle_timeout`/`max_duration` закрывают стрим; dial-control отвергает loopback/private вне тест-оверрайда; клиент без SAN `tgproxy-server` → отказ; `mtproto.enabled: false` → 404; goleak после закрытия.
- [x] **M9-T5 · Агент: пробы DC и capabilities** (S-agent)
  - Файлы: `internal/agent/mtproto_probe.go` (TCP-connect к одному адресу каждого DC раз в `dc_probe_interval`, джиттер), `internal/agent/status.go:26` (`capabilities`, `mtproto{streams, dc{up, rtt_ms}}`), `internal/transport/client.go` (`AgentStatus.Capabilities []string`, `AgentStatus.MTProto *MTProtoStatus`), `internal/agent/config_endpoint.go` (приём `dc_probe_interval` от сервера).
  - Тесты первыми: статус содержит `mtproto/1` только при `enabled`; недоступный DC → `up:false` через одну пробу, восстановление — через одну; RTT > 0; старый JSON статуса (без полей) парсится сервером без ошибки.
- [x] **M9-T6 · `StreamTransport` (dial)** (S-agent)
  - Файлы: `internal/transport/stream.go` (`StreamTransport`, `streamConn`: `io.Pipe` → тело, `resp.Body` → чтение, `CloseWrite`/`CloseRead`/`Close`, дедлайны, `RemoteAddr` `*net.TCPAddr`), `internal/transport/stream_dial.go` (второй `http.Transport` на агента, `http2.Transport` с `MaxReadFrameSize`, окнами ≥4 МБ, `StrictMaxConcurrentStreams`, PING), `registry.go`/`both.go` (выбор реализации по `AgentRef.Mode`; reverse — `ErrNotSupported` до M11-T1).
  - Тесты первыми: `OpenMTProto` возвращает conn только после 200; 403/502/503 агента → `*PhaseError` с фазой из заголовка; `CloseWrite` доставляет EOF агенту, обратное направление продолжает работать; Bot API-запросы и 500 MTProto-стримов идут по разным TCP (проверка через `httptrace`/счётчик соединений); goleak.
- [x] **M9-T7 · Wiring агента** (S-wire)
  - Файлы: `internal/app/agent.go` (конфиг `mtproto`, пробы, метрики-заглушки), SIGHUP для лимитов.
  - Приёмка среза: `curl --http2 --cert … -X POST https://127.0.0.1:8443/_agent/mtproto/dc/2` открывает стрим до fake-DC (dev) и до реального DC 2 (агент с доступом); `/_agent/status` содержит `capabilities` и матрицу DC.

**Срез M9:** агент — рабочий TCP-релей к DC с лимитами и пробами; сервер открывает стримы через `StreamTransport` в dial-режиме; секреты в БД.

---

## M10 — Сервер MTProto: разводка, адаптер mtg, Network через агентов · объём **L**

Цель: клиент с FakeTLS-секретом проходит через сервер и агента до DC; невалидный клиент видит обычный TLS.

- [x] **M10-T1 · `faketls`: разбор ClientHello и HMAC-разводка** (S-mtproto) · зависит от M9-T0
  - Файлы: `internal/mtproto/faketls/clienthello.go` (`ReadFirstRecord(r, max=16KiB)`, `Parse(b) (Hello{SNI, Random, SessionID, raw}, error)`), `match.go` (`Match(hello, secrets []Key, domain string, now, skew) (idx int, ok bool)`: HMAC-SHA256 по ClientHello с обнулённым `random`, `subtle.ConstantTimeCompare`, timestamp из XOR последних 4 байт, перебор всех секретов без раннего выхода), `fuzz_test.go`.
  - Тесты первыми: эталонные ClientHello, сгенерированные probe-клиентом (M10-T6) и захваченные у tdlib (testdata); неверный SNI / HMAC / timestamp вне окна → `ok=false`; два секрета — выбирается верный; не-Handshake запись и >16 КиБ → ошибка; `testing.AllocsPerRun` фиксирует отсутствие аллокаций на секрет; **fuzz** `FuzzParseClientHello` (в `make fuzz` и nightly).
- [ ] **M10-T2 · `mux`: muxListener, replayConn, fronting-листенер** (S-mtproto) · зависит от M10-T1
  - Файлы: `internal/mtproto/mux/listener.go` (`New(inner net.Listener, deps) *Listener`; `Accept()` отдаёт только fallthrough-соединения TLS-обработчику; MTProto-соединения уходят в `Handler.ServeMTProto(idx, conn)`), `replayconn.go` (повтор peek-байтов, `RemoteAddr` `*net.TCPAddr`), `limits.go` (семафор рукопожатий, счётчик на IP, `max_conns`), `fronting.go` (`127.0.0.1:0`, только PROXY v2 с loopback через `go-proxyproto`, отдаёт conn в тот же TLS-обработчик с исходным IP).
  - Тесты первыми: Accept не блокируется медленным клиентом (100 «молчунов» + 1 нормальный); забаненный IP закрыт до чтения; лимит на IP и глобальный → закрытие + `mtproto_conn_limit`; fallthrough отдаёт байт-в-байт исходный поток (`crypto/tls` handshake проходит с реальным сертификатом); валидный HMAC → `ServeMTProto` с верным индексом; нет capable-агентов → fallthrough; паника в обработчике не роняет листенер; fronting-листенер отвергает не-loopback и соединения без PROXY v2; дедлайн `handshake_timeout`; goleak.
- [ ] **M10-T3 · `Manager`: инстансы mtglib.Proxy по секретам** (S-mtproto) · зависит от M9-T0, M9-T3
  - Файлы: `internal/mtproto/manager.go` (снимок секретов по версии ≤2 с, `KEK.Open` с `aad "mtproto/<id>"`, инстанс на секрет, общий `antireplay.NewStableBloomFilter`, `ipblocklist.NewNoop`, `PreferIP: "only-ipv4"`, `DomainFronting` на fronting-листенер, `Shutdown` при отзыве; реестр conn с отменой, если M9-T0 показал, что `Shutdown` не рвёт relay), `events.go` (EventStream → `Observer`, маршрутизация по secret id, replay → `Bans.Record(ip, mtproto_replay)`), `logger.go` (mtg Logger → slog через `redact`).
  - Тесты первыми: добавление секрета подхватывается без рестарта; отзыв рвёт активное соединение ≤2 с; `grace_until` держит старый секрет до срока; ключ не появляется в логах (захват slog + regex `ee[0-9a-f]{32}` и сырой hex ключа); replay второго одинакового ClientHello → fronting + `Record`.
- [ ] **M10-T4 · `upstream.Network` через агентов** (S-mtproto) · зависит от M9-T6, M10-T5
  - Файлы: `internal/mtproto/upstream/network.go` (`Dial`/`DialContext`: addr→DC, `context.WithTimeout(dial_timeout)`, `Balancer.Pick(dc)`, `StreamTransport.OpenMTProto`, учёт `exclude` в пределах одного соединения клиента), `addrmap.go` (из `essentials.TelegramCoreAddresses`), `conn.go` (`essentials.Conn` поверх стрима, release балансировщика на `Close`), `nativedialer.go`.
  - Тесты первыми: неизвестный адрес → ошибка без обращения к агентам; IPv4-набор `tgapi.DCAddrs` ≡ `essentials.TelegramCoreAddresses` (защита от рассинхрона таблиц); ошибка агента A → следующий Dial mtg идёт на агента B; inflight уменьшается на `Close`, а не на открытие; дедлайны conn работают.
- [x] **M10-T5 · Keyed-балансировщик (agent, dc)** (S-proxy) · параллельно с M10-T1…T3
  - Файлы: `internal/server/balancer/keyed.go` (`NewKeyed(opts) *Keyed`; `Update(agents []KeyedCandidate{ID, Weight, Healthy, Draining, Capable, DC map[int]DCState{Up, RTT}})`, `Pick(ctx, dc, exclude)`; переиспользует `ewma.go`, `breaker.go`), `internal/server/agents` — проброс `Capabilities`/`MTProto` из статуса в событие реестра.
  - Тесты первыми: агент без `mtproto/1` не выбирается; `dc.up=false` исключает агента только для этого DC; EWMA засевается `rtt_ms`; score = (streams+1)×EWMA/weight, P2C на 10k выборок распределяет пропорционально; breaker по ключу не влияет на другие DC того же агента и на Bot API-балансировщик; draining исключает; покрытие ≥ 85%.
- [x] **M10-T6 · Probe-клиент и fake-DC** (S-mtproto) · параллельно с M10-T1
  - Файлы: `internal/mtproto/link/link.go` (`Build(host, port, key, domain) (tg, https string)`, `Parse(link) (host, port, key, domain, error)`), `internal/mtproto/probe/client.go` (FakeTLS ClientHello с HMAC → ServerHello → obfuscated2 → `req_pq_multi` → `resPQ`), `internal/mtproto/probe/fakedc.go` (obfuscated2-сервер, отвечает `resPQ`).
  - Тесты первыми: `link.Parse(link.Build(…))` — круговой; ссылка содержит `ee` + 32 hex + hex домена; probe против fake-DC напрямую (без прокси) получает `resPQ` с нашим nonce; неверный секрет → ошибка рукопожатия, а не зависание.
- [ ] **M10-T7 · Wiring сервера** (S-wire) · зависит от M10-T1…T6
  - Файлы: `internal/app/server.go` (`Serve`, ~`:348`: в shared-режиме `proxyLn` оборачивается `mux.Listener` до `srv.ServeTLS`; dedicated — свой `net.Listen` + внутренний `http.Server` с `ingTLS` и заглушкой; fronting-листенер; `Manager` в `runObs`-подобном жизненном цикле; graceful shutdown: стоп Accept → `Manager.Close` с ожиданием до `shutdownTimeout`), `internal/app/mtproto.go` (сборка зависимостей), проверка `fronting_domain` против `tlsin.CertInfo` при старте и на событии перезагрузки сертификата; NTP-проверка (предупреждение + метрика).
  - Тесты первыми: `enabled: false` — листенер прокси ведёт себя байт-в-байт как раньше (регресс Bot API: весь существующий набор `internal/app` зелёный); `fronting_domain` не в SAN → ошибка старта; dedicated listen поднимается и отдаёт TLS-заглушку.
- [ ] **M10-T8 · Integration in-process** (S-wire) · зависит от M10-T7
  - Файлы: `internal/app/mtproto_e2e_test.go`.
  - Сценарии: probe через server → agent (dial) → fake-DC получает `resPQ`; невалидный HMAC получает настоящий сертификат и HTTP-ответ прокси; replay → TLS-сайт + счётчик автобана; отзыв секрета рвёт соединение; DC down на агенте A → соединение через B; агент без capability не используется; Bot API `getMe` параллельно с 200 MTProto-стримами — p95 не растёт > 2×.
  - Приёмка среза: `tgproxy mtproto probe --link …` в dev до fake-DC и до реального Telegram (агент с доступом к DC); ручной вход официального клиента по ссылке.

**Срез M10:** MTProto работает в dial-режиме на shared- и dedicated-листенере; невалидные соединения неотличимы от сайта.

---

## M11 — Reverse-пул, защита, наблюдаемость · объём **L**

- [ ] **M11-T1 · Reverse: сервер** (S-proxy + S-agent, разные файлы) · зависит от M9-T6
  - Файлы: `internal/server/gateway/gateway.go` (ALPN `tgproxy-mtproto/1` в `NextProtos` (`:143`), ветка в разборе `NegotiatedProtocol` (`:286`), регистрация соединения в MTProto-пуле агента; отдельный лимит соединений на агента), `internal/transport/stream_reverse.go` (пул h2-клиентов по классу `mtproto`, выбор наименее загруженного conn, сигнал «нужно ещё соединение» при ≥`max_streams_per_conn`), `internal/transport/reverse.go` (константа `ALPNMTProto`).
  - Тесты первыми: соединение с ALPN `tgproxy-mtproto/1` без валидного клиентского сертификата → отказ; MTProto-стримы не идут по соединениям Bot API и наоборот; при 2×`max_streams_per_conn` стримах сервер просит у агента ещё соединение; разрыв MTProto-соединения рвёт его стримы, Bot API не затронут.
- [ ] **M11-T2 · Reverse: агент** (S-agent) · параллельно с M11-T1
  - Файлы: `internal/agent/connector.go` (второй класс соединений: ALPN `tgproxy-mtproto/1` рядом с `ALPNReverse` (`:23`), `reverse_conns` минимум, рост по сигналу сервера, backoff как у основного), `internal/agent/reverse_conns.go`.
  - Тесты первыми: агент держит `reverse_conns` MTProto-соединений; сервер без поддержки ALPN (старый) → агент работает только с Bot API-классом без ошибок в цикле; drain не закрывает живые стримы.
- [ ] **M11-T3 · Лимиты и изоляция** (S-mtproto) · зависит от M10-T2, M10-T3
  - Файлы: `internal/mtproto/mux/limits.go` (`max_conns` секрета, CIDR секрета), `internal/mtproto/budget.go` (проверка fd-бюджета против `RLIMIT_NOFILE` при старте), SIGHUP-перечитывание лимитов.
  - Тесты первыми: `max_conns` секрета → закрытие с `mtproto_conn_limit`; CIDR секрета: валидный HMAC из чужой сети → fallthrough (неотличимо от неверного секрета); новые лимиты по SIGHUP без разрыва живых; предупреждение при `max_conns×2 + 16384 > RLIMIT_NOFILE`.
- [ ] **M11-T4 · Причины отказа и fail2ban** (S-proxy) · параллельно с M11-T3
  - Файлы: `internal/server/access/static.go` (`ReasonMTProtoReplay` — `CountsForBan()=true`, `ReasonMTProtoConnLimit` — false, `ReasonMTProtoBadSecret` — false, резерв для dedicated-режима; список `Reasons`), `internal/server/ban/ban.go` (`Record` уже принимает `access.Reason`, `:142` — проверить, что защищённые адреса `protect.go` не банятся по новым причинам), записи `ErrorEvent{Phase: "mtproto"}`.
  - Тесты первыми: `threshold` replay с одного IP → автобан; conn_limit и bad_secret в счётчик не идут; защищённый адрес не банится; запись в «Ошибках» с фазой `mtproto`, IP и причиной, без секрета.
- [ ] **M11-T5 · Метрики** (S-obs + инструментирование S-mtproto, S-agent — параллельно)
  - Файлы: `internal/metrics/server.go`, `internal/metrics/agent.go` (метрики из `docs/mtproto.md` §13), `internal/mtproto/observer.go`, `internal/agent/metrics.go`.
  - Тесты первыми: `testutil.CollectAndCompare` на каждую метрику; `promlint` чист; в метках нет IP/ключей (сквозной regex по выдаче `/metrics`); `secret` — имя, не префикс.
- [ ] **M11-T6 · Алерты** (S-obs) · зависит от M11-T5
  - Файлы: `internal/server/notify/types.go` (`mtproto_dc_unreachable`, `mtproto_no_capable_agents`, `mtproto_overload`), правила срабатывания и resolved.
  - Тесты первыми: DC down на всех capable-агентах > 1 мин → firing, восстановление одного → resolved; 0 capable при `enabled` → firing; > 90% `max_conns` 5 мин → firing; дедуп и лимиты общие.
- [ ] **M11-T7 · Журнал соединений и история** (S-obs + S-core) · зависит от M9-T3
  - Файлы: `internal/store/sqlite/migrations/0010_samples_mtproto.sql` (S-core), `internal/server/history/*` (ряды `mtproto_conns`, `mtproto_bytes_in/out`), `internal/mtproto/journal.go` (батч-писатель сессий раз в 10 с, очередь с потолком, переполнение → метрика, а не блокировка), retention как у `error_events`.
  - Тесты первыми: 10k завершённых соединений за 10 с пишутся одним батчем; переполнение очереди не блокирует relay; Prune по retention; ряды в 10s/5m агрегируются.
- [ ] **M11-T8 · Wiring** (S-wire): reverse-пул в `internal/app/server.go`/`agent.go`, алерты, журнал, SIGHUP.
  - Приёмка среза: reverse-агент за NAT обслуживает MTProto (probe до fake-DC и реального DC); метрики и алерты видны в `/metrics`; replay-флуд с одного IP приводит к автобану.

**Срез M11:** оба режима связи, защита от злоупотреблений, полная наблюдаемость.

---

## M12 — API, CLI, UI · объём **L**

- [ ] **M12-T1 · Сервис секретов и API** (S-web) · зависит от M9-T3, M10-T6
  - Файлы: `internal/server/web/api/mtproto.go` (сервис: генерация ключа `crypto/rand`, `KEK.Seal` c `aad "mtproto/<id>"`, ссылка через `link.Build`), `internal/server/web/api/mtproto_http.go` (маршруты из `docs/mtproto.md` §12, `RequireAuth`+`Protect` как `access_http.go`), `internal/server/web/auth/` — механизм «свежего TOTP» (отметка времени последней проверки TOTP в сессии, `RequireFreshTOTP(5m)`; сейчас его нет — добавляется), аудит `mtproto_secret.*`.
  - Тесты первыми: POST возвращает ссылку один раз, GET списка — только префикс; `/link` без свежего TOTP → `401 totp_required`, со свежим → ссылка + аудит `reveal`; DELETE без `confirm=yes` → 400; rotate создаёт новый секрет и ставит `grace_until`; CSRF как у остальных; ключ не в ответах (кроме create/link) и не в аудите.
- [ ] **M12-T2 · Stats API** (S-web) · зависит от M10-T5, M11-T5
  - Файлы: `internal/server/web/api/stats.go` (`GET /api/v1/mtproto/stats`: agent×dc streams/rtt/up/errors, итоги), ряды `mtproto_conns`, `mtproto_bps` в `stats/timeseries`, фильтр `phase=mtproto` в `errors`.
  - Тесты первыми: форма JSON; пустая матрица при `enabled:false`; ряды в timeseries.
- [ ] **M12-T3 · CLI** (S-wire) · зависит от M12-T1
  - Файлы: `cmd/tgproxy/mtproto.go` (`mtproto secret add|list|delete|rotate|link`, `mtproto probe --link [--dc] [--timeout]`), тесты команд по образцу `ban_test.go`.
  - Тесты первыми: `list` не печатает ключ; `link` без KEK → понятная ошибка; `probe` код возврата 0/1, ссылка из аргумента/`--link-stdin` не печатается в лог.
- [ ] **M12-T4 · UI: вкладка «MTProto»** (S-web) · зависит от M12-T1, M12-T2
  - Файлы: `internal/server/web/screens/mtproto.templ|.go|_deps.go`, навигация в `shell.go`; макет — `docs/design/MTProto.dc.html` (создаётся ролью `ui` до задачи).
  - Содержимое: таблица секретов (имя, префикс, статус, соединения, действия), создание (ссылка показывается один раз), модалка «Ссылка + QR» (`renderQR`, `internal/server/web/auth/qr.go:10`; запрос TOTP при несвежем), отзыв с подтверждением, ротация, матрица агент×DC.
  - Тесты первыми: golden-рендер; QR-модалка не рендерится без свежего TOTP; htmx-действия с CSRF.
- [ ] **M12-T5 · UI: интеграция в существующие экраны** (S-web) · параллельно с M12-T4
  - Файлы: `screens/agents.templ` (чип `mtproto/1`, статус DC), `screens/overview.templ` (KPI «MTProto: соединения, полоса», ряды на графике), `screens/errors.templ` (фаза `mtproto`).
  - Тесты первыми: golden-рендер с/без capability; KPI скрыт при `enabled:false`.
- [ ] **M12-T6 · Wiring** (S-wire): маршруты API/UI, зависимость `Manager` → stats.
  - Приёмка среза: секрет создан в UI, QR отсканирован официальным клиентом, клиент работает; отзыв из UI рвёт соединение ≤2 с; матрица agent×DC живая.

**Срез M12:** MTProto управляется из UI/CLI/API без правки конфигов.

---

## M13 — Поставка, документация, Validation · объём **M**

- [ ] **M13-T1 · Пакет** (S-pkg)
  - Файлы: `packaging/systemd/tgproxy-server.service:17` (`LimitNOFILE=1048576`), `tgproxy-agent.service:17` (`262144`), `packaging/etc/server.yaml`/`agent.yaml` (закомментированный блок `mtproto:`), `NOTICE` в пакете.
  - Приёмка: `systemd-analyze security` не хуже 2.0; deb-smoke зелёный.
- [ ] **M13-T2 · Smoke и деплой** (S-pkg)
  - Файлы: `packaging/ci/smoke-inner.sh` (сервер+агент+fake-DC в контейнере, `tgproxy mtproto probe`), `scripts/deploy.sh` (опциональный шаг: при `PROD_MTPROTO_LINK` в `deploy/.env` → `tgproxy mtproto probe --link-stdin` на сервере; значение не печатается), `deploy/.env.example`.
  - Тест: `shellcheck`; `DEPLOY_DRY_RUN=1` показывает шаг probe без значения ссылки.
- [ ] **M13-T3 · Документация** (S-pkg)
  - Файлы: `docs/operations.md` (раздел «MTProto»: включение, NTP, sysctl, фаервол агентов — исходящий 443 к сетям Telegram, ротация/отзыв, диагностика, признаки блокировки, переход на dedicated IP), `README.md` (кратко + ссылка), актуализация `docs/mtproto.md` по итогам реализации.
- [ ] **M13-T4 · Security-проход** (все скоупы, параллельно по своим файлам)
  - Фаззеры `faketls`, `mux` (первая запись) — 60 s без находок; `internal/app/mtprotoleak_e2e_test.go` — ключ секрета не находится в логах сервера/агентов, метриках, ответах API (кроме create/link), аудите, SSE, дампе БД (кроме `secret_enc`); `redact` маскирует `ee[0-9a-f]{32,}` и `secret=`; `gosec`, `govulncheck` (включая зависимости mtg) чисты.
- [ ] **M13-T5 · Нагрузочный smoke** (S-pkg)
  - Файлы: `scripts/bench/mtproto/` (N probe-клиентов + fake-DC с потоковым эхо).
  - Цели: 5000 одновременных соединений и 200 Мбит/с через 2 агента на стенде; Bot API p95 overhead при этом < 2× от базового (M7-T2); RSS сервера и fd в бюджете; без утечек горутин.
- [ ] **M13-T6 · Релиз** (S-pkg): тег минорной версии, release-workflow зелёный, release notes с разделом «MTProto (beta)».

### Validation (по глобальным правилам)

Порядок строго по правилам пользователя; файл сценария — источник правды, перечитывается перед каждым действием.

- [ ] **MV-1** · Оркестратор спрашивает платформы (`AskUserQuestion`, multiSelect): **Backend**, **Web** (Android/iOS/Desktop — ручная проверка официальным клиентом, см. MV-6).
- [ ] **MV-2** · Создать `./swarm-report/tgproxy-mtproto-e2e-scenario.md` (один раз). Каркас:
  - Backend: `/healthz` 200; `/metrics` содержит `tgp_mtproto_*`; `/_agent/status` всех агентов содержит `mtproto/1`; `tgproxy mtproto probe --link …` → 0 (через dial-агента и через reverse-агента — по очереди, drain другого); `openssl s_client -connect host:port -servername <fronting_domain>` показывает настоящий сертификат; ClientHello с неверным секретом → обычный HTTP-ответ прокси; повтор ClientHello (replay) → TLS-сайт, после `threshold` — бан IP стенда-зонда; отзыв секрета → probe падает ≤2 с; DC down симулирован фаерволом на одном агенте → probe проходит через другой, `tgp_mtproto_dc_up` = 0 для пары; Bot API `getMe` работает параллельно; ключ не встречается в `journalctl -u tgproxy-server`.
  - Web (`playwright-cli -s=tgproxy`): вкладка «MTProto» — создать секрет (ссылка показана один раз), «Ссылка + QR» требует TOTP, отзыв; «Агенты» — чип `mtproto/1`; «Обзор» — KPI MTProto; «Ошибки» — фильтр `mtproto`.
- [ ] **MV-3** · Деплой на прод: `make deploy` (с шагом probe при `PROD_MTPROTO_LINK`) → успешный health check. Без него проверки не начинаются.
- [ ] **MV-4** · Unit/integration: `make test-race`, `make fuzz FUZZTIME=30s`.
- [ ] **MV-5** · Web-проверки через `playwright-cli` по правилам сессий (`list` → `open`/поиск в открытых → вопрос пользователю); окно на передний план не выводить.
- [ ] **MV-6** · Backend-проверки по сценарию + ручная проверка пользователем: официальный клиент Telegram (мобильный/десктоп) по QR — чтение каналов, отправка медиа.
- [ ] **MV-7** · После каждого шага — `[x]` в файле сценария; при ошибках — откат в соответствующую веху с описанием.
- [ ] **MV-8** · Отчёт `./swarm-report/tgproxy-mtproto-<YYYY-MM-DD>.md`.

**Срез M13:** MTProto в релизе, проверен на проде, задокументирован.

---

## Зависимости и параллельность

| Задача | Зависит от | Скоуп | Параллельно с |
|---|---|---|---|
| M9-T0 | — | S-mtproto | M9-T1, M9-T2, M9-T3 |
| M9-T1, M9-T2, M9-T3 | — | S-core (разные файлы) | друг с другом, M9-T0 |
| M9-T4 | M9-T1, M9-T2 | S-agent | M9-T3, M9-T0 |
| M9-T5 | M9-T4 | S-agent | M9-T6 (разные файлы) |
| M9-T6 | M9-T1 | S-agent | M9-T4, M9-T5 |
| M9-T7 | M9-T1…T6 | S-wire | — |
| M10-T1 | M9-T0 | S-mtproto | M10-T5, M10-T6 |
| M10-T2 | M10-T1 | S-mtproto | M10-T5 |
| M10-T3 | M9-T0, M9-T3 | S-mtproto | M10-T5 |
| M10-T4 | M9-T6, M10-T5 | S-mtproto | M10-T6 |
| M10-T5 | M9-T5 | S-proxy | M10-T1…T3, M10-T6 |
| M10-T6 | M9-T0 | S-mtproto | M10-T1, M10-T5 |
| M10-T7, M10-T8 | M10-T1…T6 | S-wire | — |
| M11-T1 / M11-T2 | M9-T6 / M9-T4 | S-proxy+S-agent / S-agent | друг с другом, M11-T3…T7 |
| M11-T3 | M10-T2, M10-T3 | S-mtproto | M11-T1, M11-T4…T7 |
| M11-T4 | M10-T3 | S-proxy | M11-T3, M11-T5 |
| M11-T5 | M10-T7 | S-obs (+S-mtproto, S-agent) | M11-T3, M11-T4 |
| M11-T6 | M11-T5 | S-obs | M11-T7 |
| M11-T7 | M9-T3 | S-obs + S-core | M11-T1…T6 |
| M11-T8 | M11-T1…T7 | S-wire | — |
| M12-T1 | M9-T3, M10-T6 | S-web | M11 целиком |
| M12-T2 | M10-T5, M11-T5 | S-web | M12-T1 |
| M12-T3 | M12-T1 | S-wire | M12-T4, M12-T5 |
| M12-T4, M12-T5 | M12-T1, M12-T2 | S-web | друг с другом (разные файлы) |
| M12-T6 | M12-T1…T5 | S-wire | — |
| M13-T1, M13-T3 | M10-T7 | S-pkg | M11, M12 |
| M13-T2 | M12-T3 (probe CLI) | S-pkg | M13-T4 |
| M13-T4, M13-T5 | M12-T6 | все / S-pkg | друг с другом |
| M13-T6 | M13-T1…T5 | S-pkg | — |
| MV-* | M13-T6 | оркестратор | — |

Критический путь: M9-T0 → M10-T1 → M10-T2 → M10-T7 → M10-T8 → M11-T5 → M12-T2 → M12-T4 → M12-T6 → M13-T4 → M13-T6 → MV.
Максимальная параллельность: 3–4 exec-агента — M9: S-core ∥ S-mtproto (спайк) ∥ S-agent; M10: S-mtproto ∥ S-proxy (keyed) ∥ S-mtproto/link-probe (разные пакеты); M11: S-agent+S-proxy (reverse) ∥ S-mtproto (лимиты) ∥ S-obs; M12: S-web ∥ S-web (разные экраны) ∥ S-pkg (M13-T1/T3 заранее). S-web может стартовать M12-T1 сразу после M10-T6, не дожидаясь M11.

## Оценка объёма

| Фаза | Объём | Задач |
|---|---|---|
| M9 Основа | M | 8 |
| M10 Сервер MTProto | L | 8 |
| M11 Reverse, защита, наблюдаемость | L | 8 |
| M12 API/CLI/UI | L | 6 |
| M13 Поставка + Validation | M | 6 + 8 |
| **Итого** | | **44** |

## Риски и меры

| Риск | Мера |
|---|---|
| HOL и лимиты h2 при тысячах стримов (медиа тормозит Bot API) | отдельный пул TCP (dial) и класс соединений ALPN (reverse); `MaxConcurrentStreams` 500, окна ≥4 МБ, динамический пул; нагрузочный smoke M13-T5 с контролем p95 Bot API; запасной вариант — TLS-соединение на сессию с пулом прогретых |
| Нестабильный API mtg, скрытое поведение (panic на `RemoteAddr`, `Shutdown`) | pin v2.2.8, адаптер в `internal/mtproto`, контракт-тесты M9-T0 до любой реализации |
| Рассинхрон таблиц DC (mtg vs агент) | тест эквивалентности в M10-T4; обновление таблицы только релизом |
| Расхождение времени клиент/сервер → массовые отказы рукопожатия | окно `time_skew` 2m, NTP-проверка при старте, метрика `handshake_failures_total{reason="time_skew"}` |
| Двойная проверка replay (mux + mtg) даёт ложные повторы | replay проверяется только в mtg (общий кэш); mux в кэш не пишет — тест в M10-T3 |
| Пассивный DPI по отпечатку ServerHello FakeTLS | dedicated IP как рекомендация, мониторинг fallthrough/connections; критерии перехода на свою реализацию (`docs/mtproto.md` §15) |
| Исчерпание fd/портов на агенте и сервере | `LimitNOFILE`, sysctl в документации, лимиты `max_streams`/`max_conns`, проверка бюджета при старте |
| Рост трафика (медиа) и стоимость каналов агентов | метрика `bytes_total{agent}`, `max_conns` на секрет; квоты полосы — ОВ-M4 |
| Утечка секрета (логи, UI, аудит) | KEK-шифрование, только префикс в выводе, свежий TOTP для ссылки, `redact`, сквозной тест «секрет нигде» |
| Блокировка IP MTProto задевает Bot API (shared) | dedicated `listen` на отдельном IP — рекомендованный прод-режим |
| Регресс Bot API от обёртки листенера | `enabled:false` — листенер не оборачивается; полный набор `internal/app` в M10-T7 |

## Открытые вопросы

См. `docs/mtproto.md` §17 (ОВ-M1…ОВ-M9). Дополнительно для плана:

| # | Вопрос | Дефолт до ответа |
|---|---|---|
| ОВ-P1 | Макет экрана «MTProto» | роль `ui` готовит `docs/design/MTProto.dc.html` до M12-T4 |
| ОВ-P2 | Прод-стенд для MV: shared или dedicated | shared на текущем порту прокси |
| ОВ-P3 | Ссылка для `PROD_MTPROTO_LINK` | отдельный служебный секрет `deploy-probe`, хранится только в `deploy/.env` |
