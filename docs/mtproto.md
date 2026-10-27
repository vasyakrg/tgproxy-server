# tgproxy — MTProto-прокси для клиентов Telegram

Статус: v1 (beta), сверено с реализацией (2026-10-27); исходный дизайн — итог консилиума architect / security / devops / api. Вариант A — на базе `github.com/9seconds/mtg/v2` (v2.2.8, MIT).
Краткая выжимка решений — `docs/architecture.md` §15; план реализации — `docs/plan-mtproto.md`. Расхождение плана и этого документа = ошибка плана. Эксплуатация — `docs/operations.md` (раздел «MTProto»).

## 1. Цели и не-цели

**Цели**
- Пользовательские приложения Telegram (iOS/Android/Desktop/Web-клиенты на tdlib) подключаются к серверу tgproxy как к MTProto-прокси по ссылке `tg://proxy?…` с секретом FakeTLS (`ee…`).
- Трафик клиента уходит в Telegram через агентов (те же агенты, тот же mTLS/HTTP2-канал, режимы `dial` и `reverse`), а не напрямую с сервера.
- Балансировка по агентам по нагрузке (активные стримы) и качеству соединения с конкретным DC (RTT connect, ошибки) — отдельно для каждой пары (агент, DC).
- Активный зонд (ТСПУ, сканеры) на порту прокси видит обычный TLS-сайт с настоящим сертификатом сервера, а не MTProto.
- Изоляция: MTProto выключен по умолчанию, его сбои и нагрузка не роняют и не голодят прокси Bot API.

**Не-цели**
- Middle-proxy / ad-tag (спонсорский канал) — mtg v2 их не поддерживает.
- Простые (`dd`) и «сырые» секреты — только FakeTLS (`ee`).
- Учёт пользователей Telegram, расшифровка или анализ содержимого MTProto (сервер видит только obfuscated2-поток, ключей сессий у него нет).
- HA нескольких серверов, общий anti-replay между инстансами.
- Своя реализация FakeTLS/obfuscated2 — только при выполнении критериев §15.

## 2. Топология

```
 Telegram-клиент                server (контур без Telegram)                       agent (Telegram доступен)          Telegram DC
 ───────────────                ─────────────────────────────                      ─────────────────────────          ───────────
                 TCP :443/:8443  ┌───────────────────────────────────────────┐
  FakeTLS (ee) ─────────────────►│ muxListener (shared с proxy-листенером    │
  ClientHello+HMAC               │ или dedicated host:port)                  │
                                 │   ├─ ban? лимиты? первая TLS-запись       │
                                 │   ├─ SNI+HMAC совпал с секретом i ──────┐ │
                                 │   └─ иначе ──► обычный TLS (tlsin)      │ │
                                 │                 Bot API / «сайт»        │ │
                                 │ mtglib.Proxy[i].ServeConn ◄─────────────┘ │
                                 │   FakeTLS ↔ obfuscated2(клиент)           │
                                 │   obfuscated2(DC) ← делает mtg            │
                                 │   Network.Dial("tcp4","149.154.x.y:443")  │
                                 │     └─ адаптер: addr→DC → keyed P2C       │
                                 │        (agent, dc) → StreamTransport      │
                                 └──────────────┬────────────────────────────┘
                                                │ mTLS 1.3, HTTP/2 стрим
                                                │ POST /_agent/mtproto/dc/{dc}
                                                │ (dial: отдельный пул TCP;
                                                │  reverse: ALPN tgproxy-mtproto/1)
                                                ▼
                                       ┌───────────────────────────┐  TCP :443 (v4|v6)
                                       │ agent: чистый TCP-релей   │──────────────────► DC n
                                       │ IP DC из вшитой таблицы,  │   байты как есть
                                       │ dial-control, лимиты      │
                                       └───────────────────────────┘
```

Шифрование к DC (obfuscated2 «сервер → DC») выполняет mtg на сервере; агент не знает ни секретов, ни ключей, ни протокола — он соединяет h2-стрим с TCP-сокетом к IP из собственной таблицы по номеру DC. Компрометация агента не раскрывает секреты прокси; компрометация сервера не превращает агента в открытый TCP-прокси (адреса — только сети Telegram, порт 443).

mtg зафиксирован на `v2.2.8` и закрыт тонким адаптером в `internal/mtproto` (скоуп **S-mtproto**). Пакет mtg `network` не импортируется — `Network` реализуем сами. Новые транзитивные зависимости: `panjf2000/ants/v2`, `pires/go-proxyproto`, `OneOfOne/xxhash`, `tylertreat/BoomFilters` (лицензии MIT/Apache-2.0 — проверяются в M9-T0).

## 3. Поток соединения пошагово

1. **Accept.** `muxListener.Accept` получает TCP и сразу отдаёт его в отдельную горутину (Accept никогда не блокируется чтением клиента). На каждое соединение — `recover`: паника MTProto-кода закрывает только это соединение.
2. **Бан.** `ban.Banned(ip)` до чтения первого байта → закрыть (без ответа, как дешёвый 403 Bot API). IP — из `RemoteAddr`; `trusted_proxies`/PROXY-protocol снаружи для MTProto не поддерживаются (см. §15 п. 7).
3. **Лимиты до рукопожатия.** Глобальный семафор незавершённых рукопожатий `max_pending_handshakes` и счётчик `max_conns_per_ip` (активные + незавершённые). Превышение → закрыть; запись в «Ошибках» с причиной `mtproto_conn_limit` (в автобан не считается), метрики `handshake_failures_total{reason="conn_limit"}` и `connections_total{secret="unknown",result="conn_limit"}`. Тот же отказ даёт лимит `max_conns` секрета (проверяется после совпадения HMAC).
4. **Первая TLS-запись.** Чтение заголовка записи (5 байт) + тела ≤16 КБ с дедлайном `handshake_timeout`. Не `Handshake` (22) / не ClientHello / превышение размера → **fallthrough** (шаг 7) с уже прочитанными байтами.
5. **Разводка по секрету.** Разбор ClientHello (`internal/mtproto/faketls`): SNI должен быть равен `fronting_domain`; для каждого активного секрета считается HMAC-SHA256(key, ClientHello с обнулённым `random`) и сравнивается через `subtle.ConstantTimeCompare` со всеми 32 байтами `random`, кроме последних 4, XOR которых даёт timestamp; timestamp в окне `±time_skew`. Перебор идёт по **всем** секретам без раннего выхода (время ответа не зависит от номера секрета). CIDR секрета (если задан) проверяется после совпадения HMAC. Нет совпадения (в т.ч. timestamp вне окна `time_skew`, секрет не из CIDR) → fallthrough, метрика `tgp_mtproto_fallthrough_total` (без IP; это не отказ). Расхождение часов поэтому видно только как рост fallthrough, отдельной причины `time_skew` в метриках нет.
6. **MTProto.** Совпал секрет `i` → есть capable-агенты (иначе fallthrough, §9) → лимиты секрета (`max_conns`) → `inst[i].ServeConn(replayConn)`: `replayConn` сначала отдаёт прочитанные байты, затем читает сокет; `RemoteAddr()` гарантированно `*net.TCPAddr` (mtglib/stream_context.go:52 делает type assertion — иначе panic). Далее внутри mtg:
   1. повторная проверка ClientHello (дёшево) → `AntiReplayCache.SeenBefore(sessionID)` — **единственное** место проверки повтора (mtg передаёт **SessionID** ClientHello — 32 байта, а не HMAC-digest; вызывается ровно один раз и только для ClientHello с верными SNI/HMAC/timestamp; общий кэш на все инстансы; muxListener в кэш не пишет, иначе mtg увидел бы свой же SessionID как повтор; подтверждено контракт-тестом M9-T0). Повтор → `EventReplayAttack` → domain fronting (см. п. 7б), запись в «Ошибках» `mtproto_replay` (единственная MTProto-причина, идущая в автобан), `handshake_failures_total{reason="replay"}`, `connections_total{secret="unknown",result="replay"}`;
   2. FakeTLS ServerHello + ChangeCipherSpec, obfuscated2 `ReadHandshake` клиента → номер DC. **Знак DC mtg отбрасывает** (`abs`): media-DC (`-2`) неотличим от `2`, к Telegram всегда уходит положительный номер (агент отрицательный и нулевой DC всё равно отвергает `400`, §5); `0` → DC 2; DC вне таблицы (не `1…5`, `203`) → при `AllowFallbackOnUnknownDC` DC 2, иначе соединение закрывается без единого `Dial`;
   3. для каждого адреса `telegram.GetAddresses(dc)`: `Network.Dial("tcp4", "149.154.167.51:443")` (только `Dial`: `DialContext` mtg для DC не вызывает; номера DC в вызове нет; при `PreferIP=only-ipv4` — только IPv4, адреса DC перебираются в случайном порядке) → наш адаптер (§4.3); ошибка → mtg пробует следующий адрес → естественный повтор на другом агенте;
   4. `SendHandshake(conn, dc)` — obfuscated2 к DC делает mtg; затем двунаправленный relay до закрытия/`IdleTimeout`. Адрес берётся из `essentials.TelegramCoreAddresses` (mtg), поэтому он должен совпадать с вшитой таблицей `internal/tgapi/dc.go` (сверка — тест в `internal/mtproto`).
7. **Fallthrough.** Соединение (с повтором прочитанных байтов) уходит в обычный TLS-обработчик: тот же `http.Server` прокси Bot API с `tlsin` (shared) или, в dedicated-режиме, внутренний `http.Server`, отдающий 404/«заглушку» с тем же сертификатом. Невалидные соединения **никогда** не проксируются наружу (никакого open relay).
   - 7б. **Domain fronting mtg** (replay, ошибки FakeTLS внутри mtg) направлен на внутренний листенер `127.0.0.1:<random>` (`ProxyOpts.DomainFrontingIP=127.0.0.1`, `DomainFrontingPort`, `DomainFrontingProxyProtocol=true` — плоские поля, структуры `DomainFronting` в mtg нет), принимающий только PROXY v2 с loopback и отдающий соединение в тот же TLS-обработчик с исходным IP клиента. Подтверждено: mtg ходит на fronting через `Network.NativeDialer()` (не через `Dial`), PROXY v2-заголовок (src = `RemoteAddr` переданного conn, dst = fronting-адрес) пишется **лениво, перед первым записанным байтом**, затем идут байты клиента без изменений (включая не-TLS мусор); ответ сайта проксируется клиенту. Внутренний листенер не проходит через muxListener (нет цикла) и не слушает внешние интерфейсы.
8. **Завершение.** `EventFinish` приходит **без причины закрытия и без ошибки** — mtg её не сообщает, и наш слой её не восстанавливает. Итог соединения различается только так: достигнут DC (`connections_total{result="ok"}`) или закрыто до DC (`result="closed"`); `replay` и `conn_limit` фиксируются на входе (п. 3, 5). Запись в журнал (`mtproto_sessions`): время начала и конца, IP, id секрета, DC, байты in/out; `close_reason` всегда `closed`, поле агента всегда пустое — события mtg не связывают поток с `Dial`, распределение по агентам видно в метриках `tgp_mtproto_streams{agent,dc}`. Затем освобождаются слоты лимитов и `Release` в балансировщике (на закрытие стрима).

## 4. Компоненты и интерфейсы

### 4.1 Раскладка пакетов

```
internal/mtproto                 Manager: снимок секретов → инстансы mtglib.Proxy (connSet, Run/Reload/Close); Observer: MetricsObserver (метрики) и Journal (mtproto_sessions)
internal/mtproto/faketls         разбор ClientHello, HMAC-разводка по секретам, timestamp-окно (fuzz)
internal/mtproto/mux             muxListener, replayConn, fronting-листенер (PROXY v2, loopback), лимиты рукопожатий
internal/mtproto/upstream        Network (mtglib.Network) поверх StreamTransport + keyed-балансировщика; addr→DC
internal/mtproto/link            сборка tg://proxy и https://t.me/proxy, ee<key><hex(domain)>
internal/mtproto/probe           тест-клиент: FakeTLS → obfuscated2 → req_pq_multi → resPQ; fake-DC для тестов
internal/tgapi/dc.go             таблица DC → IPv4/IPv6 (включая media), сети Telegram для dial-control (S-core)
internal/agent/mtproto.go        POST /_agent/mtproto/dc/{dc}: TCP-релей, лимиты, drain, пробы DC (S-agent)
internal/transport/stream*.go    StreamTransport: DialStream (отдельный пул TCP) и ReverseStream (класс ALPN tgproxy-mtproto/1) (S-agent)
internal/app/mtproto*.go         wiring сервера: проверка fronting_domain по SAN, KEK, Manager+mux, алерты, вкладка и API
internal/agent/mtproto*.go       релей, пул reverse-соединений (PUT /_agent/mtproto/pool), пробы DC, tgp_agent_mtproto_*
internal/server/balancer/keyed.go  P2C по ключу (agent, dc) (S-proxy)
```

### 4.2 Ключевые интерфейсы

```go
// internal/transport — отдельно от AgentTransport (internal/transport/client.go:32).
type StreamTransport interface {
    // OpenMTProto открывает full-duplex h2-стрим к агенту и возвращает его как net.Conn
    // после ответа 200 (агент уже соединился с DC). Ошибка — *PhaseError (dial|tls|timeout|agent).
    OpenMTProto(ctx context.Context, agent AgentRef, dc int) (net.Conn, error)
}

// internal/mtproto/upstream (consumer-side)
type Picker interface { // реализует KeyedPicker поверх balancer.Keyed
    Pick(ctx context.Context, dc int, exclude ...balancer.AgentID) (Lease, error)
}
type Lease interface { // захваченный стрим на (agent, dc)
    Agent() balancer.AgentID
    Report(balancer.Result) // исход открытия: Latency → EWMA, TransportError → breaker
    Release()               // на закрытие стрима, не на ответ
}

// internal/mtproto/mux (consumer-side)
type Router interface{ Route() Route } // снимок разводки Manager; nil — fallthrough
type Hooks struct {
    Banned        func(netip.Addr) bool // бан до чтения первого байта
    OnReject      func(netip.Addr, Reason) // conn_limit | handshake_timeout | bad_record
    OnFallthrough func()
}

// internal/mtproto
type Secrets interface { // реализует store.MTProtoSecretRepo
    ListActive(ctx context.Context, now time.Time) ([]store.MTProtoSecret, int64 /*version*/, error)
    Version(ctx context.Context) (int64, error)
}
type Observer interface { // события mtg → метрики и журнал
    Start(secretID int64, streamID string, ip netip.Addr)
    ConnectedToDC(secretID int64, streamID string, dc int)
    Traffic(secretID int64, streamID string, n uint, fromTelegram bool)
    Finish(secretID int64, streamID string)
}
```

Адаптер `upstream.Network` реализует `mtglib.Network`:
- `Dial(network, address)` → `DialContext(context.Background(), …)`: `address` → DC по обратному отображению `essentials.TelegramCoreAddresses` (таблица публичная, отображение однозначное; неизвестный адрес → `ErrUnknownAddress`, никаких произвольных адресов); `context.WithTimeout(agent_pool.dial_timeout)`; `Picker.Pick(dc)` → `StreamTransport.OpenMTProto` → `essentials.Conn` (`leaseConn`). Агент, на котором открытие стрима к этому DC недавно упало, исключается из следующего `Pick` на 5 с (mtg перебирает адреса DC последовательно — так повтор уходит на другого агента; если других кандидатов нет, берётся любой). Ошибки открытия считаются в `tgp_mtproto_upstream_errors_total{agent,dc,phase}`, `phase` = `dial|timeout|no_agent|unknown_dc|other` (агента нет — метка `agent="none"`).
- Возвращаемый conn: запись → тело запроса (`bodyPipe`), чтение → `resp.Body`; `CloseWrite` закрывает pipe (END_STREAM), `CloseRead` закрывает `resp.Body`; `Close` — оба + отмена стрима; `RemoteAddr` — `*net.TCPAddr` (адрес h2-соединения с агентом); дедлайны — через таймер с отменой ctx стрима. Жизнь стрима не привязана к ctx `Dial`: он ограничивает только установку. `leaseConn` считает байты (`in` — запись к Telegram, `out` — чтение) и активные стримы по (agent, dc) и один раз делает `Release` на `Close`.
- `MakeHTTPClient` / `NativeDialer` — нативные (`net.Dialer`): используются mtg только для domain fronting (у нас — loopback) и AutoUpdate (выключен).

### 4.3 Мульти-секреты

`mtglib.ProxyOpts.Secret` — один секрет на инстанс, поэтому `Manager` держит N инстансов `mtglib.Proxy` (по одному на активный секрет) с общими: `Network` (адаптер), `AntiReplayCache` (`antireplay.NewStableBloomFilter(replay_cache, antireplay.DefaultStableBloomFilterErrorRate)` — `errorRate` передавать явно: `0` mtg не заменяет дефолтом), `IPBlocklist`/`IPAllowlist` (`ipblocklist.NewNoop` — бан и CIDR проверяем сами до mtg), `EventStream` (свой экземпляр-обёртка на каждый инстанс с зашитым secret id: события mtg секрет не несут; поля — `EventStart.RemoteIP` из `RemoteAddr`, `EventConnectedToDC{RemoteIP, DC}` (DC уже после fallback), `EventTraffic{Traffic, IsRead}` (считается на стороне Telegram/fronting, `IsRead`=байты от Telegram клиенту; 64-байтный handshake к DC не входит), `EventDomainFronting`, `EventReplayAttack`; у всех `StreamID` и `Timestamp`), `Logger` (адаптер к slog через `redact`). Параметры: `Concurrency` не применяется в `ServeConn` → лимиты свои (§9); `IdleTimeout = idle_timeout`; `HandshakeTimeout = handshake_timeout`; `TolerateTimeSkewness = time_skew`; `PreferIP = "only-ipv4"` (v4/v6 к DC выбирает агент; обязательно: дефолт mtg `prefer-ipv6` начинает с `tcp6`); `AutoUpdate = false` и пустой `DoppelGangerURLs` (иначе mtg сам ходит в HTTP через `Network.MakeHTTPClient`, который при этом обязан возвращать не-nil клиент); `AllowFallbackOnUnknownDC = true` (неизвестный DC клиента → DC по умолчанию mtg); `DomainFronting` → внутренний loopback-листенер (§3 п. 7б). `DCOverrides`/`UseTestDCs` объявлены в mtg, но не используются — не трогаем.

Снимок секретов перечитывается по версии таблицы (`DefaultPollInterval` = 2 с, как `access_rules`) и по истечении ближайшего `grace_until`: новый секрет → новый инстанс; смена только `cidrs`/`max_conns` → копия инстанса без пересоздания mtg; отзыв/выключение/окончание grace → инстанс убирается из разводки и выводится из работы. Активные соединения Manager рвёт сам (`connSet`): `Serve` регистрирует conn инстанса, при выводе новые conn не принимаются (`enter` → false), зарегистрированные закрываются (`conn.Close` завершает `ServeConn` естественным путём), затем ждём выхода всех `Serve` (`drainTimeout` = 5 с; не дождались — предупреждение в логе) и только после этого вызываем `Shutdown()` (освобождение пула/горутин). `Manager.Close()` делает то же для всех инстансов (останов сервера: до `Shutdown` HTTP-серверов, `mux.Close` ждёт обработчики). `Route()` возвращает `nil` (→ fallthrough), если нет активных секретов или нет capable-агентов (`Available`). Паника в `Serve` перехватывается и закрывает только это соединение. На `Shutdown()` во время рукопожатия не полагаемся: он отменяет ctx потоков, и в mtglib v2.2.8 это гоняется с `ServeConn` (запись `streamContext.clientConn` в `proxy.go` против чтения в `streamContext.Close` из `context.AfterFunc`; найдено под `-race`). Инстанс после `Shutdown` одноразовый: соединение, пришедшее после него, закрывается без `Dial`, повторное использование недопустимо.

## 5. Контракт агента

| | |
|---|---|
| Запрос | `POST /_agent/mtproto/dc/{dc}` по уже существующему mTLS-каналу (dial: отдельный пул; reverse: класс соединений `tgproxy-mtproto/1`), HTTP/2, full-duplex: тело запроса — байты к DC, тело ответа — байты от DC |
| Заголовки | `X-Request-ID` (ULID), `X-TGP-DC` (дублирует путь, со знаком; расхождение → 400) |
| `{dc}` | целое: `1…5`, `203` (CDN-DC, есть в таблице mtg); отрицательные (media) от сервера **не приходят** — mtg отбрасывает знак (§3 п. 6.2); агент отрицательные, `0` и нечисловые значения отвергает `400` (fail-closed); если mtg начнёт передавать знак — отображение добавляется на сервере в `upstream.Network`, а не в агенте |
| Адрес | **только** из вшитой в бинарь таблицы `internal/tgapi/dc.go` (IPv4; при `mtproto.ipv6: true` сначала IPv6, затем IPv4), порт 443; без DNS; сервер адрес не передаёт. Перебор адресов DC — по порядку в рамках `dial_timeout`. Обновление таблицы — только релизом с подписью |
| Dial-control | `dcDialControl` (`internal/agent/mtproto_dial.go`), по образцу `egressDialControl`: запрет loopback/private/link-local/multicast/unspecified + allowlist префиксов Telegram (`tgapi.TelegramPrefixes`); адрес вне сетей Telegram → `403` |
| Успех | `200` + `Flush` сразу после TCP-connect к DC; далее копирование в обе стороны до EOF/ошибки/`idle_timeout`/`max_duration` |
| Ошибки | `404` (`mtproto.enabled: false`), `400` (DC ≤ 0/не число или расхождение с `X-TGP-DC`), `403` (DC не в таблице или адрес вне allowlist), `503` (лимит `max_streams` или `draining`, `X-TGP-Error-Phase: pre-send`), `502` + `X-TGP-Error-Phase: dial|timeout` (DC недоступен; считается в `tgp_agent_dial_errors_total` и `tgp_agent_mtproto_dial_errors_total{dc,kind}`), `X-TGP-Source: agent` |
| Лимиты | `max_streams` (на процесс), `dial_timeout`, `idle_timeout`, `max_duration` (страховка от «вечных» стримов, по умолчанию 24h). По SIGHUP меняются на лету (новые лимиты — для новых стримов), `enabled` — только рестарт |
| Drain | новые стримы → `503`; живые доживают до `TimeoutStopSec` юнита |
| Статус | `/_agent/status` дополняется `capabilities: ["mtproto/1"]` и `mtproto: {streams, dc: {"2": {up, rtt_ms}, …}}`; пробы — TCP-connect к первому адресу каждого DC раз в `dc_probe_interval` с джиттером ±20% (тем же dialer'ом и dial-control, что релей; без отправки данных; одна неудача → `up=false`, одна удача → `up=true`). Период меняется на лету: `PUT /_agent/config` (`dc_probe_interval`, 1s…1h) и SIGHUP |

**Совместимость.** Сервер включает агента в MTProto-пул только по наличию capability `mtproto/1` в статусе (не по версии). Старый агент без capability исключается из пула, Bot API через него работает как раньше. `agent.yaml: mtproto.enabled: false` → capability не публикуется, эндпоинт отвечает `404`. Старый сервер не знает ALPN `tgproxy-mtproto/1`: новый reverse-агент тихо повторяет попытку MTProto-класса раз в 10 минут, Bot API-класс не страдает.

## 6. Транспорт server ↔ agent

Цель — медиа-трафик клиентов не создаёт HOL-блокировку для Bot API.

| | `dial` | `reverse` |
|---|---|---|
| Соединения | `DialStream`: отдельный `http.Transport` на агента (отдельные TCP = отдельный пул, не пересекается с пулом Bot API) | `ReverseStream`: отдельный класс соединений агента с ALPN `tgproxy-mtproto/1` (gateway `NextProtos` предлагает его только при `mtproto.enabled`; агент — `NewMTProtoConnector`), клиентский сертификат обязателен |
| Размер пула | по потребности: при достижении `SETTINGS_MAX_CONCURRENT_STREAMS` агента транспорт открывает новое соединение, а не блокирует вызывающего (строгий лимит не включён); до 4 простаивающих соединений на агента | динамический: стартует с `reverse_conns_min` агента (2); сервер растит пул, когда стримы заполняют соединения (≥ `max_streams_per_conn` на соединение), и сжимает, когда нагрузка ≤ половины ёмкости n−1 соединений и прошло ≥60 с после последнего роста; запрос — `PUT /_agent/mtproto/pool {"conns": N}` по уже открытому MTProto-соединению (дебаунс 5 с на агента), агент ограничивает N в `[reverse_conns_min, reverse_conns_max]` и отвечает `204`; сверх `agent_pool.max_reverse_conns` сервер вытесняет самое старое соединение gracefully (дозавершение стримов ≤30 с) |
| HTTP/2 | начальные окна потока и соединения 4 МиБ, `MaxReadFrameSize` 1 МиБ, PING 15 s (таймаут 5 s) | то же; роли h2 развёрнуты, как в §4.1 архитектуры. Стрим идёт по наименее загруженному соединению (учёт стримов на сервере); соединение, умершее до записи в агента, заменяется следующим |

По MTProto-классу доступны только `POST /_agent/mtproto/dc/{dc}` и `PUT /_agent/mtproto/pool`; Bot API и управление агентом по нему недоступны (`404`).

`internal/transport/both.go` и `registry.go` расширяются реализацией `StreamTransport` (выбор по `AgentRef.Mode`). Разрыв mTLS-соединения рвёт все его стримы → mtg закрывает клиентские соединения, клиент Telegram переподключается сам. Метрика `tgp_agent_reverse_conns{agent}` на сервере относится к классу Bot API; MTProto-соединения агента отдельной метрикой не выставляются.

## 7. Балансировка

Отдельный экземпляр балансировщика `balancer.Keyed` (`internal/server/balancer/keyed.go`: P2C, EWMA, breaker из того же пакета) с ключом **(agent, dc)**. Состав кандидатов синхронизируется с реестром агентов по событиям и раз в 5 с (`Update`); состояние ключей сохраняется, пока агент в реестре:

| Сигнал | Уровень | Источник |
|---|---|---|
| health, draining, weight | агент | реестр агентов (`internal/server/agents`), общий с Bot API |
| capability `mtproto/1` | агент | `/_agent/status` |
| `dc.up` | (agent, dc) | проба агента; `up=false` → агент исключён **только для этого DC** |
| inflight = активные стримы | (agent, dc) | `Lease`: +1 на `Pick`, −1 на `Release` при закрытии conn, а не на ответ |
| EWMA (время до `200` = connect к DC) | (agent, dc) | засевается `rtt_ms` пробы, пока на ключе не было реальных наблюдений; α=0.3, затухание при простое 5 s; обновляется через `Lease.Report` |
| breaker | (agent, dc) | 5 подряд ошибок открытия стрима (`Report{TransportError}`) → open 30 s → half-open; отмена (`Canceled`) не считается ошибкой |

`score = (streams + 1) × EWMA / weight`, P2C. Агент допустим для DC, только если он healthy, не draining, capable, `weight > 0` и для этого DC известна проба с `up=true`; нет записи о DC — агент для него не выбирается. Нет кандидатов → `ErrNoCandidates`. Без sticky: каждое соединение клиента выбирается заново (клиент Telegram держит несколько соединений к разным DC). Ошибка открытия стрима → следующий `Pick` исключает агента (5 с) для следующего адреса DC в той же попытке mtg. Учёт полосы (байт/с на агента) в score — вторым этапом после замеров на проде (ОВ-M3); в v1 только метрика `tgp_mtproto_bytes_total{direction,agent}`.

## 8. Безопасность

**MUST**
- Невалидное соединение (нет SNI=`fronting_domain`, HMAC не совпал, timestamp вне окна) получает настоящий TLS сервера; MTProto-признаков в ответе нет; наружу ничего не проксируется.
- `fronting_domain` совпадает с доменом входного сертификата: проверка по SAN действующего сертификата (wildcard `*.x` покрывает одну метку; для `acme` до первого выпуска — по `tls.domains`). При старте несовпадение — ошибка, MTProto не стартует; при перезагрузке сертификата — предупреждение в логе (клиенты с несовпадающим доменом получат fallthrough). `tls.mode=off` + `listen: shared` → ошибка валидации; MTProto без TLS на входе не поднимается вовсе.
- HMAC сравнивается constant-time, перебор всех секретов без раннего выхода.
- Anti-replay: общий StableBloomFilter (`replay_cache`, по умолчанию 4 MiB) на все инстансы; повтор → domain fronting + `mtproto_replay` (считается в автобан).
- Секреты в БД — только зашифрованными `pki.KEK.Seal` (`aad = "mtproto/<id>"`); без `pki.kek_file` MTProto не включается (ошибка валидации при `mtproto.enabled: true`).
- Секрет в UI/CLI/логах/аудите/метриках — только префикс (первые 2 байта ключа, 4 hex-символа), `redact` распознаёт `ee[0-9a-f]{32,}` и `secret=` в ссылках. Ссылка показывается один раз при создании/ротации; повторно — только по явному запросу: в UI/API после свежего TOTP (≤5 мин, иначе `401 totp_required`), в CLI `tgproxy mtproto secret link` (доступ к БД и KEK на хосте); везде с аудитом `mtproto_secret.reveal`.
- MTProto-секрет и ключ доступа Bot API раздельны: разные таблицы, разные префиксы, взаимной подстановки нет.
- Агент: адрес DC только из вшитой таблицы, порт 443, dial-control; сервер не может заставить агента соединиться с произвольным адресом.
- Содержимое трафика не логируется и не сохраняется никогда. Метки метрик без IP и секретов.
- Свои адреса (`internal/server/ban/protect.go`: `trusted_proxies`, агенты, сети правил, loopback/private) не банятся и по MTProto-причинам.

**SHOULD**
- Рекомендованный прод: dedicated `listen` на отдельном IP (блокировка IP MTProto-прокси не задевает Bot API).
- NTP на сервере (chrony/systemd-timesyncd); при старте сервер пишет в лог предупреждение о необходимости синхронизации времени (окно `time_skew`, по умолчанию 2 мин). Проверки `timedatectl` и отдельной метрики нет.
- Лимит соединений на секрет (`max_conns`) и опц. CIDR секрета для «своих» групп пользователей.
- Ротация секрета с `grace_until` (дефолт 0 — старый перестаёт работать сразу; максимум 720h). Старый секрет переименовывается в `<имя>~<id>`, новый наследует имя, CIDR, `max_conns` и `enabled`.
- Фаззинг парсера ClientHello в `make fuzz` и nightly.

## 9. Изоляция и лимиты

- `mtproto.enabled: false` по умолчанию; `true` без `pki.kek_file` — ошибка валидации. Нет ни одного capable-агента в пуле (up и с capability) или нет активных секретов → `Route()` пуст и muxListener отправляет и валидные соединения в TLS-обработчик (клиент увидит «недоступен», зонд — обычный сайт); виден рост `fallthrough_total` и алерт `mtproto_no_capable_agents`. Значение `result="no_agents"` в `connections_total` зарезервировано и не выставляется; отсутствие агента для конкретного DC видно в `upstream_errors_total{phase="no_agent"}`.
- Паника/ошибка MTProto не роняет листенер: `recover` на соединение, Accept-цикл отдельно.
- Лимиты сервера: `max_conns` (20000, глобально), `max_conns_per_ip` (64), `max_pending_handshakes` (по умолчанию 1024), `max_conns` секрета. Резерв под Bot API: `max_conns × 2 + 16384` не должно превышать `RLIMIT_NOFILE` процесса (проверка при старте и по SIGHUP, предупреждение в логе; на не-unix платформах не проверяется).
- Лимиты агента: `max_streams` (по умолчанию 10000), отдельно от `/tg/*`.

## 10. Конфигурация

`server.yaml` (значения — дефолты `config.DefaultServer`):

```yaml
mtproto:
  enabled: false
  listen: shared               # shared | host:port (dedicated)
  public_host: ""              # хост в ссылке; пусто — хост server.public_base_url
  public_port: 0               # 0 — порт листенера (shared — listen.proxy, dedicated — mtproto.listen)
  fronting_domain: ""          # обязателен при enabled; = домен входного сертификата
  max_conns: 20000
  max_conns_per_ip: 64
  max_pending_handshakes: 1024
  handshake_timeout: 5s
  idle_timeout: 5m
  time_skew: 2m                # 30s..10m
  replay_cache: 4MiB           # 1MiB..256MiB; суффиксы B|KiB|MiB|GiB|KB|MB|GB
  dc_probe_interval: 30s       # валидируется; на агентов сервером пока не рассылается (период агента — agent.yaml / PUT /_agent/config)
  agent_pool:
    reverse_conns: 2           # валидируется; рантаймом не используется (стартовый размер пула задаёт агент: reverse_conns_min)
    max_reverse_conns: 16      # потолок MTProto-соединений агента на сервере; >= reverse_conns; согласуйте с agent reverse_conns_max
    max_streams_per_conn: 500  # порог загрузки соединения для роста пула reverse
    dial_timeout: 5s           # установка стрима к DC через агента
```

`agent.yaml` (дефолты `config.DefaultAgent`):

```yaml
mtproto:
  enabled: true                # сервер всё равно требует capability
  max_streams: 10000
  dial_timeout: 5s
  idle_timeout: 5m             # не больше max_duration
  max_duration: 24h
  ipv6: false
  dc_probe_interval: 30s       # 1s..1h; сервер может менять через PUT /_agent/config
  reverse_conns_min: 2         # границы пула MTProto-соединений reverse/both (>= 1)
  reverse_conns_max: 16        # >= reverse_conns_min
```

Правила: `enabled`/`listen`/`fronting_domain` — только рестарт (при SIGHUP предупреждение «require restart, not applied»). По SIGHUP сервер применяет лимиты входа mux: `max_conns`, `max_conns_per_ip`, `max_pending_handshakes`, `handshake_timeout` (живые соединения не рвутся) и перепроверяет fd-бюджет; `public_host`/`public_port` подхватываются при следующей выдаче ссылки. Остальное (`idle_timeout`, `time_skew`, `replay_cache`, `agent_pool.*`) читается при старте — нужен рестарт. Агент по SIGHUP применяет `max_streams`, `dial/idle/max_duration`, `ipv6`, `dc_probe_interval`. Таблицу DC через YAML не подменить; для тестов — неэкспортируемый оверрайд, как `OverrideTelegramAPIURL` (`internal/config/defaults.go:123`). Валидация — `internal/config/validate.go` (`ValidateServer`, `ValidateAgent`): `fronting_domain` — FQDN из ≥2 меток без порта, wildcard и IP; `listen=shared` требует `tls.mode ≠ off`; dedicated `listen` не совпадает (один порт и совпадающий или wildcard-хост) с `listen.proxy/admin/metrics/agent_gateway`; `time_skew` ∈ [30s, 10m]; `replay_cache` ∈ [1MiB, 256MiB]; `enabled: true` требует `fronting_domain` и `pki.kek_file`; `max_reverse_conns >= reverse_conns`; агент: `reverse_conns_max >= reverse_conns_min >= 1`, `idle_timeout <= max_duration`. Env-переменных/YAML для подмены таблицы DC нет.

## 11. Хранилище

Миграция `0009_mtproto.sql` (последняя сейчас — `0008_bans.sql`):

```
mtproto_secrets (
  id INTEGER PK, name TEXT UNIQUE NOT NULL,
  secret_enc BLOB NOT NULL,          -- KEK.Seal(key[16]), aad "mtproto/<id>"
  prefix TEXT NOT NULL,              -- первые 2 байта ключа в hex (4 символа), для UI/логов
  cidrs TEXT NULL,                   -- JSON, опционально
  max_conns INTEGER NOT NULL DEFAULT 0,  -- 0 — без лимита секрета
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at, revoked_at NULL, grace_until NULL,
  rotated_from INTEGER NULL REFERENCES mtproto_secrets(id))
-- триггеры инкрементируют versions('mtproto_secrets'), как для access_rules (0001_init.sql:95)

mtproto_sessions (                   -- журнал соединений, retention как error_events
  id INTEGER PK, started_at, ended_at, client_ip TEXT, secret_id INTEGER,
  dc INTEGER, agent_id TEXT, bytes_in INTEGER, bytes_out INTEGER, close_reason TEXT)
```

Миграция `0010_samples_mtproto.sql`: столбцы `mtproto_conns`, `mtproto_bytes_in`, `mtproto_bytes_out` в `samples_10s`/`samples_5m`. Журнал пишется батчами раз в 10 с (горячий путь в БД не пишет; очередь до 100 000 записей, при переполнении или сбое записи сессии теряются — счётчик `Dropped`), очистка раз в 5 мин, хранение 30 суток (как `error_events`). `agent_id` и `close_reason` в записи не информативны: первый пуст, второй всегда `closed` (§3 п. 8). Redis не затрагивается. Ссылки хранятся не как строка, а собираются из ключа на лету.

## 12. API, CLI, UI

**API** (`RequireAuth` + `Protect`, как `internal/server/web/api/access_http.go`; `internal/server/web/api/mtproto*.go`). Работает и при `mtproto.enabled: false` (подготовка секретов) — ответы помечаются `"disabled": true`:

| Метод | Путь | Поведение |
|---|---|---|
| GET | `/api/v1/mtproto/secrets` | `{items, disabled}`; элемент: id, name, prefix, cidrs, max_conns, enabled, `status` (`active\|grace\|disabled\|revoked`), created_at, revoked_at, grace_until, rotated_from, active_conns |
| POST | `/api/v1/mtproto/secrets` | `{name, cidrs?, max_conns?}` → ключ генерирует сервер (`crypto/rand`, 16 байт); `201` + запись + `link {tg, https, qr_svg}` **один раз**; нет `public_host`/`fronting_domain` → секрет создан, вместо ссылки `link_error: endpoint_not_configured` |
| PATCH | `/api/v1/mtproto/secrets/{id}` | name, cidrs, max_conns, enabled (частичное обновление) |
| DELETE | `/api/v1/mtproto/secrets/{id}?confirm=yes` | отзыв: `revoked_at`, разрыв активных соединений (≤2 с); `204`; без `confirm=yes` — `400 confirm_required` |
| POST | `/api/v1/mtproto/secrets/{id}/rotate` | `{grace?}` ("1h", 0…720h) → новый секрет (ссылка один раз), старый с `grace_until` |
| GET | `/api/v1/mtproto/secrets/{id}/link` | только при свежем TOTP (≤5 мин, иначе `401 totp_required`); `{tg, https, qr_svg, disabled}`; аудит `mtproto_secret.reveal`; отозванный секрет — `404` |
| GET | `/api/v1/mtproto/stats` | `{enabled, agents[{agent_id, capable, streams, dc[{dc, up, rtt_ms, streams, errors}]}], totals{active_conns, bytes_in, bytes_out, secrets_active}}`; при выключенном MTProto — пустая матрица и нули |

Ошибки: `422 validation` (поля), `404 not_found`, `409 endpoint_not_configured`. Имя секрета — до 64 символов (буквы, цифры, пробел, `.`, `_`, `-`), `max_conns` 0…1 000 000 (0 — без лимита). Аудит: `mtproto_secret.create|update|revoke|rotate|reveal` (ключ в аудит не попадает). Ссылка: `tg://proxy?server=<public_host>&port=<port>&secret=ee<hex key><hex fronting_domain>` и `https://t.me/proxy?…` (те же параметры).

**CLI** (`cmd/tgproxy/mtproto.go`, работает с БД напрямую, как `ban`/`access`; нужен `pki.kek_file`; действия пишутся в аудит): `tgproxy mtproto secret add --name <имя> [--cidr …] [--max-conns N] -c server.yaml`, `list`, `delete <id|name> [--yes]`, `rotate <id|name> [--grace 1h]`, `link <id|name>` (печатает ссылку; TOTP не требуется — доступ к хосту, БД и KEK уже даёт больше) — всё с `-c`; `tgproxy mtproto probe --link <tg://…>|--link-stdin [--dc 2] [--timeout 10s] [--handshake-only]` (тест-клиент §14, код возврата 0/1; `--link-stdin` — чтобы ссылка не попадала в `ps`; `--handshake-only` — только FakeTLS без обмена с DC).

**UI** (`internal/server/web/screens`): вкладка «MTProto» — таблица секретов (префикс, статус, соединения, действия), модалка «Ссылка + QR» (запрос TOTP, если не свежий), создание, ротация и отзыв с подтверждением, матрица агент × DC (streams / RTT / up). «Агенты» — чип «MTProto» у capable-агентов. «Обзор» — ряды MTProto (соединения, полоса) при включённом MTProto. Графики — ряды `mtproto_conns`, `mtproto_bps` в `stats/timeseries`. «Ошибки» — фаза `mtproto` и причины `mtproto_replay`, `mtproto_conn_limit` (`mtproto_bad_secret` в списке причин есть, но резерв — сервер её не выставляет).

## 13. Метрики и алерты

Server (`internal/metrics/server_mtproto.go`):

| Метрика | Метки |
|---|---|
| `tgp_mtproto_client_conns` (gauge) | `listener` (shared\|dedicated) |
| `tgp_mtproto_connections_total` | `secret` (имя; `unknown` — до выбора секрета), `result` (выставляются: `ok` — достигнут DC, `closed` — закрыто до DC, `replay`, `conn_limit`; `no_agents`, `upstream_error` разрешены, но не выставляются) |
| `tgp_mtproto_handshake_failures_total` | `reason` (выставляются: `timeout`, `bad_record`, `replay`, `conn_limit`; `time_skew` разрешён, но не выставляется) |
| `tgp_mtproto_fallthrough_total` | — |
| `tgp_mtproto_bytes_total` | `direction` (`in` — клиент → Telegram, `out` — Telegram → клиент), `agent` |
| `tgp_mtproto_streams` (gauge) | `agent`, `dc` |
| `tgp_mtproto_dc_rtt_seconds` (gauge) | `agent`, `dc` |
| `tgp_mtproto_dc_up` (gauge) | `agent`, `dc` |
| `tgp_mtproto_upstream_errors_total` | `agent` (`none` — агент не выбран), `dc`, `phase` (`dial\|timeout\|no_agent\|unknown_dc\|other`) |
| `tgp_mtproto_session_duration_seconds` (histogram) | — |

`dc_up`/`dc_rtt_seconds` зеркалят пробы DC из статуса capable-агентов (при `up=false` RTT = 0); серии агента удаляются с агентом.

Agent: `tgp_agent_mtproto_streams{dc}`, `tgp_agent_mtproto_dial_errors_total{dc,kind}` (`kind` = `dns\|refused\|timeout\|tls\|other`), `tgp_agent_mtproto_bytes_total{direction}` (`in` — клиент → DC, `out` — DC → клиент); дополнительно общие `tgp_agent_dial_errors_total{kind}`.

Кардинальность: `secret` = число секретов (≤ сотен, см. §15), `dc` ≤ 10, `agent` = число агентов. IP и ключи в метки не попадают.

Алерты (`internal/server/notify/mtproto.go`; проверка раз в 5 с): `mtproto_dc_unreachable` (ключ по DC: DC down на всех capable-агентах > 1 мин, resolved — когда DC поднялся хотя бы на одном), `mtproto_no_capable_agents` (MTProto включён, capable-агентов 0), `mtproto_overload` (активных соединений > 90% `max_conns` непрерывно 5 мин). Дедуп/лимиты — общие.

## 14. Тестирование

- **Unit (TDD, покрытие ≥85%)**: `faketls` (таблица валидных/невалидных ClientHello, окно времени, несколько секретов, constant-time перебор), `mux` (бан до чтения, лимиты, fallthrough байт-в-байт, recover, `RemoteAddr` = `*net.TCPAddr`), `upstream` (addr→DC, неизвестный адрес → ошибка, повтор на другом агенте, CloseWrite/CloseRead), `keyed` (P2C по (agent, dc), DC down исключает только DC, засев EWMA), `link` (формат ссылки), агент (лимиты, drain, dial-control, 403/503/502).
- **Контракт-тесты mtg** (M9-T0): поведение, на которое опирается дизайн; при обновлении mtg падают первыми.
- **Probe-клиент** `internal/mtproto/probe`: FakeTLS ClientHello с HMAC → чтение ServerHello → obfuscated2 → `req_pq_multi` → ожидание `resPQ` (без авторизации). Он же — `tgproxy mtproto probe` (режим `--handshake-only` проверяет только FakeTLS) и fake-DC (отвечает `resPQ`) для integration.
- **Integration in-process**: server + agent (dial и reverse) + fake-DC; сценарии: успешный resPQ; отзыв секрета рвёт соединение; replay → TLS-сайт + бан-счётчик; невалидный HMAC → TLS-сайт с настоящим сертификатом; агент без capability не используется; DC down на одном агенте → трафик на другом.
- **Fuzz**: `faketls.ParseClientHello`, `mux` первая запись (`make fuzz`, nightly).
- **«Секрет нигде»**: по образцу `internal/app/tokenleak_e2e_test.go` — ключ секрета не встречается в логах, метриках, ответах API (кроме link), аудите, дампе БД (только `secret_enc`).
- **smoke.sh**: `tgproxy mtproto probe` против поднятого в контейнере сервера+агента с fake-DC.
- **Ручной e2e**: клиент на tdlib (`addProxy` `proxyTypeMtproto`, секрет `ee…`) или официальное приложение по ссылке; Telethon `ee` не поддерживает.
- **Информативный**: сравнение JA3S ServerHello FakeTLS vs `crypto/tls` (ожидаемо различаются, см. §16) — не валит CI.

## 15. Известные ограничения и критерии перехода на свою реализацию

Ограничения:
1. ServerHello FakeTLS у mtg фиксированного вида и по отпечатку не совпадает с нашим `crypto/tls`. Активный зонд его не увидит (невалидный HMAC получает настоящий TLS), пассивный DPI отличить может.
2. Нет ad-tag / middle-proxy.
3. API mtg v2 нестабилен → pin `v2.2.8` + адаптер + контракт-тесты; обновление mtg — отдельной задачей.
4. Один инстанс `mtglib.Proxy` на секрет: память/горутины растут линейно с числом секретов.
5. Doppelganger mtg (имитация таймингов/размеров TLS-записей) включён всегда и не отключается: на инстанс — фоновая горутина, на соединение — горутина-писатель, перегруппирующая и задерживающая трафик **Telegram → клиент** на случайную задержку (Weibull, порядка миллисекунд). Влияет на латентность и число горутин; задержка и ёмкость замеряются в M10-T8.
6. Событие `EventFinish` не несёт причины закрытия (§3 п. 8), события — секрета и агента: в журнале `close_reason` всегда `closed`, `agent_id` пуст.
7. Клиентский IP только из `RemoteAddr` — за L4-балансировщиком без PROXY protocol бан и лимиты по IP бессмысленны.
8. Anti-replay только в памяти одного процесса; после рестарта окно повторов открыто на `time_skew`.
9. `mtglib.Proxy.Shutdown()` гоняется с рукопожатием в `ServeConn` (mtg v2.2.8, поле `streamContext.clientConn`), поэтому Manager сначала сам закрывает conn инстанса и ждёт выхода `Serve` (§4.3); `Shutdown()` вызывается, когда активных потоков нет.

Переход на свою реализацию FakeTLS + obfuscated2 (~1000 строк; логика mtg под MIT с атрибуцией в `NOTICE`) — при любом из условий:
- отпечаток ServerHello становится подтверждённой причиной блокировок;
- ломающие изменения mtg, требующие переписывания адаптера, или прекращение поддержки;
- число секретов > 500 (стоимость N инстансов);
- нужен ad-tag/middle-proxy.

## 16. Эксплуатация

Подробная инструкция — `docs/operations.md`, раздел «MTProto». Кратко:

- **systemd**: `LimitNOFILE=1048576` (server), `262144` (agent) — `packaging/systemd/tgproxy-{server,agent}.service`. Сервер предупреждает в логе, если `max_conns×2 + 16384` больше `RLIMIT_NOFILE`.
- **sysctl** (только документация, пакет не меняет): агент — `net.ipv4.ip_local_port_range = 10000 65000`, `net.ipv4.tcp_tw_reuse = 1`; сервер — `net.core.somaxconn = 4096`, `net.ipv4.tcp_keepalive_time = 60`.
- **Фаервол**: сервер — входящий порт MTProto (shared — тот же, что прокси; dedicated — `mtproto.listen`); агент — исходящий TCP 443 к сетям Telegram (список — `tgapi.TelegramPrefixes` в `internal/tgapi/dc.go`, продублирован в `operations.md`).
- **NTP** на сервере обязателен (окно `time_skew`).
- **deploy**: опциональный шаг `scripts/deploy.sh` — если в `deploy/.env` задан `PROD_MTPROTO_LINK`, после health check выполняется `tgproxy mtproto probe` по этой ссылке (ненулевой код — провал деплоя). Значение — секрет, в вывод не печатается.

## 17. Открытые вопросы (с дефолтами)

| # | Вопрос | Статус / дефолт |
|---|---|---|
| ОВ-M1 | Порт: shared или dedicated на проде | Решено в коде: поддерживаются оба режима, по умолчанию `shared`; dedicated IP — рекомендация для прода после первых признаков блокировки (`operations.md`) |
| ОВ-M2 | `fronting_domain` = основной домен прокси или отдельный поддомен с тем же сертификатом | Закрыт: любой домен из SAN входного сертификата (wildcard покрывает одну метку); проверяется при старте |
| ОВ-M3 | Учитывать ли полосу (байт/с) в score балансировщика | Открыт: нет в v1; решение после 2 недель метрик `bytes_total{agent}` |
| ОВ-M4 | Квоты полосы/трафика на секрет | Открыт: нет в v1, только `max_conns` |
| ОВ-M5 | Обработка отрицательных (media) DC и `AllowFallbackOnUnknownDC` в mtg v2.2.8 | Закрыт контракт-тестом M9-T0: знак DC отбрасывается (`-2`→`2`), неизвестный DC → DC 2 при `AllowFallbackOnUnknownDC: true`, иначе закрытие без `Dial`; `true` зафиксирован в `Manager`; агент отрицательный DC отвергает `400` |
| ОВ-M6 | Retention журнала соединений | Закрыт: 30 суток, как `error_events` |
| ОВ-M7 | IPv6 от агента к DC | Закрыт: выключен по умолчанию (`ipv6: false`), включается на агенте |
| ОВ-M8 | Поддержка PROXY protocol на внешнем MTProto-листенере (за L4-балансировщиком) | Закрыт: нет (клиентский IP только из `RemoteAddr`, §15 п. 7) |
| ОВ-M9 | Срок «свежести» TOTP для показа ссылки | Закрыт: 5 минут (`auth.FreshTOTPWindow`) |
