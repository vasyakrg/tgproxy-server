# tgproxy — MTProto-прокси для клиентов Telegram

Статус: черновик v1 (2026-10-27), итог консилиума architect / security / devops / api. Вариант A — на базе `github.com/9seconds/mtg/v2` (v2.2.8, MIT).
Краткая выжимка решений — `docs/architecture.md` §15; план реализации — `docs/plan-mtproto.md`. Расхождение плана и этого документа = ошибка плана.

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
3. **Лимиты до рукопожатия.** Глобальный семафор незавершённых рукопожатий `max_pending_handshakes` и счётчик `max_conns_per_ip` (активные + незавершённые). Превышение → закрыть, причина `mtproto_conn_limit`.
4. **Первая TLS-запись.** Чтение заголовка записи (5 байт) + тела ≤16 КБ с дедлайном `handshake_timeout`. Не `Handshake` (22) / не ClientHello / превышение размера → **fallthrough** (шаг 7) с уже прочитанными байтами.
5. **Разводка по секрету.** Разбор ClientHello (`internal/mtproto/faketls`): SNI должен быть равен `fronting_domain`; для каждого активного секрета считается HMAC-SHA256(key, ClientHello с обнулённым `random`) и сравнивается через `subtle.ConstantTimeCompare` со всеми 32 байтами `random`, кроме последних 4, XOR которых даёт timestamp; timestamp в окне `±time_skew`. Перебор идёт по **всем** секретам без раннего выхода (время ответа не зависит от номера секрета). CIDR секрета (если задан) проверяется после совпадения HMAC. Нет совпадения → fallthrough, метрика `tgp_mtproto_fallthrough_total` (без IP; это не отказ).
6. **MTProto.** Совпал секрет `i` → есть capable-агенты (иначе fallthrough, §9) → лимиты секрета (`max_conns`) → `inst[i].ServeConn(replayConn)`: `replayConn` сначала отдаёт прочитанные байты, затем читает сокет; `RemoteAddr()` гарантированно `*net.TCPAddr` (mtglib/stream_context.go:52 делает type assertion — иначе panic). Далее внутри mtg:
   1. повторная проверка ClientHello (дёшево) → `AntiReplayCache.SeenBefore(sessionID)` — **единственное** место проверки повтора (mtg передаёт **SessionID** ClientHello — 32 байта, а не HMAC-digest; вызывается ровно один раз и только для ClientHello с верными SNI/HMAC/timestamp; общий кэш на все инстансы; muxListener в кэш не пишет, иначе mtg увидел бы свой же SessionID как повтор; подтверждено контракт-тестом M9-T0). Повтор → `EventReplayAttack` → domain fronting (см. п. 7б) и причина `mtproto_replay`;
   2. FakeTLS ServerHello + ChangeCipherSpec, obfuscated2 `ReadHandshake` клиента → номер DC. **Знак DC mtg отбрасывает** (`abs`): media-DC (`-2`) неотличим от `2`, к Telegram всегда уходит положительный номер; `0` → DC 2; DC вне таблицы (не `1…5`, `203`) → при `AllowFallbackOnUnknownDC` DC 2, иначе соединение закрывается без единого `Dial`;
   3. для каждого адреса `telegram.GetAddresses(dc)`: `Network.Dial("tcp4", "149.154.167.51:443")` (только `Dial`: `DialContext` mtg для DC не вызывает; номера DC в вызове нет; при `PreferIP=only-ipv4` — только IPv4, адреса DC перебираются в случайном порядке) → наш адаптер (§4.3); ошибка → mtg пробует следующий адрес → естественный повтор на другом агенте;
   4. `SendHandshake(conn, dc)` — obfuscated2 к DC делает mtg; затем двунаправленный relay до закрытия/`IdleTimeout`.
7. **Fallthrough.** Соединение (с повтором прочитанных байтов) уходит в обычный TLS-обработчик: тот же `http.Server` прокси Bot API с `tlsin` (shared) или, в dedicated-режиме, внутренний `http.Server`, отдающий 404/«заглушку» с тем же сертификатом. Невалидные соединения **никогда** не проксируются наружу (никакого open relay).
   - 7б. **Domain fronting mtg** (replay, ошибки FakeTLS внутри mtg) направлен на внутренний листенер `127.0.0.1:<random>` (`ProxyOpts.DomainFrontingIP=127.0.0.1`, `DomainFrontingPort`, `DomainFrontingProxyProtocol=true` — плоские поля, структуры `DomainFronting` в mtg нет), принимающий только PROXY v2 с loopback и отдающий соединение в тот же TLS-обработчик с исходным IP клиента. Подтверждено: mtg ходит на fronting через `Network.NativeDialer()` (не через `Dial`), PROXY v2-заголовок (src = `RemoteAddr` переданного conn, dst = fronting-адрес) пишется **лениво, перед первым записанным байтом**, затем идут байты клиента без изменений (включая не-TLS мусор); ответ сайта проксируется клиенту. Внутренний листенер не проходит через muxListener (нет цикла) и не слушает внешние интерфейсы.
8. **Завершение.** `EventFinish` (**без причины закрытия и без ошибки** — mtg её не сообщает; причину и итог — `mtproto_conn_limit`/`replay`/`dc_error`/`idle`/`revoked` — определяет наш слой по состоянию обёрнутых conn и ctx) → запись в журнал соединений (время, IP, secret id/имя, DC, байты in/out, длительность; агент в журнал не попадает — события mtg не связывают поток с `Dial`, распределение по агентам видно в метриках `tgp_mtproto_streams{agent,dc}`), метрики, освобождение слотов лимитов и `release` балансировщика.

## 4. Компоненты и интерфейсы

### 4.1 Раскладка пакетов

```
internal/mtproto                 Manager: снимок секретов → инстансы mtglib.Proxy; Start/Reload/Close; EventStream → Observer
internal/mtproto/faketls         разбор ClientHello, HMAC-разводка по секретам, timestamp-окно (fuzz)
internal/mtproto/mux             muxListener, replayConn, fronting-листенер (PROXY v2, loopback), лимиты рукопожатий
internal/mtproto/upstream        Network (mtglib.Network) поверх StreamTransport + keyed-балансировщика; addr→DC
internal/mtproto/link            сборка tg://proxy и https://t.me/proxy, ee<key><hex(domain)>
internal/mtproto/probe           тест-клиент: FakeTLS → obfuscated2 → req_pq_multi → resPQ; fake-DC для тестов
internal/tgapi/dc.go             таблица DC → IPv4/IPv6 (включая media), сети Telegram для dial-control (S-core)
internal/agent/mtproto.go        POST /_agent/mtproto/dc/{dc}: TCP-релей, лимиты, drain, пробы DC (S-agent)
internal/transport/stream*.go    StreamTransport: dial-пул и reverse-класс соединений (S-agent)
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

// internal/mtproto (consumer-side)
type Balancer interface {
    Pick(ctx context.Context, dc int, exclude []string) (agentID string, release func(Result), err error)
}
type Bans interface {
    Banned(netip.Addr) bool
    Record(netip.Addr, access.Reason)
}
type Secrets interface { // реализует store
    ListActive(ctx context.Context) ([]store.MTProtoSecret, uint64 /*version*/, error)
}
type Observer interface { // журнал соединений + метрики
    ConnFinished(ConnRecord)
    HandshakeFailed(reason string)
}
```

Адаптер `upstream.Network` реализует `mtglib.Network`:
- `Dial(network, address)` / `DialContext(ctx, …)`: `address` → DC по обратному отображению `essentials.TelegramCoreAddresses` (таблица публичная, отображение однозначное; неизвестный адрес → ошибка, никаких произвольных адресов); `ctx` у `Dial` нет → свой `context.WithTimeout(dial_timeout)`; `Balancer.Pick(dc)` → `StreamTransport.OpenMTProto` → `essentials.Conn`.
- Возвращаемый conn: запись → тело запроса (`io.Pipe`), чтение → `resp.Body`; `CloseWrite` закрывает pipe (END_STREAM), `CloseRead` закрывает `resp.Body`; `Close` — оба + отмена стрима; `RemoteAddr` — `*net.TCPAddr` DC; дедлайны — через таймер с отменой ctx стрима.
- `MakeHTTPClient` / `NativeDialer` — нативные (`net.Dialer`): используются mtg только для domain fronting (у нас — loopback) и AutoUpdate (выключен).

### 4.3 Мульти-секреты

`mtglib.ProxyOpts.Secret` — один секрет на инстанс, поэтому `Manager` держит N инстансов `mtglib.Proxy` (по одному на активный секрет) с общими: `Network` (адаптер), `AntiReplayCache` (`antireplay.NewStableBloomFilter(replay_cache, antireplay.DefaultStableBloomFilterErrorRate)` — `errorRate` передавать явно: `0` mtg не заменяет дефолтом), `IPBlocklist`/`IPAllowlist` (`ipblocklist.NewNoop` — бан и CIDR проверяем сами до mtg), `EventStream` (свой экземпляр-обёртка на каждый инстанс с зашитым secret id: события mtg секрет не несут; поля — `EventStart.RemoteIP` из `RemoteAddr`, `EventConnectedToDC{RemoteIP, DC}` (DC уже после fallback), `EventTraffic{Traffic, IsRead}` (считается на стороне Telegram/fronting, `IsRead`=байты от Telegram клиенту; 64-байтный handshake к DC не входит), `EventDomainFronting`, `EventReplayAttack`; у всех `StreamID` и `Timestamp`), `Logger` (адаптер к slog через `redact`). Параметры: `Concurrency` не применяется в `ServeConn` → лимиты свои (§9); `IdleTimeout = idle_timeout`; `HandshakeTimeout = handshake_timeout`; `TolerateTimeSkewness = time_skew`; `PreferIP = "only-ipv4"` (v4/v6 к DC выбирает агент; обязательно: дефолт mtg `prefer-ipv6` начинает с `tcp6`); `AutoUpdate = false` и пустой `DoppelGangerURLs` (иначе mtg сам ходит в HTTP через `Network.MakeHTTPClient`, который при этом обязан возвращать не-nil клиент); `AllowFallbackOnUnknownDC = true` (неизвестный DC клиента → DC по умолчанию mtg); `DomainFronting` → внутренний loopback-листенер (§3 п. 7б). `DCOverrides`/`UseTestDCs` объявлены в mtg, но не используются — не трогаем.

Снимок секретов перечитывается по версии таблицы (как `access_rules`, ≤2 с): новый секрет → новый инстанс; отзыв/выключение → инстанс убирается из разводки и `Shutdown()`; активные соединения рвутся самим `Shutdown()`: он отменяет ctx инстанса, закрывает клиентский и DC-conn активных relay и возвращается после выхода всех `ServeConn` (подтверждено контракт-тестом M9-T0 — свой реестр conn **не нужен**). Инстанс после `Shutdown` одноразовый: соединение, пришедшее после него, закрывается без `Dial`, повторное использование недопустимо.

## 5. Контракт агента

| | |
|---|---|
| Запрос | `POST /_agent/mtproto/dc/{dc}` по уже существующему mTLS-каналу (dial: отдельный пул; reverse: класс соединений `tgproxy-mtproto/1`), HTTP/2, full-duplex: тело запроса — байты к DC, тело ответа — байты от DC |
| Заголовки | `X-Request-ID` (ULID), `X-TGP-DC` (дублирует путь, со знаком; расхождение → 400) |
| `{dc}` | целое: `1…5`, `203` (CDN-DC, есть в таблице mtg); отрицательные (media) от сервера **не приходят** — mtg отбрасывает знак (§3 п. 6.2); агент отрицательные и `0` отвергает `400` (fail-closed); если mtg начнёт передавать знак — отображение добавляется на сервере в `upstream.Network`, а не в агенте |
| Адрес | **только** из вшитой в бинарь таблицы `internal/tgapi/dc.go` (IPv4; IPv6 при `mtproto.ipv6: true` и доступности), порт 443; без DNS; сервер адрес не передаёт. Обновление таблицы — только релизом с подписью |
| Dial-control | по образцу `egressDialControl` (`internal/agent/egress.go:73`) + allowlist префиксов Telegram (`internal/tgapi`): запрет loopback/private/link-local/multicast/unspecified |
| Успех | `200` + `Flush` сразу после TCP-connect к DC; далее копирование в обе стороны до EOF/ошибки/`idle_timeout`/`max_duration` |
| Ошибки | `400` (некорректный DC/заголовок), `403` (DC не в таблице/allowlist), `503` (лимит `max_streams` или `draining`, `X-TGP-Error-Phase: pre-send`), `502` + `X-TGP-Error-Phase: dial|timeout` (DC недоступен), `X-TGP-Source: agent` |
| Лимиты | `max_streams` (на процесс), `dial_timeout`, `idle_timeout`, `max_duration` (страховка от «вечных» стримов, по умолчанию 24h) |
| Drain | новые стримы → `503`; живые доживают до `TimeoutStopSec` юнита |
| Статус | `/_agent/status` дополняется `capabilities: ["mtproto/1"]` и `mtproto: {streams, dc: {"2": {up, rtt_ms}, …}}`; пробы — TCP-connect к каждому DC раз в `dc_probe_interval` (по одному адресу на DC, без отправки данных) |

**Совместимость.** Сервер включает агента в MTProto-пул только по наличию capability `mtproto/1` в статусе (не по версии). Старый агент без capability исключается из пула, Bot API через него работает как раньше. `agent.yaml: mtproto.enabled: false` → capability не публикуется, эндпоинт отвечает `404`.

## 6. Транспорт server ↔ agent

Цель — медиа-трафик клиентов не создаёт HOL-блокировку для Bot API.

| | `dial` | `reverse` |
|---|---|---|
| Соединения | второй `http.Transport` на агента (отдельные TCP = отдельный пул, свой `MaxConnsPerHost`) | отдельный класс соединений агента с ALPN `tgproxy-mtproto/1` (gateway `internal/server/gateway/gateway.go:143` — добавить в `NextProtos`; агент `internal/agent/connector.go:103`) |
| Размер пула | по потребности: новое соединение при ≥`max_streams_per_conn` активных стримов на существующих | динамический: агент держит `reverse_conns` (мин. 1) и по сигналу сервера (заголовок в `/_agent/status`-ответе на poll или h2 SETTINGS-перегрузке) открывает ещё до `ceil(streams/max_streams_per_conn)+1` |
| HTTP/2 | `MaxConcurrentStreams = max_streams_per_conn` (500), начальные окна потока/соединения ≥4 МБ, PING 15 s | то же; роли h2 развёрнуты, как в §4.1 архитектуры |

`internal/transport/both.go` и `registry.go` расширяются реализацией `StreamTransport` (выбор по `AgentRef.Mode`). Разрыв mTLS-соединения рвёт все его стримы → mtg закрывает клиентские соединения, клиент Telegram переподключается сам.

## 7. Балансировка

Отдельный экземпляр балансировщика (на базе `internal/server/balancer`: P2C, EWMA, breaker) с ключом **(agent, dc)**:

| Сигнал | Уровень | Источник |
|---|---|---|
| health, draining, weight | агент | реестр агентов (`internal/server/agents`), общий с Bot API |
| capability `mtproto/1` | агент | `/_agent/status` |
| `dc.up` | (agent, dc) | проба агента; `up=false` → агент исключён **только для этого DC** |
| inflight = активные стримы | (agent, dc) | счётчик адаптера (+1 на Pick, −1 на закрытие conn, а не на ответ) |
| EWMA (время до `200` = connect к DC) | (agent, dc) | засевается `rtt_ms` пробы; Peak-EWMA, α=0.3, τ=5 s |
| breaker | (agent, dc) | 5 подряд ошибок открытия стрима → open 30 s → half-open |

`score = (streams + 1) × EWMA × 1/weight`, P2C. Без sticky: каждое соединение клиента выбирается заново (клиент Telegram держит несколько соединений к разным DC). Ошибка открытия стрима → `Pick` c `exclude` для следующего адреса DC в той же попытке mtg. Учёт полосы (байт/с на агента) в score — вторым этапом после замеров на проде (ОВ-M3); в v1 только метрика `tgp_mtproto_bytes_total{direction,agent}`.

## 8. Безопасность

**MUST**
- Невалидное соединение (нет SNI=`fronting_domain`, HMAC не совпал, timestamp вне окна) получает настоящий TLS сервера; MTProto-признаков в ответе нет; наружу ничего не проксируется.
- `fronting_domain` совпадает с доменом входного сертификата (`tls.domains` для `acme`, SAN сертификата для `files`, хост `public_base_url`); проверка при старте и при перезагрузке сертификата. `tls.mode=off` + `listen: shared` → ошибка валидации.
- HMAC сравнивается constant-time, перебор всех секретов без раннего выхода.
- Anti-replay: общий StableBloomFilter (`replay_cache`, по умолчанию 4 MiB) на все инстансы; повтор → domain fronting + `mtproto_replay` (считается в автобан).
- Секреты в БД — только зашифрованными `pki.KEK.Seal` (`internal/pki/kek.go:123`, `aad = "mtproto/<id>"`); без `pki.kek_file` MTProto не включается (ошибка старта при `mtproto.enabled: true`).
- Секрет в UI/CLI/логах/аудите/метриках — только префикс (`ee1a2b…`), `redact` распознаёт `ee[0-9a-f]{32,}` и `secret=` в ссылках. Полная ссылка — только на явный запрос после свежего TOTP (≤5 мин), с аудитом `mtproto_secret.reveal`.
- MTProto-секрет и ключ доступа Bot API раздельны: разные таблицы, разные префиксы, взаимной подстановки нет.
- Агент: адрес DC только из вшитой таблицы, порт 443, dial-control; сервер не может заставить агента соединиться с произвольным адресом.
- Содержимое трафика не логируется и не сохраняется никогда. Метки метрик без IP и секретов.
- Свои адреса (`internal/server/ban/protect.go`: `trusted_proxies`, агенты, сети правил, loopback/private) не банятся и по MTProto-причинам.

**SHOULD**
- Рекомендованный прод: dedicated `listen` на отдельном IP (блокировка IP MTProto-прокси не задевает Bot API).
- NTP на сервере (chrony/systemd-timesyncd); при старте — предупреждение и метрика, если `timedatectl` сообщает `NTPSynchronized=no` (окно `time_skew` 2 мин).
- Лимит соединений на секрет (`max_conns`) и опц. CIDR секрета для «своих» групп пользователей.
- Ротация секрета с `grace_until` (дефолт 0 — старый перестаёт работать сразу).
- Фаззинг парсера ClientHello в `make fuzz` и nightly.

## 9. Изоляция и лимиты

- `mtproto.enabled: false` по умолчанию; `true` без `pki.kek_file` — ошибка валидации. Нет ни одного capable-агента в пуле → muxListener отправляет и валидные соединения в TLS-обработчик (клиент увидит «недоступен», зонд — обычный сайт), метрика `connections_total{result="no_agents"}`.
- Паника/ошибка MTProto не роняет листенер: `recover` на соединение, Accept-цикл отдельно.
- Лимиты сервера: `max_conns` (20000, глобально), `max_conns_per_ip` (64), `max_pending_handshakes` (по умолчанию 1024), `max_conns` секрета. Резерв под Bot API: fd-бюджет MTProto = `max_conns × 2` должен быть меньше `LimitNOFILE` минимум на 16384 (проверка при старте, предупреждение).
- Лимиты агента: `max_streams` (по умолчанию 10000), отдельно от `/tg/*`.

## 10. Конфигурация

`server.yaml`:

```yaml
mtproto:
  enabled: false
  listen: shared               # shared | host:port (dedicated)
  public_host: ""              # хост в ссылке; пусто — хост public_base_url
  public_port: 0               # 0 — порт листенера
  fronting_domain: ""          # обязателен; = домен входного сертификата
  max_conns: 20000
  max_conns_per_ip: 64
  max_pending_handshakes: 1024
  handshake_timeout: 5s
  idle_timeout: 5m
  time_skew: 2m
  replay_cache: 4MiB
  dc_probe_interval: 30s       # пробрасывается агентам через /_agent/config
  agent_pool:
    reverse_conns: 2
    max_streams_per_conn: 500
    dial_timeout: 5s
```

`agent.yaml`:

```yaml
mtproto:
  enabled: true                # сервер всё равно требует capability
  max_streams: 10000
  dial_timeout: 5s
  idle_timeout: 5m
  max_duration: 24h
  ipv6: false
  dc_probe_interval: 30s       # 1s..1h; сервер может менять через PUT /_agent/config
```

Правила: `enabled`/`listen`/`fronting_domain` — только рестарт; лимиты и таймауты — SIGHUP. Таблицу DC через YAML не подменить; для тестов — неэкспортируемый оверрайд, как `OverrideTelegramAPIURL` (`internal/config/defaults.go:123`). Валидация — `internal/config/validate.go` (`ValidateServer`, `ValidateAgent`): `fronting_domain` — FQDN без порта; `listen=shared` требует `tls.mode ≠ off`; dedicated `listen` не совпадает с `listen.proxy/admin/metrics/agent_gateway`; `time_skew` ∈ [30s, 10m]; `replay_cache` ∈ [1MiB, 256MiB]; `enabled: true` требует `pki.kek_file`.

## 11. Хранилище

Миграция `0009_mtproto.sql` (последняя сейчас — `0008_bans.sql`):

```
mtproto_secrets (
  id INTEGER PK, name TEXT UNIQUE NOT NULL,
  secret_enc BLOB NOT NULL,          -- KEK.Seal(key[16]), aad "mtproto/<id>"
  prefix TEXT NOT NULL,              -- первые 4 байта hex, для UI/логов
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

Миграция `0010_samples_mtproto.sql`: столбцы `mtproto_conns`, `mtproto_bytes_in`, `mtproto_bytes_out` в `samples_10s`/`samples_5m`. Журнал пишется батчами раз в 10 с (горячий путь в БД не пишет). Redis не затрагивается. Ссылки хранятся не как строка, а собираются из ключа на лету.

## 12. API, CLI, UI

**API** (`RequireAuth` + `Protect`, как `internal/server/web/api/access_http.go`):

| Метод | Путь | Поведение |
|---|---|---|
| GET | `/api/v1/mtproto/secrets` | список: id, name, prefix, cidrs, max_conns, enabled, created_at, revoked_at, grace_until, active_conns |
| POST | `/api/v1/mtproto/secrets` | `{name, cidrs?, max_conns?}` → ключ генерирует сервер (`crypto/rand`, 16 байт); ответ — запись + ссылка **один раз** |
| PATCH | `/api/v1/mtproto/secrets/{id}` | name, cidrs, max_conns, enabled |
| DELETE | `/api/v1/mtproto/secrets/{id}?confirm=yes` | отзыв: `revoked_at`, разрыв активных соединений |
| POST | `/api/v1/mtproto/secrets/{id}/rotate` | `{grace?}` → новый секрет, старый с `grace_until` |
| GET | `/api/v1/mtproto/secrets/{id}/link` | только при свежем TOTP (≤5 мин, иначе `401 totp_required`); `{tg, https, qr_svg}`; аудит `mtproto_secret.reveal` |
| GET | `/api/v1/mtproto/stats` | матрица agent × dc: streams, rtt_ms, up, errors; итоги: conns, bps in/out |

Аудит: `mtproto_secret.create|update|revoke|rotate|reveal`. Ссылка: `tg://proxy?server=<public_host>&port=<port>&secret=ee<hex key><hex fronting_domain>` и `https://t.me/proxy?…` (те же параметры).

**CLI** (`cmd/tgproxy/mtproto.go`, работает с БД напрямую, как `ban`/`access`): `tgproxy mtproto secret add <name> [--cidr …] [--max-conns N]`, `list`, `delete <id|name>`, `rotate <id|name> [--grace 1h]`, `link <id|name>` (печатает ссылку; ключ KEK обязателен), `tgproxy mtproto probe --link <tg://…> [--dc 2] [--timeout 10s]` (тест-клиент §14, код возврата 0/1).

**UI** (`internal/server/web/screens`): вкладка «MTProto» — таблица секретов (префикс, статус, соединения, действия), модалка «Ссылка + QR» (переиспользует `renderQR` из `internal/server/web/auth/qr.go:10`; запрос TOTP, если не свежий), матрица агент × DC (streams / RTT / up). «Агенты» — чип `mtproto/1`. «Обзор» — KPI «MTProto: соединения, полоса». Графики — ряды `mtproto_conns`, `mtproto_bps` в `stats/timeseries`. «Ошибки» — фаза `mtproto` (replay, conn_limit, upstream).

## 13. Метрики и алерты

Server:

| Метрика | Метки |
|---|---|
| `tgp_mtproto_client_conns` (gauge) | `listener` (shared\|dedicated) |
| `tgp_mtproto_connections_total` | `secret` (имя), `result` (ok\|replay\|conn_limit\|no_agents\|upstream_error\|closed) |
| `tgp_mtproto_handshake_failures_total` | `reason` (timeout\|bad_record\|replay\|time_skew\|conn_limit) |
| `tgp_mtproto_fallthrough_total` | — |
| `tgp_mtproto_bytes_total` | `direction` (in\|out), `agent` |
| `tgp_mtproto_streams` (gauge) | `agent`, `dc` |
| `tgp_mtproto_dc_rtt_seconds` (gauge) | `agent`, `dc` |
| `tgp_mtproto_dc_up` (gauge) | `agent`, `dc` |
| `tgp_mtproto_upstream_errors_total` | `agent`, `dc`, `phase` |
| `tgp_mtproto_session_duration_seconds` (histogram) | — |

Agent: `tgp_agent_mtproto_streams{dc}`, `tgp_agent_mtproto_dial_errors_total{dc,kind}`, `tgp_agent_mtproto_bytes_total{direction}`.

Кардинальность: `secret` = число секретов (≤ сотен, см. §15), `dc` ≤ 10, `agent` = число агентов. IP и ключи в метки не попадают.

Алерты (`internal/server/notify`): `mtproto_dc_unreachable` (DC down на всех capable-агентах > 1 мин), `mtproto_no_capable_agents` (MTProto включён, capable-агентов 0), `mtproto_overload` (> 90% `max_conns` 5 мин). Дедуп/лимиты — общие.

## 14. Тестирование

- **Unit (TDD, покрытие ≥85%)**: `faketls` (таблица валидных/невалидных ClientHello, окно времени, несколько секретов, constant-time перебор), `mux` (бан до чтения, лимиты, fallthrough байт-в-байт, recover, `RemoteAddr` = `*net.TCPAddr`), `upstream` (addr→DC, неизвестный адрес → ошибка, повтор на другом агенте, CloseWrite/CloseRead), `keyed` (P2C по (agent, dc), DC down исключает только DC, засев EWMA), `link` (формат ссылки), агент (лимиты, drain, dial-control, 403/503/502).
- **Контракт-тесты mtg** (M9-T0): поведение, на которое опирается дизайн; при обновлении mtg падают первыми.
- **Probe-клиент** `internal/mtproto/probe`: FakeTLS ClientHello с HMAC → чтение ServerHello → obfuscated2 → `req_pq_multi` → ожидание `resPQ` (без авторизации). Он же — `tgproxy mtproto probe` и fake-DC (отвечает `resPQ`) для integration.
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
6. Событие `EventFinish` не несёт причины закрытия (§3 п. 8), события — секрета.
7. Клиентский IP только из `RemoteAddr` — за L4-балансировщиком без PROXY protocol бан и лимиты по IP бессмысленны.
8. Anti-replay только в памяти одного процесса; после рестарта окно повторов открыто на `time_skew`.

Переход на свою реализацию FakeTLS + obfuscated2 (~1000 строк; логика mtg под MIT с атрибуцией в `NOTICE`) — при любом из условий:
- отпечаток ServerHello становится подтверждённой причиной блокировок;
- ломающие изменения mtg, требующие переписывания адаптера, или прекращение поддержки;
- число секретов > 500 (стоимость N инстансов);
- нужен ad-tag/middle-proxy.

## 16. Эксплуатация

- **systemd**: `LimitNOFILE=1048576` (server), `262144` (agent) — сейчас `65536` в `packaging/systemd/tgproxy-{server,agent}.service:17`.
- **sysctl** (только документация, пакет не меняет): агент — `net.ipv4.ip_local_port_range = 10000 65000`, `net.ipv4.tcp_tw_reuse = 1`; сервер — `net.core.somaxconn = 4096`, `net.ipv4.tcp_keepalive_time = 60`.
- **Фаервол**: сервер — входящий порт MTProto (shared — тот же, что прокси); агент — исходящий TCP 443 к сетям Telegram (список — `internal/tgapi/dc.go`, дублируется в `operations.md`).
- **NTP** на сервере обязателен.
- **operations.md**: раздел «MTProto» — включение, выдача ссылки, ротация/отзыв, диагностика (`tgproxy mtproto probe`, матрица agent×DC), признаки блокировки (рост fallthrough при падении `connections_total`), переход на dedicated IP.
- **deploy**: опциональный шаг `scripts/deploy.sh` — если в `deploy/.env` задан `PROD_MTPROTO_LINK`, после health check выполнить `tgproxy mtproto probe --link "$PROD_MTPROTO_LINK"` (ненулевой код — провал деплоя). Значение — секрет, в вывод не печатается.

## 17. Открытые вопросы (с дефолтами)

| # | Вопрос | Дефолт до ответа |
|---|---|---|
| ОВ-M1 | Порт: shared или dedicated на проде | shared на старте; dedicated IP — рекомендация для прода после первых блокировок |
| ОВ-M2 | `fronting_domain` = основной домен прокси или отдельный поддомен с тем же сертификатом | основной домен `public_base_url` |
| ОВ-M3 | Учитывать ли полосу (байт/с) в score балансировщика | нет в v1; решение после 2 недель метрик `bytes_total{agent}` |
| ОВ-M4 | Квоты полосы/трафика на секрет | нет в v1, только `max_conns` |
| ОВ-M5 | Обработка отрицательных (media) DC и `AllowFallbackOnUnknownDC` в mtg v2.2.8 | закрыт контракт-тестом M9-T0: знак DC отбрасывается (`-2`→`2`), неизвестный DC → DC 2 при `AllowFallbackOnUnknownDC: true`, иначе закрытие без `Dial`; дефолт — `true` |
| ОВ-M6 | Retention журнала соединений | как `error_events` |
| ОВ-M7 | IPv6 от агента к DC | выключен (`ipv6: false`) |
| ОВ-M8 | Поддержка PROXY protocol на внешнем MTProto-листенере (за L4-балансировщиком) | нет |
| ОВ-M9 | Срок «свежести» TOTP для показа ссылки | 5 минут |
