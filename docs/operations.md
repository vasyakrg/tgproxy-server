# Эксплуатация

Команды выполняются на хосте сервера (если не сказано иное). CLI работает напрямую с БД по конфигу, поэтому от имени владельца данных: `sudo runuser -u tgproxy -- tgproxy ...`. Пути ниже — дефолты deb.

## Что где хранится

| Что | Путь | Критичность |
|---|---|---|
| БД (агенты, CA, сертификаты, правила доступа, аудит, история) | `/var/lib/tgproxy/tgproxy.db` (+ `-wal`, `-shm`) | высокая |
| KEK (ключ шифрования ключа CA и TOTP-секретов) | `/etc/tgproxy/kek` (0400 `tgproxy`) | критична |
| Конфиг и пользователи | `/etc/tgproxy/server.yaml`, `users_database.yml` | высокая |
| Сертификат входа (`tls.mode: files`) | `tls.cert_file`, `tls.key_file` | средняя |
| Кэш ACME (`tls.mode: acme`) | `tls.cache_dir` (`/var/lib/tgproxy/acme`) | низкая (перевыпускается) |
| Доверенный кэш пакетов (root) | `/var/cache/tgproxy/packages/<версия>/`, `prev.deb` | низкая |
| Загруженные релизы сервера | `/var/lib/tgproxy/updates/downloads/<версия>/` | низкая |

## Бэкап и восстановление

БД — SQLite в WAL-режиме; копировать «горячие» файлы по отдельности нельзя. Варианты:

```sh
# горячий бэкап (нужен пакет sqlite3)
sudo runuser -u tgproxy -- sqlite3 /var/lib/tgproxy/tgproxy.db ".backup '/var/lib/tgproxy/backup.db'"
# либо остановить сервер и скопировать tgproxy.db вместе с -wal/-shm
sudo systemctl stop tgproxy-server
```

Бэкап включает `backup.db`, `server.yaml`, `users_database.yml`, файлы сертификата входа. **KEK храните отдельно от бэкапа БД** (офлайн: менеджер паролей, сейф): БД без KEK не восстанавливает CA, а бэкап с KEK рядом отдаёт ключ CA любому, кто получил бэкап.

Восстановление:

1. `sudo systemctl stop tgproxy-server`
2. Положить БД в `/var/lib/tgproxy/tgproxy.db` (`tgproxy:tgproxy`, 0600), удалить старые `tgproxy.db-wal` и `tgproxy.db-shm`.
3. Положить KEK в `/etc/tgproxy/kek` (`tgproxy:tgproxy`, 0400) — тот же, которым шифровалась БД.
4. `tgproxy config validate --mode server -c /etc/tgproxy/server.yaml`, `sudo systemctl start tgproxy-server`.
5. Агенты переподключатся сами (сертификаты и CA — из восстановленной БД). Сертификаты, выпущенные после бэкапа, сервер не знает: такие агенты потребуют повторной установки/enrollment.

## Потеря KEK

KEK шифрует ключ CA (таблица `pki_ca`) и TOTP-секреты в `users_database.yml`. Без него:

- ключ CA не расшифровать: сервер не может выпускать и продлевать сертификаты, `pki init` существующий CA не перезаписывает;
- TOTP-секреты нечитаемы: вход в админку невозможен до повторного `totp enroll`.

Данные ботов и правила доступа не пострадают (токены не хранятся). Восстановление — это пересоздание PKI:

1. `sudo systemctl stop tgproxy-server`; сделайте копию БД.
2. Новый KEK: `sudo mv /etc/tgproxy/kek /etc/tgproxy/kek.lost; sudo tgproxy pki kek-init --out /etc/tgproxy/kek && sudo chown tgproxy:tgproxy /etc/tgproxy/kek`.
3. Удалить старый CA из БД и создать новый:
   `sudo runuser -u tgproxy -- sqlite3 /var/lib/tgproxy/tgproxy.db "DELETE FROM pki_ca;"`, затем `sudo runuser -u tgproxy -- tgproxy pki init -c /etc/tgproxy/server.yaml`.
4. Для каждого администратора: `tgproxy totp enroll <user>` и новый `totp_secret_enc` в `users_database.yml`.
5. Все агенты не доверяют новому CA: `reverse` — новый токен (`tgproxy agents enroll-token --name <имя>`) и `tgproxy agent enroll` на хосте; `dial` — переустановка мастером в UI.

Процедура не прогонялась на боевом стенде: сначала проверьте её на копии БД.

## Ротация ключа minisign

Два ключа живут одновременно (`update.pubkeys` — 1–2 элемента; пусто = вшитые в бинарь). Агенты проверяют подпись ключами, вшитыми в их бинарь, поэтому порядок строгий:

1. Сгенерировать новый ключ, добавить его публичную часть вторым в `update.pubkeys` (и в список вшиваемых ключей релиза, см. [release.md](release.md)).
2. Выпустить релиз, подписанный **старым** ключом, и раскатить его на сервер и все агенты. После этого у всех в бинаре оба ключа.
3. Переключить секрет `MINISIGN_SECRET_KEY` на новый ключ; следующие релизы подписаны им.
4. В следующем релизе убрать старый ключ; старый приватный ключ уничтожить.

Компрометация приватного ключа: заменить секрет в environment `release` и выпустить релиз, подписанный новым ключом. Агенты, у которых нового ключа нет в бинаре, такой релиз не примут (так и задумано) — для них остаётся ручная установка deb (`dpkg -i` по SSH).

## Сброс host key (мастер установки по SSH)

После переустановки ОС целевого хоста мастер отвечает «Ключ хоста отличается от закреплённого». Сброс только через CLI (не из UI):

```sh
sudo runuser -u tgproxy -- tgproxy hostkeys list -c /etc/tgproxy/server.yaml
sudo runuser -u tgproxy -- tgproxy hostkeys forget <host:port> -c /etc/tgproxy/server.yaml   # покажет отпечаток и спросит y/N; --yes — без вопроса
```

Событие пишется в аудит (`hostkey.forget`). При следующей установке отпечаток подтверждается заново — сверяйте его с консолью хостинга.

## Баны и автобан

Источник правды — таблица `bans` в SQLite; сервер перечитывает её по версии каждые ~2 с, поэтому баны из CLI/UI действуют без рестарта.

```sh
sudo runuser -u tgproxy -- tgproxy ban list -c /etc/tgproxy/server.yaml
sudo runuser -u tgproxy -- tgproxy ban add --ip 203.0.113.7 --duration 24h --comment "скан" -c /etc/tgproxy/server.yaml   # 30m, 1h, 7d; либо --permanent
sudo runuser -u tgproxy -- tgproxy ban delete --ip 203.0.113.7 -c /etc/tgproxy/server.yaml                               # или --id N
```

- **Клиент с правилом «сеть + ключ» получает 403 и сам себя «банит».** Это И: запрос из сети без ключа — `key_required`. Сети правил доступа от автобана защищены (клиент из разрешённой сети не банится никогда), но 403 он получает, пока не добавит ключ в адрес (`/k/<ключ>/bot…`) или заголовок `X-Proxy-Key`. Хотите «сеть ИЛИ ключ» — заведите два правила.
- **Кого забанило по ошибке.** «Баны» → иконка разбана; в «Ошибках» фильтр «Причина»/IP покажет, чем именно он набрал порог. Эскалация (1ч → 24ч → 7д) хранится в строке бана; разбан её сбрасывает.
- **Автобан не срабатывает.** Проверьте `ban.enabled`; что клиент не за reverse proxy без `trusted_proxies` (тогда клиентом считается адрес прокси — приватный/доверенный адрес не банится); что отказы именно `no_rule|key_required|bad_key` (`rate_limited` не считается). Журнал: `ban: autoban` (WARN) и `ban: autoban skipped, address is protected`.
- **Откуда IP.** `client_ip` берётся из `X-Forwarded-For` только если соединение пришло с `trusted_proxies` (правый недоверенный адрес); иначе — адрес соединения. IPv6 банится целой /64.
- **Метрики/графики.** `tgp_denied_total{reason}`; забаненные запросы (`banned`) в журнал ошибок не пишутся (флуд), лог — Debug (`logging.level: debug`).
- Запись `ban.create|ban.delete|ban.auto` в аудите; переменная `ban.*` — только через рестарт (`SIGHUP` предупредит, что не применяется).

### GeoIP (флаги стран)

Файл `geoip.file` (по умолчанию `/usr/share/tgproxy/geoip/dbip-country-lite.mmdb`) поставляется пакетом и обновляется вместе с ним; отдельного обновления и сетевых запросов нет. Нет файла или он битый — сервер стартует, в журнале `geoip database not found/unavailable`, флаги не показываются. Своя база: положите mmdb в любое место и укажите в `geoip.file` (формат MaxMind DB, записи `country.iso_code`). Лицензия DB-IP Lite — CC BY 4.0 (атрибуция «IP Geolocation by DB-IP» показана в UI).

## Сертификаты

- **Агент**: листовой сертификат 90 дней, агент сам продлевает его по mTLS на 2/3 срока (`/_agent/csr` → `/_agent/cert`), рестарт не нужен. Отпечаток CA: `tgproxy pki fingerprint -c /etc/tgproxy/server.yaml`.
- **Агент пропустил ротацию** (был выключен дольше остатка срока): `reverse` — новый токен и `tgproxy agent enroll`; `dial` — переустановка из UI.
- **CA** живёт 10 лет. Замены на месте нет: смена CA = процедура из «Потеря KEK», шаги 3 и 5 (старый KEK можно сохранить).
- **Отзыв**: denylist серийников плюс короткий TTL.
- **Сертификат входа**: `files` — подменить файлы (подхватится сам; проверка: UI «Система → Сертификат входа»); `acme` — продлевается сам. Алерты: `ingress_cert_expiring` (< 14 дней), `ingress_cert_invalid`.

## Lockout входа в админку

10 неудачных попыток входа пользователя за 15 минут блокируют его на 15 минут (алерт `login_lockout`, аудит `login.lockout`); ещё действует лимит 5 попыток/мин на IP+пользователя. Блокировка снимается сама. Принудительно (состояние лежит в БД, рестарт не нужен):

```sh
sudo runuser -u tgproxy -- sqlite3 /var/lib/tgproxy/tgproxy.db \
  "DELETE FROM rate_windows WHERE key LIKE 'login:lock:%' OR key LIKE 'login:fail:%';"
```

Если вход невозможен из-за TOTP — `tgproxy totp enroll <user>` и новый `totp_secret_enc` в `users_database.yml` (`SIGHUP`/`systemctl reload tgproxy-server`; сессии пользователя сбросятся).

## Обновление пакета и конфиги (.dpkg-dist)

Все неинтерактивные установки (`update apply`, `deploy-helper install`, мастер установки по SSH, `scripts/deploy.sh`) вызывают `dpkg --force-confdef --force-confold -i` с `DEBIAN_FRONTEND=noninteractive` и пустым stdin: конфиг, правленный оператором (`/etc/tgproxy/server.yaml`, `agent.yaml`), не перезаписывается и dpkg не задаёт вопросов «Y/I/N/O/D/Z». Если шаблон конфига в новом релизе изменился, он ляжет рядом как `*.dpkg-dist`.

После обновления проверьте и при необходимости перенесите новые опции вручную:

```sh
ls /etc/tgproxy/*.dpkg-dist
diff /etc/tgproxy/server.yaml /etc/tgproxy/server.yaml.dpkg-dist
```

При наличии `.dpkg-dist` `update apply` пишет предупреждение в `result.json` (поле `warning`) и в `journalctl -u tgproxy-update-*`, а `scripts/deploy.sh` печатает «ВНИМАНИЕ» с путями. После переноса опций `.dpkg-dist` можно удалить.

Если установка всё же оборвалась и пакет в состоянии `unpacked`/`half-configured`: `sudo dpkg --configure -a` (с теми же `--force-confdef --force-confold`), затем `systemctl restart tgproxy-server`.

## Нестандартный data_dir (юниты самообновления)

Path-юниты смотрят дефолтные пути: сервер `/var/lib/tgproxy/updates/staged/request`, агент `/var/lib/tgproxy/agent/updates/staged/request` (`data_dir` и `update.staging_dir` из шаблонов конфигов). При другом `data_dir`/`update.staging_dir` `tgproxy config validate` предупредит; нужны drop-in'ы, а основному сервису — запись в новый каталог (`ProtectSystem=strict`):

```ini
# systemctl edit tgproxy-update-agent.path
[Path]
PathExists=
PathExists=/data/tgproxy/agent/updates/staged/request

# systemctl edit tgproxy-update-agent.service
[Unit]
ConditionPathExists=
ConditionPathExists=/data/tgproxy/agent/updates/staged/request
[Service]
ExecStart=
ExecStart=/usr/bin/tgproxy update apply --data-dir /data/tgproxy/agent --component agent --work-dir /run/tgproxy-update-agent

# systemctl edit tgproxy-agent
[Service]
ReadWritePaths=/data/tgproxy/agent
```

Для сервера то же с `tgproxy-update-server.{path,service}`, `--component server`, `--work-dir /run/tgproxy-update-server`. После правки: `systemctl daemon-reload && systemctl restart tgproxy-update-agent.path`. Пустая строка перед новым значением обязательна (сбрасывает дефолт).

## MTProto

Прокси для клиентов Telegram (FakeTLS, beta): клиент подключается по ссылке `tg://proxy?…`, трафик уходит в Telegram через агентов. Выключен по умолчанию. Дизайн и контракты — [mtproto.md](mtproto.md).

### Включение

1. KEK обязателен: `pki.kek_file` в `server.yaml` (секреты MTProto шифруются им; без KEK `mtproto.enabled: true` не пройдёт валидацию).
2. `tls.mode` — `files` или `acme`. `tls.mode: off` с `listen: shared` несовместим: невалидные соединения должны получить настоящий TLS сервера, а MTProto без TLS на входе не поднимается.
3. `fronting_domain` — домен, который есть в SAN входного сертификата (для `acme` — в `tls.domains`; wildcard `*.example.com` покрывает одну метку). Он же попадает в секрет и в SNI клиентов. Не совпал — сервер не стартует; после перевыпуска сертификата без этого домена — предупреждение в логе, а клиенты получают обычный TLS-сайт.
4. Конфиг (остальные поля и дефолты — [mtproto.md](mtproto.md) §10):
   ```yaml
   mtproto:
     enabled: true
     listen: shared                 # либо "203.0.113.10:443" — отдельный листенер
     fronting_domain: tgproxy.example.com
     public_host: ""                # хост в ссылке; пусто — хост server.public_base_url
   ```
5. `tgproxy config validate --mode server -c /etc/tgproxy/server.yaml`, затем `systemctl restart tgproxy-server`. `enabled`, `listen` и `fronting_domain` применяются только рестартом; `max_conns`, `max_conns_per_ip`, `max_pending_handshakes`, `handshake_timeout` — по `SIGHUP`/`systemctl reload`; остальное (`idle_timeout`, `time_skew`, `replay_cache`, `agent_pool.*`) — рестартом.
6. Агенты: на `agent.yaml` `mtproto.enabled: true` (по умолчанию), версия с поддержкой MTProto. Сервер берёт в пул только агентов с capability `mtproto/1` (чип «MTProto» в UI «Агенты»); старые агенты продолжают обслуживать Bot API.

**Shared или dedicated.** `listen: shared` — MTProto на том же порту, что прокси ботов (`listen.proxy`): мало настроек, но блокировка IP по признакам MTProto заденет и Bot API. Для прода рекомендуем `listen: "<отдельный IP>:443"` (`host:port` не должен совпадать с `listen.proxy/admin/metrics/agent_gateway`): на нём невалидные соединения получают 404 с тем же сертификатом, а блокировка этого IP не трогает ботов. Укажите `public_host`/`public_port`, если адрес в ссылке отличается от `public_base_url`.

### Подготовка хостов

- **NTP (обязательно на сервере).** Рукопожатие FakeTLS содержит время клиента; допустимое расхождение — `mtproto.time_skew` (по умолчанию 2 мин, 30 с…10 мин). Часы сервера ушли — валидные клиенты не проходят и видят обычный сайт: растёт `tgp_mtproto_fallthrough_total`, отдельной причины нет. `chronyc tracking` или `timedatectl` (`System clock synchronized: yes`). При включении сервер пишет в лог напоминание о синхронизации.
- **sysctl** (пакет их не меняет):
  ```sh
  # агент: много исходящих соединений к DC
  sysctl -w net.ipv4.ip_local_port_range="10000 65000"
  sysctl -w net.ipv4.tcp_tw_reuse=1
  # сервер: очередь приёма и быстрое обнаружение мёртвых клиентов
  sysctl -w net.core.somaxconn=4096
  sysctl -w net.ipv4.tcp_keepalive_time=60
  ```
  Постоянно — в `/etc/sysctl.d/90-tgproxy.conf`.
- **LimitNOFILE.** Юниты пакета: сервер `1048576`, агент `262144`. Сервер при старте и по `SIGHUP` предупреждает (`mtproto: fd-бюджет не хватает`), если `max_conns × 2 + 16384` превышает лимит процесса; при своём drop-in юнита либо поднимите `LimitNOFILE`, либо уменьшите `mtproto.max_conns`.
- **Фаервол.** Сервер: входящий TCP на порт MTProto (shared — порт `listen.proxy`, dedicated — порт `mtproto.listen`). Агент: исходящий TCP 443 к сетям Telegram (список вшит в бинарь, `tgapi.TelegramPrefixes`; адреса вне него агент не откроет, даже если разрешит фаервол):
  ```
  149.154.160.0/20   91.108.4.0/22     91.108.8.0/22     91.108.12.0/22
  91.108.16.0/22     91.108.20.0/22    91.108.56.0/22    95.161.64.0/20
  185.76.151.0/24    91.105.192.0/23
  2001:b28:f23d::/48 2001:b28:f23f::/48 2001:67c:4e8::/48
  2001:b28:f23c::/48 2a0a:f280::/32
  ```
  IPv6 используется только при `mtproto.ipv6: true` на агенте. Для `reverse`-агентов на сервере по-прежнему нужен открытый `:8444`.

### Секреты: создание, ссылка, ротация, отзыв

Источник правды — таблица `mtproto_secrets` (ключ зашифрован KEK, наружу — только префикс из 4 hex-символов). Сервер перечитывает её по версии каждые ~2 с, поэтому изменения из UI/CLI/API действуют без рестарта; секрет можно подготовить и при `mtproto.enabled: false`.

- **UI**: вкладка «MTProto» — создать, ротировать, отозвать, показать ссылку и QR. Ссылка при создании/ротации показывается **один раз**; повторно — «Ссылка» с вводом свежего TOTP-кода (окно 5 мин), действие пишется в аудит `mtproto_secret.reveal`.
- **CLI** (напрямую в БД, нужен KEK; от владельца данных):
  ```sh
  sudo runuser -u tgproxy -- tgproxy mtproto secret add --name team-a --cidr 203.0.113.0/24 --max-conns 200 -c /etc/tgproxy/server.yaml
  sudo runuser -u tgproxy -- tgproxy mtproto secret list -c /etc/tgproxy/server.yaml
  sudo runuser -u tgproxy -- tgproxy mtproto secret link team-a -c /etc/tgproxy/server.yaml
  sudo runuser -u tgproxy -- tgproxy mtproto secret rotate team-a --grace 1h -c /etc/tgproxy/server.yaml
  sudo runuser -u tgproxy -- tgproxy mtproto secret delete team-a --yes -c /etc/tgproxy/server.yaml
  ```
  `--cidr` (повторяемый) ограничивает сети клиентов секрета, `--max-conns` — число одновременных соединений (0 — без лимита). `link` CLI TOTP не спрашивает (доступ к хосту, БД и KEK уже достаточен), но пишет `mtproto_secret.reveal` в аудит.
- **API**: `GET|POST /api/v1/mtproto/secrets`, `PATCH|DELETE /api/v1/mtproto/secrets/{id}` (отзыв — `?confirm=yes`), `POST …/{id}/rotate` (`{"grace":"1h"}`), `GET …/{id}/link` (свежий TOTP, иначе `401 totp_required`). Те же права, что у остальных `/api/v1`.
- **Ротация.** Создаётся новый ключ с тем же именем, CIDR и `max_conns`; старый получает `grace_until` (`--grace`, до 720h; по умолчанию 0 — перестаёт работать сразу) и переименовывается в `<имя>~<id>`. Раздайте новую ссылку, дождитесь окончания grace — старые соединения рвутся сами.
- **Отзыв** необратим: активные соединения секрета закрываются в течение ~2 с. Утёкшую ссылку отзывайте сразу.
- Ключ не пишется ни в логи, ни в метрики, ни в аудит. Метка `secret` в метриках — имя секрета; не кладите в имя ничего чувствительного.

### Диагностика

1. **Проба с клиентской стороны.** Полный путь (FakeTLS → obfuscated2 → запрос к DC → ответ `resPQ`):
   ```sh
   printf %s 'tg://proxy?server=…&port=443&secret=ee…' | tgproxy mtproto probe --link-stdin --dc 2
   ```
   Код возврата 0 — прокси работает целиком. `--handshake-only` проверяет только FakeTLS (DC и агенты не нужны). Передавайте ссылку через `--link-stdin`: ключ в аргументах виден в `ps`. Ссылка не попадает в сообщения об ошибках.
2. **Матрица агент × DC.** UI «MTProto» (или `GET /api/v1/mtproto/stats`): по каждому агенту — `up`, RTT и число стримов по DC 1…5 и 203. Агент в матрице без DC или с `capable: false` — MTProto на нём выключен или версия старая. DC `up=false` исключает агента только для этого DC.
3. **Метрики** (`/metrics`, подробнее — [mtproto.md](mtproto.md) §13):
   - `tgp_mtproto_client_conns{listener}` — активные клиенты; `tgp_mtproto_connections_total{secret,result}` — итоги (`ok` — дошли до DC, `closed` — закрыто до DC, `replay`, `conn_limit`);
   - `tgp_mtproto_fallthrough_total` — соединения, отданные TLS-сайту (чужие зонды, клиенты с чужим секретом/временем, а также валидные клиенты, когда нет живых секретов или capable-агентов);
   - `tgp_mtproto_handshake_failures_total{reason}` (`timeout`, `bad_record`, `replay`, `conn_limit`);
   - `tgp_mtproto_streams{agent,dc}`, `tgp_mtproto_dc_up{agent,dc}`, `tgp_mtproto_dc_rtt_seconds{agent,dc}`, `tgp_mtproto_upstream_errors_total{agent,dc,phase}` (`dial`, `timeout`, `no_agent`, `unknown_dc`, `other`; `agent="none"` — агента для DC не нашлось), `tgp_mtproto_bytes_total{direction,agent}`;
   - на агенте: `tgp_agent_mtproto_streams{dc}`, `tgp_agent_mtproto_dial_errors_total{dc,kind}`, `tgp_agent_mtproto_bytes_total{direction}`.
4. **Алерты** (Telegram админам): `mtproto_dc_unreachable` — DC недоступен со всех capable-агентов дольше минуты (проверьте фаервол агентов и маршрут до сетей Telegram); `mtproto_no_capable_agents` — MTProto включён, но нет живых агентов с поддержкой (версия, `mtproto.enabled` на агентах, статус агентов); `mtproto_overload` — больше 90% `mtproto.max_conns` дольше 5 минут (поднимайте лимит вместе с `LimitNOFILE` или добавьте листенер/сервер).
5. **Причины отказов** в «Ошибках» (фаза `mtproto`, фильтр «Причина»; секрета в записи нет): `mtproto_replay` — повтор ClientHello (ретрансляция перехваченного рукопожатия; **учитывается автобаном**, см. «Баны и автобан»); `mtproto_conn_limit` — превышены `max_conns`, `max_conns_per_ip` (64 по умолчанию; за NAT много клиентов с одного IP), `max_pending_handshakes` или `max_conns` секрета (в автобан не идёт). `mtproto_bad_secret` в фильтре есть, но сервер её не выставляет.
6. **Типичные случаи.**
   - Клиент «подключается» и видит обычный сайт/не работает, `fallthrough_total` растёт: секрет не тот или отозван; `fronting_domain`≠домен ссылки; часы клиента или сервера вне `time_skew`; нет capable-агентов (смотрите `mtproto_no_capable_agents`); клиент не из CIDR секрета.
   - `connections_total{result="closed"}` растёт, `ok` нет: клиент прошёл FakeTLS, но до DC не дошёл — смотрите `upstream_errors_total` и матрицу агент × DC.
   - `upstream_errors_total{phase="timeout"|"dial"}` у одного агента: агент не достаёт DC (фаервол, маршрут); логи агента `mtproto dial failed`/`mtproto dial timeout`.
   - `phase="no_agent"`: для DC нет подходящего агента (все `down`, draining, без проб — первая проба идёт при старте агента и далее раз в `dc_probe_interval`).
   - Обрыв всех соединений агента при перезапуске/обновлении агента — штатно: клиент Telegram переподключается сам.
   - Журнал соединений (`mtproto_sessions`: время, IP, секрет, DC, байты) хранится 30 суток; поле агента и причина закрытия в нём не заполняются.

### Признаки блокировки и переход на dedicated IP

Признаки: падает `rate(tgp_mtproto_connections_total{result="ok"})` и число клиентов при росте `tgp_mtproto_fallthrough_total` или `handshake_failures_total{reason="timeout"}`; жалобы пользователей из конкретных сетей при рабочем `mtproto probe` с вашей стороны; блокировка порта ботов при shared (Bot API ботов страдает вместе с MTProto).

Порядок действий:
1. Проверьте, что это не NTP и не сертификат: `chronyc tracking`, UI «Система → Сертификат входа», `mtproto probe` с внешнего хоста.
2. Если IP сервера под блокировкой, выделите отдельный IP под MTProto и переведите на него `listen: "<IP>:443"`, при необходимости `public_host`/`public_port` (рестарт). Сертификат и `fronting_domain` должны остаться валидными для имени, которое резолвится в этот IP. Разошлите новые ссылки (адрес в ссылке меняется — `secret` остаётся тем же, но клиентам нужна ссылка с новым `server`/`port`: `tgproxy mtproto secret link`).
3. Прод-рекомендация — dedicated с самого начала: блокировка IP MTProto-прокси не затрагивает прокси ботов.

Ограничение: ServerHello FakeTLS (библиотека mtg) отличается по отпечатку от `crypto/tls`; активный зонд видит настоящий сайт, пассивный DPI отличить может. Критерии перехода на собственную реализацию — [mtproto.md](mtproto.md) §15.

### Reverse-агенты (за NAT)

- MTProto идёт по отдельному классу соединений агент → сервер с ALPN `tgproxy-mtproto/1` (тот же `:8444`, клиентский сертификат обязателен), независимо от Bot API: медиа не блокирует запросы ботов. Отдельных портов и настроек сертификатов не нужно.
- Размер пула MTProto-соединений агента динамический: старт с `mtproto.reverse_conns_min` агента (2); сервер просит больше, когда на соединении ≥ `mtproto.agent_pool.max_streams_per_conn` (500) стримов, и сжимает при простое (не чаще раза в 60 с); запрос — `PUT /_agent/mtproto/pool`. Границы: агент `reverse_conns_min`…`reverse_conns_max` (по умолчанию 2…16), сервер `agent_pool.max_reverse_conns` (16) — держите их согласованными, иначе сервер будет вытеснять лишние соединения. Ключ `agent_pool.reverse_conns` на сервере сейчас не влияет на размер пула.
- Совместимость: агент без capability `mtproto/1` в MTProto-пул не попадает, но Bot API обслуживает как раньше. Новый reverse-агент при старом сервере (нет ALPN) не ломает подключение для ботов и раз в 10 минут тихо повторяет MTProto-класс.
- Проверка: серверная `tgp_agent_reverse_conns{agent}` считает только Bot API-класс; MTProto-стримы агента — `tgp_mtproto_streams{agent,dc}` и матрица в UI. В журнале сервера `gateway: reverse channel attached … class=mtproto`.

## Troubleshooting

Журналы: `journalctl -u tgproxy-server -o cat` (JSON), `journalctl -u tgproxy-agent -o cat`, `journalctl -u tgproxy-update-server -u tgproxy-update-agent`.

**Агент down.** UI «Агенты» и `tgp_agent_up`; `/readyz` отвечает 503, если нет ни одного агента up. Статус опрашивается раз в 5 с; 3 неудачи — down.
- `dial`: с сервера `curl -v --connect-timeout 5 https://<агент>:8443/` (ожидается TLS-рукопожатие/отказ без клиентского сертификата, не таймаут) — проверить порт, firewall, `systemctl status tgproxy-agent` на агенте, срок сертификата (`cert_not_after` в статусе агента).
- `tgp_agent_dial_errors_total{kind}` на агенте и логи показывают фазу: `dial`, `tls`, `timeout`.
- Агент не достаёт `api.telegram.org` — `GET /_agent/healthz` вернёт 503 (кэш TLS-пробы 10 с).

**Reverse-агент не подключается.**
- С хоста агента: `curl -vk https://<сервер>:8444/` — `:8444` должен быть открыт из сети агента.
- На сервере `tgp_agent_reverse_conns{agent="<id>"}` должна быть 2; `tgp_enroll_attempts_total{result}` показывает отказы enrollment.
- Enrollment: токен одноразовый и живёт 1 час — выпустить новый; утёкший токен отозвать: UI «Агенты → Агент за NAT → Ожидающие подключения» или `tgproxy agents enroll-token -c /etc/tgproxy/server.yaml --list` и `--revoke <id|имя>` (SQL-правки БД не нужны; после отзыва `/enroll` и `/enroll/package/*` отвечают 401, в аудите `enrollment.revoke`); если `reverse`-агент нужно перевести в `dial`/`both` (`PUT /_agent/config` → `422 … требует listen.api`), добавьте в `agent.yaml` `listen.api: ":8443"` (`agent enroll` его для `reverse` не пишет) и перезапустите агента; команда установки работает под root и под пользователем с sudo (на хосте без curl сама ставит его через apt; нужен доступ к apt-репозиториям); «загрузите релиз X в Система → Обновления» — в кэше загрузок сервера нет подписанного пакета версии сервера (на хосте с уже установленным tgproxy: `agents enroll-token --installed`); `curl: (60)` при установке — имя хоста gateway не в SAN сертификата сервера (перезапустите сервер после смены `agent_gateway_url`); ошибка отпечатка CA — взять свежий `tgproxy pki fingerprint`; лимит 5 попыток/мин на IP.
- `server_url` в `agent.yaml` должен быть доступным с агента (на сервере для него есть `server.agent_gateway_url`).
- Сертификат агента просрочен — повторный enrollment.

**Обновление откатилось.**
- Итог всегда в `result.json`: сервер `/var/lib/tgproxy/updates/result.json`, агент `/var/lib/tgproxy/agent/updates/result.json` (поля `version`, `ok`, `rolled_back`, `error`, `warning`, `at`).
- Ход применения: `journalctl -u tgproxy-update-server` (или `-agent`) — подпись, `dpkg -i`, health-проба (сервер: `/healthz` 30 с; агент: за 60 с непрерывно `active` ≥ 15 с без рестартов, и `/healthz` на loopback-metrics).
- Причина падения самого сервиса: `journalctl -u tgproxy-server` / `-agent` за время обновления.
- Откат использует `prev.deb` в `/var/cache/tgproxy/packages`; версия, не прошедшая health, удаляется из доверенного кэша. Повторить обновление можно только исправленным релизом.
- Пакет не принят: подпись не сошлась (релиз подписан не вшитым ключом), версия ниже `update.min_version`, `request` не обработан — проверить `systemctl status tgproxy-update-agent.path` (включён ли) и что пути юнитов совпадают с `data_dir` (см. выше).
- Снимок-деплой (`make deploy` в режиме snapshot) не имеет подписи и вшитых ключей: такой сервер/агент обновления не примет — это защита, а не поломка.
