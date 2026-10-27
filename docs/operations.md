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

## Troubleshooting

Журналы: `journalctl -u tgproxy-server -o cat` (JSON), `journalctl -u tgproxy-agent -o cat`, `journalctl -u tgproxy-update-server -u tgproxy-update-agent`.

**Агент down.** UI «Агенты» и `tgp_agent_up`; `/readyz` отвечает 503, если нет ни одного агента up. Статус опрашивается раз в 5 с; 3 неудачи — down.
- `dial`: с сервера `curl -v --connect-timeout 5 https://<агент>:8443/` (ожидается TLS-рукопожатие/отказ без клиентского сертификата, не таймаут) — проверить порт, firewall, `systemctl status tgproxy-agent` на агенте, срок сертификата (`cert_not_after` в статусе агента).
- `tgp_agent_dial_errors_total{kind}` на агенте и логи показывают фазу: `dial`, `tls`, `timeout`.
- Агент не достаёт `api.telegram.org` — `GET /_agent/healthz` вернёт 503 (кэш TLS-пробы 10 с).

**Reverse-агент не подключается.**
- С хоста агента: `curl -vk https://<сервер>:8444/` — `:8444` должен быть открыт из сети агента.
- На сервере `tgp_agent_reverse_conns{agent="<id>"}` должна быть 2; `tgp_enroll_attempts_total{result}` показывает отказы enrollment.
- Enrollment: токен одноразовый и живёт 1 час — выпустить новый; команда установки работает под root и под пользователем с sudo (на хосте без curl сама ставит его через apt; нужен доступ к apt-репозиториям); «загрузите релиз X в Система → Обновления» — в кэше загрузок сервера нет подписанного пакета версии сервера (на хосте с уже установленным tgproxy: `agents enroll-token --installed`); `curl: (60)` при установке — имя хоста gateway не в SAN сертификата сервера (перезапустите сервер после смены `agent_gateway_url`); ошибка отпечатка CA — взять свежий `tgproxy pki fingerprint`; лимит 5 попыток/мин на IP.
- `server_url` в `agent.yaml` должен быть доступным с агента (на сервере для него есть `server.agent_gateway_url`).
- Сертификат агента просрочен — повторный enrollment.

**Обновление откатилось.**
- Итог всегда в `result.json`: сервер `/var/lib/tgproxy/updates/result.json`, агент `/var/lib/tgproxy/agent/updates/result.json` (поля `version`, `ok`, `rolled_back`, `error`, `at`).
- Ход применения: `journalctl -u tgproxy-update-server` (или `-agent`) — подпись, `dpkg -i`, health-проба (сервер: `/healthz` 30 с; агент: за 60 с непрерывно `active` ≥ 15 с без рестартов, и `/healthz` на loopback-metrics).
- Причина падения самого сервиса: `journalctl -u tgproxy-server` / `-agent` за время обновления.
- Откат использует `prev.deb` в `/var/cache/tgproxy/packages`; версия, не прошедшая health, удаляется из доверенного кэша. Повторить обновление можно только исправленным релизом.
- Пакет не принят: подпись не сошлась (релиз подписан не вшитым ключом), версия ниже `update.min_version`, `request` не обработан — проверить `systemctl status tgproxy-update-agent.path` (включён ли) и что пути юнитов совпадают с `data_dir` (см. выше).
- Снимок-деплой (`make deploy` в режиме snapshot) не имеет подписи и вшитых ключей: такой сервер/агент обновления не примет — это защита, а не поломка.
