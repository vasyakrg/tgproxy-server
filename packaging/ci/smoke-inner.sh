#!/usr/bin/env bash
# Выполняется ВНУТРИ контейнера с systemd (см. smoke.sh).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef -y -q)
step() { printf '\n=== %s ===\n' "$*"; }
fail() { echo "FAIL: $*" >&2; systemctl status tgproxy-server --no-pager -l >&2 || true; journalctl -u tgproxy-server --no-pager -n 30 >&2 || true; exit 1; }

wait_healthz() {
  for _ in $(seq 1 30); do
    curl -fsSk https://127.0.0.1:8090/healthz >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

step "install"
apt-get update -q >/dev/null
"${APT[@]}" install /pkg/tgproxy.deb
getent passwd tgproxy >/dev/null || fail "пользователь tgproxy не создан"
[ "$(getent passwd tgproxy | cut -d: -f7)" = /usr/sbin/nologin ] || fail "shell != nologin"
[ "$(stat -c '%U:%G %a' /etc/tgproxy)" = "root:tgproxy 750" ] || fail "права /etc/tgproxy: $(stat -c '%U:%G %a' /etc/tgproxy)"
[ "$(stat -c '%U:%G %a' /etc/tgproxy/server.yaml)" = "root:tgproxy 640" ] || fail "права server.yaml"
[ "$(stat -c '%U:%G %a' /var/lib/tgproxy)" = "tgproxy:tgproxy 750" ] || fail "права /var/lib/tgproxy"
[ "$(stat -c '%U:%G %a' /var/cache/tgproxy/packages)" = "root:root 755" ] || fail "доверенный кэш пакетов: права $(stat -c '%U:%G %a' /var/cache/tgproxy/packages)"
[ ! -e /var/lib/tgproxy/packages ] || fail "устаревший /var/lib/tgproxy/packages остался"
systemctl is-enabled tgproxy-server.service >/dev/null 2>&1 && fail "server включён после установки"
systemctl is-active tgproxy-server.service >/dev/null 2>&1 && fail "server запущен после установки"
tgproxy version
# шаблоны из пакета проходят валидацию схемы
tgproxy config validate --mode server -c /etc/tgproxy/server.yaml
tgproxy config validate --mode agent -c /etc/tgproxy/agent.yaml

step "минимальный валидный конфиг (на лету)"
# самоподписанный вход (SAN = fronting_domain MTProto): FakeTLS требует TLS на входе
install -d -o root -g tgproxy -m 0750 /etc/tgproxy/tls
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj "/CN=tg.smoke.test" \
  -addext "subjectAltName=DNS:tg.smoke.test" -keyout /etc/tgproxy/tls/server.key -out /etc/tgproxy/tls/server.crt 2>/dev/null
chown root:tgproxy /etc/tgproxy/tls/server.key /etc/tgproxy/tls/server.crt
chmod 0640 /etc/tgproxy/tls/server.key /etc/tgproxy/tls/server.crt
cat > /etc/tgproxy/server.yaml <<'YAML'
# smoke-marker: локальная правка администратора
listen:
  proxy: "127.0.0.1:8080"
  admin: "127.0.0.1:8090"
  metrics: "127.0.0.1:9090"
  agent_gateway: "127.0.0.1:8444"
tls:
  mode: files
  cert_file: /etc/tgproxy/tls/server.crt
  key_file: /etc/tgproxy/tls/server.key
mtproto:
  enabled: true
  listen: "127.0.0.1:8445"
  public_host: 127.0.0.1
  public_port: 8445
  fronting_domain: tg.smoke.test
agents:
  - id: smoke
    url: https://127.0.0.1:8443
    mode: dial
auth:
  users_file: /etc/tgproxy/users_database.yml
  allow_password_only: true   # только smoke
logging:
  level: info
  format: json
access_rules:
  - name: localhost
    cidrs: [127.0.0.0/8]
YAML
HASH="$(printf 'smoke-password\n' | tgproxy hashpw)"
cat > /etc/tgproxy/users_database.yml <<YAML
users:
  admin:
    displayname: Smoke
    password: '$HASH'
    email: admin@example.test
    telegram_id: 0
YAML
chown root:tgproxy /etc/tgproxy/server.yaml /etc/tgproxy/users_database.yml
chmod 0640 /etc/tgproxy/server.yaml /etc/tgproxy/users_database.yml
tgproxy pki kek-init --out /etc/tgproxy/kek
chown tgproxy:tgproxy /etc/tgproxy/kek
# CA создаётся один раз в БД сервера (ключ CA под KEK); от имени tgproxy — БД принадлежит ему.
runuser -u tgproxy -- tgproxy pki init -c /etc/tgproxy/server.yaml
# mTLS-материал dial-агента из CA сервера (в каталог данных агента из packaging/etc/agent.yaml)
runuser -u tgproxy -- tgproxy pki dev-agents -c /etc/tgproxy/server.yaml --out /var/lib/tgproxy/agent --agent smoke
sed -i 's|^  api: ":8443"|  api: "127.0.0.1:8443"|' /etc/tgproxy/agent.yaml
tgproxy config validate --mode agent -c /etc/tgproxy/agent.yaml
tgproxy config validate --mode server -c /etc/tgproxy/server.yaml

step "systemd-analyze verify"
systemd-analyze verify tgproxy-server.service tgproxy-agent.service tgproxy-update-server.path tgproxy-update-server.service tgproxy-update-agent.path tgproxy-update-agent.service || fail "verify"

step "start + healthz"
systemctl start tgproxy-server.service || fail "start"
wait_healthz || fail "healthz не ответил"
curl -fsSk https://127.0.0.1:8090/healthz
PID1="$(systemctl show -p MainPID --value tgproxy-server.service)"
[ "$(ps -o user= -p "$PID1")" = tgproxy ] || fail "процесс не под tgproxy: $(ps -o user= -p "$PID1")"

step "mtproto: секрет, FakeTLS-рукопожатие через dial-агента, отзыв"
# Путь проверки: сети к DC Telegram в CI нет, поэтому главный критерий — probe --handshake-only
# (ServerHello с верным HMAC возможен только когда сервер сопоставил секрет и видит capable-агента
# mtproto/1; иначе соединение уходит в обычный TLS и probe падает). Полный обмен resPQ с DC — информативно.
# Ссылка (содержит ключ) живёт только в переменной и в stdin probe, в лог не попадает.
systemctl start tgproxy-agent.service || fail "agent start"
LINK="$(runuser -u tgproxy -- tgproxy mtproto secret add -c /etc/tgproxy/server.yaml --name smoke | grep -o 'tg://proxy[^ ]*' | head -n1)"
[ -n "$LINK" ] || fail "секрет MTProto не создан / ссылка не получена"
mt_ok=0
for _ in $(seq 1 40); do
  if printf '%s' "$LINK" | tgproxy mtproto probe --link-stdin --handshake-only --timeout 5s >/dev/null 2>&1; then mt_ok=1; break; fi
  sleep 1
done
if [ "$mt_ok" != 1 ]; then
  systemctl status tgproxy-agent --no-pager -l >&2 || true
  journalctl -u tgproxy-agent --no-pager -n 20 >&2 || true
  fail "FakeTLS-рукопожатие MTProto не прошло за 40с (нет capable-агента mtproto/1 или секрет не принят)"
fi
echo "FakeTLS-рукопожатие: OK"
if printf '%s' "$LINK" | tgproxy mtproto probe --link-stdin --timeout 8s >/dev/null 2>&1; then
  echo "resPQ от DC: OK (в контейнере есть сеть к Telegram)"
else
  echo "resPQ от DC: нет (ожидаемо без сети к Telegram; не критерий smoke)"
fi
# ключ секрета не должен попасть в журнал сервера
KEYHEX="$(printf '%s' "$LINK" | sed -nE 's/.*secret=ee([0-9a-f]{32}).*/\1/p')"
[ -n "$KEYHEX" ] || fail "не удалось выделить ключ секрета для проверки утечек"
JLOG="$(journalctl -u tgproxy-server -u tgproxy-agent --no-pager 2>&1 || true)"
case "${JLOG,,}" in *"$KEYHEX"*) fail "ключ секрета MTProto найден в журнале" ;; esac
unset JLOG
runuser -u tgproxy -- tgproxy mtproto secret delete smoke --yes -c /etc/tgproxy/server.yaml >/dev/null
mt_rev=0
for _ in $(seq 1 10); do
  if ! printf '%s' "$LINK" | tgproxy mtproto probe --link-stdin --handshake-only --timeout 3s >/dev/null 2>&1; then mt_rev=1; break; fi
  sleep 1
done
[ "$mt_rev" = 1 ] || fail "после отзыва секрета рукопожатие всё ещё проходит"
echo "отзыв секрета: OK"
unset LINK KEYHEX

step "systemd-analyze security"
systemd-analyze security tgproxy-server.service --no-pager | tee /tmp/security.txt
SCORE="$(sed -nE 's/.*Overall exposure level for tgproxy-server\.service: ([0-9.]+).*/\1/p' /tmp/security.txt)"
[ -n "$SCORE" ] || fail "не удалось разобрать балл"
echo "SECURITY SCORE: $SCORE (порог ${SECURITY_MAX})"
ASCORE="$(systemd-analyze security tgproxy-agent.service --no-pager | sed -nE 's/.*Overall exposure level for tgproxy-agent\.service: ([0-9.]+).*/\1/p')"
echo "SECURITY SCORE (agent): $ASCORE"
awk -v s="${ASCORE:-99}" -v m="$SECURITY_MAX" 'BEGIN{exit !(s<=m)}' || fail "балл агента $ASCORE > $SECURITY_MAX"
awk -v s="$SCORE" -v m="$SECURITY_MAX" 'BEGIN{exit !(s<=m)}' || fail "балл $SCORE > $SECURITY_MAX"

step "upgrade поверх (тот же deb): конфиг сохранён, сервис перезапущен"
"${APT[@]}" install --reinstall /pkg/tgproxy.deb >/dev/null
grep -q 'smoke-marker' /etc/tgproxy/server.yaml || fail "конфиг перезаписан при upgrade"
wait_healthz || fail "healthz после upgrade"
PID2="$(systemctl show -p MainPID --value tgproxy-server.service)"
[ "$PID1" != "$PID2" ] || fail "сервис не перезапущен при upgrade (PID $PID1)"
echo "restarted: $PID1 -> $PID2"

step "remove: юниты остановлены"
"${APT[@]}" remove tgproxy >/dev/null
systemctl is-active tgproxy-server.service >/dev/null 2>&1 && fail "server активен после remove"
systemctl is-active tgproxy-agent.service >/dev/null 2>&1 && fail "agent активен после remove"
[ ! -x /usr/bin/tgproxy ] || fail "бинарь остался"
[ -f /etc/tgproxy/server.yaml ] || fail "конфиг удалён при remove"
getent passwd tgproxy >/dev/null || fail "пользователь удалён при remove"
pgrep -x tgproxy >/dev/null && fail "процесс tgproxy жив"

step "purge: данные и пользователь удалены"
"${APT[@]}" purge tgproxy >/dev/null
[ ! -e /etc/tgproxy ] || fail "/etc/tgproxy остался"
[ ! -e /var/cache/tgproxy ] || fail "/var/cache/tgproxy остался после purge"
[ ! -e /var/lib/tgproxy ] || fail "/var/lib/tgproxy остался"
getent passwd tgproxy >/dev/null && fail "пользователь остался"
getent group tgproxy >/dev/null && fail "группа осталась"

echo; echo "SMOKE OK (security score $SCORE)"
