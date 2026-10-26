#!/usr/bin/env bash
# Выполняется ВНУТРИ контейнера с systemd (см. smoke.sh).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef -y -q)
step() { printf '\n=== %s ===\n' "$*"; }
fail() { echo "FAIL: $*" >&2; systemctl status tgproxy-server --no-pager -l >&2 || true; journalctl -u tgproxy-server --no-pager -n 30 >&2 || true; exit 1; }

wait_healthz() {
  for _ in $(seq 1 30); do
    curl -fsS http://127.0.0.1:8090/healthz >/dev/null 2>&1 && return 0
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
systemctl is-enabled tgproxy-server.service >/dev/null 2>&1 && fail "server включён после установки"
systemctl is-active tgproxy-server.service >/dev/null 2>&1 && fail "server запущен после установки"
tgproxy version
# шаблоны из пакета проходят валидацию схемы
tgproxy config validate --mode server -c /etc/tgproxy/server.yaml
tgproxy config validate --mode agent -c /etc/tgproxy/agent.yaml

step "минимальный валидный конфиг (на лету)"
cat > /etc/tgproxy/server.yaml <<'YAML'
# smoke-marker: локальная правка администратора
listen:
  proxy: "127.0.0.1:8080"
  admin: "127.0.0.1:8090"
  metrics: "127.0.0.1:9090"
  agent_gateway: "127.0.0.1:8444"
tls:
  mode: "off"
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
# До M5 (выпуск CA сервером) сервер требует готовые mTLS-материалы в pki.dir: берём dev-PKI.
tgproxy pki dev-init --out /var/lib/tgproxy/pki --agent smoke
chown -R tgproxy:tgproxy /var/lib/tgproxy/pki
tgproxy config validate --mode server -c /etc/tgproxy/server.yaml

step "systemd-analyze verify"
systemd-analyze verify tgproxy-server.service tgproxy-agent.service tgproxy-update.path tgproxy-update.service || fail "verify"

step "start + healthz"
systemctl start tgproxy-server.service || fail "start"
wait_healthz || fail "healthz не ответил"
curl -fsS http://127.0.0.1:8090/healthz
PID1="$(systemctl show -p MainPID --value tgproxy-server.service)"
[ "$(ps -o user= -p "$PID1")" = tgproxy ] || fail "процесс не под tgproxy: $(ps -o user= -p "$PID1")"

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
[ ! -x /usr/bin/tgproxy ] || fail "бинарь остался"
[ -f /etc/tgproxy/server.yaml ] || fail "конфиг удалён при remove"
getent passwd tgproxy >/dev/null || fail "пользователь удалён при remove"
pgrep -x tgproxy >/dev/null && fail "процесс tgproxy жив"

step "purge: данные и пользователь удалены"
"${APT[@]}" purge tgproxy >/dev/null
[ ! -e /etc/tgproxy ] || fail "/etc/tgproxy остался"
[ ! -e /var/lib/tgproxy ] || fail "/var/lib/tgproxy остался"
getent passwd tgproxy >/dev/null && fail "пользователь остался"
getent group tgproxy >/dev/null && fail "группа осталась"

echo; echo "SMOKE OK (security score $SCORE)"
