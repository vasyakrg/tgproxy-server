#!/usr/bin/env bash
# Деплой сервера tgproxy на прод. Конфигурация: deploy/.env (шаблон deploy/.env.example)
# или окружение. DEPLOY_DRY_RUN=1 печатает план и ничего не выполняет.
#
# Агентов скрипт не трогает: их обновляет сервер подписанным релизом (docs/architecture.md §12).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'ВНИМАНИЕ: %s\n' "$*" >&2; }
die()  { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }

ENV_FILE="${DEPLOY_ENV:-$ROOT/deploy/.env}"
if [ -f "$ENV_FILE" ]; then
  # Файл оператора (deploy/.env, не коммитится); уже заданные в окружении переменные приоритетнее.
  for _v in PROD_SERVER_HOST PROD_SERVER_SSH_USER PROD_SERVER_SSH_PORT PROD_SSH_KEY PROD_PUBLIC_URL \
    PROD_ADMIN_URL PROD_AGENT_HOSTS PROD_AGENT_SSH_USER DEPLOY_MODE DEPLOY_TAG DEPLOY_REPO DEPLOY_DEB \
    DEPLOY_ALLOW_DOWNGRADE DEPLOY_HEALTH_TIMEOUT; do
    if [ -n "${!_v+x}" ]; then eval "_keep_$_v=\${$_v}"; fi
  done
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
  for _v in PROD_SERVER_HOST PROD_SERVER_SSH_USER PROD_SERVER_SSH_PORT PROD_SSH_KEY PROD_PUBLIC_URL \
    PROD_ADMIN_URL PROD_AGENT_HOSTS PROD_AGENT_SSH_USER DEPLOY_MODE DEPLOY_TAG DEPLOY_REPO DEPLOY_DEB \
    DEPLOY_ALLOW_DOWNGRADE DEPLOY_HEALTH_TIMEOUT; do
    _k="_keep_$_v"
    if [ -n "${!_k+x}" ]; then export "$_v=${!_k}"; fi
  done
fi

DRY="${DEPLOY_DRY_RUN:-0}"
MODE="${DEPLOY_MODE:-snapshot}"
REPO="${DEPLOY_REPO:-vasyakrg/tgproxy-server}"
HEALTH_TIMEOUT="${DEPLOY_HEALTH_TIMEOUT:-30}"

req() { [ -n "${!1:-}" ] || die "не задана $1 (deploy/.env или окружение)"; }
req PROD_SERVER_HOST
req PROD_SERVER_SSH_USER
req PROD_ADMIN_URL
case "$MODE" in snapshot|release) ;; *) die "DEPLOY_MODE=$MODE: допустимо snapshot|release" ;; esac
case "$HEALTH_TIMEOUT" in ''|*[!0-9]*) die "DEPLOY_HEALTH_TIMEOUT должен быть числом" ;; esac

SSH_PORT="${PROD_SERVER_SSH_PORT:-22}"
AGENT_USER="${PROD_AGENT_SSH_USER:-$PROD_SERVER_SSH_USER}"
ADMIN_URL="${PROD_ADMIN_URL%/}"

# Проверка ключа хоста — всегда (known_hosts оператора); BatchMode — без интерактивных запросов.
SSH_OPTS=(-o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10)
[ -n "${PROD_SSH_KEY:-}" ] && SSH_OPTS+=(-i "${PROD_SSH_KEY/#\~/$HOME}" -o IdentitiesOnly=yes)

rssh() { local host="$1" user="$2"; shift 2; ssh "${SSH_OPTS[@]}" -p "$SSH_PORT" "$user@$host" "$@"; }
rscp() { scp "${SSH_OPTS[@]}" -P "$SSH_PORT" "$@"; }

TAG=""
if [ "$MODE" = release ]; then
  TAG="${DEPLOY_TAG:-$(git describe --tags --exact-match 2>/dev/null || true)}"
  [ -n "$TAG" ] || die "release: HEAD не на теге, задайте DEPLOY_TAG=vX.Y.Z"
  case "$TAG" in v[0-9]*) ;; *) die "тег $TAG: ожидается vX.Y.Z" ;; esac
fi

# ---------- план ----------
AGENTS_PLAN="пропуск"
[ -z "${PROD_AGENT_HOSTS:-}" ] || AGENTS_PLAN="systemctl is-active tgproxy-agent + версия (только чтение)"
cat <<PLAN
План деплоя
  режим:      $MODE${TAG:+ ($TAG, $REPO)}
  сервер:     $PROD_SERVER_SSH_USER@$PROD_SERVER_HOST:$SSH_PORT (StrictHostKeyChecking=yes)
  health:     $ADMIN_URL/healthz, /readyz (до ${HEALTH_TIMEOUT}s каждый)
  агенты:     ${PROD_AGENT_HOSTS:-не заданы} (только чтение; обновляются сервером)
  шаги:
    1. получить deb: $( [ "$MODE" = release ] && echo "скачать $TAG из GitHub Releases, проверить sha256 + minisign (packaging/minisign.pub)" || echo "${DEPLOY_DEB:-make snapshot -> dist/tgproxy_*_amd64.deb}" )
    2. ssh: tgproxy установлен и забутстраплен (/etc/tgproxy/kek), иначе чеклист и выход с ошибкой
    3. защита от даунгрейда (dpkg --compare-versions), scp deb во временный каталог
    4. sudo dpkg -i, sudo systemctl restart tgproxy-server, сверка версии, очистка
    5. $ADMIN_URL/healthz, затем /readyz (>=1 агент up)
    6. агенты: $AGENTS_PLAN
    7. $( [ "$MODE" = release ] && echo "агенты: обновить из UI «Система -> Обновления» (сервер сам скачивает подписанный релиз из GitHub)" || echo "агенты НЕ трогаем: snapshot не подписан, агенты его не примут (так задумано)" )
PLAN
if [ "$DRY" = 1 ]; then log "DEPLOY_DRY_RUN=1: ничего не выполнено"; exit 0; fi

for _c in ssh scp curl; do command -v "$_c" >/dev/null || die "нужен $_c"; done

WORK="$(mktemp -d)"
REMOTE_TMP=""
cleanup() {
  [ -n "$REMOTE_TMP" ] && rssh "$PROD_SERVER_HOST" "$PROD_SERVER_SSH_USER" "rm -rf -- '$REMOTE_TMP'" >/dev/null 2>&1 || true
  rm -rf -- "$WORK"
}
trap cleanup EXIT

# ---------- 1. deb ----------
DEB=""
if [ "$MODE" = release ]; then
  command -v minisign >/dev/null || die "release: нужен minisign для проверки подписи"
  grep -q '^RW' packaging/minisign.pub || die "packaging/minisign.pub — заглушка (ОВ-4), подпись проверить нечем"
  base="https://github.com/$REPO/releases/download/$TAG"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/checksums.txt" "$base/checksums.txt"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/checksums.txt.minisig" "$base/checksums.txt.minisig"
  minisign -V -p packaging/minisign.pub -m "$WORK/checksums.txt" -x "$WORK/checksums.txt.minisig" >/dev/null \
    || die "подпись checksums.txt НЕ сошлась"
  name="$(awk '$2 ~ /^tgproxy_.*_amd64\.deb$/ {print $2}' "$WORK/checksums.txt" | head -n1)"
  [ -n "$name" ] || die "в checksums.txt нет amd64 deb"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$name" "$base/$name"
  want="$(awk -v n="$name" '$2 == n {print $1}' "$WORK/checksums.txt")"
  if command -v sha256sum >/dev/null; then got="$(sha256sum "$WORK/$name" | awk '{print $1}')"; else got="$(shasum -a 256 "$WORK/$name" | awk '{print $1}')"; fi
  [ "$want" = "$got" ] || die "sha256 $name не совпал с подписанным checksums.txt"
  DEB="$WORK/$name"
  log "release $TAG: подпись и sha256 проверены ($name)"
else
  if [ -n "${DEPLOY_DEB:-}" ]; then
    DEB="$DEPLOY_DEB"
  else
    log "make snapshot"
    make snapshot >&2
    DEB="$(find dist -maxdepth 1 -name 'tgproxy_*_amd64.deb' -print 2>/dev/null | sort | tail -n1)"
  fi
  [ -f "$DEB" ] || die "deb не найден: ${DEB:-dist/tgproxy_*_amd64.deb}"
  warn "snapshot-deb без вшитых release-ключей: сервер на нём не сможет проверить/применить обновления. Только для стендов."
fi
NEW_VER="$(dpkg-deb -f "$DEB" Version 2>/dev/null || true)"
if [ -z "$NEW_VER" ]; then
  # dpkg-deb нет на macOS: версию берём из имени tgproxy_<ver>_amd64.deb
  b="$(basename "$DEB")"; b="${b#tgproxy_}"; NEW_VER="${b%_amd64.deb}"
fi
[ -n "$NEW_VER" ] || die "не удалось определить версию $DEB"
log "версия к установке: $NEW_VER"

# ---------- 2. состояние сервера ----------
SRV() { rssh "$PROD_SERVER_HOST" "$PROD_SERVER_SSH_USER" "$@"; }
bootstrap_checklist() {
  cat >&2 <<MSG

Сервер не забутстраплен ($1). Скрипт НЕ делает первичную настройку молча (ключи и пароли
не должны проходить через автоматизацию). Выполните на $PROD_SERVER_HOST вручную:
  1. sudo dpkg -i tgproxy_*.deb              # если пакет не установлен
  2. правка /etc/tgproxy/server.yaml (public_base_url, tls, access_rules), затем
     tgproxy config validate --mode server -c /etc/tgproxy/server.yaml
  3. sudo tgproxy pki kek-init --out /etc/tgproxy/kek && sudo chown tgproxy:tgproxy /etc/tgproxy/kek
     (скопируйте KEK в офлайн-хранилище: без него БД с CA и TOTP не расшифровать)
  4. sudo runuser -u tgproxy -- tgproxy pki init -c /etc/tgproxy/server.yaml
  5. пользователи: tgproxy hashpw -> /etc/tgproxy/users_database.yml (root:tgproxy 0640)
  6. TOTP: sudo tgproxy totp enroll <user>   # totp_secret_enc в users_database.yml
  7. sudo systemctl enable --now tgproxy-server
Подробности: README.md, раздел «Быстрый старт сервера». Затем запустите деплой снова.
MSG
  exit 1
}

log "проверка сервера $PROD_SERVER_HOST"
cur="$(SRV "dpkg-query -W -f='\${Status}|\${Version}' tgproxy 2>/dev/null || true")"
case "$cur" in
  "install ok installed|"*) CUR_VER="${cur#*|}" ;;
  *) bootstrap_checklist "пакет tgproxy не установлен" ;;
esac
SRV "sudo -n test -f /etc/tgproxy/kek" || bootstrap_checklist "нет /etc/tgproxy/kek"
log "установлено: $CUR_VER"

# ---------- 3. даунгрейд + загрузка ----------
if [ "${DEPLOY_ALLOW_DOWNGRADE:-0}" != 1 ] && SRV "dpkg --compare-versions '$CUR_VER' gt '$NEW_VER'"; then
  die "$NEW_VER ниже установленной $CUR_VER (min_version/даунгрейд). Для осознанного отката: DEPLOY_ALLOW_DOWNGRADE=1"
fi
REMOTE_TMP="$(SRV 'mktemp -d')"
case "$REMOTE_TMP" in /tmp/tmp.*|/tmp/*) ;; *) die "неожиданный временный каталог: $REMOTE_TMP" ;; esac
REMOTE_DEB="$REMOTE_TMP/$(basename "$DEB")"
log "scp -> $REMOTE_DEB"
rscp "$DEB" "$PROD_SERVER_SSH_USER@$PROD_SERVER_HOST:$REMOTE_DEB"

# ---------- 4. установка ----------
log "dpkg -i + restart tgproxy-server"
SRV "sudo -n dpkg -i '$REMOTE_DEB' && sudo -n systemctl restart tgproxy-server"
got_ver="$(SRV "dpkg-query -W -f='\${Version}' tgproxy")"
[ "$got_ver" = "$NEW_VER" ] || die "после установки версия $got_ver, ожидалась $NEW_VER"
SRV "systemctl is-active --quiet tgproxy-server" || die "tgproxy-server не active (journalctl -u tgproxy-server)"

# ---------- 5. health ----------
wait_ok() { # path
  local url="$ADMIN_URL$1" end=$((SECONDS + HEALTH_TIMEOUT))
  while :; do
    if curl -fsS --max-time 5 -o /dev/null "$url" 2>/dev/null; then log "OK $url"; return 0; fi
    [ "$SECONDS" -ge "$end" ] && return 1
    sleep 1
  done
}
wait_ok /healthz || die "$ADMIN_URL/healthz не ответил 200 за ${HEALTH_TIMEOUT}s"
wait_ok /readyz  || die "$ADMIN_URL/readyz: нет ни одного агента up за ${HEALTH_TIMEOUT}s"

# ---------- 6. агенты (только чтение) ----------
rc=0
for h in ${PROD_AGENT_HOSTS:-}; do
  st="$(rssh "$h" "$AGENT_USER" "systemctl is-active tgproxy-agent; dpkg-query -W -f='\${Version}' tgproxy" 2>&1 | tr '\n' ' ' || true)"
  case "$st" in
    active\ *) log "агент $h: $st" ;;
    *) warn "агент $h: $st"; rc=1 ;;
  esac
done

# ---------- 7. агенты: что дальше ----------
if [ "$MODE" = release ]; then
  log "сервер $NEW_VER обновлён. Агентов обновите из UI «Система -> Обновления» (канарейка -> батчи): сервер скачает подписанный релиз с GitHub."
else
  warn "snapshot не подписан: агенты не обновлены и не примут этот пакет (проверка подписи на агенте — по замыслу)."
fi
[ "$rc" = 0 ] || die "часть агентов не active"
log "деплой завершён: $NEW_VER"
