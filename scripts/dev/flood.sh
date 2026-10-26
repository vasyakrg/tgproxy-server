#!/usr/bin/env bash
# Нагрузка на один чат через прокси: показывает момент, когда Telegram отвечает 429
# и сервер начинает отвечать 429 сам (окно (bot, chat)) без похода к агенту.
#
# Использование: scripts/dev/flood.sh [N=60] [PROXY=http://127.0.0.1:8080]
# Токен и чат — из dev/.env (TGP_DEV_BOT_TOKEN, TGP_DEV_CHAT_ID); токен не выводится.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
n="${1:-60}"
proxy="${2:-http://127.0.0.1:8080}"

if [[ ! -f "$root/dev/.env" ]]; then
  echo "нет dev/.env (шаблон: dev/.env.example)" >&2
  exit 1
fi
set -a
# shellcheck disable=SC1091
. "$root/dev/.env"
set +a
: "${TGP_DEV_BOT_TOKEN:?TGP_DEV_BOT_TOKEN не задан в dev/.env}"
: "${TGP_DEV_CHAT_ID:?TGP_DEV_CHAT_ID не задан в dev/.env}"

body="$(mktemp)"
tally="$(mktemp)"
trap 'rm -f "$body" "$tally"' EXIT

first_429=""
first_local=""

for ((i = 1; i <= n; i++)); do
  # -w выводит только код и время; токен остаётся внутри URL и в вывод не попадает
  out="$(curl -s -o "$body" -w '%{http_code} %{time_total}' \
    --data-urlencode "chat_id=${TGP_DEV_CHAT_ID}" \
    --data-urlencode "text=flood ${i}/${n}" \
    "${proxy}/bot${TGP_DEV_BOT_TOKEN}/sendMessage" || echo '000 0')"
  code="${out%% *}"
  t="${out##* }"
  echo "$code" >>"$tally"
  retry="$(grep -o '"retry_after":[0-9]*' "$body" | head -1 | cut -d: -f2 || true)"
  if [[ "$code" == 429 ]]; then
    if [[ -z "$first_429" ]]; then
      first_429="$i"
      echo "#$i: первый 429 от Telegram через агента (retry_after=${retry:-?}, ${t}s)"
    elif [[ -z "$first_local" ]]; then
      first_local="$i"
      echo "#$i: 429 отвечает сам сервер, без похода к агенту (retry_after=${retry:-?}, ${t}s)"
    fi
  fi
done

echo "--- итоги (${n} запросов):"
sort "$tally" | uniq -c | awk '{printf "  %s: %s\n", $2, $1}'
if [[ -z "$first_429" ]]; then
  echo "429 не получено: увеличьте N (лимит Telegram — ~1 сообщение/с на чат)"
fi
