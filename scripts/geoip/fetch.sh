#!/usr/bin/env bash
# Скачивает актуальную DB-IP «IP to Country Lite» (CC BY 4.0) для сборки релиза.
# Использование: scripts/geoip/fetch.sh [выходной файл]
# По умолчанию: build/geoip/dbip-country-lite.mmdb (в git не коммитится).
# Файл публикуется раз в месяц: пробуем текущий месяц, затем предыдущий.
# Атрибуция: IP Geolocation by DB-IP — https://db-ip.com
set -euo pipefail

OUT="${1:-build/geoip/dbip-country-lite.mmdb}"
BASE="https://download.db-ip.com/free"
MIN_SIZE=1000000 # реальная база ≈ 4-8 МБ; меньше — подмена/ошибка

mkdir -p "$(dirname "$OUT")"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

month_ago() { # $1 = сколько месяцев назад; GNU date и BSD date
	date -u -d "-$1 month" +%Y-%m 2>/dev/null || date -u -v-"$1"m +%Y-%m
}

ok=""
for back in 0 1 2; do
	ym="$(month_ago "$back")"
	url="$BASE/dbip-country-lite-$ym.mmdb.gz"
	echo "fetch: $url" >&2
	if curl -fsSL --proto '=https' --tlsv1.2 --retry 3 -o "$tmp/db.mmdb.gz" "$url"; then
		ok="$ym"
		break
	fi
done
[ -n "$ok" ] || { echo "fetch: не удалось скачать базу DB-IP" >&2; exit 1; }

gunzip -c "$tmp/db.mmdb.gz" >"$tmp/db.mmdb"
size="$(wc -c <"$tmp/db.mmdb" | tr -d ' ')"
[ "$size" -ge "$MIN_SIZE" ] || { echo "fetch: файл слишком мал ($size байт)" >&2; exit 1; }

# Валидность mmdb: метаданные MaxMind DB заканчивают файл маркером \xAB\xCD\xEFMaxMind.com.
if ! LC_ALL=C grep -aq $'\xab\xcd\xef''MaxMind.com' "$tmp/db.mmdb"; then
	echo "fetch: нет маркера метаданных MaxMind DB — это не mmdb" >&2
	exit 1
fi
# Настоящим читателем (тот же код, что в сервере).
go run ./scripts/geoip/check "$tmp/db.mmdb" || { echo "fetch: проверка mmdb не прошла" >&2; exit 1; }

mv "$tmp/db.mmdb" "$OUT"
chmod 0644 "$OUT"
echo "fetch: $OUT ($ok, $size байт)" >&2
