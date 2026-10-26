#!/usr/bin/env bash
# Печатает абсолютный путь к deb под архитектуру docker-хоста (собирает при необходимости).
# На Apple Silicon релизный deb (amd64) под Rosetta не проходит hardening юнитов (скрыт /proc/sys),
# поэтому для ЛОКАЛЬНЫХ проверок собирается такой же deb под arm64 в dist-smoke-arm64. В релиз arm64 не входит.
set -euo pipefail
cd "$(dirname "$0")/../.."

case "$(docker info --format '{{.Architecture}}')" in
  x86_64)
    [ -n "$(ls dist/tgproxy_*_amd64.deb 2>/dev/null)" ] || goreleaser release --snapshot --clean --skip=sign,archive >/dev/null
    DEB="$(ls dist/tgproxy_*_amd64.deb | head -n1)"
    ;;
  aarch64|arm64)
    sed '/^    ignore:/,+2d' .goreleaser.yaml | sed '1a\
dist: dist-smoke-arm64' > .goreleaser.smoke-arm64.yaml
    trap 'rm -f .goreleaser.smoke-arm64.yaml' EXIT
    goreleaser release -f .goreleaser.smoke-arm64.yaml --snapshot --clean --skip=sign,archive >/dev/null
    DEB="$(ls dist-smoke-arm64/tgproxy_*_arm64.deb | head -n1)"
    ;;
  *) echo "неподдерживаемая архитектура docker" >&2; exit 1 ;;
esac
[ -f "$DEB" ] || { echo "deb не найден: $DEB" >&2; exit 1; }
echo "$(cd "$(dirname "$DEB")" && pwd)/$(basename "$DEB")"
