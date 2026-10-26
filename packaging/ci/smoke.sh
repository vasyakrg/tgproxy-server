#!/usr/bin/env bash
# Smoke-тест deb в контейнере debian:12 с systemd (PID 1).
# Запуск: packaging/ci/smoke.sh [путь/к/tgproxy_*.deb]   (по умолчанию dist/tgproxy_*_amd64.deb)
# Порог systemd-analyze security: SECURITY_MAX (по умолчанию 2.0).
set -euo pipefail

cd "$(dirname "$0")/../.."
HOST_ARCH="$(docker info --format '{{.Architecture}}')"
case "$HOST_ARCH" in
  x86_64) PLATFORM="linux/amd64" ;;
  aarch64|arm64) PLATFORM="linux/arm64" ;;
  *) echo "неподдерживаемая архитектура docker: $HOST_ARCH" >&2; exit 1 ;;
esac

if [ -n "${1:-}" ]; then
  DEB="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
else
  DEB="$(packaging/ci/native-deb.sh)"
fi
[ -f "$DEB" ] || { echo "deb не найден: $DEB" >&2; exit 1; }
IMAGE="tgproxy-smoke-systemd:local"
NAME="tgproxy-smoke-$$"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q --platform "$PLATFORM" -t "$IMAGE" -f packaging/ci/Dockerfile.systemd packaging/ci >/dev/null

docker run -d --platform "$PLATFORM" --name "$NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -v "$DEB:/pkg/tgproxy.deb:ro" \
  -v "$PWD/packaging/ci/smoke-inner.sh:/smoke-inner.sh:ro" \
  -e SECURITY_MAX="${SECURITY_MAX:-2.0}" \
  "$IMAGE" /sbin/init >/dev/null

# systemd готов?
for _ in $(seq 1 60); do
  state="$(docker exec "$NAME" systemctl is-system-running 2>/dev/null || true)"
  case "$state" in running|degraded) break ;; esac
  sleep 1
done
echo "systemd state: ${state:-unknown}"
case "${state:-}" in running|degraded) ;; *) docker logs "$NAME" | tail -30; exit 1 ;; esac

docker exec -e SECURITY_MAX="${SECURITY_MAX:-2.0}" "$NAME" bash /smoke-inner.sh
