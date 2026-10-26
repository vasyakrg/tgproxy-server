#!/bin/sh
# Ждёт enrollment (команда из UI «Агент за NAT» или TGP_ENROLL_TOKEN в окружении),
# затем запускает агента. Слушающих портов агент в режиме reverse не открывает.
set -eu
CFG=/etc/tgproxy/agent.yaml
CRT=/var/lib/tgproxy/agent/agent.crt

if [ ! -f "$CRT" ] && [ -n "${TGP_ENROLL_TOKEN:-}" ]; then
  tgproxy agent enroll --server "${TGP_SERVER_URL:?TGP_SERVER_URL}" \
    --ca-fingerprint "${TGP_CA_FINGERPRINT:?TGP_CA_FINGERPRINT}" -c "$CFG"
fi

while [ ! -f "$CRT" ]; do
  echo "nat-agent: жду enrollment: docker compose -f dev/docker-compose.yml exec -e TGP_ENROLL_TOKEN=<токен> nat-agent tgproxy agent enroll --server https://host.docker.internal:8444 --ca-fingerprint <SHA256:...>"
  sleep 5
done
exec tgproxy agent -c "$CFG"
