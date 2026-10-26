#!/bin/sh
# tgproxy prerm: при remove — остановить и отключить юниты. При upgrade — ничего.
set -e

systemd_running() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

case "$1" in
remove|deconfigure)
    if systemd_running; then
        systemctl disable --now tgproxy-update-server.path tgproxy-update-agent.path tgproxy-server.service tgproxy-agent.service >/dev/null 2>&1 || true
        systemctl stop tgproxy-update-server.service tgproxy-update-agent.service >/dev/null 2>&1 || true
    fi
    ;;
upgrade|failed-upgrade) ;;
*)
    echo "prerm called with unknown argument '$1'" >&2
    exit 1
    ;;
esac

exit 0
