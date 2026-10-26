#!/bin/sh
# tgproxy postrm: daemon-reload; при purge — удалить данные, конфиги и пользователя.
set -e

systemd_running() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

case "$1" in
remove|upgrade|disappear)
    if systemd_running; then
        systemctl daemon-reload || true
    fi
    ;;
purge)
    if systemd_running; then
        systemctl daemon-reload || true
    fi
    rm -rf /var/lib/tgproxy /var/lib/tgproxy-incoming /etc/tgproxy
    if getent passwd tgproxy >/dev/null 2>&1; then
        deluser --system tgproxy >/dev/null 2>&1 || userdel tgproxy >/dev/null 2>&1 || true
    fi
    if getent group tgproxy >/dev/null 2>&1; then
        delgroup --system tgproxy >/dev/null 2>&1 || groupdel tgproxy >/dev/null 2>&1 || true
    fi
    ;;
failed-upgrade|abort-install|abort-upgrade) ;;
*)
    echo "postrm called with unknown argument '$1'" >&2
    exit 1
    ;;
esac

exit 0
