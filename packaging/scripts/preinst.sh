#!/bin/sh
# tgproxy preinst: системный пользователь tgproxy (идемпотентно).
set -e

case "$1" in
install|upgrade)
    if ! getent group tgproxy >/dev/null 2>&1; then
        addgroup --system tgproxy >/dev/null 2>&1 || groupadd --system tgproxy
    fi
    if ! getent passwd tgproxy >/dev/null 2>&1; then
        adduser --system --ingroup tgproxy --no-create-home --home /var/lib/tgproxy \
            --shell /usr/sbin/nologin --gecos "tgproxy service" tgproxy >/dev/null 2>&1 ||
            useradd --system --gid tgproxy --no-create-home --home-dir /var/lib/tgproxy \
                --shell /usr/sbin/nologin --comment "tgproxy service" tgproxy
    fi
    ;;
abort-upgrade) ;;
*)
    echo "preinst called with unknown argument '$1'" >&2
    exit 1
    ;;
esac

exit 0
