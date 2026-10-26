#!/bin/sh
# tgproxy postinst: daemon-reload; при upgrade — try-restart активных юнитов.
# При первой установке ничего не включается и не запускается.
set -e

systemd_running() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

case "$1" in
configure)
    # Права каталогов/файлов не зависят от umask установщика и от предыдущих версий.
    chown root:tgproxy /etc/tgproxy
    chmod 0750 /etc/tgproxy
    chown tgproxy:tgproxy /var/lib/tgproxy
    chmod 0750 /var/lib/tgproxy

    # Доверенный кэш пакетов (root:root 0755) — вне /var/lib/tgproxy: тот каталог принадлежит
    # tgproxy, и сервис мог бы подменить в нём каталог. Пишут только root-процессы
    # (`tgproxy update apply`, `deploy-helper stage`) после проверки minisign.
    install -d -m 0755 -o root -g root /var/cache/tgproxy /var/cache/tgproxy/packages
    # Прежнее расположение кэша (внутри каталога tgproxy) больше не используется и не доверяется.
    rm -rf /var/lib/tgproxy/packages
    # Приём от tgproxy-deploy (0730). incoming вне /var/lib/tgproxy:
    # тот каталог 0750 tgproxy:tgproxy, deploy в него не заходит.
    if getent group tgproxy-deploy >/dev/null 2>&1; then
        install -d -m 0730 -o root -g tgproxy-deploy /var/lib/tgproxy-incoming
    else
        install -d -m 0700 -o root -g root /var/lib/tgproxy-incoming
    fi

    if systemd_running; then
        systemctl daemon-reload || true
        if [ -n "$2" ]; then
            # upgrade: перезапускаем только то, что уже запущено
            systemctl try-restart tgproxy-server.service tgproxy-agent.service tgproxy-update-server.path tgproxy-update-agent.path || true
        fi
    fi

    if [ -z "$2" ]; then
        cat <<'MSG'
tgproxy установлен. Автозапуск НЕ включён.
  1. Отредактируйте /etc/tgproxy/server.yaml (сервер) или /etc/tgproxy/agent.yaml (агент).
  2. Проверка:  tgproxy config validate --mode server -c /etc/tgproxy/server.yaml
  3. Запуск:    systemctl enable --now tgproxy-server   (или tgproxy-agent)
  4. Самообновление (по желанию): systemctl enable --now tgproxy-update-server.path   (или tgproxy-update-agent.path на агенте;
     путь агента рассчитан на data_dir=/var/lib/tgproxy/agent — иначе переопределите юнит drop-in'ом)
MSG
    fi
    ;;
abort-upgrade|abort-remove|abort-deconfigure) ;;
*)
    echo "postinst called with unknown argument '$1'" >&2
    exit 1
    ;;
esac

exit 0
