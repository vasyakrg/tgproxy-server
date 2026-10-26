# nat-agent: агент в reverse-режиме без опубликованных портов (только dev).
# Бинарь linux кладёт `make dev-target-up` (bin/tgproxy-linux -> dev/nat-agent/tgproxy).
FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /etc/tgproxy /var/lib/tgproxy
COPY tgproxy /usr/local/bin/tgproxy
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/tgproxy /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
