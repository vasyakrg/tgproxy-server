# Тестовая цель для SSH-установщика (M5). Только dev.
FROM debian:12
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && useradd -m -s /bin/bash deploy \
 && echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy \
 && echo 'deploy:deploy' | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
