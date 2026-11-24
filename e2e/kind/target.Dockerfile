# A plain Linux server of the fictional company: sshd, key-only login for the auditor account, sudo for read-only
# inspection. HARDEN=no leaves password authentication on (the finding the e2e test expects on one host).
FROM debian:bookworm-slim
ARG HARDEN=yes
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      openssh-server sudo iproute2 procps python3 >/dev/null && rm -rf /var/lib/apt/lists/* \
 && useradd -m -s /bin/bash auditor && echo 'auditor ALL=(root) NOPASSWD: ALL' > /etc/sudoers.d/auditor \
 && mkdir -p /run/sshd /home/auditor/.ssh && chmod 700 /home/auditor/.ssh && chown auditor:auditor /home/auditor/.ssh \
 && if [ "$HARDEN" = yes ]; then printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin no\n' > /etc/ssh/sshd_config.d/10-hardening.conf; \
    else printf 'PasswordAuthentication yes\nPermitRootLogin yes\n' > /etc/ssh/sshd_config.d/10-legacy.conf; fi
# the auditor's public key is mounted at start (e2e/kind/run.sh), host keys are generated per container
CMD ["sh", "-c", "ssh-keygen -A >/dev/null && install -o auditor -m 600 /keys/auditor.pub /home/auditor/.ssh/authorized_keys && exec /usr/sbin/sshd -D -e"]
