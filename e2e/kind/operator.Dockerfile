# The fictional company's operator workstation: a clean Linux box with only what docs/quickstart.md asks for
# (python3, git, ssh, nmap, kubectl). The platform itself is NOT in this image: run.sh installs it from the public
# repository inside the container, exactly as the quickstart says.
FROM python:3.13-slim
ARG KUBECTL_VERSION=v1.34.2
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      git openssh-client nmap curl ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/* \
 && arch=$(dpkg --print-architecture) \
 && curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${arch}/kubectl" \
 && chmod 755 /usr/local/bin/kubectl && useradd -m -s /bin/bash ops
USER ops
WORKDIR /home/ops
CMD ["sleep", "infinity"]
