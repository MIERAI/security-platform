# security-platform runner image: the runner, core, collectors and adapters (stdlib + PyYAML) plus kubectl for the
# in-cluster k8s collector. Heavy scanners (trivy, nmap, kube-bench) are NOT in this image: those collectors run on
# hosts that have them (see docs/runner.md). Runs as non-root (65532), read-only root filesystem friendly.
FROM python:3.13-slim@sha256:6d68eb6310a906f26c7638eb6ea7557d4261662df3181af2f80f1f9a7e34c549
ARG TARGETARCH=amd64
ARG KUBECTL_VERSION=v1.36.5
ARG KUBECTL_SHA256_amd64=33bc88a24c3b09cf55bfd59e6ca977881b61fc3f25ab65bc80c65b430248648e
ARG KUBECTL_SHA256_arm64=88fc1aca8fd0c1b44fe379f67c39bd6858bdfc50241dc55775f84d0f5b31da3a
ARG VERSION=dev
COPY deploy/requirements.lock /tmp/requirements.lock
RUN set -eu; \
    python3 -c "import urllib.request; urllib.request.urlretrieve('https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl', '/usr/local/bin/kubectl')"; \
    want=$(eval echo \${KUBECTL_SHA256_${TARGETARCH}}); echo "$want  /usr/local/bin/kubectl" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/kubectl; \
    pip install --no-cache-dir --require-hashes -r /tmp/requirements.lock; rm /tmp/requirements.lock   # = --require-hashes -r deploy/requirements.lock
WORKDIR /opt/security-platform
COPY LICENSE NOTICE README.md ./
COPY runner runner
COPY core core
COPY sdk sdk
COPY adapters adapters
COPY collectors collectors
COPY generators generators
COPY schema schema
COPY deploy deploy
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SP_IMAGE_VERSION=${VERSION}
LABEL org.opencontainers.image.title="security-platform" org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
ENTRYPOINT ["python3", "/opt/security-platform/runner/runner.py"]
CMD ["version"]
