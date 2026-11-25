# security-platform runner image: the runner, core, collectors and adapters (stdlib + PyYAML) plus kubectl for the
# in-cluster k8s collector, and the `sp` Go binary (docs/go.md) at /usr/local/bin/sp, which runs the components that
# moved to Go and hands everything else to the Python implementation in /opt/security-platform. Heavy scanners
# (trivy, nmap, kube-bench) are NOT in this image: those collectors run on hosts that have them (see docs/runner.md).
# Runs as non-root (65532), read-only root filesystem friendly (nothing is written outside mounted volumes).
#
# Build arguments: VERSION = the commit (the image workflow passes its short hash), RELEASE = the product release
# vX.Y.Z when the image is built from a product tag (empty: a development build, named dev-g<VERSION>). Both go into
# /opt/security-platform/RELEASE, which `sp version` and security_runner_info{release} report.
#
# Targets: the default (last stage) is the runner image described above. `--target sp-static` is the Go-only image for
# when the runner's components have moved: distroless/static, the binary alone.

# ---- the sp binary: built natively for the target platform, static, reproducible ------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27.4@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS sp-build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG RELEASE=""
WORKDIR /src
COPY go.mod go.sum ./
# modules checked against go.sum (and the checksum database); a separate layer so code changes reuse it
RUN GOTOOLCHAIN=local GOFLAGS=-mod=readonly go mod download && go mod verify
COPY cmd cmd
COPY internal internal
# no .git in the build: VCS facts come from the RELEASE file instead; GOTOOLCHAIN=local: the image's Go, no download
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOTOOLCHAIN=local GOFLAGS=-mod=readonly \
    go build -trimpath -buildvcs=false \
      -ldflags="-buildid= -X github.com/MIERAI/security-platform/internal/buildinfo.productRelease=${RELEASE}" \
      -o /out/sp ./cmd/sp
# RELEASE file: version= (the product tag, or dev-g<commit>), commit=
ARG VERSION=dev
RUN set -eu; \
    rel="$RELEASE"; [ -n "$rel" ] || rel="dev-g$VERSION"; \
    case "$rel$VERSION" in *[!0-9A-Za-z.+-]*) echo "refusing RELEASE='$RELEASE' VERSION='$VERSION'" >&2; exit 1;; esac; \
    if [ -n "$RELEASE" ]; then echo "$RELEASE" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$' \
      || { echo "RELEASE='$RELEASE' is not a product tag vX.Y.Z" >&2; exit 1; }; fi; \
    printf 'version=%s\ncommit=%s\n' "$rel" "$VERSION" > /out/RELEASE

# ---- Go-only image (opt-in target) ------------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5 AS sp-static
COPY --from=sp-build /out/sp /usr/local/bin/sp
LABEL org.opencontainers.image.title="security-platform-sp" org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/sp"]
CMD ["version"]

# ---- the runner image (default target) --------------------------------------------------------------------------
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
COPY LICENSE NOTICE README.md CHANGELOG.md ./
COPY runner runner
COPY core core
COPY sdk sdk
COPY adapters adapters
COPY collectors collectors
COPY events events
COPY cli cli
COPY notifier notifier
COPY generators generators
COPY scorecard scorecard
COPY schema schema
COPY deploy deploy
# evidence the scorecard reads on an in-cluster hub (docs, examples, generated dashboards, the e2e result, tests that
# enforce contracts and plain language): documents only, nothing here is executed by the runner
COPY bin bin
COPY dist dist
COPY docs docs
COPY examples examples
COPY e2e e2e
COPY tests tests
COPY --from=sp-build /out/RELEASE RELEASE
COPY --from=sp-build /out/sp /usr/local/bin/sp
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SP_IMAGE_VERSION=${VERSION} SP_PY_HOME=/opt/security-platform
LABEL org.opencontainers.image.title="security-platform" org.opencontainers.image.licenses="Apache-2.0"
USER 65532:65532
ENTRYPOINT ["python3", "/opt/security-platform/runner/runner.py"]
CMD ["version"]
