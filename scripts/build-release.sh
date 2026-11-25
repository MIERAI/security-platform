#!/usr/bin/env bash
# Reproducible release build of the sp binary for every published platform, plus SHA256SUMS.
# usage: scripts/build-release.sh <release name> <output dir>
#   <release name>  vX.Y.Z[-PRE] for a release (linked into the binary: `sp version`), anything else for a
#                   development build (the binary then calls itself dev-g<commit>)
#   <output dir>    created; must not exist yet
# The same commit and toolchain (go.mod `toolchain`) give byte-identical binaries on any host: no cgo, no file
# paths (-trimpath), no build id, VCS facts from the commit (-buildvcs). Users can rebuild and compare checksums
# (docs/install.md).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REL=${1:?usage: build-release.sh <release name> <output dir>}
OUT=${2:?usage: build-release.sh <release name> <output dir>}
[[ $REL =~ ^[0-9A-Za-z][0-9A-Za-z.+-]*$ ]] || { echo "build-release: refusing release name '$REL'" >&2; exit 2; }
[[ ! -e $OUT ]] || { echo "build-release: $OUT exists" >&2; exit 2; }
want=$(awk '$1 == "toolchain" {print $2}' "$ROOT/go.mod")
got=$(cd "$ROOT" && go env GOVERSION)
[[ $want == "$got" ]] || { echo "build-release: go.mod wants $want, this is $got" >&2; exit 2; }
if [[ -n $(git -C "$ROOT" status --porcelain --untracked-files=no) ]]; then
  echo "build-release: note: uncommitted changes; the binaries record vcs.modified=true and call themselves dev" >&2
fi

PLATFORMS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 android/arm64)
LDFLAGS="-buildid= -X github.com/MIERAI/security-platform/internal/buildinfo.productRelease=$REL"
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
for p in "${PLATFORMS[@]}"; do
  os=${p%/*} arch=${p#*/} ext=''
  [[ $os == windows ]] && ext=.exe
  name="sp-$REL-$os-$arch$ext"
  (cd "$ROOT" && env -u GOFLAGS CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -buildvcs=true -ldflags="$LDFLAGS" -o "$OUT/$name" ./cmd/sp)
  echo "built $name" >&2
done
cd "$OUT"
if command -v sha256sum >/dev/null; then sha256sum sp-*; else shasum -a 256 sp-*; fi > SHA256SUMS
cat SHA256SUMS
