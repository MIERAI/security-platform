#!/bin/sh
# Run the conformance suite against the Go implementation of the components that have one (docs/go.md):
# ledger (`sp ledger merge`) and remediation (`sp ledger track`). No expected-failures list: the target-behaviour
# cases of the known deviations (LEDGER-D1..D5) must pass.
#   conformance/impl/go/run.sh [run.py options, e.g. -v]           builds cmd/sp with the go toolchain first
#   SP_GO_BIN=/path/to/sp conformance/impl/go/run.sh               uses that binary
# The harness needs Python 3.10+ ($SP_PYTHON, default python3); the Go implementation needs nothing else.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
BIN=${SP_GO_BIN:-}
TMP=
if [ -z "$BIN" ]; then
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  (cd "$ROOT" && go build -trimpath -o "$TMP/sp" ./cmd/sp)
  BIN=$TMP/sp
fi
status=0
SP_IMPL_LEDGER="$BIN ledger merge" SP_IMPL_REMEDIATION="$BIN ledger track" \
  "${SP_PYTHON:-python3}" "$ROOT/conformance/run.py" --require-all --component ledger --component remediation "$@" || status=$?
exit "$status"
