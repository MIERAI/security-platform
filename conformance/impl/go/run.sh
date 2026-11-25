#!/bin/sh
# Run the conformance suite against the Go implementation of the components that have one (docs/go.md):
# ledger (`sp ledger merge`), remediation (`sp ledger track`), the collectors exposure, codehost-github,
# codehost-gitea, agent-claude-code and detection (`sp <collector> collect`) and the events shipper (`sp events
# ship`). No expected-failures list: the target-behaviour cases of the known deviations must pass.
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
# the collectors read the product tree (detections/catalog.yaml) through SP_PY_HOME, as an installed sp finds it
SP_PY_HOME=${SP_PY_HOME:-$ROOT} \
SP_IMPL_COLLECTOR_EXPOSURE="$BIN exposure collect" SP_IMPL_COLLECTOR_CODEHOST_GITHUB="$BIN codehost-github collect" \
SP_IMPL_COLLECTOR_CODEHOST_GITEA="$BIN codehost-gitea collect" \
SP_IMPL_COLLECTOR_AGENT_CLAUDE_CODE="$BIN agent-claude-code collect" SP_IMPL_COLLECTOR_DETECTION="$BIN detection collect" \
SP_IMPL_EVENTS="$BIN events ship" \
  "${SP_PYTHON:-python3}" "$ROOT/conformance/run.py" --require-all --component collector-exposure \
  --component collector-codehost-github --component collector-codehost-gitea --component collector-agent-claude-code \
  --component collector-detection --component events "$@" || status=$?
exit "$status"
