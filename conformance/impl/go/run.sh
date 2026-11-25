#!/bin/sh
# Run the conformance suite against the Go implementation of the components that have one (docs/go.md):
# ledger (`sp ledger merge`), remediation (`sp ledger track`), cli (`sp init|doctor|run|status|findings|explain|
# digest|notify`), the collectors exposure, codehost-github, codehost-gitea, agent-claude-code and detection
# (`sp <collector> collect`), the events shipper (`sp events ship`) and the exec-adapter collectors
# (`sp host|host-sbom|secrets-files collect`). No expected-failures list: the target-behaviour cases of the known
# deviations must pass. The cli cases need the product tree (this checkout).
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
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac   # the cases run in their sandboxes
status=0
SP_IMPL_LEDGER="$BIN ledger merge" SP_IMPL_REMEDIATION="$BIN ledger track" SP_IMPL_CLI="$ROOT/conformance/impl/go/cli" \
  SP_IMPL_COLLECTOR_HOST="$BIN host collect" SP_IMPL_COLLECTOR_HOST_SBOM="$BIN host-sbom collect" \
  SP_IMPL_COLLECTOR_SECRETS_FILES="$BIN secrets-files collect" \
  SP_GO_SP="$BIN" SP_PY_HOME="$ROOT" TZ=UTC \
  "${SP_PYTHON:-python3}" "$ROOT/conformance/run.py" --require-all --component ledger --component remediation \
  --component cli --component collector-host --component collector-host-sbom --component collector-secrets-files \
  "$@" || status=$?
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
