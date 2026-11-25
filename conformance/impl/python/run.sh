#!/bin/sh
# Run the conformance suite against the reference (Python) implementation.
#   SP_PYTHON=/path/to/python3 conformance/impl/python/run.sh [run.py options, e.g. --component ledger -v]
# The interpreter needs PyYAML (YAML configs, as in production). Known deviations of the reference implementation are
# listed in expected-failures.txt: those cases describe the TARGET behaviour and must pass in a new implementation.
HERE=$(cd "$(dirname "$0")" && pwd)
for c in ledger remediation scorecard runner cli collector-cloud collector-agent-claude-code collector-k8s collector-vuln-intel \
         collector-identity collector-exposure collector-codehost-github collector-codehost-gitea collector-detection events; do
  v=SP_IMPL_$(echo "$c" | tr 'a-z-' 'A-Z_')
  eval "[ -n \"\${$v}\" ] || export $v=\"\$HERE/$c\""
done
# not Python at all: the protocol's example collector in POSIX sh
[ -n "${SP_IMPL_COLLECTOR_EXAMPLE:-}" ] || export SP_IMPL_COLLECTOR_EXAMPLE="$HERE/../../../contracts/collector-protocol/examples/collector.sh"
exec "${SP_PYTHON:-python3}" "$HERE/../../run.py" --require-all --expected-failures "$HERE/expected-failures.txt" "$@"
