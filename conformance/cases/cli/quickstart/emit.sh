#!/bin/sh
# a fake collector: copies a fixture findings document into the run directory (collector-protocol output)
set -e
[ -n "$EMIT_FAIL" ] && { echo "emit: failing on purpose" >&2; exit "$EMIT_FAIL"; }
cp "$EMIT_DOC" "$SP_RUN_DIR/${SP_COLLECTOR_NAME:-host}.findings.json"
