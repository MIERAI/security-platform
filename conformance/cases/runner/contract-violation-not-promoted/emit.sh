#!/bin/sh
# a fake collector: copies a fixture findings document into the run directory (collector-protocol output)
set -e
[ -n "$EMIT_SLEEP" ] && sleep "$EMIT_SLEEP"
[ -n "$EMIT_MARK" ] && echo "$SP_RUN_DIR" >> "$EMIT_MARK"
[ -n "$EMIT_ENV" ] && env | grep -E '^(SP_|MY_)' | sort > "$EMIT_ENV"
[ -n "$EMIT_FAIL" ] && exit "$EMIT_FAIL"
cp "$EMIT_DOC" "$SP_RUN_DIR/${EMIT_AS:-host}.findings.json"
