#!/bin/sh
# A complete collector in POSIX sh, to show that the collector protocol (contracts/collector-protocol/SPEC.md) needs no
# SDK and no particular language. It reports files that anyone may write to.
#
#   inputs : SP_RUN_DIR (required), EXAMPLE_FILES (colon-separated paths, from the job's `env:`),
#            EXAMPLE_HOST (asset scope, default: short host name), SP_COLLECTOR_NAME (default example-files)
#   output : $SP_RUN_DIR/<name>.findings.json (findings/1.2), evidence under $SP_RUN_DIR/raw/<name>/
#   exit   : 0 = document written (gaps included); 2 = usage error (no document)
# Run it from the runner as a `command` job: {type: command, collector: example-files, argv: [/path/collector.sh], ...}
set -eu
: "${SP_RUN_DIR:?SP_RUN_DIR not set}"
NAME=${SP_COLLECTOR_NAME:-example-files}
HOST=${EXAMPLE_HOST:-$(hostname | cut -d. -f1 | tr 'A-Z' 'a-z')}
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
sha12() { if command -v sha1sum >/dev/null 2>&1; then printf '%s' "$1" | sha1sum | cut -c1-12
          else printf '%s' "$1" | shasum -a 1 | cut -c1-12; fi; }
json() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }     # paths and words only: no control characters

STARTED=$(now)
mkdir -p "$SP_RUN_DIR/raw/$NAME"
COV="" FIND="" SEP1="" SEP2=""
OLDIFS=$IFS; IFS=:
for f in ${EXAMPLE_FILES:-}; do
  IFS=$OLDIFS
  asset="file:$HOST:$f"
  if [ ! -e "$f" ]; then
    COV="$COV$SEP1{\"asset\": \"$(json "$asset")\", \"status\": \"gap\", \"reason\": \"not found\"}"; SEP1=", "
    continue
  fi
  COV="$COV$SEP1{\"asset\": \"$(json "$asset")\", \"status\": \"ok\"}"; SEP1=", "
  perms=$(ls -ld "$f" | cut -c1-10)
  echo "$f $perms" >> "$SP_RUN_DIR/raw/$NAME/modes.txt"     # evidence: metadata only, never file contents
  case "$perms" in
    ????????w?)
      check=example.world_writable_file layer=data-secrets
      id=$(sha12 "$layer|$asset|$check")
      FIND="$FIND$SEP2{\"id\": \"$id\", \"check\": \"$check\", \"layer\": \"$layer\", \"asset\": \"$(json "$asset")\",
 \"title\": \"anyone can write $(json "$f")\", \"severity\": \"high\", \"evidence\": \"raw/$NAME/modes.txt\",
 \"remediation\": \"chmod o-w $(json "$f")\", \"needs_human\": false, \"owner\": \"platform\", \"observed_at\": \"$(now)\",
 \"kind\": \"compliance\"}"; SEP2=", " ;;
  esac
done
IFS=$OLDIFS
cat > "$SP_RUN_DIR/$NAME.findings.json.tmp" <<EOF
{"schema_version": "1.2",
 "collector": {"name": "$NAME", "version": "0.1.0", "tools": {}},
 "run": {"started_at": "$STARTED", "finished_at": "$(now)", "instance": "$(json "${SP_INSTANCE_NAME:-}")"},
 "coverage": [$COV],
 "findings": [$FIND]}
EOF
mv "$SP_RUN_DIR/$NAME.findings.json.tmp" "$SP_RUN_DIR/$NAME.findings.json"   # the document appears complete or not at all
echo "[$NAME 0.1.0] done" >&2
