#!/usr/bin/env bash
# End-to-end test of the cloud collector on ONE machine, with NO cloud account: every cloud endpoint is local.
#
#   LocalStack community (pinned)      AWS: S3, EC2, IAM, STS (AssumeRoleWithWebIdentity), deliberately misconfigured
#   mock-oauth2-server (pinned)        the workload's OIDC issuer (like a Kubernetes projected token or CI OIDC)
#   cloudmock.py (this directory)      GCP STS / iamcredentials / getIamPolicy and Entra token / ARM role assignments
#
# What it proves (assert_cloud.py): the platform logs in with SHORT-LIVED credentials only (OIDC -> STS), checks its OWN
# permissions (read-only expected; an over-privileged identity is a finding and is refused), runs THREE engines
# (Prowler, Steampipe, ScoutSuite) plus a Security Hub export against the same account into ONE ledger without double counting, classifies
# findings into the four pillars, closes findings when the resources are fixed (next covered run), records every
# failure (expired token, wrong audience, missing role, denied impersonation, unknown app; GCP ADC missing / revoked /
# a key file / denied / missing service account) as a coverage gap with its
# reason, writes no credential to disk, and the scorecard's cloud dimension is applicable here and N/A without cloud.
# What it does NOT prove: see docs/cloud.md "What is validated where" (LocalStack does not enforce IAM; the GCP/Azure
# endpoints are our mocks; GCP/Azure scans use contract fixtures).
#
# usage: e2e/cloud-localstack/run.sh [--keep] [--down]
#   --keep   leave containers and the work directory (inspect; then --down)
#   --down   tear down only
# Needs: docker, python3 >= 3.10, uv (Prowler's own Python 3.12 environment), network for images and tools (first run).
# SP_CLOUD_E2E_TOOLS=DIR reuses a tool install (Prowler, Steampipe) between runs; default: built in the work dir, removed.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NAME=${SP_CLOUD_E2E_NAME:-sp-cloud-e2e}
LS_IMAGE=${SP_CLOUD_E2E_LOCALSTACK:-localstack/localstack:4.14.0@sha256:3ebc37595918b8accb852f8048fef2aff047d465167edd655528065b07bc364a}
OIDC_IMAGE=${SP_CLOUD_E2E_OIDC:-ghcr.io/navikt/mock-oauth2-server:6.1.5@sha256:d88e445d55c4ff6eed59b02d86adfece47d985233b1616fb712669b98328c8a2}
LS_PORT=${SP_CLOUD_E2E_LS_PORT:-14566} OIDC_PORT=18080 MOCK_PORT=18090   # the mock scenario names the issuer port
KEEP= DOWN=
while [[ $# -gt 0 ]]; do case $1 in --keep) KEEP=1; shift;; --down) DOWN=1; shift;; *) sed -n '2,22p' "$0"; exit 2;; esac; done
STATE=${TMPDIR:-/tmp}/$NAME.state

say() { printf '\n== %s\n' "$*" >&2; }
down() {
  docker rm -f -v "$NAME-localstack" "$NAME-oidc" >/dev/null 2>&1 || true
  if [[ -f $STATE ]]; then
    local pid wd
    read -r pid wd < "$STATE" || true
    [[ ${pid:-x} =~ ^[0-9]+$ && $pid -gt 1 ]] && kill "$pid" 2>/dev/null || true
    [[ -n ${wd:-} && -d $wd && $wd == */sp-cloud-e2e.* ]] && rm -rf "$wd"
    rm -f "$STATE"
  fi
}
if [[ -n $DOWN ]]; then down; echo "torn down" >&2; exit 0; fi
down
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sp-cloud-e2e.XXXXXX")
TOOLS=${SP_CLOUD_E2E_TOOLS:-$WORK/install}
MOCK_PID=
finish() {
  rc=$?
  echo "${MOCK_PID:-none} $WORK" > "$STATE"
  [[ ${MOCK_PID:-x} =~ ^[0-9]+$ ]] && [[ -z $KEEP ]] && kill "$MOCK_PID" 2>/dev/null || true
  if [[ -n $KEEP ]]; then echo "kept: containers $NAME-*, work dir $WORK; tear down with $0 --down" >&2
  else say "teardown"; down; fi
  [[ $rc == 0 ]] && echo "E2E PASSED" >&2 || echo "E2E FAILED (rc=$rc)" >&2
  exit $rc
}
trap finish EXIT
T_START=$(date +%s)

say "1. pinned tools, the way a deployment installs them (render.py env / tool-env; ticks never download)"
python3 "$ROOT/deploy/render.py" env --install "$TOOLS" >/dev/null
python3 "$ROOT/deploy/render.py" tool-env --install "$TOOLS" --tool prowler >/dev/null
python3 "$ROOT/deploy/render.py" tool-env --install "$TOOLS" --tool steampipe >/dev/null
python3 "$ROOT/deploy/render.py" tool-env --install "$TOOLS" --tool scoutsuite >/dev/null
PY=$TOOLS/env/bin/python3                                  # the runner's environment (PyYAML)
TPY=$TOOLS/tools/prowler/current/bin/python3              # Prowler's own environment (boto3: used to SEED LocalStack)
echo "ok   prowler $("$TPY" -c 'import importlib.metadata as m; print(m.version("prowler"))'), steampipe $("$TOOLS/tools/steampipe/current/bin/steampipe" --version | awk '{print $NF}'), scoutsuite $("$TOOLS/tools/scoutsuite/current/bin/python3" -c 'import importlib.metadata as m; print(m.version("scoutsuite"))')"

say "2. local endpoints: LocalStack (AWS), an OIDC issuer, the GCP/Azure token mock"
docker run -d --name "$NAME-localstack" -p "127.0.0.1:$LS_PORT:4566" -e SERVICES=s3,ec2,iam,sts "$LS_IMAGE" >/dev/null
docker run -d --name "$NAME-oidc" -p "127.0.0.1:$OIDC_PORT:8080" -e JSON_CONFIG="$(cat "$HERE/oidc-config.json")" "$OIDC_IMAGE" >/dev/null
python3 "$HERE/cloudmock.py" --port "$MOCK_PORT" --config "$HERE/mock-scenario.json" & MOCK_PID=$!
for _ in $(seq 60); do
  curl -fsS "127.0.0.1:$LS_PORT/_localstack/health" 2>/dev/null | grep -q '"iam": "available"' \
    && curl -fsS "127.0.0.1:$OIDC_PORT/workload/.well-known/openid-configuration" >/dev/null 2>&1 \
    && curl -fsS "127.0.0.1:$MOCK_PORT/health" >/dev/null 2>&1 && break
  sleep 2
done
curl -fsS "127.0.0.1:$LS_PORT/_localstack/health" | grep -q '"edition": "community"'
echo "ok   LocalStack community, OIDC issuer and cloud mock are up"

say "3. the fictional company's AWS account: the platform's role + deliberate misconfigurations (seeded as admin)"
export SP_E2E_LS="http://127.0.0.1:$LS_PORT" SP_E2E_WORK=$WORK SP_E2E_OIDC="http://127.0.0.1:$OIDC_PORT"
"$TPY" -I "$HERE/seed.py" seed

say "4. instance config (JSON: no PyYAML needed) and the first scan"
"$PY" -I "$HERE/make_instance.py" "$WORK" "$TOOLS" "$HERE" "$LS_PORT" "$OIDC_PORT" "$MOCK_PORT"
DATA=$WORK/data
mkdir -p "$DATA" "$WORK/home"
scan() {   # $1 = run name; the collector runs as a scheduled job would, with an EMPTY home and no ambient cloud keys
  local run=$WORK/runs/$1
  ( cd "$ROOT" && env -i PATH="$PATH" HOME="$WORK/home" TMPDIR="$WORK/tmp" SP_INSTANCE="$WORK/instance.json" SP_RUN_DIR="$run" \
      AWS_ACCESS_KEY_ID=ambient-admin-key-must-not-be-used AWS_SECRET_ACCESS_KEY=ambient \
      "$PY" collectors/cloud/collector.py ) 2>&1 | tail -1
  "$PY" "$ROOT/core/ledger.py" --run "$run" --data "$DATA" >/dev/null
  mkdir -p "$DATA/latest" && cp "$run"/cloud.findings.json "$DATA/latest/cloud.findings.json"
}
mkdir -p "$WORK/tmp"
"$PY" -I "$HERE/seed.py" asff "$WORK/securityhub.json" failed
scan 1
"$PY" -I "$HERE/assert_cloud.py" first "$WORK"

say "5. fix three misconfigurations (public bucket, open SSH, console user without MFA); scan again"
"$TPY" -I "$HERE/seed.py" fix
"$PY" -I "$HERE/seed.py" asff "$WORK/securityhub.json" passed
scan 2
"$PY" -I "$HERE/assert_cloud.py" second "$WORK"

say "6. failure modes: every one is a coverage gap with its reason (never 'no findings')"
"$PY" -I "$HERE/assert_cloud.py" failures "$WORK" "$PY" "$ROOT"

say "6b. GCP with the operator's ADC (source adc): impersonated service account, evidence, discovery gcp"
"$PY" -I "$HERE/assert_cloud.py" adc "$WORK" "$ROOT"

say "7. scorecard: the cloud dimension applies here; without cloud it is N/A and the overall score is unchanged"
"$PY" -I "$HERE/assert_cloud.py" scorecard "$WORK" "$PY" "$ROOT"

say "8. no credential on disk; temporary directories removed"
"$PY" -I "$HERE/assert_cloud.py" secrets "$WORK"

DUR=$(( $(date +%s) - T_START ))
"$PY" -I - "$HERE/last-pass.json" "$DUR" "$LS_IMAGE" "$OIDC_IMAGE" \
  "$("$TPY" -c 'import importlib.metadata as m; print(m.version("prowler"))')" \
  "$("$TOOLS/tools/steampipe/current/bin/steampipe" --version | awk '{print $NF}' | tr -d v)" "$(python3 "$ROOT/cli/release.py" --repo "$ROOT" --dev)" <<'EOF'
import json, sys, time
p, dur, ls, oidc, prowler, steampipe, ref = sys.argv[1:]
json.dump({"schema": "security-platform/e2e-result/v1", "test": "e2e/cloud-localstack/run.sh", "result": "pass",
           "passed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "installed": ref, "total_seconds": int(dur),
           "environment": {"aws": "LocalStack community " + ls.split("@")[0].split(":")[-1], "oidc_issuer": oidc.split("@")[0],
                           "gcp_azure": "cloudmock.py (token flows only)", "prowler": prowler, "steampipe": steampipe}},
          open(p, "w"), indent=1)
print(f"wrote {p}")
EOF
