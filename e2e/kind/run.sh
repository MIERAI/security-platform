#!/usr/bin/env bash
# End-to-end proof of generality: the platform installed in a SECOND, different environment, from the public
# repository only, following docs/quickstart.md. A fictional company ("Acme") on a laptop with Docker:
#
#   docker network 10.250.99.0/29 (the company LAN)            kind cluster (the company's Kubernetes)
#    .2 app-1   plain Linux server, ssh, password login ON       kube-prometheus-stack (Prometheus Operator, Grafana)
#    .3 app-2   plain Linux server, ssh, hardened                namespace legacy: a privileged pod (bait)
#    .4 gitea   code host (no GitHub): org acme, 2 repos         namespace security-platform: metrics exporter
#    .5 (unused address: must NOT become a coverage gap)
#    .6 ops     the operator's workstation: python3, git, ssh, nmap, kubectl; installs the platform from git
#
# Adapters differ from the first instance on purpose: static CIDR discovery (no overlay network), ssh exec with an
# ssh config, codehost-gitea, a kubernetes-configmap sink scraped through a ServiceMonitor. The test passes when
# collectors -> ledger -> remediation -> metrics -> Prometheus -> Grafana dashboard all work, then tears it all down.
#
# usage: e2e/kind/run.sh [--local] [--ref REF] [--keep]
#   --local    install this checkout's HEAD (a git bundle) instead of the public repository (pre-merge testing)
#   --ref REF  branch, tag or commit of the public repository (default: main)
#   --keep     leave everything running (inspect, then run again with --down)
#   --down     tear down only
# Needs: docker, kind, kubectl, helm, network access (images, chart, the public repository). ~10 minutes.
# shellcheck disable=SC2016  # commands for the operator's container are single-quoted on purpose (ops evaluates them there)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
NAME=${SP_E2E_NAME:-sp-e2e}
REPO=${SP_E2E_REPO:-https://github.com/MIERAI/security-platform.git}
REF=main LOCAL='' KEEP='' DOWN=''
while [[ $# -gt 0 ]]; do case $1 in
  --local) LOCAL=1; shift;; --ref) REF=$2; shift 2;; --keep) KEEP=1; shift;; --down) DOWN=1; shift;;
  *) sed -n '2,24p' "$0"; exit 2;; esac; done
NET=$NAME-lan SUBNET=10.250.99.0/29 OPS=$NAME-ops
KCTX=kind-$NAME
KPS_VERSION=${SP_E2E_KPS_VERSION:-93.9.0}
GITEA_IMAGE=${SP_E2E_GITEA_IMAGE:-gitea/gitea:1.24.6}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sp-e2e.XXXXXX")
PF_PIDS=()

say() { printf '\n== %s\n' "$*" >&2; }
down() {
  for p in "${PF_PIDS[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done
  kind delete cluster --name "$NAME" >/dev/null 2>&1 || true
  docker rm -f -v "$NAME-app-1" "$NAME-app-2" "$NAME-gitea" "$OPS" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
finish() {
  rc=$?
  if [[ -n $KEEP ]]; then echo "kept: kind cluster $NAME, containers $NAME-*; tear down with $0 --down" >&2
  else say "teardown"; down; fi
  rm -rf "$WORK"
  [[ $rc == 0 ]] && echo "E2E PASSED" >&2 || echo "E2E FAILED (rc=$rc)" >&2
  exit $rc
}
if [[ -n $DOWN ]]; then down; rm -rf "$WORK"; exit 0; fi
trap finish EXIT
ops() { docker exec -i "$OPS" bash -lc "$1"; }          # a command on the operator's workstation
retry() { local n=$1; shift; for _ in $(seq "$((n - 1))"); do "$@" 2>/dev/null && return 0; sleep 5; done; "$@"; }

T_START=$(date +%s)
say "1. the company's Kubernetes cluster (kind) and monitoring stack"
kind get clusters 2>/dev/null | grep -qx "$NAME" || kind create cluster --name "$NAME" --wait 120s
kubectl --context "$KCTX" create namespace legacy --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f - >/dev/null
kubectl --context "$KCTX" -n legacy apply -f - >/dev/null <<'EOF'
apiVersion: v1
kind: Pod
metadata: { name: old-agent }
spec:
  containers:
    - { name: agent, image: registry.k8s.io/pause:3.10, securityContext: { privileged: true } }
EOF
helm --kube-context "$KCTX" upgrade --install kps kube-prometheus-stack --repo https://prometheus-community.github.io/helm-charts \
  --version "$KPS_VERSION" -n monitoring --create-namespace -f "$HERE/kps-values.yaml" --wait --timeout 10m >/dev/null

say "2. the company LAN: two ssh servers, a Gitea code host, the operator's workstation"
docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$SUBNET" "$NET" >/dev/null
mkdir -p "$WORK/keys" && ssh-keygen -q -t ed25519 -N '' -C auditor@acme -f "$WORK/keys/auditor"
ssh-keygen -q -t ed25519 -N '' -C ci@acme -f "$WORK/keys/deploy"
docker build -q -t sp-e2e-target:legacy --build-arg HARDEN=no -f "$HERE/target.Dockerfile" "$HERE" >/dev/null
docker build -q -t sp-e2e-target:hardened --build-arg HARDEN=yes -f "$HERE/target.Dockerfile" "$HERE" >/dev/null
docker build -q -t sp-e2e-operator -f "$HERE/operator.Dockerfile" "$HERE" >/dev/null
docker rm -f "$NAME-app-1" "$NAME-app-2" "$NAME-gitea" "$OPS" >/dev/null 2>&1 || true
docker run -d --name "$NAME-app-1" --network "$NET" --ip 10.250.99.2 -v "$WORK/keys/auditor.pub:/keys/auditor.pub:ro" sp-e2e-target:legacy >/dev/null
docker run -d --name "$NAME-app-2" --network "$NET" --ip 10.250.99.3 -v "$WORK/keys/auditor.pub:/keys/auditor.pub:ro" sp-e2e-target:hardened >/dev/null
docker run -d --name "$NAME-gitea" --network "$NET" --ip 10.250.99.4 -e GITEA__security__INSTALL_LOCK=true \
  -e GITEA__database__DB_TYPE=sqlite3 -e GITEA__server__ROOT_URL=http://10.250.99.4:3000/ "$GITEA_IMAGE" >/dev/null
docker run -d --name "$OPS" --network "$NET" --ip 10.250.99.6 sp-e2e-operator >/dev/null
docker network connect kind "$OPS"

say "3. Gitea: organisation acme, a public repo without protection (+ a write deploy key), a protected private repo"
retry 40 ops 'curl -fsS http://10.250.99.4:3000/api/v1/version >/dev/null'
ADMIN_PW=$(python3 -c 'import secrets; print(secrets.token_hex(16))')
docker exec -u git "$NAME-gitea" gitea admin user create --admin --username acme-admin --password "$ADMIN_PW" \
  --email admin@acme.example --must-change-password=false >/dev/null
# the platform's token: read-only scopes, written straight into a 0600 file on the workstation (never printed)
docker exec -u git "$NAME-gitea" gitea admin user generate-access-token --username acme-admin --token-name security-platform \
  --scopes read:repository,read:organization,read:user --raw \
  | ops 'umask 077; mkdir -p ~/.config/security-platform && cat > ~/.config/security-platform/gitea.token'
DEPLOY_PUB=$(cat "$WORK/keys/deploy.pub")
printf '%s\n' "$ADMIN_PW" | ops "set -e; read -r PW; G=http://10.250.99.4:3000/api/v1; c() { curl -fsS -u acme-admin:\"\$PW\" -H 'Content-Type: application/json' \"\$@\" >/dev/null; }
  c -X POST \$G/orgs -d '{\"username\":\"acme\",\"visibility\":\"public\"}'
  c -X POST \$G/orgs/acme/repos -d '{\"name\":\"webapp\",\"auto_init\":true,\"private\":false,\"default_branch\":\"main\"}'
  c -X POST \$G/orgs/acme/repos -d '{\"name\":\"infra\",\"auto_init\":true,\"private\":true,\"default_branch\":\"main\"}'
  c -X POST \$G/repos/acme/infra/branch_protections -d '{\"rule_name\":\"main\",\"enable_push\":false,\"required_approvals\":1}'
  c -X POST \$G/repos/acme/webapp/keys -d '{\"title\":\"ci-deploy\",\"key\":\"$DEPLOY_PUB\",\"read_only\":false}'"
unset ADMIN_PW

say "4. the operator's workstation: ssh access, cluster access"
ops 'umask 077; mkdir -p ~/.ssh ~/.kube; cat > ~/.ssh/id_ed25519' < "$WORK/keys/auditor"
ops 'cat > ~/.ssh/config <<EOF
Host app-1
  HostName 10.250.99.2
Host app-2
  HostName 10.250.99.3
Host app-*
  User auditor
  IdentityFile ~/.ssh/id_ed25519
EOF
chmod 600 ~/.ssh/config'
retry 20 ops 'ssh-keyscan -q -t ed25519 10.250.99.2 10.250.99.3 > ~/.ssh/known_hosts.new && [ $(wc -l < ~/.ssh/known_hosts.new) = 2 ] && mv ~/.ssh/known_hosts.new ~/.ssh/known_hosts'
kind get kubeconfig --internal --name "$NAME" | ops 'umask 077; cat > ~/.kube/config'

say "5. install the platform from git, as docs/quickstart.md says"
T_CLONE=$(date +%s)
if [[ -n $LOCAL ]]; then
  git -C "$ROOT" bundle create "$WORK/repo.bundle" HEAD 2>/dev/null
  docker cp "$WORK/repo.bundle" "$OPS:/tmp/repo.bundle"
  SRC=/tmp/repo.bundle CO=HEAD
else
  SRC=$REPO CO=$REF
fi
ops "set -e; rm -rf security-platform; git -c init.defaultBranch=main clone -q '$SRC' security-platform && cd security-platform && git -c advice.detachedHead=false checkout -q '$CO'
  python3 -m venv ~/.venvs/security-platform && ~/.venvs/security-platform/bin/pip install -q --require-hashes -r deploy/requirements.lock
  echo installed \$(python3 cli/release.py --dev)"
ops 'mkdir -p ~/bin && ln -sf ~/security-platform/bin/sp ~/bin/sp'
ops 'PATH=~/.venvs/security-platform/bin:$PATH sp init ~/acme-security --name acme >/dev/null'
docker exec -i "$OPS" bash -c 'cat > ~/acme-security/instance.yaml' < "$HERE/instance.yaml"
ops 'PATH=~/.venvs/security-platform/bin:$PATH sp doctor --data ~/acme-security'

say "6. the platform's in-cluster parts: metrics exporter (ServiceMonitor) and the Grafana dashboards"
if [[ $(uname -m) == x86_64 || $(uname -m) == amd64 ]] && [[ -z $LOCAL ]]; then
  IMG=ghcr.io/mierai/security-platform TAG=$(ops 'git -C ~/security-platform rev-parse --short=7 HEAD')
else  # the published image is linux/amd64 only (docs/faq.md): build the same Dockerfile for this machine
  if [[ -n $LOCAL ]]; then docker build -q -t security-platform:e2e "$ROOT" >/dev/null
  else docker build -q -t security-platform:e2e "$REPO#$REF" >/dev/null; fi
  kind load docker-image security-platform:e2e --name "$NAME" >/dev/null
  IMG=security-platform TAG=e2e
fi
ops "set -e; mkdir -p ~/acme-gitops/security-platform && cd ~/acme-gitops/security-platform
cat > kustomization.yaml <<EOF
namespace: security-platform
resources: [../../security-platform/deploy/kubernetes]
images: [{name: security-platform, newName: $IMG, newTag: $TAG}]
# kindnet's NetworkPolicy implementation also drops the exporter's REPLIES under an egress-deny policy (docs/faq.md);
# on this CNI the exporter keeps its ingress policy only. A Calico/Cilium/kube-router cluster needs no patch.
patches:
  - target: {kind: NetworkPolicy, name: security-platform-metrics}
    patch: |-
      - {op: replace, path: /spec/policyTypes, value: [Ingress]}
      - {op: remove, path: /spec/egress}
EOF
kubectl create namespace security-platform --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl apply -k . >/dev/null
for f in ~/security-platform/dist/*dashboard*.configmap.yaml; do kubectl -n monitoring apply -f \$f >/dev/null; done
kubectl -n security-platform rollout status deploy/security-platform-metrics --timeout=180s >/dev/null"

say "7. first run: every job once, then the metrics"
ops 'PATH=~/.venvs/security-platform/bin:$PATH sp run --data ~/acme-security'
FIRST_FINDINGS=$(( $(date +%s) - T_CLONE ))
echo "ok   clone to first findings: ${FIRST_FINDINGS}s (target: 900s)"
[[ $FIRST_FINDINGS -le 900 ]] || { echo "FAIL: slower than the quickstart promises" >&2; exit 1; }
docker exec -i "$OPS" bash -lc 'python3 - ~/acme-security' < "$HERE/assert_ledger.py"
ops 'PATH=~/.venvs/security-platform/bin:$PATH; sp status --data ~/acme-security; sp findings --data ~/acme-security --open --severity high'
ID=$(ops "PATH=~/.venvs/security-platform/bin:\$PATH sp findings --data ~/acme-security --open --check ssh.password_auth_enabled --ids" | head -1)
ops "PATH=~/.venvs/security-platform/bin:\$PATH sp explain --data ~/acme-security $ID" | tee "$WORK/explain.txt"
grep -q "How to fix" "$WORK/explain.txt"
ops 'PATH=~/.venvs/security-platform/bin:$PATH sp digest --data ~/acme-security --daily' | tee "$WORK/digest.txt"
if grep -E '10\.250\.99\.|app-1|app-2|acme/webapp|acme/infra|legacy' "$WORK/digest.txt"; then echo "FAIL digest leaks asset details" >&2; exit 1; fi
echo "ok   daily summary carries no asset details"

say "7b. keep it running (quickstart step 5): versioned install, pinned environment, one tick; the notify job"
ops 'set -e; S=~/acme-security; I=~/.local/opt/security-platform; PATH=~/.venvs/security-platform/bin:$PATH
cat >> $S/instance.yaml <<EOF
notify:
  - {type: file, path: ~/acme-security/outbox/summary.txt}
EOF
python3 - $S/instance.yaml <<EOF
import sys, yaml
p = sys.argv[1]; d = yaml.safe_load(open(p))
d["runner"]["jobs"]["notify"] = {"type": "notify", "schedule": "* * * * *"}
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
EOF
~/security-platform/bin/sp-install --dev $I >/dev/null   # --dev: --ref may be a branch (no product tag)
$I/current/deploy/render.py env --install $I >/dev/null
$I/current/deploy/render.py wrapper --install $I --instance $S/instance.yaml --data $S > $I/tick.sh
sh $I/tick.sh
grep -q "notify: rc=0" $S/state/runner/tick.log
grep -q "Security " $S/outbox/summary.txt'
echo "ok   scheduled install: sp-install + render.py env/wrapper; a tick ran the due notify job (summary delivered)"

say "8. Prometheus scrapes the exporter; Grafana shows the dashboards"
kubectl --context "$KCTX" -n monitoring port-forward svc/kps-kube-prometheus-stack-prometheus 19090:9090 >/dev/null 2>&1 & PF_PIDS+=($!)
kubectl --context "$KCTX" -n monitoring port-forward svc/kps-grafana 13000:80 >/dev/null 2>&1 & PF_PIDS+=($!)
q() { curl -fsS --get --data-urlencode "query=$1" http://127.0.0.1:19090/api/v1/query; }
has_series() { q "$1" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["data"]["result"] else 1)'; }
retry 60 has_series 'security_findings{namespace="security-platform",status="open"}' || { echo "FAIL: Prometheus has no security_findings" >&2; exit 1; }
echo "ok   Prometheus: security_* series scraped from the exporter (ServiceMonitor, NetworkPolicy from monitoring)"
GPW=$(kubectl --context "$KCTX" -n monitoring get secret kps-grafana -o jsonpath='{.data.admin-password}' | base64 -d)
g() { curl -fsS -u "admin:$GPW" "$@"; }
for uid in security-platform security-platform-overview; do
  retry 30 sh -c "curl -fsS -u 'admin:$GPW' 'http://127.0.0.1:13000/api/search?tag=security-platform' | grep -q '\"uid\":\"$uid\"'" \
    || { echo "FAIL: dashboard $uid not provisioned" >&2; exit 1; }
done
echo "ok   Grafana: dashboards provisioned by the sidecar: $(g 'http://127.0.0.1:13000/api/search?tag=security-platform' | python3 -c 'import json,sys; print(", ".join(d["title"] for d in json.load(sys.stdin)))')"
DS=$(g http://127.0.0.1:13000/api/datasources | python3 -c 'import json,sys; print(next(d["uid"] for d in json.load(sys.stdin) if d["type"]=="prometheus"))')
g -H 'Content-Type: application/json' http://127.0.0.1:13000/api/ds/query -d "{\"from\":\"now-1h\",\"to\":\"now\",\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS\"},\"expr\":\"sum by (severity) (security_findings{status=\\\"open\\\"})\",\"instant\":true}]}" \
  | python3 -c 'import json,sys; f=json.load(sys.stdin)["results"]["A"]["frames"]; assert f, "no data"; print("ok   Grafana: panel query returns", len(f), "series")'
g -H 'Content-Type: application/json' http://127.0.0.1:13000/api/ds/query -d "{\"from\":\"now-1h\",\"to\":\"now\",\"queries\":[{\"refId\":\"A\",\"datasource\":{\"uid\":\"$DS\"},\"expr\":\"min by (pillar) (security_score{pillar!=\\\"\\\",dimension=\\\"\\\"})\",\"instant\":true}]}" \
  | python3 -c 'import json,sys; f=json.load(sys.stdin)["results"]["A"]["frames"]; assert f, "no scorecard data"; print("ok   Grafana: overview score-by-pillar query returns", len(f), "pillars")'
unset GPW

DUR=$(( $(date +%s) - T_START ))
python3 - "$HERE/last-pass.json" "$(ops 'python3 ~/security-platform/cli/release.py --dev')" "$FIRST_FINDINGS" "$DUR" \
  "$KPS_VERSION" "$GITEA_IMAGE" "$(kubectl --context "$KCTX" version -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["serverVersion"]["gitVersion"])')" <<'EOF'
import json, sys, time
p, ref, first, dur, kps, gitea, k8s = sys.argv[1:]
json.dump({"schema": "security-platform/e2e-result/v1", "test": "e2e/kind/run.sh", "result": "pass",
           "passed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "installed": ref,
           "clone_to_first_findings_seconds": int(first), "total_seconds": int(dur),
           "environment": {"kubernetes": k8s, "kube_prometheus_stack": kps, "code_host": gitea,
                           "discovery": "static CIDR", "exec": "ssh", "metrics": "kubernetes-configmap + ServiceMonitor"}},
          open(p, "w"), indent=1)
print(f"wrote {p} (commit it: evidence for the scorecard's generality and usability controls)")
EOF
