"""Conformance cases of the `k8s` collector (collector-protocol/1.0, findings/1.2): a fake kubectl on PATH replays
recorded API answers per cluster (fakes/fake_kubectl.py); kube-bench runs from a tarball through a fake sudo.
Imported by gen_cases.py, which passes its helpers (write_case, collector_env, protocol_checks)."""
import io
import json
import os
import struct
import tarfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
C = "collector-protocol/1.0 / findings/1.2"
CANARY = "k8s-conformance-env-canary-6b1f"         # a pod env value and a Secret's data: never in any output
SECRET_CANARY = "k8s-conformance-secret-canary-93d0"
READ_ONLY = r"^[a-z-]+: (?!get |auth whoami )"        # a logged kubectl call that is not a read verb


def meta(name, ns=None, **kw):
    m = {"name": name, "uid": f"uid-{ns}-{name}"}
    if ns:
        m["namespace"] = ns
    m.update(kw)
    return m


def pod(ns, name, containers, owner=None, labels=None, phase="Running", init=None, **spec):
    md = meta(name, ns, labels=labels or {})
    if owner:
        md["ownerReferences"] = [{"kind": owner[0], "name": owner[1]}]
    statuses = [{"name": c["name"], "imageID": c.pop("_image_id", "")} for c in containers]
    s = dict(spec, containers=containers)
    if init:
        s["initContainers"] = init
    return {"metadata": md, "spec": s, "status": {"phase": phase, "containerStatuses": statuses}}


def ctr(name, image, sc=None, env=None, image_id=""):
    c = {"name": name, "image": image, "_image_id": image_id}
    if sc is not None:
        c["securityContext"] = sc
    if env:
        c["env"] = env
    return c


def binding(kind, name, role_kind, role, subjects, ns=None):
    return {"kind": kind, "metadata": meta(name, ns), "roleRef": {"kind": role_kind, "name": role}, "subjects": subjects}


def subj(kind, name, ns=None):
    s = {"kind": kind, "name": name}
    if ns:
        s["namespace"] = ns
    return s


def rules(*r):
    return [{"apiGroups": g, "resources": res, "verbs": v} for g, res, v in r]


def prod_cluster():
    web = {"app": "web"}
    pods = [
        pod("web", "app-7d4b9c8f6d-abcde", [ctr("app", "registry.example/web:1.4", {"runAsNonRoot": True},
                                                 env=[{"name": "API_TOKEN", "value": CANARY}],
                                                 image_id="registry.example/web@sha256:" + "a" * 64)],
            owner=("ReplicaSet", "app-7d4b9c8f6d"), labels=web),
        pod("web", "app-7d4b9c8f6d-fghij", [ctr("app", "registry.example/web:1.4", {"runAsNonRoot": True},
                                                 image_id="registry.example/web@sha256:" + "a" * 64)],
            owner=("ReplicaSet", "app-7d4b9c8f6d"), labels=web),
        pod("data", "db-0", [ctr("db", "registry.example/db:16", {"privileged": True,
                                                                  "capabilities": {"add": ["SYS_ADMIN", "NET_RAW"]}})],
            owner=("StatefulSet", "db"), labels={"app": "db"}, volumes=[{"name": "d", "hostPath": {"path": "/var/lib/db"}}]),
        pod("kube-system", "node-agent-x2x9z", [ctr("agent", "registry.example/agent:2")],
            owner=("DaemonSet", "node-agent"), hostNetwork=True, hostPID=True,
            init=[ctr("init", "registry.example/agent-init:2", {"privileged": True})]),
        pod("web", "backup-28123456-q7x2p", [ctr("backup", "registry.example/backup:1")], owner=("Job", "backup-28123456"),
            phase="Succeeded"),
        pod("default", "debug", [ctr("sh", "busybox:1.36", {"runAsUser": 1000})], phase="Pending"),
    ]
    for p in pods:      # init containers' statuses
        for c in p["spec"].get("initContainers") or []:
            p["status"].setdefault("initContainerStatuses", []).append({"name": c["name"], "imageID": c.pop("_image_id", "")})
    return {"resources": {
        "namespaces": [{"metadata": meta(n)} for n in ("default", "web", "data", "kube-system")],
        "pods": pods,
        "services": [{"metadata": meta("web", "web"), "spec": {"type": "NodePort", "selector": web}},
                     {"metadata": meta("db", "data"), "spec": {"type": "ClusterIP", "selector": {"app": "db"}}}],
        "networkpolicies": [{"metadata": meta("deny-all", "web"), "spec": {"podSelector": {}}},
                            {"metadata": meta("only-other", "data"), "spec": {"podSelector": {"matchLabels": {"app": "other"}}}}],
        "clusterroles": [{"metadata": meta("cluster-admin"), "rules": rules([["*"], ["*"], ["*"]])},
                         {"metadata": meta("secret-reader"), "rules": rules([[""], ["secrets"], ["get", "list"]])},
                         {"metadata": meta("exec"), "rules": rules([[""], ["pods/exec"], ["create"]])},
                         {"metadata": meta("view"), "rules": rules([[""], ["pods"], ["get", "list"]])}],
        "clusterrolebindings": [
            binding("ClusterRoleBinding", "admins", "ClusterRole", "cluster-admin",
                    [subj("User", "alice"), subj("Group", "system:masters")]),
            binding("ClusterRoleBinding", "ci-secrets", "ClusterRole", "secret-reader", [subj("ServiceAccount", "deployer", "ci")]),
            binding("ClusterRoleBinding", "sys-exec", "ClusterRole", "exec", [subj("ServiceAccount", "agent", "kube-system")]),
            binding("ClusterRoleBinding", "viewers", "ClusterRole", "view", [subj("Group", "devs")])],
        "rolebindings": [binding("RoleBinding", "exec-bob", "ClusterRole", "exec", [subj("User", "bob")], ns="web")],
        "roles": [],
        "secrets": [
            {"metadata": meta("old-api-key", "web", creationTimestamp="2020-01-01T00:00:00Z"), "type": "Opaque",
             "data": {"key": SECRET_CANARY}},
            {"metadata": meta("fresh", "web", creationTimestamp="{utc:-86400}"), "type": "Opaque", "data": {"key": SECRET_CANARY}},
            {"metadata": meta("sh.helm.release.v1.web.v3", "web", creationTimestamp="2020-01-01T00:00:00Z"),
             "type": "helm.sh/release.v1"},
            {"metadata": meta("legacy-token", "ci", creationTimestamp="2020-01-01T00:00:00Z"),
             "type": "kubernetes.io/service-account-token"}],
        "policyreports.wgpolicyk8s.io": [
            {"metadata": meta("pr-web", "web"), "results": [{"policy": "require-limits", "result": "fail"},
                                                            {"policy": "disallow-latest", "result": "pass"}],
             "summary": {"pass": 1, "fail": 1}}],
        "clusterpolicyreports.wgpolicyk8s.io": [
            {"metadata": meta("cpr"), "results": [{"policy": "require-limits", "result": "fail"},
                                                  {"policy": "no-host-ns", "result": "error"}],
             "summary": {"fail": 1, "error": 1}}]},
        "whoami": {"username": "kubernetes-admin", "groups": ["system:masters", "system:authenticated"]}}


def lab_cluster():
    return {"resources": {
        "namespaces": [{"metadata": meta("default")}],
        "pods": [pod("tools", "builder-5c9d8b7f6-k2j4h", [ctr("dind", "registry.example/dind:27", {"privileged": True})],
                     owner=("ReplicaSet", "builder-5c9d8b7f6"))],
        "services": [], "networkpolicies": []}}


KUBE_BENCH = {"Controls": [{"id": "1", "tests": [{"section": "1.1", "results": [
    {"test_number": "1.1.1", "test_desc": "Ensure that the API server pod specification file permissions are set to 600",
     "status": "PASS", "scored": True},
    {"test_number": "1.2.6", "test_desc": "Ensure that the --kubelet-certificate-authority argument is set",
     "status": "FAIL", "scored": True, "remediation": "Follow the Kubernetes documentation and set up the TLS connection.\nThen restart."},
    {"test_number": "4.2.9", "test_desc": "Ensure that the eventRecordQPS argument is set to a level which ensures capture",
     "status": "FAIL", "scored": False, "remediation": ""},
    {"test_number": "4.2.12", "test_desc": "Verify that the RotateKubeletServerCertificate argument is set to true",
     "status": "WARN", "scored": True}]}]}]}


def kube_bench_tarball(fail=False):
    """kube-bench_0.9.0_linux_amd64.tar.gz: a kube-bench stand-in (sh) printing a recorded result, and cfg/."""
    script = "#!/bin/sh\n" + ("echo 'cannot read config' >&2\nexit 1\n" if fail else
                              "cat <<'JSON'\n" + json.dumps(KUBE_BENCH) + "\nJSON\n")
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data, mode in (("kube-bench", script.encode(), 0o755), ("cfg/config.yaml", b"controls: {}\n", 0o644)):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime, ti.uname, ti.gname = len(data), mode, 1700000000, "root", "root"
            t.addfile(ti, io.BytesIO(data))
    return gzip_stored(raw.getvalue())


def gzip_stored(data):
    """gzip with stored (uncompressed) deflate blocks and a fixed header: the same bytes from every Python/zlib."""
    co = zlib.compressobj(0, zlib.DEFLATED, -15)
    body = co.compress(data) + co.flush()
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + body + struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)


def files(clusters, extra=None):
    f = {"instance.json": "instance.json", "data/.keep": {"text": ""},
         "bin/kubectl": {"text": "#!/bin/sh\nexec \"{python}\" \"{case}/fake_kubectl.py\" \"$@\"\n", "mode": "0755"},
         "bin/sudo": {"text": "#!/bin/sh\n[ \"$1\" = \"-n\" ] && shift\nexec \"$@\"\n", "mode": "0755"}}
    for name in clusters:
        f[f"kube/{name}.json"] = f"{name}.json"
    f.update(extra or {})
    return f


def env(h, extra=None):
    return h.collector_env(dict({"PATH": "{sandbox}/bin:{path}", "FAKE_KUBE_DIR": "{sandbox}/kube",
                                 "FAKE_KUBE_LOG": "{sandbox}/.svc-kubectl.calls"}, **(extra or {})))


def read_only():
    return {"file": ".svc-kubectl.calls", "not_regex": [READ_ONLY]}


def kc(name):
    return "{sandbox}/kube/" + name + ".yaml"


def wl(name, ns, kind, owner):
    return f"k8s-workload:{name}/{ns}/{kind}/{owner}"


def posture_case(h):
    inst = {"name": "conformance", "kubernetes": [
        {"name": "prod", "kubeconfig": kc("prod"), "role": "prod", "host_exec": {"type": "local"},
         "kube_bench": {"benchmark": "cis-1.9", "tarball": "kube-bench_0.9.0_linux_amd64.tar.gz"}},
        {"name": "lab", "kubeconfig": kc("lab"), "role": "lab", "parts": ["workloads", "policy"]}]}
    F = "run/k8s.findings.json"
    findings = [
        {"check": "k8s.pod.privileged", "asset": wl("prod", "data", "StatefulSet", "db"), "severity": "high", "layer": "workload",
         "title": "prod/data/StatefulSet/db: privileged", "kind": "compliance", "evidence": "raw/k8s/prod-workloads.json"},
        {"check": "k8s.pod.cap.sys_admin", "asset": wl("prod", "data", "StatefulSet", "db"), "severity": "medium"},
        {"check": "k8s.pod.hostpath", "asset": wl("prod", "data", "StatefulSet", "db"), "severity": "medium",
         "title": "prod/data/StatefulSet/db: hostPath:/var/lib/db"},
        {"check": "k8s.pod.hostpid", "asset": wl("prod", "kube-system", "DaemonSet", "node-agent"), "severity": "high"},
        {"check": "k8s.pod.hostnetwork", "asset": wl("prod", "kube-system", "DaemonSet", "node-agent"), "severity": "medium"},
        {"check": "k8s.pod.privileged", "asset": wl("prod", "kube-system", "DaemonSet", "node-agent"), "severity": "high"},
        {"check": "k8s.netpol.missing", "asset": "k8s-namespace:prod/data", "severity": "medium",
         "title": "1 pod(s) in prod/data not selected by any NetworkPolicy (flat network)", "evidence": "raw/k8s/prod-netpol.json"},
        {"check": "k8s.netpol.missing", "asset": "k8s-namespace:prod/default", "severity": "medium"},
        {"check": "k8s.netpol.missing", "asset": "k8s-namespace:prod/kube-system", "severity": "medium"},
        {"check": "k8s.rbac.cluster_admin_pods_exec_rbac_write_secrets_read_wildcard", "asset": "k8s-identity:prod/User:alice",
         "severity": "high", "layer": "identity"},
        {"check": "k8s.rbac.secrets_read", "asset": "k8s-identity:prod/ServiceAccount:ci/deployer", "severity": "medium"},
        {"check": "k8s.rbac.pods_exec", "asset": "k8s-identity:prod/User:bob", "severity": "medium",
         "title": "User:bob has pods-exec (ns:web, via exec)"},
        {"check": "k8s.policy.fail.require-limits", "asset": "k8s-cluster:prod", "severity": "low",
         "title": "admission/background policy 'require-limits' failing in 2 namespace(s)"},
        {"check": "k8s.policy.fail.no-host-ns", "asset": "k8s-cluster:prod"},
        {"check": "k8s.operator_cred_system_masters", "asset": "k8s-identity:prod/operator-kubeconfig", "severity": "high",
         "evidence": "raw/k8s/prod-whoami.json"},
        {"check": "cis.cis-1.9.1.2.6", "asset": "k8s-cluster:prod", "severity": "medium", "refs": ["cis:cis-1.9:1.2.6"],
         "remediation": "Follow the Kubernetes documentation and set up the TLS connection."},
        {"check": "cis.cis-1.9.4.2.9", "asset": "k8s-cluster:prod", "severity": "low", "remediation": "see benchmark"},
        {"check": "k8s.pod.privileged", "asset": wl("lab", "tools", "Deployment", "builder"), "severity": "medium"},
        {"check": "k8s.netpol.missing", "asset": "k8s-namespace:lab/tools", "severity": "low"},
        {"check": "k8s.policy.engine_missing", "asset": "k8s-cluster:lab", "severity": "low"}]
    absent = [{"asset": wl("prod", "web", "Deployment", "app")}, {"asset": {"$regex": "backup"}},
              {"asset": {"$regex": "system:masters|kube-system/agent|devs"}}, {"asset": "k8s-namespace:prod/web"},
              {"check": "k8s.pod.cap.net_raw"}]
    inventory = {"schema": "security-platform/inventory/v1", "kind": "container-image", "complete": True,
                 "sources": {"k8s-cluster:prod": "complete", "k8s-cluster:lab": "complete"},
                 "items": [
                     {"cluster": "prod", "image": "registry.example/web:1.4", "image_id": "registry.example/web@sha256:" + "a" * 64,
                      "namespaces": ["web"], "workloads": [wl("prod", "web", "Deployment", "app")], "exposed": True, "prod": True},
                     {"cluster": "prod", "image": "registry.example/db:16", "image_id": "", "namespaces": ["data"],
                      "workloads": [wl("prod", "data", "StatefulSet", "db")], "exposed": False, "prod": True},
                     {"cluster": "prod", "image": "registry.example/agent:2", "image_id": "", "namespaces": ["kube-system"],
                      "workloads": [wl("prod", "kube-system", "DaemonSet", "node-agent")], "exposed": True, "prod": True},
                     {"cluster": "prod", "image": "registry.example/agent-init:2", "exposed": True},
                     {"cluster": "prod", "image": "busybox:1.36", "namespaces": ["default"], "exposed": False},
                     {"cluster": "lab", "image": "registry.example/dind:27", "exposed": False, "prod": False}]}
    metrics = [{"name": "security_k8s_pods_root_capable_containers", "labels": {"cluster": "prod"}, "value": 3},
               {"name": "security_k8s_pods_without_netpol", "labels": {"cluster": "prod"}, "value": 3},
               {"name": "security_k8s_wide_rbac_subjects", "labels": {"cluster": "prod"}, "value": 3},
               {"name": "security_secrets_total", "labels": {"store": "k8s:prod"}, "value": 2},
               {"name": "security_secrets_older_than_90d", "labels": {"store": "k8s:prod"}, "value": 1},
               {"name": "security_k8s_policyreport_results", "labels": {"cluster": "prod", "result": "fail"}, "value": 2},
               {"name": "security_k8s_policy_engine_present", "labels": {"cluster": "lab"}, "value": 0},
               {"name": "security_cis_results", "labels": {"cluster": "prod", "result": "fail"}, "value": 2},
               {"name": "security_cis_results", "labels": {"cluster": "prod", "result": "warn"}, "value": 1},
               {"name": "security_inventory_images", "value": 6},
               {"name": "security_collector_gaps", "labels": {"collector": "k8s"}, "value": 0}]
    h.write_case("collector-k8s", "posture-and-image-inventory", {
        "title": "Two clusters through kubectl (read verbs only): privileged / host namespaces / hostPath / capabilities, "
                 "NetworkPolicy coverage, wide RBAC, Secret metadata, PolicyReports, the operator's own credential, CIS "
                 "through kube-bench; severities lowered outside prod; the image inventory is complete. Env values and "
                 "Secret data never reach the output",
        "contract": C, "origin": "collectors/k8s/collector.py; tests/test_retired.py::K8sInventory",
        "files": files(["prod", "lab"], {"data/kube-bench_0.9.0_linux_amd64.tar.gz": {"raw": "kube-bench.tar.gz"}}),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s", canaries=[CANARY, SECRET_CANARY]) + [
                       {"json": F, "subset": {"collector": {"tools": {"kube-bench": "0.9.0"}},
                                              "coverage": {"$unordered": [{"asset": "k8s-cluster:prod", "status": "ok"},
                                                                          {"asset": "k8s-cluster:lab", "status": "ok"},
                                                                          {"asset": "cis:prod", "status": "ok"}]},
                                              "findings": {"$unordered": findings}}},
                       {"json": F, "subset": {"findings": {"$not_contains": absent}}},
                       {"json": "run/inventory.k8s-images.json", "subset": inventory},
                       {"json": "run/raw/k8s/prod-secrets-metadata.json", "subset": {"$unordered": [
                           {"ns": "web", "name": "old-api-key", "type": "Opaque", "created": "2020-01-01T00:00:00Z"},
                           {"ns": "web", "name": "fresh", "type": "Opaque"}]}},
                       {"prom": "run/k8s.prom", "has": metrics},
                       read_only(),
                       {"file": ".svc-kubectl.calls", "regex": [r"^prod: get pods -A -o json$", r"^prod: auth whoami -o json$",
                                                                r"^lab: get pods -A -o json$"]}]},
                  {"name": "collect as another name: one inventory per collector instance", "remove": ["run"],
                   "exec": {"impl": "collector-k8s", "env": env(h, {"SP_COLLECTOR_NAME": "k8s-incluster"})},
                   "expect": [{"json": "run/k8s-incluster.findings.json", "schema": "findings",
                               "subset": {"collector": {"name": "k8s-incluster"}}},
                              {"json": "run/inventory.k8s-incluster-images.json", "subset": {"complete": True}},
                              {"absent": "run/inventory.k8s-images.json"}]}]},
        {"instance.json": inst, "fake_kubectl.py": open(os.path.join(HERE, "fakes", "fake_kubectl.py")).read(),
         "prod.json": prod_cluster(), "lab.json": lab_cluster(), "kube-bench.tar.gz": kube_bench_tarball()})


def partial_case(h):
    inst = {"name": "conformance", "kubernetes": [
        {"name": "prod", "kubeconfig": kc("prod"), "role": "prod", "parts": ["workloads"]},
        {"name": "down", "kubeconfig": kc("down"), "role": "prod"},
        {"name": "rbaconly", "kubeconfig": kc("rbaconly"), "parts": ["rbac"]}]}
    rbaconly = {"resources": {"namespaces": [], "clusterroles": [], "clusterrolebindings": [], "rolebindings": [], "roles": []}}
    h.write_case("collector-k8s", "unreachable-cluster-makes-inventory-partial", {
        "title": "An unreachable cluster is a coverage gap (exit 0), and the image inventory says it is partial: "
                 "`complete: false`, with `sources` naming the cluster that failed and the one whose workloads were not "
                 "listed; the reachable cluster is still reported",
        "contract": C, "origin": "tests/test_retired.py::K8sInventory::test_complete_only_when_every_cluster_listed",
        "files": files(["prod", "down", "rbaconly"]),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s") + [
                       {"json": "run/k8s.findings.json", "subset": {
                           "coverage": {"$unordered": [
                               {"asset": "k8s-cluster:prod", "status": "ok"},
                               {"asset": "k8s-cluster:down", "status": "gap", "reason": {"$regex": "Unable to connect"}},
                               {"asset": "k8s-cluster:rbaconly", "status": "ok"}]},
                           "findings": {"$contains": [{"check": "k8s.pod.privileged", "asset": wl("prod", "data", "StatefulSet", "db")}]}}},
                       {"json": "run/inventory.k8s-images.json", "subset": {
                           "complete": False, "items": {"$len": 5},
                           "sources": {"k8s-cluster:prod": "complete", "k8s-cluster:down": "failed: RuntimeError",
                                       "k8s-cluster:rbaconly": "not inventoried (parts without workloads)"}}},
                       {"prom": "run/k8s.prom", "has": [{"name": "security_collector_gaps", "labels": {"collector": "k8s"}, "value": 1}]},
                       read_only()]}]},
        {"instance.json": inst, "fake_kubectl.py": open(os.path.join(HERE, "fakes", "fake_kubectl.py")).read(),
         "prod.json": prod_cluster(), "rbaconly.json": rbaconly,
         "down.json": {"unreachable": "Unable to connect to the server: dial tcp 192.0.2.10:6443: connect: connection refused"}})


def cases(h):
    posture_case(h)
    partial_case(h)
    deviation_cases(h)


def deviation_cases(h):
    """Target behaviour the Python collector does not have (contracts/collector-protocol/SPEC.md, Known deviations)."""
    fk = open(os.path.join(HERE, "fakes", "fake_kubectl.py")).read()
    forbidden = {"error": 'Error from server (Forbidden): clusterrolebindings.rbac.authorization.k8s.io is forbidden: User '
                          '"system:serviceaccount:security:reader" cannot list resource "clusterrolebindings"'}
    c = prod_cluster()
    c["resources"]["clusterrolebindings"] = forbidden
    c["resources"]["secrets"] = {"error": 'Error from server (Forbidden): secrets is forbidden: User '
                                          '"system:serviceaccount:security:reader" cannot list resource "secrets"'}
    h.write_case("collector-k8s", "failing-part-is-a-gap-of-that-part", {
        "title": "One part that cannot be read (RBAC or Secrets forbidden) is a gap of that part only: the cluster stays "
                 "covered, the other parts (PolicyReports, the operator credential) are still evaluated, findings of the "
                 "failed part stay unknown (a gap on k8s-identity:<cluster>), and an unreadable Secret list is never "
                 "reported as zero Secrets",
        "contract": C, "deviation": "K8S-D1", "origin": "an in-cluster reader without `list clusterrolebindings` lost every later part",
        "files": files(["prod"]),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s") + [
                       {"json": "run/k8s.findings.json", "subset": {
                           "coverage": {"$contains": [
                               {"asset": "k8s-cluster:prod", "status": "ok"},
                               {"asset": "k8s-identity:prod", "status": "gap", "reason": {"$regex": "rbac: .*[Ff]orbidden"}},
                               {"asset": "k8s-cluster:prod/secrets", "status": "gap", "reason": {"$regex": "[Ff]orbidden"}}]},
                           "findings": {"$contains": [{"check": "k8s.policy.fail.require-limits"},
                                                      {"check": "k8s.operator_cred_system_masters"},
                                                      {"check": "k8s.pod.privileged"}]}}},
                       {"prom": "run/k8s.prom", "absent": [{"name": "security_secrets_total"}]},
                       read_only()]}]},
        {"instance.json": {"name": "conformance", "kubernetes": [{"name": "prod", "kubeconfig": kc("prod"), "role": "prod"}]},
         "fake_kubectl.py": fk, "prod.json": c})

    c = lab_cluster()
    c["resources"]["policyreports.wgpolicyk8s.io"] = {
        "error": 'Error from server (Forbidden): policyreports.wgpolicyk8s.io is forbidden: User "reader" cannot list resource "policyreports"'}
    h.write_case("collector-k8s", "unreadable-policy-reports-are-a-gap", {
        "title": "PolicyReports that exist but cannot be listed (forbidden) are a narrow gap of the policy checks, never "
                 "the finding that no policy engine is installed; only a missing resource type means no engine",
        "contract": C, "deviation": "K8S-D2", "origin": "any kubectl error was read as `no admission policy engine`",
        "files": files(["lab"]),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s") + [
                       {"json": "run/k8s.findings.json", "subset": {
                           "coverage": {"$contains": [{"asset": "k8s-cluster:lab", "status": "ok"},
                                                      {"asset": "k8s-cluster:lab/policy", "status": "gap",
                                                       "checks": ["k8s.policy.*"], "reason": {"$regex": "[Ff]orbidden"}}]},
                           "findings": {"$not_contains": [{"check": "k8s.policy.engine_missing"}]}}},
                       read_only()]}]},
        {"instance.json": {"name": "conformance", "kubernetes": [{"name": "lab", "kubeconfig": kc("lab"), "parts": ["workloads", "policy"]}]},
         "fake_kubectl.py": fk, "lab.json": c})

    h.write_case("collector-k8s", "kube-bench-failure-keeps-cis-findings", {
        "title": "When kube-bench fails, the CIS findings on k8s-cluster:<name> stay unknown: a narrow gap "
                 "k8s-cluster:<name>/cis with checks cis.* (a gap on cis:<name> alone let the ledger fix them)",
        "contract": C, "deviation": "K8S-D3", "origin": "the cluster's ok entry covered the CIS findings of a failed kube-bench run",
        "files": files(["lab"], {"data/kube-bench_0.9.0_linux_amd64.tar.gz": {"raw": "kube-bench.tar.gz"}}),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s") + [
                       {"json": "run/k8s.findings.json", "subset": {
                           "coverage": {"$contains": [{"asset": "k8s-cluster:lab", "status": "ok"},
                                                      {"asset": "cis:lab", "status": "gap", "reason": {"$regex": "kube-bench failed"}},
                                                      {"asset": "k8s-cluster:lab/cis", "status": "gap", "checks": ["cis.*"],
                                                       "reason": {"$regex": "kube-bench failed"}}]}}}]}]},
        {"instance.json": {"name": "conformance", "kubernetes": [
            {"name": "lab", "kubeconfig": kc("lab"), "parts": ["workloads", "cis"], "host_exec": {"type": "local"},
             "kube_bench": {"benchmark": "cis-1.9", "tarball": "kube-bench_0.9.0_linux_amd64.tar.gz"}}]},
         "fake_kubectl.py": fk, "lab.json": lab_cluster(), "kube-bench.tar.gz": kube_bench_tarball(fail=True)})

    c = {"resources": {"namespaces": [], "clusterroles": [], "clusterrolebindings": [],
                       "roles": [{"metadata": meta("secret-reader", "web"), "rules": rules([[""], ["secrets"], ["get"]])}],
                       "rolebindings": [binding("RoleBinding", "carol-reads", "Role", "secret-reader", [subj("User", "carol")], ns="web")]}}
    h.write_case("collector-k8s", "namespaced-role-is-evaluated", {
        "title": "A RoleBinding to a namespaced Role is judged by the Role's rules like one to a ClusterRole: reading "
                 "Secrets through a Role is reported",
        "contract": C, "deviation": "K8S-D4", "origin": "only ClusterRole references were looked up",
        "files": files(["rbac"]),
        "steps": [{"name": "collect", "exec": {"impl": "collector-k8s", "env": env(h), "writes_only_under": ["run"]},
                   "expect": h.protocol_checks("k8s") + [
                       {"json": "run/k8s.findings.json", "subset": {"findings": [
                           {"check": "k8s.rbac.secrets_read", "asset": "k8s-identity:rbac/User:carol", "severity": "medium",
                            "layer": "identity", "title": "User:carol has secrets-read (ns:web, via secret-reader)"}]}},
                       read_only(), {"file": ".svc-kubectl.calls", "regex": [r"^rbac: get roles -A -o json$"]}]}]},
        {"instance.json": {"name": "conformance", "kubernetes": [{"name": "rbac", "kubeconfig": kc("rbac"), "role": "prod",
                                                                  "parts": ["rbac"]}]},
         "fake_kubectl.py": fk, "rbac.json": c})
