#!/usr/bin/env python3
"""Collector `k8s`: Kubernetes posture, any distro, READ-ONLY (get/list only; nothing is deployed).

Instance config `kubernetes: [{name, kubeconfig, role, host_exec?, kube_bench?: {benchmark, tarball}}]`.
Checks: privileged / host namespaces / hostPath / added capabilities, NetworkPolicy coverage, RBAC
(cluster-admin bindings, wildcard roles, secret readers), Secret metadata (names/types/ages only, never data),
Kyverno/wgpolicy PolicyReports summary, the operator credential itself, CIS via kube-bench run on the node
(read-only; extracted to a temp dir and removed). Also writes the software inventory of running images
(inventory/v1) that the vuln-intel collector matches against advisories.
Pod specs carry env values: they are parsed in memory and only filtered fields are stored.
"""
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import exec as ex  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()


def kget(kc, *args):
    p = subprocess.run(["kubectl", "--kubeconfig", os.path.expanduser(kc), "get", *args, "-o", "json"],
                       capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip()[-200:])
    return json.loads(p.stdout)["items"]


def ts(s):
    return time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone


def owner(pod):
    refs = pod["metadata"].get("ownerReferences") or []
    if not refs:
        return "Pod", pod["metadata"]["name"]
    k, n = refs[0]["kind"], refs[0]["name"]
    if k == "ReplicaSet":
        return "Deployment", re.sub(r"-[a-z0-9]{6,10}$", "", n)
    if k == "Job":
        return "Job", re.sub(r"-[0-9]{6,}$", "", n)
    return k, n


def selects(sel, labels):
    return bool(sel) and all(labels.get(k) == v for k, v in sel.items())


def np_selects(np, labels):
    ps = np["spec"].get("podSelector") or {}
    ml = ps.get("matchLabels") or {}
    exprs = ps.get("matchExpressions") or []
    if not ml and not exprs:
        return True
    if not all(labels.get(k) == v for k, v in ml.items()):
        return False
    for e in exprs:
        op, key, vals = e["operator"], e["key"], e.get("values", [])
        if op == "In" and labels.get(key) not in vals:
            return False
        if op == "NotIn" and labels.get(key) in vals:
            return False
        if op == "Exists" and key not in labels:
            return False
        if op == "DoesNotExist" and key in labels:
            return False
    return True


def cluster(c, k, inventory):
    name, kc, prod = k["name"], k["kubeconfig"], k.get("role") == "prod"
    A = f"k8s-cluster:{name}"
    pods = [p for p in kget(kc, "pods", "-A") if p["status"].get("phase") in ("Running", "Pending")]
    svcs = kget(kc, "services", "-A")
    nps = kget(kc, "networkpolicies", "-A")
    c.ok(A)
    # --- exposure map: pods behind NodePort/LoadBalancer services --------------------------------
    exposed = set()
    for s in svcs:
        if s["spec"].get("type") in ("NodePort", "LoadBalancer"):
            for p in pods:
                if p["metadata"]["namespace"] == s["metadata"]["namespace"] and \
                        selects(s["spec"].get("selector"), p["metadata"].get("labels") or {}):
                    exposed.add(p["metadata"]["uid"])
    for p in pods:
        if p["spec"].get("hostNetwork"):
            exposed.add(p["metadata"]["uid"])
    # --- pod security ----------------------------------------------------------------------------
    wl = {}
    root_like, no_np = 0, {}
    images = {}
    for p in pods:
        ns, md, spec = p["metadata"]["namespace"], p["metadata"], p["spec"]
        ok_, on = owner(p)
        key = f"k8s-workload:{name}/{ns}/{ok_}/{on}"
        w = wl.setdefault(key, {"issues": set(), "ns": ns})
        if spec.get("hostNetwork"):
            w["issues"].add("hostNetwork")
        if spec.get("hostPID"):
            w["issues"].add("hostPID")
        if spec.get("hostIPC"):
            w["issues"].add("hostIPC")
        for v in spec.get("volumes") or []:
            if "hostPath" in v:
                w["issues"].add("hostPath:" + v["hostPath"]["path"])
        psc = spec.get("securityContext") or {}
        statuses = {s["name"]: s.get("imageID", "") for s in (p["status"].get("containerStatuses") or []) +
                    (p["status"].get("initContainerStatuses") or [])}
        for ct in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            sc = ct.get("securityContext") or {}
            if sc.get("privileged"):
                w["issues"].add("privileged")
            caps = set((sc.get("capabilities") or {}).get("add") or [])
            for cap in caps & {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "SYS_MODULE"}:
                w["issues"].add("cap:" + cap)
            nonroot = sc.get("runAsNonRoot", psc.get("runAsNonRoot"))
            uid = sc.get("runAsUser", psc.get("runAsUser"))
            if not nonroot and not uid:
                root_like += 1
            img = ct["image"]
            e = images.setdefault(img, {"cluster": name, "image": img, "image_id": statuses.get(ct["name"], ""),
                                        "namespaces": set(), "workloads": set(), "exposed": False, "prod": prod})
            e["namespaces"].add(ns)
            e["workloads"].add(key)
            e["exposed"] |= md["uid"] in exposed
        labels = md.get("labels") or {}
        if not any(n["metadata"]["namespace"] == ns and np_selects(n, labels) for n in nps):
            no_np.setdefault(ns, 0)
            no_np[ns] += 1
    ev = c.raw(f"{name}-workloads.json", {k2: {"ns": v["ns"], "issues": sorted(v["issues"])} for k2, v in wl.items()})
    sevmap = {"privileged": "high", "hostPID": "high", "hostNetwork": "medium", "hostIPC": "medium"}
    for key, w in wl.items():
        for issue in sorted(w["issues"]):
            base = issue.split(":")[0]
            sev = sevmap.get(base, "medium")
            if not prod and sev == "high":
                sev = "medium"
            c.finding("workload", key, f"k8s.pod.{base.lower()}" + (f".{issue.split(':',1)[1].lower()}" if base == "cap" else ""),
                      f"{key.split(':',1)[1]}: {issue}", sev, ev,
                      "drop the privilege or record an exception (system components) with expiry",
                      kind="compliance")
    c.metric("security_k8s_pods_root_capable_containers", root_like, "Containers without runAsNonRoot/runAsUser",
             cluster=name)
    ev_np = c.raw(f"{name}-netpol.json", {"namespaces_without_policy": no_np, "policies": len(nps)})
    for ns, n in sorted(no_np.items()):
        c.finding("workload", f"k8s-namespace:{name}/{ns}", "k8s.netpol.missing",
                  f"{n} pod(s) in {name}/{ns} not selected by any NetworkPolicy (flat network)",
                  "medium" if prod else "low", ev_np, "default-deny NetworkPolicy + explicit allows")
    c.metric("security_k8s_pods_without_netpol", sum(no_np.values()), "Pods not selected by any NetworkPolicy",
             cluster=name)
    for img, e in images.items():
        e["namespaces"], e["workloads"] = sorted(e["namespaces"]), sorted(e["workloads"])
        inventory.append(e)
    # --- RBAC ------------------------------------------------------------------------------------
    crbs, crs = kget(kc, "clusterrolebindings"), {r["metadata"]["name"]: r for r in kget(kc, "clusterroles")}
    rbs = kget(kc, "rolebindings", "-A")

    def wide(rules):
        w = set()
        for r in rules or []:
            v, res, g = set(r.get("verbs", [])), set(r.get("resources", [])), set(r.get("apiGroups", []))
            if "*" in v and "*" in res:
                w.add("wildcard")
            if res & {"secrets", "*"} and v & {"get", "list", "watch", "*"} and g & {"", "*"}:
                w.add("secrets-read")
            if res & {"pods/exec", "*"} and v & {"create", "*"}:
                w.add("pods-exec")
            if res & {"clusterrolebindings", "rolebindings", "*"} and v & {"create", "update", "patch", "bind", "escalate", "*"}:
                w.add("rbac-write")
        return w

    rb_ev = []
    for b in crbs + rbs:
        rr = b["roleRef"]
        role = crs.get(rr["name"]) if rr["kind"] == "ClusterRole" else None
        flags = set()
        if rr["name"] == "cluster-admin":
            flags.add("cluster-admin")
        if role:
            flags |= wide(role.get("rules"))
        if not flags:
            continue
        scope = "cluster" if b["kind"] == "ClusterRoleBinding" else f"ns:{b['metadata']['namespace']}"
        for s in b.get("subjects") or []:
            subj = f"{s['kind']}:{s.get('namespace', '') + '/' if s.get('namespace') else ''}{s['name']}"
            if s["name"].startswith("system:") and s["kind"] != "ServiceAccount":
                continue
            if s.get("namespace") == "kube-system" or rr["name"].startswith("system:"):
                continue
            rb_ev.append(dict(binding=b["metadata"]["name"], scope=scope, subject=subj, role=rr["name"], flags=sorted(flags)))
    ev_rb = c.raw(f"{name}-rbac.json", rb_ev)
    for r in rb_ev:
        sev = "high" if ("cluster-admin" in r["flags"] or "wildcard" in r["flags"]) and r["scope"] == "cluster" else "medium"
        if not prod and sev == "high":
            sev = "medium"
        c.finding("identity", f"k8s-identity:{name}/{r['subject']}", "k8s.rbac." + "_".join(f.replace("-", "_") for f in r["flags"]),
                  f"{r['subject']} has {','.join(r['flags'])} ({r['scope']}, via {r['role']})", sev, ev_rb,
                  "least privilege: scope to namespaces / specific verbs; document why if required")
    c.metric("security_k8s_wide_rbac_subjects", len({r["subject"] for r in rb_ev}), "Subjects with wide RBAC", cluster=name)
    # --- Secrets: metadata only (custom-columns never fetches .data) ------------------------------
    p = subprocess.run(["kubectl", "--kubeconfig", os.path.expanduser(kc), "get", "secrets", "-A", "--no-headers", "-o",
                        "custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp"],
                       capture_output=True, text=True, timeout=60)
    secrets = [dict(zip(["ns", "name", "type", "created"], l.split())) for l in p.stdout.splitlines() if l.strip()]
    secrets = [s for s in secrets if s["type"] not in ("helm.sh/release.v1", "kubernetes.io/service-account-token")]
    old = [s for s in secrets if time.time() - ts(s["created"]) > 90 * 86400]
    c.raw(f"{name}-secrets-metadata.json", secrets)
    c.metric("security_secrets_total", len(secrets), "Secrets (metadata only)", store=f"k8s:{name}")
    c.metric("security_secrets_older_than_90d", len(old), "Secrets older than 90 days", store=f"k8s:{name}")
    # --- policy reports ---------------------------------------------------------------------------
    try:
        reps = kget(kc, "policyreports.wgpolicyk8s.io", "-A") + kget(kc, "clusterpolicyreports.wgpolicyk8s.io")
        agg = {}
        for r in reps:
            for res in r.get("results") or []:
                if res.get("result") in ("fail", "error"):
                    agg.setdefault(res.get("policy", "?"), set()).add(r["metadata"].get("namespace", "-"))
        summ = {}
        for r in reps:
            for kk, vv in (r.get("summary") or {}).items():
                summ[kk] = summ.get(kk, 0) + vv
        ev_pr = c.raw(f"{name}-policyreports.json", {"summary": summ, "failing": {k2: sorted(v) for k2, v in agg.items()}})
        for pol, nss in agg.items():
            c.finding("workload", f"k8s-cluster:{name}", f"k8s.policy.fail.{pol}",
                      f"admission/background policy '{pol}' failing in {len(nss)} namespace(s)", "low", ev_pr,
                      "fix the resources or the policy", kind="compliance")
        for kk, vv in summ.items():
            c.metric("security_k8s_policyreport_results", vv, "PolicyReport results", cluster=name, result=kk)
    except RuntimeError:
        c.metric("security_k8s_policy_engine_present", 0, "PolicyReport CRDs present", cluster=name)
        c.finding("workload", f"k8s-cluster:{name}", "k8s.policy.engine_missing",
                  "no admission policy engine reports (no PolicyReports)", "low" if not prod else "medium",
                  c.raw(f"{name}-policyreports.json", {"present": False}), "install a policy engine (e.g. Kyverno) in audit mode")
    # --- operator credential ----------------------------------------------------------------------
    p = subprocess.run(["kubectl", "--kubeconfig", os.path.expanduser(kc), "auth", "whoami", "-o", "json"],
                       capture_output=True, text=True, timeout=30)
    if p.returncode == 0:
        who = json.loads(p.stdout)["status"]["userInfo"]
        if "system:masters" in who.get("groups", []):
            c.finding("identity", f"k8s-identity:{name}/operator-kubeconfig", "k8s.operator_cred_system_masters",
                      "the operator's kubeconfig is a system:masters client certificate (bypasses RBAC, cannot be revoked before expiry)",
                      "high" if prod else "medium", c.raw(f"{name}-whoami.json", {"groups": who.get("groups"), "username": who.get("username")}),
                      "use a per-person RBAC identity (OIDC or a cert bound to a ClusterRole), keep the admin cert offline")
    # --- CIS via kube-bench on the node ----------------------------------------------------------
    kb = k.get("kube_bench")
    if kb and k.get("host_exec"):
        kube_bench(c, name, k, kb)
    elif kb:
        c.gap(f"cis:{name}", "kube-bench needs host_exec")


def kube_bench(c, name, k, kb):
    tar = os.path.join(os.environ.get("SP_DATA", "."), kb["tarball"])
    e = ex.executor(k["host_exec"])
    # temp dir on the node, removed afterwards; kube-bench only READS config files and process args
    script = ('set -e; D=$(mktemp -d /tmp/sp-kube-bench.XXXXXX); trap "rm -rf $D" EXIT; tar xzf - -C $D; cd $D; '
              f'sudo -n ./kube-bench --config-dir cfg --benchmark {kb["benchmark"]} --json 2>/dev/null')
    rc, out, err = _run_with_tar(e, script, tar)
    if rc != 0 or not out.strip():
        c.gap(f"cis:{name}", f"kube-bench failed rc={rc}: {err.strip()[-160:]}")
        return
    c.tools["kube-bench"] = os.path.basename(tar).split("_")[1]
    data = json.loads(out)
    fails, totals = [], {"pass": 0, "fail": 0, "warn": 0, "info": 0}
    for ctl in data.get("Controls", []):
        for g in ctl.get("tests", []):
            for r in g.get("results", []):
                st = r.get("status", "").lower()
                totals[st] = totals.get(st, 0) + 1
                if st == "fail":
                    fails.append(dict(id=r["test_number"], desc=r["test_desc"], scored=r.get("scored"),
                                      remediation=(r.get("remediation") or "")[:300]))
    ev = c.raw(f"{name}-kube-bench.json", {"benchmark": kb["benchmark"], "totals": totals, "fails": fails})
    c.ok(f"cis:{name}")
    for f in fails:
        c.finding("workload", f"k8s-cluster:{name}", f"cis.{kb['benchmark']}.{f['id']}", f"CIS {f['id']} FAIL: {f['desc']}",
                  "medium" if f.get("scored") else "low", ev, f["remediation"].split("\n")[0] or "see benchmark",
                  kind="compliance", refs=[f"cis:{kb['benchmark']}:{f['id']}"])
    for st, n in totals.items():
        c.metric("security_cis_results", n, "kube-bench results", cluster=name, result=st)


def _run_with_tar(e, script, tar):
    # stream the tarball over stdin (binary-safe via base64 to keep the text-mode exec adapter)
    import base64
    b64 = base64.b64encode(open(tar, "rb").read()).decode()
    return e.run(["sh", "-c", script.replace("tar xzf - -C $D", "base64 -d | tar xzf - -C $D")], stdin=b64, timeout=600)


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("k8s", VERSION)
    inventory = []
    for k in inst.get("kubernetes", []):
        try:
            cluster(c, k, inventory)
        except Exception as err:  # noqa: BLE001
            c.gap(f"k8s-cluster:{k['name']}", f"{type(err).__name__}: {str(err)[:200]}")
    with open(os.path.join(c.out, "inventory.k8s-images.json"), "w") as f:
        json.dump({"schema": "security-platform/inventory/v1", "kind": "container-image", "items": inventory}, f, indent=1)
    c.metric("security_inventory_images", len(inventory), "Running images (cluster x image)")
    c.write()


if __name__ == "__main__":
    main()
