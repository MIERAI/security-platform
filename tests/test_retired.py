"""Retired assets: an asset that disappeared from an authoritative, COMPLETE inventory closes its findings
(fixed, asset_retired); a partial or failed inventory never does (unknown); reappearance reopens (regression).
Covers the ledger rule (`complete_scope`), the vuln-intel image inventory and the k8s inventory's completeness."""
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "core"), os.path.join(ROOT, "sdk")]
import validate  # noqa: E402
from spsdk import fid  # noqa: E402


def finding(image, cve="CVE-2099-0001"):
    asset = f"image:{image}"
    return {"id": fid("supply-chain", asset, f"vuln.{cve.lower()}"), "check": f"vuln.{cve.lower()}",
            "layer": "supply-chain", "asset": asset, "title": f"{cve} in lib", "severity": "critical",
            "evidence": "raw/vuln-intel/matches.json#x", "remediation": "update lib", "needs_human": False,
            "owner": "platform", "observed_at": "2026-11-24T08:00:00Z", "kind": "vulnerability"}


def doc(findings, coverage):
    return {"schema_version": "1.1", "collector": {"name": "vuln-intel", "version": "0.5.0"},
            "run": {"started_at": "2026-11-24T08:00:00Z", "finished_at": "2026-11-24T09:00:00Z"},
            "coverage": coverage, "findings": findings}


COMPLETE = {"asset": "inventory:container-image", "status": "ok", "complete_scope": "image:"}


class LedgerRetirement(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.n = 0

    def tearDown(self):
        shutil.rmtree(self.d)

    def run_ledger(self, d):
        self.n += 1
        r = os.path.join(self.d, "runs", str(self.n))
        os.makedirs(r)
        self.assertEqual(validate.validate_findings(d), [])
        with open(os.path.join(r, "vuln-intel.findings.json"), "w") as f:
            json.dump(d, f)
        subprocess.run([sys.executable, os.path.join(ROOT, "core", "ledger.py"), "--run", r, "--data", self.d],
                       check=True, capture_output=True)
        return json.load(open(os.path.join(self.d, "ledger.json")))["entries"]

    def test_retired_image_closes_and_reappearance_reopens(self):
        old = finding("registry.example/app:1.0")
        E = self.run_ledger(doc([old], [{"asset": "image:registry.example/app:1.0", "status": "ok"}, COMPLETE]))
        self.assertEqual(E[old["id"]]["status"], "open")
        # the workload moved to 1.1: the complete inventory no longer lists 1.0
        E = self.run_ledger(doc([], [{"asset": "image:registry.example/app:1.1", "status": "ok"}, COMPLETE]))
        self.assertEqual(E[old["id"]]["status"], "fixed")
        self.assertEqual(E[old["id"]]["fixed_reason"], "asset_retired")
        self.assertIsNotNone(E[old["id"]]["time_to_fix_days"])
        # rolled back to 1.0 with the same CVE: a regression
        E = self.run_ledger(doc([old], [{"asset": "image:registry.example/app:1.0", "status": "ok"}, COMPLETE]))
        self.assertEqual(E[old["id"]]["status"], "open")
        self.assertEqual(E[old["id"]]["reopened_count"], 1)
        self.assertIsNone(E[old["id"]]["fixed_reason"])

    def test_partial_or_failed_inventory_does_not_close(self):
        old = finding("registry.example/app:1.0")
        self.run_ledger(doc([old], [{"asset": "image:registry.example/app:1.0", "status": "ok"}, COMPLETE]))
        # no completeness declared (a cluster failed, or an older collector): unknown
        E = self.run_ledger(doc([], [{"asset": "image:registry.example/app:1.1", "status": "ok"}]))
        self.assertEqual(E[old["id"]]["status"], "open")
        # the inventory entry itself is a gap: a gap never declares a scope
        E = self.run_ledger(doc([], [{"asset": "image:registry.example/app:1.1", "status": "ok"},
                                     {"asset": "inventory:container-image", "status": "gap", "reason": "x",
                                      "complete_scope": "image:"}]))
        self.assertEqual(E[old["id"]]["status"], "open")
        # still listed but its scan failed (gap): the image exists, state unknown
        E = self.run_ledger(doc([], [{"asset": "image:registry.example/app:1.0", "status": "gap", "reason": "sbom rc=1"},
                                     COMPLETE]))
        self.assertEqual(E[old["id"]]["status"], "open")

    def test_scope_limits_retirement(self):
        img, repo = finding("registry.example/app:1.0"), dict(finding("x"), asset="repo:lib",
                                                              id=fid("supply-chain", "repo:lib", "vuln.cve-2099-0001"))
        self.run_ledger(doc([img, repo], [{"asset": "image:registry.example/app:1.0", "status": "ok"},
                                          {"asset": "repo:lib", "status": "ok"}, COMPLETE]))
        E = self.run_ledger(doc([], [COMPLETE]))       # nothing listed: images retired, the repo is outside the scope
        self.assertEqual(E[img["id"]]["fixed_reason"], "asset_retired")
        self.assertEqual(E[repo["id"]]["status"], "open")

    def test_covered_fix_has_its_own_reason(self):
        f = finding("registry.example/app:1.0")
        self.run_ledger(doc([f], [{"asset": "image:registry.example/app:1.0", "status": "ok"}]))
        E = self.run_ledger(doc([], [{"asset": "image:registry.example/app:1.0", "status": "ok"}]))
        self.assertEqual((E[f["id"]]["status"], E[f["id"]]["fixed_reason"]), ("fixed", "not_observed"))

    def test_scope_must_name_an_asset_type(self):
        d = doc([], [{"asset": "inventory:x", "status": "ok", "complete_scope": ""}])
        self.assertTrue(validate.validate_findings(d))


def load(name, path):
    os.environ.setdefault("SP_RUN_DIR", tempfile.mkdtemp())
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class VulnIntelInventory(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        sys.path.insert(0, os.path.join(ROOT, "collectors", "vuln-intel"))
        self.vi = load("vulnintel", os.path.join(ROOT, "collectors", "vuln-intel", "collector.py"))

    def tearDown(self):
        shutil.rmtree(self.d)

    def inv(self, name, **extra):
        p = os.path.join(self.d, f"inventory.{name}.json")
        with open(p, "w") as f:
            json.dump(dict({"schema": "security-platform/inventory/v1", "kind": "container-image",
                            "items": [{"cluster": name, "image": f"{name}/app:1", "exposed": False}]}, **extra), f)
        return p

    def test_complete_only_when_every_inventory_is(self):
        a = self.inv("a", complete=True, sources={"k8s-cluster:a": "complete"})
        items, complete, partial = self.vi.image_inventory([a])
        self.assertEqual((len(items), complete, partial), (1, True, []))
        b = self.inv("b", complete=False, sources={"k8s-cluster:b": "failed: RuntimeError"})
        _, complete, partial = self.vi.image_inventory([a, b])
        self.assertFalse(complete)
        self.assertIn("k8s-cluster:b failed", partial[0])
        old = self.inv("old")                                  # an older producer: completeness unknown
        self.assertFalse(self.vi.image_inventory([a, old])[1])
        self.assertFalse(self.vi.image_inventory([])[1])       # no inventory at all declares nothing


FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json, sys
a = sys.argv[1:]
if "--kubeconfig" in a and "broken" in a[a.index("--kubeconfig") + 1]:
    sys.exit("Unable to connect to the server")
res = a[a.index("get") + 1]
pod = {"metadata": {"name": "app-7d4b9c8f6d-abcde", "namespace": "web", "uid": "u1", "labels": {},
                    "ownerReferences": [{"kind": "ReplicaSet", "name": "app-7d4b9c8f6d"}]},
       "spec": {"containers": [{"name": "app", "image": "registry.example/app:1.1",
                                "securityContext": {"runAsNonRoot": True}}]},
       "status": {"phase": "Running", "containerStatuses": [{"name": "app", "imageID": ""}]}}
print(json.dumps({"items": [pod] if res == "pods" else []}))
'''


class K8sInventory(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        b = os.path.join(self.d, "bin")
        os.makedirs(b)
        k = os.path.join(b, "kubectl")
        with open(k, "w") as f:
            f.write(FAKE_KUBECTL.replace("/usr/bin/env python3", sys.executable))
        os.chmod(k, os.stat(k).st_mode | stat.S_IEXEC)
        self.path = b

    def tearDown(self):
        shutil.rmtree(self.d)

    def collect(self, clusters):
        inst = os.path.join(self.d, "instance.json")
        with open(inst, "w") as f:
            json.dump({"kubernetes": clusters}, f)
        run = os.path.join(self.d, "run")
        shutil.rmtree(run, ignore_errors=True)
        env = dict(os.environ, PATH=self.path + os.pathsep + os.environ["PATH"], SP_RUN_DIR=run, SP_INSTANCE=inst,
                   SP_DATA=self.d)
        env.pop("SP_COLLECTOR_NAME", None)
        subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "k8s", "collector.py")], env=env, check=True,
                       capture_output=True)
        return json.load(open(os.path.join(run, "inventory.k8s-images.json")))

    def test_complete_only_when_every_cluster_listed(self):
        inv = self.collect([{"name": "a", "kubeconfig": "/x/a", "parts": ["workloads"]}])
        self.assertTrue(inv["complete"])
        self.assertEqual([i["image"] for i in inv["items"]], ["registry.example/app:1.1"])
        inv = self.collect([{"name": "a", "kubeconfig": "/x/a", "parts": ["workloads"]},
                            {"name": "b", "kubeconfig": "/x/broken", "parts": ["workloads"]}])
        self.assertFalse(inv["complete"])
        self.assertEqual(inv["sources"]["k8s-cluster:b"], "failed: RuntimeError")
        inv = self.collect([{"name": "a", "kubeconfig": "/x/a", "parts": ["rbac"]}])   # images not listed at all
        self.assertFalse(inv["complete"])


if __name__ == "__main__":
    unittest.main()
