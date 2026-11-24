"""In-cluster hub: the authenticated inbox (kubernetes-secret spool over the API), least privilege of each identity,
store-and-forward from sites (offline-safe), site states, control files only from trusted sites, the snapshot
contract (security-platform/snapshot/v1) and its safe extraction, the ConfigMap sink over the API."""
import base64
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "runner"), ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "core"), os.path.dirname(__file__)]
import runner  # noqa: E402
import snapshot  # noqa: E402
from adapters import kubeapi, sinks, spool  # noqa: E402
from fakekube import FakeKube  # noqa: E402

FX = os.path.join(ROOT, "tests", "fixtures", "host.findings.json")
S = lambda *v: {("secrets", x) for x in v}      # noqa: E731
C = lambda *v: {("configmaps", x) for x in v}   # noqa: E731


class Hub(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.kube = FakeKube({"t-hub": {"user": "hub", "verbs": S("list", "get", "delete", "create", "patch") | C("create", "get", "patch")},
                              "t-vantage": {"user": "site-vantage", "verbs": S("create")},
                              "t-ws": {"user": "site-workstation", "verbs": S("create", "get")}})
        self.tok = {}
        for t in ("t-hub", "t-vantage", "t-ws"):
            p = os.path.join(self.d, t)
            with open(p, "w") as f:
                f.write(t + "\n")
            os.chmod(p, 0o600)
            self.tok[t] = p

    def tearDown(self):
        self.kube.close()
        shutil.rmtree(self.d)

    def api(self, tok, **kw):
        return dict({"type": "kubernetes-secret", "namespace": "hub", "server": self.kube.url, "token_file": self.tok[tok]}, **kw)

    def cmd_job(self):
        p = os.path.join(self.d, "job.py")
        with open(p, "w") as f:
            f.write(f"import os,shutil; shutil.copy({FX!r}, os.path.join(os.environ['SP_RUN_DIR'], 'host.findings.json'))\n")
        return {"type": "command", "collector": "host", "schedule": "* * * * *", "argv": [sys.executable, p]}

    def write(self, name, obj):
        p = os.path.join(self.d, name)
        with open(p, "w") as f:
            json.dump(obj, f)
        return p

    # ---- the inbox ------------------------------------------------------------------------------------------
    def test_inbox_roundtrip_and_least_privilege(self):
        site = spool.spool(self.api("t-vantage", site="vantage"))
        site.put("a.findings.json", '{"v": 1}')
        site.put("a.findings.json", '{"v": 2}')                    # the same name again (e.g. a job state)
        with self.assertRaises(kubeapi.KubeError) as e:
            site.list()                                              # a writer cannot read the inbox
        self.assertEqual(e.exception.status, 403)
        hub = spool.spool(self.api("t-hub", site="vantage"))
        self.assertEqual(hub.list(), ["a.findings.json"])
        self.assertEqual(hub.get("a.findings.json"), '{"v": 2}')    # newest wins
        self.assertEqual(spool.spool(self.api("t-hub", site="other")).list(), [])
        self.assertEqual(spool.spool(self.api("t-hub", site="vantage", box="state")).list(), [])
        hub.ack("a.findings.json")
        self.assertEqual(hub.list(), [])
        for o in self.kube.objects.get(("hub", "secrets"), {}).values():
            self.fail(f"left behind: {o['metadata']['name']}")

    def test_token_file_must_be_private(self):
        os.chmod(self.tok["t-vantage"], 0o644)
        with self.assertRaises(PermissionError):
            spool.spool(self.api("t-vantage", site="vantage")).put("x.json", "{}")

    def test_configmap_sink_over_the_api(self):
        sinks.publish({"type": "kubernetes-configmap", "namespace": "hub", "name": "security-platform-metrics",
                       "server": self.kube.url, "token_file": self.tok["t-hub"]}, "a 1\n")
        cm = self.kube.objects[("hub", "configmaps")]["security-platform-metrics"]
        self.assertEqual(cm["data"]["security-platform.prom"], "a 1\n")

    # ---- site -> inbox -> hub -------------------------------------------------------------------------------
    def site_instance(self, server_ok=True):
        to = self.api("t-vantage", site="vantage")
        if not server_ok:
            to["server"] = "http://127.0.0.1:9"                      # nothing listens: offline
        return self.write("site.json", {"name": "t", "runner": {
            "site": "vantage", "role": "site",
            "outbox": [{"type": "local", "dir": os.path.join(self.d, "q-out")}],
            "state_outbox": [{"type": "local", "dir": os.path.join(self.d, "q-state")}],
            "forward": [{"from": {"type": "local", "dir": os.path.join(self.d, "q-out")}, "to": to},
                        {"from": {"type": "local", "dir": os.path.join(self.d, "q-state")}, "to": dict(to, box="state")}],
            "jobs": {"host": self.cmd_job()}}})

    def hub_instance(self, data_jobs=None):
        hub_api = {"server": self.kube.url, "token_file": self.tok["t-hub"], "namespace": "hub"}
        jobs = {"ingest-vantage": {"type": "ingest", "schedule": "* * * * *", "site": "vantage",
                                   "source": dict(hub_api, type="kubernetes-secret", site="vantage"),
                                   "site_state": dict(hub_api, type="kubernetes-secret", site="vantage", box="state"),
                                   "site_collectors": {"host": "30 3 * * *"}}}
        jobs.update(data_jobs or {})
        return self.write("hub.json", {"name": "t", "runner": {
            "site": "hub", "role": "hub", "jobs": jobs,
            "sinks": [dict(hub_api, type="kubernetes-configmap", name="security-platform-metrics")]}})

    def test_site_pushes_and_the_hub_ingests(self):
        site_data, hub_data = os.path.join(self.d, "site"), os.path.join(self.d, "hubdata")
        self.assertEqual(runner.main(["tick", "--instance", self.site_instance(), "--data", site_data]), 0)
        self.assertEqual([f for f in os.listdir(os.path.join(self.d, "q-out")) if f.endswith(".json")], [])   # delivered
        self.assertEqual(runner.main(["tick", "--instance", self.hub_instance(), "--data", hub_data]), 0)
        st = json.load(open(os.path.join(hub_data, "state", "runner", "ingest-vantage.json")))
        self.assertEqual(st["last_rc"], 0, st)
        self.assertTrue(json.load(open(os.path.join(hub_data, "ledger.json")))["entries"])
        self.assertEqual([k for k in self.kube.objects.get(("hub", "secrets"), {})], [])   # inbox drained
        m = self.kube.objects[("hub", "configmaps")]["security-platform-metrics"]["data"]["security-platform.prom"]
        self.assertIn('security_runner_job_last_success_timestamp_seconds{job="host",site="vantage"}', m)
        self.assertIn('security_runner_job_last_success_timestamp_seconds{job="forward-0",site="vantage"}', m)

    def test_forward_keeps_documents_while_offline(self):
        site_data = os.path.join(self.d, "site")
        inst = self.site_instance(server_ok=False)
        self.assertEqual(runner.main(["tick", "--instance", inst, "--data", site_data]), 0)
        q = os.path.join(self.d, "q-out")
        self.assertEqual(len([f for f in os.listdir(q) if f.endswith(".findings.json")]), 1)   # still queued
        st = json.load(open(os.path.join(site_data, "state", "runner", "forward-0.json")))
        self.assertEqual((st["last_rc"], st["failures_total"]), (75, 1))
        runner.main(["tick", "--instance", self.site_instance(), "--data", site_data])     # back online
        self.assertEqual([f for f in os.listdir(q) if f.endswith(".findings.json")], [])
        self.assertEqual(len(spool.spool(self.api("t-hub", site="vantage")).list()), 1)

    def test_control_files_only_from_trusted_sites(self):
        ws_data, hub_data = os.path.join(self.d, "ws"), os.path.join(self.d, "hubdata")
        os.makedirs(ws_data)
        self.write("ws/exceptions.yaml", {"exceptions": {"abc": {"approved_by": "x", "expires": "2099-01-01", "reason": "r"}}})
        ws = self.write("ws.json", {"name": "t", "runner": {"site": "workstation", "role": "site",
                                                             "outbox": self.api("t-ws", site="workstation"),
                                                             "jobs": {"push": {"type": "push", "schedule": "* * * * *",
                                                                               "files": {"exceptions": "exceptions.yaml"}}}}})
        self.assertEqual(runner.main(["run", "push", "--instance", ws, "--data", ws_data]), 0)
        self.assertEqual(runner.main(["run", "push", "--instance", ws, "--data", ws_data]), 0)   # unchanged: not re-sent
        api = {"server": self.kube.url, "token_file": self.tok["t-hub"], "namespace": "hub", "type": "kubernetes-secret"}
        untrusted = self.hub_instance({"ingest-workstation": {"type": "ingest", "schedule": "* * * * *", "site": "workstation",
                                                              "source": dict(api, site="workstation")}})
        runner.main(["run", "ingest-workstation", "--instance", untrusted, "--data", hub_data])
        self.assertFalse(os.path.exists(os.path.join(hub_data, "exceptions.yaml")))          # not accepted
        runner.main(["run", "push", "--instance", ws, "--data", ws_data])
        os.remove(os.path.join(ws_data, "state", "runner", "push.json"))                     # forget: send again
        runner.main(["run", "push", "--instance", ws, "--data", ws_data])
        trusted = self.hub_instance({"ingest-workstation": {"type": "ingest", "schedule": "* * * * *", "site": "workstation",
                                                            "source": dict(api, site="workstation"),
                                                            "accept_control": ["exceptions"]}})
        self.assertEqual(runner.main(["run", "ingest-workstation", "--instance", trusted, "--data", hub_data]), 0)
        got = runner.load_config(os.path.join(hub_data, "exceptions.yaml"))
        self.assertEqual(got["exceptions"]["abc"]["approved_by"], "x")

    # ---- snapshots --------------------------------------------------------------------------------------------
    def test_snapshot_published_and_pulled(self):
        hub_data, ws_data = os.path.join(self.d, "hubdata"), os.path.join(self.d, "ws")
        os.makedirs(os.path.join(hub_data, "reports"))
        self.write("hubdata/ledger.json", {"entries": {"x": 1}})
        self.write("hubdata/reports/r.json", {"r": 1})
        snap = {"server": self.kube.url, "token_file": self.tok["t-hub"], "namespace": "hub", "name": "security-platform-snapshot"}
        hub = self.hub_instance({"snapshot": {"type": "snapshot", "schedule": "* * * * *", "to": snap}})
        self.assertEqual(runner.main(["run", "snapshot", "--instance", hub, "--data", hub_data]), 0)
        ws = self.write("ws.json", {"name": "t", "runner": {"site": "workstation", "role": "hub", "jobs": {
            "pull": {"type": "pull-snapshot", "schedule": "* * * * *", "into": "hub-snapshots/lab",
                     "from": dict(snap, token_file=self.tok["t-ws"])}}}})
        self.assertEqual(runner.main(["run", "pull", "--instance", ws, "--data", ws_data]), 0)
        self.assertEqual(json.load(open(os.path.join(ws_data, "hub-snapshots", "lab", "ledger.json"))), {"entries": {"x": 1}})
        man = json.load(open(os.path.join(ws_data, "hub-snapshots", "lab", "MANIFEST.json")))
        self.assertEqual((man["schema"], sorted(man["files"])), (snapshot.SCHEMA, ["ledger.json", "reports/r.json"]))

    def test_unpack_rejects_unsafe_or_tampered(self):
        def tar(members, manifest):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as t:
                for n, b in [("MANIFEST.json", json.dumps(manifest).encode())] + members:
                    ti = tarfile.TarInfo(n)
                    ti.size = len(b)
                    t.addfile(ti, io.BytesIO(b))
            return buf.getvalue()
        import hashlib
        h = hashlib.sha256(b"x").hexdigest()
        into = os.path.join(self.d, "into")
        for blob in (tar([("../evil", b"x")], {"schema": snapshot.SCHEMA, "files": {"../evil": h}}),
                     tar([("a", b"y")], {"schema": snapshot.SCHEMA, "files": {"a": h}}),
                     tar([("a", b"x"), ("b", b"x")], {"schema": snapshot.SCHEMA, "files": {"a": h}}),
                     tar([("a", b"x")], {"schema": "other/v9", "files": {"a": h}})):
            with self.assertRaises(ValueError):
                snapshot.unpack(blob, into)
            self.assertFalse(os.path.exists(os.path.join(self.d, "evil")))
        self.assertEqual(snapshot.unpack(tar([("a", b"x")], {"schema": snapshot.SCHEMA, "files": {"a": h}}), into)["files"], {"a": h})
        self.assertEqual(base64.b64encode(b"x"), b"eA==")


class Manifests(unittest.TestCase):
    """The hub's Kubernetes manifests keep their least-privilege promises (no Secret access cluster-wide; writes only
    to its own objects; sites create-only)."""
    def test_rbac(self):
        import yaml
        docs = list(yaml.safe_load_all(open(os.path.join(ROOT, "deploy", "kubernetes", "hub", "rbac.yaml"))))
        by = {(d["kind"], d["metadata"]["name"]): d for d in docs}
        cr = by[("ClusterRole", "security-platform-hub-read")]
        for r in cr["rules"]:
            self.assertNotIn("secrets", r["resources"])
            self.assertLessEqual(set(r["verbs"]), {"get", "list"})
        hub = by[("Role", "security-platform-hub")]
        for r in hub["rules"]:
            if set(r["verbs"]) & {"patch", "update"}:
                self.assertTrue(r.get("resourceNames"), r)
        self.assertEqual(by[("Role", "security-platform-inbox-writer")]["rules"], [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}])
        reader = by[("Role", "security-platform-snapshot-reader")]["rules"][0]
        self.assertEqual((reader["verbs"], reader["resourceNames"]), (["get"], ["security-platform-snapshot"]))
        for crb in [d for d in docs if d["kind"] == "ClusterRoleBinding"]:
            # kustomize's namespace transformer only rewrites subjects in "default" (or none): anything else would
            # bind a ServiceAccount of a namespace that does not exist
            self.assertEqual({s.get("namespace", "default") for s in crb["subjects"]}, {"default"})
        kust = yaml.safe_load(open(os.path.join(ROOT, "deploy", "kubernetes", "hub", "kustomization.yaml")))
        for f in kust["resources"]:
            self.assertTrue(os.path.exists(os.path.join(ROOT, "deploy", "kubernetes", "hub", f)))
        json.load(open(os.path.join(ROOT, "deploy", "kubernetes", "hub", "hub.example.json")))


if __name__ == "__main__":
    unittest.main()
