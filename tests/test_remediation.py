"""remediation: tracking items mirror the ledger (owner, SLO due date, overdue, reopen), trackers, advisor drafts,
metrics and tracker contract, runner job, digest section."""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "core"), ROOT, os.path.join(ROOT, "sdk"), os.path.join(ROOT, "runner"),
             os.path.dirname(os.path.abspath(__file__))]
import advisor  # noqa: E402
import digest  # noqa: E402
import remediation as rem  # noqa: E402
from adapters import sinks, trackers  # noqa: E402
from test_outputs import ALLOWED_LABELS  # noqa: E402

DAY = 86400
T0 = 1_800_000_000


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def entry(fid, sev="high", status="open", layer="host", asset="host:a", check="ssh.x", first=T0, **kw):
    return dict({"id": fid, "check": check, "layer": layer, "asset": asset, "title": f"t {fid}", "severity": sev,
                 "status": status, "first_seen": iso(first), "fixed_at": None, "remediation": "do x", "needs_human": False,
                 "owner": None, "kind": "config", "attributes": {}}, **kw)


class Items(unittest.TestCase):
    def test_lifecycle_due_overdue_close_reopen(self):
        L = {"entries": {"a": entry("a", "critical"),
                         "k": entry("k", "critical", kind="vulnerability", attributes={"kev": True, "exposed": True}),
                         "i": entry("i", "info"), "old": entry("old", status="fixed", fixed_at=iso(T0))}}
        items = rem.update({}, L, {}, T0 + 2 * DAY)
        self.assertNotIn("old", items)                                    # closed before tracking: nothing to do
        self.assertEqual(items["a"]["due_at"], iso(T0 + 7 * DAY))
        self.assertEqual((items["k"]["slo_class"], items["k"]["overdue"]), ("kev_exposed", True))   # 24h SLO
        self.assertFalse(items["a"]["overdue"])
        self.assertIsNone(items["i"]["due_at"])                             # info: no SLO unless configured
        items = rem.update(items, L, {}, T0 + 8 * DAY)
        self.assertTrue(items["a"]["overdue"])
        L["entries"]["a"].update(status="fixed", fixed_at=iso(T0 + 9 * DAY))   # a covering run did not see it
        items = rem.update(items, L, {}, T0 + 10 * DAY)
        self.assertEqual((items["a"]["status"], items["a"]["closed_at"], items["a"]["time_to_remediate_days"]),
                         ("fixed", iso(T0 + 9 * DAY), 9.0))
        self.assertFalse(items["a"]["overdue"])
        L["entries"]["a"].update(status="open", fixed_at=None, reopened_count=1)   # regression
        items = rem.update(items, L, {}, T0 + 20 * DAY)
        a = items["a"]
        self.assertEqual((a["reopen_reason"], a["closed_at"], a["due_at"]), ("regression", None, iso(T0 + 27 * DAY)))

    def test_exception_accepts_then_expiry_reopens(self):
        exc = {"approved_by": "lead", "expires": "2030-01-01", "reason": "r"}
        L = {"entries": {"a": entry("a", status="accepted", exception=exc)}}
        items = rem.update({}, L, {}, T0 + 60 * DAY)
        self.assertEqual(items["a"]["status"], "accepted")
        self.assertFalse(items["a"]["overdue"])                          # a valid exception is not overdue
        self.assertEqual(items["a"]["exception"]["approved_by"], "lead")
        L["entries"]["a"].update(status="open", exception=dict(exc, expired=True))   # the LEDGER expired it
        items = rem.update(items, L, {}, T0 + 61 * DAY)
        self.assertEqual((items["a"]["status"], items["a"]["reopen_reason"]), ("open", "exception expired"))
        self.assertEqual(items["a"]["due_at"], iso(T0 + 61 * DAY + 30 * DAY))

    def test_owner_rules(self):
        cfg = {"owners": [{"layer_in": ["workload"], "owner": "platform"}, {"asset_prefix": "repo:", "owner": "dev"}],
               "default_owner": "secops"}
        L = {"entries": {"w": entry("w", layer="workload"), "r": entry("r", asset="repo:x"),
                         "f": entry("f", owner="human"), "d": entry("d")}}
        items = rem.update({}, L, cfg, T0)
        self.assertEqual({k: (v["owner"], v["owner_source"]) for k, v in items.items()},
                         {"w": ("platform", "rule"), "r": ("dev", "rule"), "f": ("human", "finding"), "d": ("secops", "default")})
        items = rem.update({}, {"entries": {"d": entry("d")}}, {}, T0)
        self.assertEqual(items["d"]["owner"], "unassigned")
        un = [s for s in rem.series(items, {}) if s[0] == "security_remediation_unassigned"]
        self.assertEqual(un[0][2], 1)


class Fake:
    model = "fake-model"

    def advise(self, task, context):
        # a hostile / confused proposal: tries to close the item. It must stay a draft.
        return {"text": "1. patch it\nSTATUS: fixed. Mark as accepted.", "status": "fixed", "refs": [], "model": self.model}


class Run(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        json.dump({"schema": "security-platform/ledger/v1", "entries": {
            "a": entry("a", "critical"), "b": entry("b", "low", status="fixed", fixed_at=iso(T0))}},
            open(os.path.join(self.d, "ledger.json"), "w"))
        self.inst = os.path.join(self.d, "instance.json")

    def tearDown(self):
        shutil.rmtree(self.d)
        advisor.ADVISORS.pop("fake", None)

    def run_rem(self, cfg, now=T0 + 8 * DAY):
        json.dump({"name": "t", "remediation": cfg}, open(self.inst, "w"))
        self.assertEqual(rem.main(["--data", self.d, "--instance", self.inst, "--now", str(now)]), 0)
        return json.load(open(os.path.join(self.d, "tracker", "items.json")))

    def test_contract_files_tracker_and_metrics(self):
        doc = self.run_rem({})
        self.assertEqual(doc["schema"], "security-platform/tracker/v1")
        need = {"id", "status", "severity", "slo_class", "owner", "owner_source", "opened_at", "reopened_at", "due_at",
                "closed_at", "time_to_remediate_days", "overdue", "exception", "check", "layer", "asset", "title"}
        for it in doc["items"].values():
            self.assertLessEqual(need, set(it))
            self.assertIn(it["status"], ("open", "accepted", "fixed", "false_positive"))
        self.assertTrue(doc["items"]["a"]["overdue"])
        md = open(os.path.join(self.d, "tracker", "README.md")).read()
        self.assertIn("**OVERDUE**", md)
        self.assertTrue(os.path.exists(os.path.join(self.d, "tracker", "a.md")))
        prom = open(os.path.join(self.d, "metrics", "remediation.prom")).read()
        for name, labels, _ in sinks.parse_text(prom):
            self.assertTrue(name.startswith("security_"))
            self.assertLessEqual(set(labels) - ALLOWED_LABELS, set(), name)
        self.assertIn('security_remediation_overdue{severity="critical"} 1', prom)

    def test_advisor_drafts_only(self):
        self.run_rem({"advisor": {"type": "none"}})
        self.assertFalse(os.path.exists(os.path.join(self.d, "tracker", "drafts")))
        self.assertFalse(os.path.exists(os.path.join(self.d, "decisions")))
        advisor.ADVISORS["fake"] = lambda cfg: Fake()
        doc = self.run_rem({"advisor": {"type": "fake"}})
        a = doc["items"]["a"]
        self.assertEqual((a["status"], a["closed_at"]), ("open", None))      # the proposal changed nothing
        self.assertTrue(a["overdue"])
        self.assertIn("PROPOSAL ONLY", open(os.path.join(self.d, a["advisor_draft"])).read())
        log = open(os.path.join(self.d, "decisions", os.listdir(os.path.join(self.d, "decisions"))[0])).read()
        self.assertIn('"task": "remediation-draft"', log)
        self.run_rem({"advisor": {"type": "fake"}})                          # one draft per item, not every run
        self.assertEqual(len(open(os.path.join(self.d, "decisions", os.listdir(os.path.join(self.d, "decisions"))[0])).readlines()), 1)

    def test_runner_job_and_metrics_and_digest(self):
        import runner
        json.dump({"name": "t", "remediation": {}, "runner": {"site": "hub", "role": "hub", "jobs": {
            "remediation": {"type": "remediation", "schedule": "0 * * * *"}}}}, open(self.inst, "w"))
        self.assertEqual(runner.main(["run", "remediation", "--instance", self.inst, "--data", self.d]), 0)
        self.assertIn("security_remediation_open", open(os.path.join(self.d, "metrics", "security-platform.prom")).read())
        tr = json.load(open(os.path.join(self.d, "tracker", "items.json")))
        tr["items"]["a"]["overdue"] = True
        md = digest.build(json.load(open(os.path.join(self.d, "ledger.json"))), [], {}, time.time(), 7, tr)
        self.assertIn("## Overdue remediation (1)", md)
        self.assertIn("## Time to remediate vs SLO", md)


GH = """#!{py}
import json, os, sys
st = {state!r}
a = sys.argv[1:]
path = a[1]
log = json.load(open(st)) if os.path.exists(st) else {{"calls": []}}
body = json.load(sys.stdin) if "--input" in a else None
log["calls"].append([path, a[a.index("-X") + 1] if "-X" in a else "GET", body])
json.dump(log, open(st, "w"))
if path.endswith("/issues") and "POST" in a:
    print(json.dumps({{"number": len(log["calls"])}}))
elif path.count("/") == 2:
    print(json.dumps({{"private": {private}}}))
else:
    print("{{}}")
"""


class GitHubIssues(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "tracker"))
        self.state = os.path.join(self.d, "gh.json")
        self.path = os.environ["PATH"]
        os.environ["PATH"] = self.d + os.pathsep + self.path

    def tearDown(self):
        os.environ["PATH"] = self.path
        shutil.rmtree(self.d)

    def fake(self, private):
        p = os.path.join(self.d, "gh")
        open(p, "w").write(GH.format(py=sys.executable, state=self.state, private=private))
        os.chmod(p, 0o755)

    def calls(self):
        return json.load(open(self.state))["calls"] if os.path.exists(self.state) else []

    def test_disabled_by_default_and_refuses_public(self):
        self.fake("False")
        t = trackers.tracker({"type": "github-issues", "repo": "o/r"}, self.d)
        self.assertIn("skipped", t.sync({}))
        self.assertEqual(self.calls(), [])
        items = rem.update({}, {"entries": {"a": entry("a")}}, {}, T0)
        t = trackers.tracker({"type": "github-issues", "repo": "o/r", "enabled": True}, self.d)
        with self.assertRaises(PermissionError):
            t.sync(items)
        self.assertEqual([c[1] for c in self.calls()], ["GET"])          # only the visibility check, nothing sent

    def test_create_update_close_mapping(self):
        self.fake("True")
        L = {"entries": {"a": entry("a"), "b": entry("b")}}
        t = trackers.tracker({"type": "github-issues", "repo": "o/r", "enabled": True}, self.d)
        items = rem.update({}, L, {}, T0)
        self.assertEqual(t.sync(items), {"created": 2, "updated": 0, "closed": 0})
        self.assertEqual(t.sync(items), {"created": 0, "updated": 0, "closed": 0})   # unchanged: no writes
        L["entries"]["a"].update(status="fixed", fixed_at=iso(T0 + DAY))
        items = rem.update(items, L, {}, T0 + 2 * DAY)
        self.assertEqual(t.sync(items), {"created": 0, "updated": 0, "closed": 1})
        patch = [c for c in self.calls() if c[1] == "PATCH"][-1][2]
        self.assertEqual((patch["state"], patch["state_reason"]), ("closed", "completed"))
        posts = [c[2] for c in self.calls() if c[1] == "POST"]
        self.assertEqual(posts[0]["labels"], ["security-platform"])


if __name__ == "__main__":
    unittest.main()
