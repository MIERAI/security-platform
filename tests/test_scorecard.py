"""scorecard: catalog contract (one file per dimension), evaluators, weakest-link scoring, attestations that expire,
regression counter, metrics contract, an organisation's own catalog, and the runner computing it on publish."""
import glob
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "scorecard"), os.path.join(ROOT, "tests"), ROOT, os.path.join(ROOT, "sdk")]
os.environ["TZ"] = "UTC"
time.tzset()
import scorecard as sc  # noqa: E402
from test_outputs import check_metrics_text  # noqa: E402

NOW = 1_800_000_000          # 2027-01-15
DAY = 86400


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t))


def write_catalog(d, dim, controls, order=1, **extra):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"{order:02d}-{dim}.yaml"), "w") as f:
        yaml.safe_dump({"schema": sc.CATALOG_SCHEMA, "dimension": dict({"id": dim, "order": order, "title": dim.title(),
                                                                        "pillars": ["people"]}, **extra),
                        "controls": controls}, f)


def ctl(cid, check="automated", weight=1, csf="PR.AA", pillars=("people",), **kw):
    c = {"id": cid, "title": cid, "csf": csf, "cis": ["6.3"], "check": check, "weight": weight, "pillars": list(pillars)}
    if check == "attested":
        c.update(validity="90d", question="really?")
    c.update(kw)
    return c


class ProductCatalog(unittest.TestCase):
    def test_lint_clean_and_one_file_per_dimension(self):
        dims, controls = sc.load_catalog([os.path.join(ROOT, "scorecard", "catalog")])
        self.assertEqual(sc.lint(dims, controls), [])
        files = sorted(glob.glob(os.path.join(ROOT, "scorecard", "catalog", "*.yaml")))
        self.assertEqual(len(files), len(dims), "one catalog file per dimension")
        for p in files:
            doc = yaml.safe_load(open(p))
            self.assertRegex(os.path.basename(p), rf"^\d\d-{doc['dimension']['id']}\.yaml$")

    def test_all_eleven_dimensions_and_four_pillars_and_six_functions(self):
        dims, controls = sc.load_catalog([os.path.join(ROOT, "scorecard", "catalog")])
        self.assertEqual(set(dims), {"design", "coverage", "intel", "operation", "alerting", "remediation", "detection",
                                     "self", "generality", "usability", "people"})
        self.assertEqual({p for c in controls for p in c["pillars"]}, set(sc.PILLARS))
        self.assertEqual({c["function"] for c in controls}, set(sc.FUNCTIONS))
        for d in dims:
            self.assertTrue([c for c in controls if c["dimension"] == d], d)
        self.assertTrue(any(c["check"] == "attested" for c in controls if c["dimension"] == "people"))

    def test_runbook_anchors_for_score_alerts(self):
        text = open(os.path.join(ROOT, "docs", "runbooks.md")).read()
        for a in ("## score-regression", "## attestation-expired"):
            self.assertIn(a, text)


class Scoring(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.data = os.path.join(self.d, "data")
        os.makedirs(os.path.join(self.data, "metrics"))
        os.makedirs(os.path.join(self.data, "latest"))
        self.cat = os.path.join(self.d, "catalog")
        ledger = {"entries": {
            "a": {"check": "identity.mfa_disabled", "status": "open", "severity": "high", "layer": "identity",
                  "asset": "identity:x/alice", "kind": "compliance", "attributes": {}},
            "b": {"check": "identity.mfa_disabled", "status": "fixed", "severity": "high", "layer": "identity",
                  "asset": "identity:x/bob", "kind": "compliance", "attributes": {}}},
            "collectors": {"identity": {"last_good_run": iso(NOW - DAY)}, "old": {"last_good_run": iso(NOW - 10 * DAY)}},
            "sli": {"gaps": {"value": 0, "target": 0, "ok": True}}}
        json.dump(ledger, open(os.path.join(self.data, "ledger.json"), "w"))
        json.dump({"collector": {"name": "identity"}, "coverage": [{"asset": "identity-provider:idp/main", "status": "ok"}]},
                  open(os.path.join(self.data, "latest", "identity.findings.json"), "w"))
        open(os.path.join(self.data, "metrics", "security-platform.prom"), "w").write(
            "security_x{collector=\"c\"} 3\nsecurity_ts 1799990000\nsecurity_sli_ok{sli=\"a\"} 1\nsecurity_sli_ok{sli=\"b\"} 0\n")
        att = {"attestations": {
            "people.valid": {"attested_by": "alice", "at": day(NOW - 10 * DAY)},
            "people.soon": {"attested_by": "alice", "at": day(NOW - 85 * DAY)},
            "people.expired": {"attested_by": "alice", "at": day(NOW - 91 * DAY)},
            "people.false": {"attested_by": "alice", "at": day(NOW - DAY), "value": False},
            "people.noby": {"at": day(NOW - DAY)},
            "people.na": {"attested_by": "alice", "expires": day(NOW + 30 * DAY), "not_applicable": "no org"}}}
        yaml.safe_dump(att, open(os.path.join(self.data, "attestations.yaml"), "w"))

    def tearDown(self):
        shutil.rmtree(self.d)

    def inst(self, **sc_):
        return {"scorecard": dict({"replace_catalog": True, "catalog_dirs": [self.cat]}, **sc_)}

    def by_id(self, r):
        return {c["id"]: c for c in r["controls"]}

    def test_evaluators(self):
        write_catalog(self.cat, "people", [
            ctl("people.mfa", source={"type": "findings", "check_in": ["identity.mfa_disabled"], "require_collector": "identity"}),
            ctl("people.mfa-max1", source={"type": "findings", "check_in": ["identity.mfa_disabled"], "max": 1}),
            ctl("people.stale", source={"type": "findings", "check_in": ["nothing"], "require_collector": "old"}),
            ctl("people.never", source={"type": "findings", "check_in": ["nothing"], "require_collector": "ghost"}),
            ctl("people.cov-ok", source={"type": "findings", "check_in": ["nothing"], "require_coverage": "identity-provider:"}),
            ctl("people.cov-missing", source={"type": "findings", "check_in": ["nothing"], "require_coverage": "overlay:"}),
            ctl("people.sli", source={"type": "sli", "sli": "gaps"}),
            ctl("people.sli-missing", source={"type": "sli", "sli": "nope"}),
            ctl("people.metric", source={"type": "metric", "name": "security_x", "match": {"collector": "c"}, "op": "<=", "value": 3}),
            ctl("people.metric-min", source={"type": "metric", "name": "security_sli_ok", "agg": "min", "op": ">=", "value": 1}),
            ctl("people.metric-age", source={"type": "metric", "name": "security_ts", "age": True, "op": "<=", "value": "1d"}),
            ctl("people.metric-absent", source={"type": "metric", "name": "security_none"}),
            ctl("people.file", check="evidence", source={"type": "file", "path": "${data}/ledger.json", "mode_max": "0600"}),
            ctl("people.var", source={"type": "file", "path": "${undefined_var}/x"}),
            ctl("people.none", source={"type": "none", "reason": "later"}),
            ctl("people.all", source={"type": "all", "of": [{"type": "sli", "sli": "gaps"}, {"type": "sli", "sli": "nope"}]}),
            ctl("people.any", source={"type": "any", "of": [{"type": "sli", "sli": "nope"}, {"type": "sli", "sli": "gaps"}]}),
        ])
        os.chmod(os.path.join(self.data, "ledger.json"), 0o644)
        r = self.by_id(sc.compute(self.data, self.inst(), NOW))
        want = {"people.mfa": "fail", "people.mfa-max1": "pass", "people.stale": "unknown", "people.never": "unknown",
                "people.cov-ok": "pass", "people.cov-missing": "unknown", "people.sli": "pass", "people.sli-missing": "unknown",
                "people.metric": "pass", "people.metric-min": "fail", "people.metric-age": "pass",
                "people.metric-absent": "unknown", "people.file": "fail", "people.var": "unknown",
                "people.none": "not_implemented", "people.all": "unknown", "people.any": "pass"}
        self.assertEqual({k: r[k]["status"] for k in want}, want)
        self.assertIn("undefined_var", r["people.var"]["detail"])

    def test_attestations_expire_and_need_a_human(self):
        write_catalog(self.cat, "people", [ctl("people." + n, check="attested")
                                           for n in ("valid", "soon", "expired", "false", "noby", "na", "missing")])
        r = sc.compute(self.data, self.inst(), NOW)
        st = {k: v["status"] for k, v in self.by_id(r).items()}
        self.assertEqual(st, {"people.valid": "pass", "people.soon": "pass", "people.expired": "expired", "people.false": "fail",
                              "people.noby": "unattested", "people.na": "na", "people.missing": "unattested"})
        self.assertIn("within 14 days", self.by_id(r)["people.soon"]["detail"])
        self.assertEqual(r["attestations"], {"valid": 2, "expiring": 1, "expired": 1, "missing": 2},
                         "valid = current (also a current 'does not hold' answer)")
        # 2 of 6 weighted controls pass (n/a is excluded from the denominator)
        self.assertAlmostEqual(r["dimensions"]["people"]["score"], 33.3)

    def test_weakest_link_and_weights(self):
        write_catalog(self.cat, "good", [ctl("good.a", source={"type": "sli", "sli": "gaps"}, weight=3),
                                         ctl("good.b", source={"type": "none"}, weight=1)], order=1)
        write_catalog(self.cat, "bad", [ctl("bad.a", source={"type": "sli", "sli": "gaps"}),
                                        ctl("bad.b", source={"type": "none"})], order=2)
        r = sc.compute(self.data, self.inst(), NOW)
        self.assertEqual((r["dimensions"]["good"]["score"], r["dimensions"]["bad"]["score"]), (75.0, 50.0))
        self.assertEqual((r["status"], r["overall"], r["weakest"]), ("FAIL", 50.0, "bad"))
        self.assertEqual(r["dimensions"]["good"]["status"], "PASS")
        # an organisation's own weights / threshold
        r = sc.compute(self.data, self.inst(threshold=50, overrides={"bad.b": {"weight": 0}}), NOW)
        self.assertEqual((r["status"], r["dimensions"]["bad"]["score"]), ("PASS", 100.0))

    def test_builtin_pillars_and_functions(self):
        write_catalog(self.cat, "meta", [
            ctl("meta.ok", source={"type": "sli", "sli": "gaps"}, pillars=["people", "network"]),
            ctl("meta.pillars", source={"type": "builtin", "name": "pillars_covered"}),
            ctl("meta.functions", csf="GV.OV", source={"type": "builtin", "name": "functions_covered"})])
        r = self.by_id(sc.compute(self.data, self.inst(pillars=["people", "network"]), NOW))
        self.assertEqual(r["meta.pillars"]["status"], "pass")
        self.assertEqual(r["meta.functions"]["status"], "fail")
        self.assertIn("GV", r["meta.functions"]["detail"])

    def test_regression_counter_and_metrics_contract(self):
        write_catalog(self.cat, "people", [ctl("people.mfa", source={"type": "findings", "check_in": ["identity.mfa_disabled"]})])
        st = os.path.join(self.data, "state", "scorecard.json")
        r = sc.update_regressions(self.data, sc.compute(self.data, self.inst(), NOW))
        self.assertEqual(r["regressions_total"]["people"], 0, "first sight is the baseline")
        ledger = json.load(open(os.path.join(self.data, "ledger.json")))
        ledger["entries"]["a"]["status"] = "fixed"
        json.dump(ledger, open(os.path.join(self.data, "ledger.json"), "w"))
        r = sc.update_regressions(self.data, sc.compute(self.data, self.inst(), NOW))
        self.assertEqual((r["status"], r["regressions_total"]["people"]), ("PASS", 0))
        ledger["entries"]["a"]["status"] = "open"
        json.dump(ledger, open(os.path.join(self.data, "ledger.json"), "w"))
        r = sc.update_regressions(self.data, sc.compute(self.data, self.inst(), NOW))
        self.assertEqual(r["regressions_total"]["people"], 1)
        r = sc.update_regressions(self.data, sc.compute(self.data, self.inst(), NOW))
        self.assertEqual(r["regressions_total"]["people"], 1, "a standing low score does not count again")
        self.assertTrue(os.path.exists(st))
        sc.write_outputs(self.data, r, NOW)
        text = open(os.path.join(self.data, "metrics", "scorecard.prom")).read()
        check_metrics_text(self, text)
        for s in ('security_score{dimension="people"}', 'security_score{pillar="people"}', 'security_score{function="PR"}',
                  'security_score{dimension="people",pillar="people"}', "security_score_overall", "security_score_pass 0",
                  'security_score_regressions_total{dimension="people"} 1', 'security_attestations{state="missing"}'):
            self.assertIn(s, text)
        self.assertNotIn("people.mfa", text, "control ids stay in the private report")
        md = open(os.path.join(self.data, "reports", "scorecard.md")).read()
        self.assertIn("people.mfa", md)

    def test_attest_cli(self):
        write_catalog(self.cat, "people", [ctl("people.pm", check="attested"),
                                           ctl("people.auto", source={"type": "sli", "sli": "gaps"})])
        inst = os.path.join(self.d, "instance.yaml")
        yaml.safe_dump(self.inst(), open(inst, "w"))
        os.remove(os.path.join(self.data, "attestations.yaml"))
        run = [sys.executable, os.path.join(ROOT, "scorecard", "scorecard.py")]
        subprocess.run(run + ["attest", "people.pm", "--data", self.data, "--instance", inst, "--by", "alice",
                              "--note", "vault checked", "--now", str(NOW)], check=True, capture_output=True)
        p = os.path.join(self.data, "attestations.yaml")
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
        a = yaml.safe_load(open(p))["attestations"]["people.pm"]
        self.assertEqual((a["attested_by"], a["value"], a["expires"]), ("alice", True, day(NOW + 90 * DAY)))
        self.assertEqual(self.by_id(sc.compute(self.data, self.inst(), NOW))["people.pm"]["status"], "pass")
        self.assertEqual(self.by_id(sc.compute(self.data, self.inst(), NOW + 91 * DAY))["people.pm"]["status"], "expired")
        p2 = subprocess.run(run + ["attest", "people.auto", "--data", self.data, "--instance", inst, "--by", "alice"],
                            capture_output=True, text=True)
        self.assertNotEqual(p2.returncode, 0, "automated controls cannot be attested")


class RunnerComputesOnPublish(unittest.TestCase):
    def test_publish_includes_scorecard(self):
        d = tempfile.mkdtemp()
        try:
            inst = os.path.join(d, "instance.json")
            json.dump({"name": "t", "runner": {"jobs": {}}}, open(inst, "w"))
            subprocess.run([sys.executable, os.path.join(ROOT, "runner", "runner.py"), "metrics", "--instance", inst,
                            "--data", os.path.join(d, "data")], check=True, capture_output=True)
            text = open(os.path.join(d, "data", "metrics", "security-platform.prom")).read()
            self.assertIn('security_score{dimension="people"}', text)
            self.assertIn("security_scorecard_last_compute_timestamp_seconds", text)
            check_metrics_text(self, text)
            self.assertTrue(os.path.exists(os.path.join(d, "data", "reports", "scorecard.json")))
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
