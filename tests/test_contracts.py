"""Language-neutral contracts (contracts/) and the conformance suite (conformance/) stay consistent with the code:
the documented findings schema equals the one the core loads, examples validate (and the core's validator agrees with
the suite's), every metric that generated rules / dashboards / SLOs / catalog controls use is registered, every metric
the platform's own code emits is registered, deviations point at real cases, and the generated cases are current.
The suite itself runs in CI (job `conformance`): conformance/impl/python/run.sh."""
import filecmp
import glob
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
C = os.path.join(ROOT, "contracts")
sys.path[:0] = [os.path.join(ROOT, "core")]
import validate  # noqa: E402

spec = importlib.util.spec_from_file_location("conformance_run", os.path.join(ROOT, "conformance", "run.py"))
conf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(conf)

ANNOTATIONS = {"description", "$comment", "title", "examples", "$id"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in ANNOTATIONS}
    if isinstance(o, list):
        return [strip(x) for x in o]
    return o


def load_yaml_or_json(p):
    with open(p) as f:
        text = f.read()
    if p.endswith(".json"):
        return json.loads(text)
    import yaml
    return yaml.safe_load(text)


class Schemas(unittest.TestCase):
    def test_findings_schema_identical_to_the_core_copy(self):
        doc = json.load(open(os.path.join(C, "findings", "findings-v1.schema.json")))
        core = json.load(open(os.path.join(ROOT, "schema", "findings-v1.schema.json")))
        self.assertEqual(strip(doc), strip(core), "contracts/findings and schema/ must have the same constraints")

    def test_every_schema_is_draft_2020_12_and_registered(self):
        files = sorted(glob.glob(os.path.join(C, "*", "*.schema.json")))
        self.assertGreaterEqual(len(files), 12)
        registered = {os.path.join(C, v) for v in conf.SCHEMAS.values()}
        for p in files:
            with self.subTest(schema=os.path.relpath(p, C)):
                s = json.load(open(p))
                self.assertEqual(s["$schema"], "https://json-schema.org/draft/2020-12/schema")
                self.assertIn(os.path.normpath(p), {os.path.normpath(x) for x in registered})

    def test_examples_validate(self):
        cases = [("findings", "findings/examples/minimal.json"), ("findings", "findings/examples/host-with-narrow-gap.json"),
                 ("findings", "findings/examples/inventory-complete-scope.json"), ("ledger", "ledger/examples/ledger.json"),
                 ("tracker", "ledger/examples/tracker-items.json"), ("exceptions", "ledger/examples/exceptions.yaml"),
                 ("scorecard", "scorecard/examples/scorecard.json"), ("scorecard-catalog", "scorecard/examples/catalog-01-example.yaml"),
                 ("attestations", "scorecard/examples/attestations.yaml"), ("runner-config", "runner/examples/instance-runner.json"),
                 ("runner-state", "runner/examples/state.json"), ("runner-status", "runner/examples/status.json"),
                 ("cli-findings", "cli/examples/findings.json"), ("metrics-registry", "metrics/registry.json")]
        for name, rel in cases:
            with self.subTest(example=rel):
                self.assertEqual(conf.schema_errors(load_yaml_or_json(os.path.join(C, rel)), conf.load_schema(name)), [])

    def test_product_catalog_and_examples_validate_as_catalog(self):
        for p in sorted(glob.glob(os.path.join(ROOT, "scorecard", "catalog", "*.yaml"))):
            with self.subTest(catalog=os.path.basename(p)):
                self.assertEqual(conf.schema_errors(load_yaml_or_json(p), conf.load_schema("scorecard-catalog")), [])

    def test_harness_and_core_validators_agree_on_findings(self):
        docs = sorted(glob.glob(os.path.join(C, "findings", "examples", "*.json")) +
                      glob.glob(os.path.join(ROOT, "tests", "fixtures", "*.findings.json")))
        schema = conf.load_schema("findings")
        for p in docs:
            with self.subTest(doc=os.path.basename(p)):
                d = json.load(open(p))
                core_ok = validate.validate_findings(d) == []
                major_ok = str(d.get("schema_version", "")).split(".")[0] == "1"
                self.assertEqual(core_ok, major_ok and conf.schema_errors(d, schema) == [])
                self.assertEqual(core_ok, not os.path.basename(p).startswith("invalid-"))


METRIC = re.compile(r"(?<![a-z0-9_])(security_[a-z0-9_]+)")


class Metrics(unittest.TestCase):
    reg = json.load(open(os.path.join(C, "metrics", "registry.json")))
    names = {m["name"] for m in reg["metrics"]}

    def test_names_unique_and_typed(self):
        self.assertEqual(len(self.names), len(self.reg["metrics"]))
        for m in self.reg["metrics"]:     # the exposition TYPE follows the suffix (sdk render); see METRICS-D1
            self.assertEqual(m["type"] == "counter", m["name"].endswith("_total"), m["name"])

    def test_everything_generated_artefacts_use_is_registered(self):
        used = set()
        for p in glob.glob(os.path.join(ROOT, "dist", "*")) + glob.glob(os.path.join(ROOT, "scorecard", "catalog", "*.yaml")) + \
                [os.path.join(ROOT, "generators", "sli-catalog.yaml"), os.path.join(ROOT, "detections", "falco", "prometheus-rules.yaml")]:
            with open(p) as f:
                used |= set(METRIC.findall(f.read()))
        self.assertEqual(sorted(used - self.names), [], "add them to contracts/metrics/registry.json")
        flagged = {m["name"] for m in self.reg["metrics"] if m.get("used_by_generated")}
        self.assertEqual(sorted(used - flagged), [], "set used_by_generated: true")

    def test_everything_the_platform_emits_is_registered(self):
        emitted = set()
        for p in [os.path.join(ROOT, f) for f in ("core/ledger.py", "core/remediation.py", "core/export.py", "runner/runner.py",
                                                  "scorecard/scorecard.py", "sdk/spsdk/__init__.py")] + \
                glob.glob(os.path.join(ROOT, "collectors", "*", "*.py")):
            with open(p) as f:     # series tuples ("security_x", {labels}, value, help) and c.metric("security_x", ...)
                emitted |= set(re.findall(r'\(\s*"(security_[a-z0-9_]+)"\s*,', f.read()))
        self.assertEqual(sorted(emitted - self.names), [])


class Deviations(unittest.TestCase):
    def test_index_expected_failures_and_cases_agree(self):
        idx = json.load(open(os.path.join(C, "index.json")))
        cases = {}
        for p in glob.glob(os.path.join(ROOT, "conformance", "cases", "*", "*", "case.json")):
            c = json.load(open(p))
            cases[os.path.relpath(os.path.dirname(p), os.path.join(ROOT, "conformance", "cases"))] = c
        xfail = {}
        for line in open(os.path.join(ROOT, "conformance", "impl", "python", "expected-failures.txt")):
            line = line.split("#", 1)[0].split()
            if line:
                xfail[line[0]] = line[1]
        for dev, case in idx["known_deviations"].items():
            with self.subTest(deviation=dev):
                spec_files = []
                for p in glob.glob(os.path.join(C, "*", "SPEC.md")):
                    with open(p) as f:
                        spec_files.append(f.read())
                self.assertTrue(any(f"| {dev} |" in s for s in spec_files), f"{dev} not in any SPEC.md deviation table")
                if case:
                    self.assertEqual(cases[case].get("deviation"), dev)
                    self.assertEqual(xfail.get(case), dev, "the reference implementation lists it as an expected failure")
        devs = {c["deviation"] for c in cases.values() if c.get("deviation")}
        self.assertEqual(devs, {d for d, c in idx["known_deviations"].items() if c})
        self.assertEqual(set(xfail), {c for c in idx["known_deviations"].values() if c})

    def test_generated_cases_are_current(self):
        with tempfile.TemporaryDirectory() as d:
            subprocess.run([sys.executable, os.path.join(ROOT, "conformance", "tools", "gen_cases.py"), "--out", d],
                           check=True, capture_output=True)
            cmp = filecmp.dircmp(d, os.path.join(ROOT, "conformance", "cases"))

            def diffs(c, rel=""):
                out = [os.path.join(rel, x) for x in c.left_only + c.right_only + c.diff_files + c.funny_files]
                for k, sub in c.subdirs.items():
                    out += diffs(sub, os.path.join(rel, k))
                return out
            self.assertEqual(diffs(cmp), [], "run python3 conformance/tools/gen_cases.py and commit")


class Harness(unittest.TestCase):
    """The suite's own matchers (a wrong matcher would make every implementation pass)."""

    def test_subset_operators(self):
        S = conf.subset_errors
        self.assertEqual(S({"a": 1, "b": 2}, {"a": 1}), [])
        self.assertTrue(S({"a": 1}, {"a": 2}))
        self.assertTrue(S({"a": 1}, {"a": 1.5}))
        self.assertTrue(S({"a": True}, {"a": 1}))
        self.assertEqual(S({"a": None}, {"a": {"$null_or_absent": True}, "b": {"$absent": True}}), [])
        self.assertTrue(S({"b": 1}, {"b": {"$absent": True}}))
        self.assertEqual(S([3, 1, 2], {"$unordered": [1, 2, 3]}), [])
        self.assertTrue(S([1, 2], {"$unordered": [1, 2, 3]}))
        self.assertEqual(S([{"x": 1}, {"x": 2}], {"$contains": [{"x": 2}]}), [])
        self.assertTrue(S([{"x": 1}], {"$not_contains": [{"x": 1}]}))
        self.assertTrue(S([1, 2], [1]))
        self.assertEqual(S(13.96, {"$approx": [14.0, 0.05]}), [])
        self.assertTrue(S(13.9, {"$approx": [14.0, 0.05]}))

    def test_schema_subset(self):
        E = conf.schema_errors
        s = {"type": "object", "required": ["a"], "properties": {"a": {"type": "integer", "minimum": 0}, "b": {"enum": ["x", None]}},
             "patternProperties": {"^z": {"const": 1}}, "additionalProperties": False}
        self.assertEqual(E({"a": 1, "b": None, "z1": 1}, s), [])
        self.assertTrue(E({"a": True}, s))
        self.assertTrue(E({"a": -1}, s))
        self.assertTrue(E({"a": 1, "q": 1}, s))
        self.assertTrue(E({"a": 1, "z": 2}, s))
        self.assertTrue(E({"t": "2026-11-25 10:00"}, {"properties": {"t": {"type": "string", "format": "date-time"}}}))

    def test_prom_parser(self):
        samples, types, errs = conf.parse_prom('# TYPE a_total counter\na_total{x="1",y="a\\"b"} 3\nb 1.5e3\n')
        self.assertEqual(errs, [])
        self.assertEqual(samples[0], ("a_total", {"x": "1", "y": 'a\\"b'}, 3.0))
        self.assertEqual(samples[1][2], 1500.0)
        self.assertEqual(types, {"a_total": "counter"})


if __name__ == "__main__":
    unittest.main()
