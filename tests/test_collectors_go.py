"""The Go collectors `sp k8s collect`, `sp vuln-intel collect`, `sp identity collect` (internal/collectors/...):

1. the black-box conformance suite of each one with NO expected failures (the target-behaviour cases of K8S-D*,
   VULN-D*, IDENTITY-D* must pass);
2. byte compatibility with the Python collectors: every conformance case without a deviation id is run with both
   implementations in identical sandboxes, and every file they write into the run directory (findings document,
   Prometheus text, evidence, inventories) must be identical once wall-clock times and the sandbox path are masked.
   A difference is either a bug or a recorded deviation; there is no third kind.

SP_GO_COLLECTORS=k8s,identity limits it to those collectors. Skipped without a Go toolchain that can build cmd/sp (go.mod names the version) or without PyYAML. SP_SKIP_GO=1 skips."""
import contextlib
import copy
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
COMPONENTS = {c: n for c, n in (("collector-k8s", "k8s"), ("collector-vuln-intel", "vuln-intel"), ("collector-identity", "identity"))
              if not os.environ.get("SP_GO_COLLECTORS") or n in os.environ["SP_GO_COLLECTORS"].split(",")}
ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z")
EPOCH = re.compile(r"(_timestamp_seconds\{[^}]*\}|_age_seconds\{[^}]*\}) \S+")
AGE = re.compile(r'"age_days": [0-9.]+')
CLOCK_METRIC = re.compile(r'("name": "security_[a-z0-9_]*_(?:age_seconds|days)",\s*"value": )[0-9.e+-]+')
CLOCK_SAMPLE = re.compile(r'^(security_[a-z0-9_]*_days\{[^}]*\}) \S+$', re.M)


def build_sp(out):
    if os.environ.get("SP_SKIP_GO"):
        raise unittest.SkipTest("SP_SKIP_GO set")
    go = shutil.which("go")
    if not go:
        raise unittest.SkipTest("no Go toolchain")
    try:
        import yaml  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("PyYAML not installed")
    p = subprocess.run([go, "build", "-o", out, "./cmd/sp"], cwd=ROOT, capture_output=True, text=True, timeout=600)
    if p.returncode:
        raise unittest.SkipTest(f"cannot build cmd/sp: {p.stderr[-300:]}")
    return out


def load_harness():
    spec = importlib.util.spec_from_file_location("conformance_run", os.path.join(ROOT, "conformance", "run.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def masked(path, root):
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode()
    except UnicodeDecodeError:
        return data
    text = text.replace(os.path.realpath(root), "<sandbox>").replace(root, "<sandbox>")
    text = EPOCH.sub(r"\1 <now>", ISO.sub("<time>", text))
    text = CLOCK_SAMPLE.sub(r"\1 <clock>", CLOCK_METRIC.sub(r"\1<clock>", text))   # ages measured on the wall clock
    return AGE.sub('"age_days": <age>', text)


class GoCollectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="sp-go-collectors-")
        cls.sp = build_sp(os.path.join(cls.tmp, "sp"))
        cls.env = dict({k: v for k, v in os.environ.items() if not k.startswith("SP_")}, SP_PY_HOME=ROOT,
                       SP_PYTHON=sys.executable, TZ="UTC", LC_ALL="C")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_conformance_without_expected_failures(self):
        for component, name in COMPONENTS.items():
            with self.subTest(component=component):
                p = subprocess.run([sys.executable, os.path.join(ROOT, "conformance", "run.py"), "--impl",
                                    f"{component}={self.sp} {name} collect", "--component", component, "--require-all"],
                                   env=self.env, capture_output=True, text=True, timeout=900)
                self.assertEqual(p.returncode, 0, p.stdout[-5000:] + p.stderr[-2000:])
                self.assertIn("fail=0", p.stdout)
                self.assertIn("xfail=0", p.stdout)
                self.assertIn("skip=0", p.stdout)

    def run_kept(self, conf, case_dir, case, impls):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), unittest.mock.patch.dict(os.environ, self.env, clear=True):
            status, msgs = conf.run_case(case_dir, case, impls, keep=True, verbose=False)
        root = re.search(r"sandbox kept: (\S+)", out.getvalue()).group(1)
        self.addCleanup(shutil.rmtree, root, True)
        return status, msgs, root

    def test_documents_are_byte_identical_to_python(self):
        conf = load_harness()
        py = os.path.join(ROOT, "conformance", "impl", "python")
        compared = 0
        for component, name in COMPONENTS.items():
            for case_name in sorted(os.listdir(os.path.join(conf.CASES, component))):
                case_dir = os.path.join(conf.CASES, component, case_name)
                case = json.load(open(os.path.join(case_dir, "case.json")))
                if case.get("deviation"):
                    continue    # the target behaviour differs from the reference by definition
                for i, step in enumerate(case["steps"]):
                    if "exec" not in step:
                        continue
                    partial = copy.deepcopy(case)
                    partial["steps"] = case["steps"][:i + 1]
                    with self.subTest(case=f"{component}/{case_name}", step=step.get("name", i)):
                        roots = {}
                        for impl, cmd in (("python", os.path.join(py, component)), ("go", f"{self.sp} {name} collect")):
                            status, msgs, roots[impl] = self.run_kept(conf, case_dir, partial, {component: cmd})
                            self.assertEqual(status, "pass", f"{impl}: {msgs}")
                        self.assert_same_run(roots["python"], roots["go"])
                        compared += 1
        self.assertGreater(compared, 0)

    def assert_same_run(self, a, b):
        files = {}
        for root in (a, b):
            run = os.path.join(root, "run")
            files[root] = sorted(os.path.relpath(os.path.join(d, f), run) for d, _, fs in os.walk(run) for f in fs)
        self.assertEqual(files[a], files[b], "the run directories hold different files")
        for rel in files[a]:
            pa, pb = masked(os.path.join(a, "run", rel), a), masked(os.path.join(b, "run", rel), b)
            self.assertEqual(pa, pb, f"run/{rel} differs between the Python and the Go collector")


if __name__ == "__main__":
    unittest.main()
