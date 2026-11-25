"""The Go collectors exposure, codehost-github, codehost-gitea, agent-claude-code, detection and the Go events shipper
against the reference: every conformance case of each component is run with both implementations and every file the
case leaves behind is compared byte for byte (conformance/tools/compare_impls.py), apart from volatile values and the
differences conformance/impl/go/explained-diffs.json explains (each one names its deviation or its reason). Cases of a
known deviation differ by design and are skipped there; conformance/impl/go/run.sh runs them against Go with no
expected failures. Skipped without a Go toolchain that builds cmd/sp or without PyYAML; SP_SKIP_GO=1 skips it."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
COMPONENTS = {"collector-exposure": "exposure collect", "collector-codehost-github": "codehost-github collect",
              "collector-codehost-gitea": "codehost-gitea collect", "collector-agent-claude-code": "agent-claude-code collect",
              "collector-detection": "detection collect", "events": "events ship"}


class GoCollectorsParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("SP_SKIP_GO") or os.environ.get("SP_SKIP_CONFORMANCE"):
            raise unittest.SkipTest("SP_SKIP_GO / SP_SKIP_CONFORMANCE set")
        if not shutil.which("go"):
            raise unittest.SkipTest("no Go toolchain")
        try:
            import yaml  # noqa: F401  - the reference reads YAML configs
        except ImportError:
            raise unittest.SkipTest("PyYAML not installed")
        cls.tmp = tempfile.mkdtemp(prefix="sp-go-parity-")
        cls.sp = os.path.join(cls.tmp, "sp")
        p = subprocess.run(["go", "build", "-trimpath", "-o", cls.sp, "./cmd/sp"], cwd=ROOT, capture_output=True, text=True,
                           timeout=600)
        if p.returncode:
            shutil.rmtree(cls.tmp, ignore_errors=True)
            raise unittest.SkipTest(f"cannot build cmd/sp: {p.stderr[-300:]}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_byte_parity_on_the_fixtures(self):
        env = dict(os.environ, SP_PYTHON=sys.executable, SP_PY_HOME=ROOT, TZ="UTC")
        for component, verb in COMPONENTS.items():
            with self.subTest(component=component):
                ref = os.path.join(ROOT, "conformance", "impl", "python", component)
                p = subprocess.run([sys.executable, os.path.join(ROOT, "conformance", "tools", "compare_impls.py"),
                                    "--component", component, "--a", ref, "--b", f"{self.sp} {verb}",
                                    "--explained", os.path.join(ROOT, "conformance", "impl", "go", "explained-diffs.json")],
                                   env=env, capture_output=True, text=True, timeout=1800)
                self.assertEqual(p.returncode, 0, p.stdout[-6000:] + p.stderr[-2000:])
                self.assertIn("unexplained=0", p.stdout)


if __name__ == "__main__":
    unittest.main()
