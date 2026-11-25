"""Runs the conformance suite (conformance/, docs/contracts.md) against the Go implementation of the components that
have one - ledger merge and track, `sp ledger ...` - through conformance/impl/go/run.sh, with NO expected failures: the
target-behaviour cases of LEDGER-D1..D5 must pass. Skipped without a Go toolchain that can build go.mod's version (the
Go CI workflow runs the Go tests; this keeps the black-box suite next to the reference's). SP_SKIP_CONFORMANCE=1 skips."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class GoImplementation(unittest.TestCase):
    def test_conformance_suite(self):
        if os.environ.get("SP_SKIP_CONFORMANCE"):
            self.skipTest("SP_SKIP_CONFORMANCE set")
        if not shutil.which("go"):
            self.skipTest("no go toolchain")
        with tempfile.TemporaryDirectory() as d:
            b = subprocess.run(["go", "build", "-trimpath", "-o", os.path.join(d, "sp"), "./cmd/sp"], cwd=ROOT,
                               capture_output=True, text=True, timeout=600)
            if b.returncode != 0 and ("toolchain" in b.stderr or "requires go" in b.stderr):
                self.skipTest(f"go toolchain cannot build go.mod's version: {b.stderr.strip()[-200:]}")
            self.assertEqual(b.returncode, 0, b.stderr[-3000:])
            env = dict(os.environ, SP_PYTHON=sys.executable, SP_GO_BIN=os.path.join(d, "sp"))
            p = subprocess.run(["/bin/sh", os.path.join(ROOT, "conformance", "impl", "go", "run.sh")], env=env,
                               capture_output=True, text=True, timeout=900)
        self.assertEqual(p.returncode, 0, p.stdout[-6000:] + p.stderr[-2000:])
        self.assertIn("fail=0", p.stdout)
        self.assertIn("xfail=0", p.stdout)
        self.assertIn("skip=0", p.stdout)


if __name__ == "__main__":
    unittest.main()
