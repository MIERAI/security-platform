"""Runs the black-box conformance suite (conformance/, docs/contracts.md) against the reference implementation in
this repository, exactly as an implementation in another language is run: as processes, through
conformance/impl/python/run.sh. Known deviations of the reference are expected failures
(conformance/impl/python/expected-failures.txt); anything else failing - or an expected failure that now passes - fails
this test. SP_SKIP_CONFORMANCE=1 skips it (e.g. a quick local run)."""
import os
import subprocess
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class ReferenceImplementation(unittest.TestCase):
    def test_conformance_suite(self):
        if os.environ.get("SP_SKIP_CONFORMANCE"):
            self.skipTest("SP_SKIP_CONFORMANCE set")
        try:
            import yaml  # noqa: F401  - the reference reads YAML configs, as in production
        except ImportError:
            self.skipTest("PyYAML not installed")
        env = dict(os.environ, SP_PYTHON=sys.executable)
        p = subprocess.run(["/bin/sh", os.path.join(ROOT, "conformance", "impl", "python", "run.sh")], env=env,
                           capture_output=True, text=True, timeout=900)
        self.assertEqual(p.returncode, 0, p.stdout[-6000:] + p.stderr[-2000:])
        self.assertIn("fail=0", p.stdout)
        self.assertIn("xpass=0", p.stdout)


if __name__ == "__main__":
    unittest.main()
