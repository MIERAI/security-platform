"""Per-asset scope: an instance can limit an asset to some collectors (e.g. personal devices: exposure only). Other
collectors skip it (no coverage gap); with `offline: expected` an offline device is not scanned and not a gap."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [ROOT, os.path.join(ROOT, "sdk")]
import spsdk  # noqa: E402
from adapters import discovery  # noqa: E402

SCOPE = [{"names": ["router-x", "router-x-overlay"], "scope": ["exposure"]},
         {"names": ["phone-y"], "scope": ["exposure"], "offline": "expected"}]


class Scope(unittest.TestCase):
    def test_in_scope(self):
        inst = {"scope": SCOPE}
        self.assertTrue(spsdk.in_scope(inst, "other", "host"))
        self.assertFalse(spsdk.in_scope(inst, "router-x", "host"))
        self.assertTrue(spsdk.in_scope(inst, "router-x-overlay", "exposure"))

    def test_apply_scope(self):
        devs = [{"name": "phone-y", "address": "192.0.2.3", "online": False, "attrs": {}},
                {"name": "router-x-overlay", "address": "192.0.2.4", "online": False, "attrs": {}},
                {"name": "z", "address": "192.0.2.5", "online": False, "attrs": {}}]
        out = discovery.apply_scope(devs, SCOPE)
        self.assertEqual([d["name"] for d in out], ["router-x-overlay", "z"])   # offline router is still a gap
        self.assertEqual(out[0]["attrs"]["scope"], ["exposure"])

    def test_collectors_skip_out_of_scope_hosts(self):
        d = tempfile.mkdtemp()
        try:
            inst = os.path.join(d, "i.json")
            json.dump({"name": "t", "scope": SCOPE,
                       "hosts": [{"name": "router-x", "exec": None, "profile": "busybox", "gap": "no key"}],
                       "secrets_files": [{"host": "router-x", "exec": None}]}, open(inst, "w"))
            for col in ("host", "host-sbom", "secrets-files"):
                run = os.path.join(d, col)
                subprocess.run([sys.executable, os.path.join(ROOT, "collectors", col, "collector.py")], check=True,
                               capture_output=True, env=dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run, SP_DATA=d))
                with open(os.path.join(run, f"{col}.findings.json")) as f:
                    self.assertEqual(json.load(f)["coverage"], [], col)
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
