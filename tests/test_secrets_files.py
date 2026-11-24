"""secrets-files end to end through the local exec adapter: unattended host keys are not "missing a passphrase",
junctions/symlinks are not walked, permissions are reported, values never are."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


@unittest.skipUnless(shutil.which("ssh-keygen"), "ssh-keygen not installed")
class SecretsFiles(unittest.TestCase):
    def test_host_keys_and_links(self):
        d = tempfile.mkdtemp()
        try:
            root = os.path.join(d, "root")
            os.makedirs(os.path.join(root, "keys"))
            for n in ("id_test", "ssh_host_ed25519_key"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", os.path.join(root, "keys", n)], check=True)
            os.symlink(os.path.join(root, "keys"), os.path.join(root, "loop"))       # walked once, not twice
            inst = os.path.join(d, "instance.json")
            json.dump({"name": "t", "secrets_files": [{"host": "h", "exec": {"type": "local"}, "roots": [root],
                                                       "python": sys.executable}]}, open(inst, "w"))
            run = os.path.join(d, "run")
            subprocess.run([sys.executable, os.path.join(ROOT, "collectors", "secrets-files", "collector.py")], check=True,
                           capture_output=True, env=dict(os.environ, SP_INSTANCE=inst, SP_RUN_DIR=run, SP_DATA=d))
            doc = json.load(open(os.path.join(run, "secrets-files.findings.json")))
            nopass = sorted(os.path.basename(f["asset"]) for f in doc["findings"] if f["check"] == "secret.ssh_key_no_passphrase")
            self.assertEqual(nopass, ["id_test"])
            items = json.load(open(os.path.join(run, "raw", "secrets-files", "h.json")))
            self.assertEqual(sorted(os.path.basename(i["path"]) for i in items), ["id_test", "ssh_host_ed25519_key"])
            self.assertNotIn("PRIVATE KEY", open(os.path.join(run, "raw", "secrets-files", "h.json")).read())
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
