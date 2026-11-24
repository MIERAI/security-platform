"""Every check a collector can emit maps to at least one ATT&CK technique (longest prefix), so checks and detections
are both expressed in attacker techniques."""
import glob
import os
import re
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
M = yaml.safe_load(open(os.path.join(ROOT, "scorecard", "attack-map.yaml")))


def techniques(check):
    best = max((p for p in M["map"] if check.startswith(p)), key=len, default=None)
    return M["map"].get(best) if best else None


def emitted_checks():
    out = set()
    for p in glob.glob(os.path.join(ROOT, "collectors", "*", "collector.py")):
        src = open(p).read()
        out |= set(re.findall(r'(?:c\.finding|F)\("[a-z-]+",\s*[^,]+,\s*f?"([a-z0-9_.-]+)', src))
        out |= set(re.findall(r'\("([a-z0-9_]+\.[a-z0-9_.]+)",\s*"(?:critical|high|medium|low|info)"', src))
    return out


class AttackMap(unittest.TestCase):
    def test_every_check_mapped(self):
        checks = emitted_checks()
        self.assertGreater(len(checks), 40)
        self.assertEqual(sorted(c for c in checks if not techniques(c)), [])

    def test_technique_ids_well_formed(self):
        for p, ts in M["map"].items():
            for t in ts:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$", p)


if __name__ == "__main__":
    unittest.main()
