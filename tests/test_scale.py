"""Scale: the indexed coverage lookup decides exactly like the linear rule it replaced, and the scale benchmark runs
(smoke size; the large sizes are opt-in: python bench/scale.py --sizes 10000:1000,100000:10000)."""
import os
import random
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path[:0] = [os.path.join(ROOT, "core"), os.path.join(ROOT, "bench")]
import ledger  # noqa: E402
import scale  # noqa: E402


def covered_linear(asset, oks, gap_names):
    """The rule as first written (one pass over every coverage entry per lookup): the reference."""
    if any(g and g in asset for g in gap_names):
        return False
    t, sc = ledger.scope(asset)
    for c in oks:
        if asset == c or any(asset.startswith(c + sep) for sep in ":/@"):
            return True
        ct, csc = ledger.scope(c)
        if t in ledger.UMBRELLA.get(ct, ()) and sc == csc:
            return True
    return False


class Scale(unittest.TestCase):
    def test_indexed_coverage_equals_linear_rule(self):
        r = random.Random(7)
        types = ["host", "k8s-cluster", "k8s-workload", "secret-file", "net-endpoint", "image", "repo", "cis", ""]
        parts = ["a", "b", "ab", "10.0.0.1", "443", "x/y", ""]
        seps = [":", "/", "@", ""]

        def name():
            return r.choice(types) + ":" + "".join(r.choice(parts) + r.choice(seps) for _ in range(r.randrange(4)))
        for _ in range(300):
            oks = [name() for _ in range(r.randrange(8))]
            cov = ledger.Coverage(oks)
            gaps = r.sample(["a", "b", ""], r.randrange(3))
            for _ in range(30):
                a = name() if r.random() < 0.6 else r.choice(oks or ["x:y"]) + r.choice(seps) + r.choice(parts)
                self.assertEqual(ledger.covered(a, cov, gaps), covered_linear(a, oks, gaps), (a, oks, gaps))

    def test_bench_smoke(self):
        res = scale.bench(400, 40, 3, 0.1, list(scale.STAGES))
        self.assertEqual(len(res["runs"]), 3)
        last = res["runs"][-1]
        for s in scale.STAGES:
            self.assertGreater(last[s][0], 0)
        # churn and exceptions went through the real lifecycle: some fixed, some accepted, the rest open
        self.assertGreater(last["status"].get("fixed", 0), 0)
        self.assertGreater(last["status"].get("accepted", 0), 0)
        self.assertEqual(last["status"]["open"] + last["status"]["accepted"], last["open_in_run"])


if __name__ == "__main__":
    unittest.main()
