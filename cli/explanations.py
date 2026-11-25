"""Plain-language explanations of checks, for people who are not security specialists (component `cli`).

  explain(check) -> {"what", "why", "fix", "verify"}   (falls back to a generic text per check family)

The texts are data, not code: internal/cli/explain/explanations.json, read here and by the Go implementation of `sp`
(which embeds the same file), so every wording lives in one place. Each entry answers four questions in everyday words:
  what    what was found, without jargon
  why     what could go wrong if it stays (the risk, concretely)
  fix     what to do, as steps a junior engineer can follow
  verify  how to see that it is fixed (the next scan closes it on its own); `{next_scan}` stands for NEXT_SCAN
Keep it generic: no environment, no product names of a particular company. A new check without an entry still gets
the family text plus the collector's own remediation line, so adding one there is encouraged but never required.
"""
import json
import os

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "internal", "cli", "explain",
                    "explanations.json")


def _load():
    with open(DATA, encoding="utf-8") as f:
        d = json.load(f)
    ns = d["next_scan"]

    def expand(e):
        return {k: v.replace("{next_scan}", ns) for k, v in e.items() if k in ("what", "why", "fix", "verify")}
    return (ns, {k: expand(v) for k, v in d["checks"].items()},
            [(f["prefix"], expand(f)) for f in d["families"]], d["layers"], d["severities"])


NEXT_SCAN, CHECKS, FAMILIES, LAYER_WORDS, SEVERITY_WORDS = _load()


def explain(check):
    e = CHECKS.get(check)
    if e:
        return dict(e)
    for prefix, fam in FAMILIES:
        if check.startswith(prefix):
            return dict(fam, verify=NEXT_SCAN)
    return dict(what="", why="", fix="", verify=NEXT_SCAN)


def headline(check, fallback=""):
    """One short plain-language line for a check (for digests and dashboards): never contains asset details."""
    w = explain(check).get("what")
    return w or fallback
