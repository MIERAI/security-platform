#!/usr/bin/env python3
"""Byte comparison of two implementations of a component on the conformance fixtures: every case of the component
is run once with each implementation (run.py --keep), then every file the case left in its sandbox is compared
between the two sandboxes, byte for byte after normalising what is volatile by nature (wall-clock times, the
sandbox path). A difference is reported unless the explained-differences file names it, with its reason.
Cases of a known deviation (`deviation` in case.json) differ by design and are skipped.

usage: compare_impls.py --component C --a CMD --b CMD [--case GLOB] [--explained FILE] [-v]
exit 0 when no unexplained difference was found.
Stdlib only, like the suite (a test tool, not product code)."""
import argparse
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SUITE = os.path.join(HERE, "..")
TIME_KEYS = {"started_at", "finished_at", "observed_at"}
ISO = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def run_suite(component, cmd, cases):
    """-> {case id: kept sandbox path}"""
    argv = [sys.executable, os.path.join(SUITE, "run.py"), "--impl", f"{component}={cmd}", "--component", component, "--keep"]
    for c in cases:
        argv += ["--case", c]
    p = subprocess.run(argv, capture_output=True, text=True, timeout=1800)
    out, kept = {}, None
    for line in p.stdout.splitlines():
        m = re.match(r"\s+sandbox kept: (\S+)", line)
        if m:
            kept = m.group(1)
            continue
        m = re.match(r"(PASS |FAIL |SKIP |XFAIL|XPASS) (\S+)", line)
        if m and kept:
            out[m.group(2)] = kept
            kept = None
    return out, p.stdout


def files(root):
    """{relative name: path}; the sandbox path inside a name (an evidence file named after a configured path) is
    replaced by <sandbox>."""
    out = {}
    slug = re.sub(r"[^a-z0-9]+", "-", root.lower()).strip("-")
    for d, dirs, fs in os.walk(root):
        dirs[:] = [x for x in dirs if x != "home" or d != root]
        for f in fs:
            rel = os.path.relpath(os.path.join(d, f), root)
            if not rel.startswith(".svc-"):
                out[rel.replace(slug, "<sandbox>")] = os.path.join(d, f)
    return out


def normalise_json(v, path="$"):
    if isinstance(v, dict):
        return {k: ("<time>" if k in TIME_KEYS and isinstance(v[k], str) else normalise_json(x, f"{path}.{k}")) for k, x in v.items()}
    if isinstance(v, list):
        return [normalise_json(x, f"{path}[{i}]") for i, x in enumerate(v)]
    return v


def json_diffs(a, b, path="$"):
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append((f"{path}.{k}", a.get(k, "<absent>"), b.get(k, "<absent>")))
            else:
                out += json_diffs(a[k], b[k], f"{path}.{k}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in json_diffs(x, y, f"{path}[{i}]")]
    return [] if a == b and type(a) is type(b) else [(path, a, b)]


def valid_ids(v, out):
    """Collects the finding ids that are sha1(layer|asset|check)[:12] of their own finding (an asset may name a
    sandbox path, so the id differs between sandboxes; a wrong id is not collected and shows as a difference)."""
    import hashlib
    if isinstance(v, dict):
        if {"id", "layer", "asset", "check"} <= set(v) and v["id"] == hashlib.sha1(
                f"{v['layer']}|{v['asset']}|{v['check']}".encode()).hexdigest()[:12]:
            out.add(v["id"])
        for x in v.values():
            valid_ids(x, out)
    elif isinstance(v, list):
        for x in v:
            valid_ids(x, out)
    return out


def normalised_text(path, sandbox):
    """The file's text with what is volatile replaced: valid finding ids, the sandbox path (also as an evidence-name
    slug), ISO times and the heartbeat series value."""
    data = open(path, "rb").read().decode("utf-8", "replace")
    if path.endswith(".json"):
        try:
            for i in valid_ids(json.loads(data), set()):
                data = data.replace(f'"{i}"', '"<valid id>"')
        except ValueError:
            pass
    slug = re.sub(r"[^a-z0-9]+", "-", sandbox.lower()).strip("-")
    data = data.replace(sandbox, "<sandbox>").replace(slug, "<sandbox>")
    data = re.sub(r"(security_collector_last_run_timestamp_seconds\{[^}]*\}) \d+", r"\1 <time>", data)
    return ISO.sub("<t>", data)


def compare_file(rel, pa, pb, sa, sb):
    """-> [(path, a, b)] differences: structural for JSON (so that a report says where), then byte for byte."""
    ta, tb = normalised_text(pa, sa), normalised_text(pb, sb)
    if rel.endswith(".json"):
        try:
            ja, jb = json.loads(ta), json.loads(tb)
        except ValueError:
            return [("$", "<bytes>", "<bytes>")] if ta != tb else []
        diffs = json_diffs(normalise_json(ja), normalise_json(jb))
        if not diffs and ta != tb:      # the same values in other bytes: key order, spacing, escapes, number forms
            diffs = [("$<format>", ta[:300], tb[:300])]
        return diffs
    return [] if ta == tb else [("$<text>", ta[:300], tb[:300])]


def explained(expl, case, rel, path):
    for e in expl:
        if fnmatch.fnmatch(case, e.get("case", "*")) and re.search(e.get("file", ".*"), rel) and re.search(e.get("path", ".*"), path):
            return e["reason"]
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--component", required=True)
    ap.add_argument("--a", required=True, help="the reference implementation's command")
    ap.add_argument("--b", required=True, help="the other implementation's command")
    ap.add_argument("--case", action="append", default=[])
    ap.add_argument("--explained", help="JSON list of {case, file, path, reason}")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    expl = json.load(open(a.explained)) if a.explained else []
    ka, outa = run_suite(a.component, a.a, a.case)
    kb, outb = run_suite(a.component, a.b, a.case)
    unexplained = explained_n = compared = 0
    try:
        for case in sorted(set(ka) & set(kb)):
            cj = json.load(open(os.path.join(SUITE, "cases", case, "case.json")))
            if cj.get("deviation"):
                print(f"skip  {case} [{cj['deviation']}]: differs by design")
                continue
            fa, fb = files(ka[case]), files(kb[case])
            compared += 1
            for rel in sorted(set(fa) | set(fb)):
                if rel not in fa or rel not in fb:
                    diffs = [("<file>", rel in fa, rel in fb)]
                else:
                    diffs = compare_file(rel, fa[rel], fb[rel], ka[case], kb[case])
                for path, x, y in diffs:
                    why = explained(expl, case, rel, path)
                    if why:
                        explained_n += 1
                        if a.verbose:
                            print(f"expl  {case} {rel} {path}: {why}")
                    else:
                        unexplained += 1
                        print(f"DIFF  {case} {rel} {path}:\n      a={json.dumps(x)[:300]}\n      b={json.dumps(y)[:300]}")
            print(f"ok    {case}" if not unexplained else f"done  {case}")
    finally:
        for d in list(ka.values()) + list(kb.values()):
            shutil.rmtree(d, ignore_errors=True)
    missing = sorted(set(ka) ^ set(kb))
    print(f"\ncases compared={compared} explained differences={explained_n} unexplained={unexplained}"
          + (f" not run by both: {missing}" if missing else ""))
    if not compared:
        print(outa[-2000:], outb[-2000:])
    return 1 if unexplained or missing or not compared else 0


if __name__ == "__main__":
    sys.exit(main())
