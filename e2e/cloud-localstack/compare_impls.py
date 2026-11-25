"""Compare two runs of the cloud collector (the Python and the Go implementation) on the same input, byte for byte
after normalising what legitimately differs between two runs: wall-clock times (run.started_at/finished_at,
findings[].observed_at, the heartbeat series), the age of an import file (evidence imports[].age_hours) and the
per-request id an emulator puts into an engine's error message ("RequestID: <uuid>", quoted in a gap's reason).
Everything else - every finding, title, severity, source, coverage entry and reason, metric and evidence file -
must be identical.

usage: compare_impls.py RUN_A RUN_B [NAME]      exit 0 identical, 1 different (a unified diff is printed)
"""
import difflib
import os
import re
import sys


TIME = re.compile(r'("(?:observed_at|started_at|finished_at)": )"[0-9T:Z-]+"')
AGE = re.compile(r'("age_hours": )[0-9.e+-]+')
# an engine's error text quoted in a reason carries the emulator's per-request id (differs between any two runs)
REQUEST_ID = re.compile(r"(RequestID: )[0-9a-fA-F-]{36}")


def norm_findings(text):
    """Byte comparison: only the time values are replaced, the formatting is compared as written."""
    return REQUEST_ID.sub(r"\1<id>", TIME.sub(r'\1"<time>"', text))


def norm_raw(text):
    return REQUEST_ID.sub(r"\1<id>", AGE.sub(r"\1<age>", text))


def norm_prom(text):
    return re.sub(r"^(security_collector_last_run_timestamp_seconds\{[^}]*\}) \d+$", r"\1 <time>", text, flags=re.M)


def files(run, name):
    out = {f"{name}.findings.json": norm_findings, f"{name}.prom": norm_prom}
    raw = os.path.join(run, "raw", name)
    for f in sorted(os.listdir(raw)) if os.path.isdir(raw) else []:
        out[os.path.join("raw", name, f)] = norm_raw
    return out


def main(a, b, name="cloud"):
    fa, fb = files(a, name), files(b, name)
    diffs = 0
    for rel in sorted(set(fa) | set(fb)):
        pa, pb = os.path.join(a, rel), os.path.join(b, rel)
        if not (os.path.exists(pa) and os.path.exists(pb)):
            print(f"only in {'A' if os.path.exists(pa) else 'B'}: {rel}")
            diffs += 1
            continue
        fn = fa.get(rel) or fb[rel]
        ta, tb = fn(open(pa).read()), fn(open(pb).read())
        if ta != tb:
            diffs += 1
            sys.stdout.writelines(difflib.unified_diff(ta.splitlines(True), tb.splitlines(True), f"A/{rel}", f"B/{rel}"))
    print(f"compared {len(set(fa) | set(fb))} files: {'identical' if not diffs else f'{diffs} different'}")
    return 1 if diffs else 0


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
