#!/usr/bin/env python3
"""Black-box conformance suite for security-platform components (docs/contracts.md).

It imports NOTHING from the implementation: every component under test is a process, started from a command line
given per component, fed fixture files, and judged only by its exit code, its stdout/stderr and the files it writes,
against golden subsets and the JSON Schemas in contracts/.

    python3 conformance/run.py [--impl COMPONENT=COMMAND ...] [--component C ...] [--case GLOB ...]
                               [--expected-failures FILE] [--keep] [--list] [-v]
    python3 conformance/run.py validate SCHEMA FILE...      # e.g. validate findings out/host.findings.json

COMMAND is a shell-style command line (split with shlex, no shell); the case's arguments are appended. Instead of
--impl, set SP_IMPL_<COMPONENT> (upper case, '-' -> '_'), e.g. SP_IMPL_LEDGER='/opt/sp-go/bin/sp-ledger merge'.
A component without an implementation is skipped (reported), unless --require-all.

Exit code: 0 = every case that ran passed (or failed as listed in --expected-failures); 1 = a failure, or an
expected failure that now passes (remove it from the list: the deviation is fixed); 2 = usage error.
Python >= 3.10, stdlib only. Case format: conformance/README.md.
"""
import argparse
import fnmatch
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONTRACTS = os.path.join(REPO, "contracts")
CASES = os.path.join(HERE, "cases")
SCHEMAS = {   # short name -> schema file under contracts/
    "findings": "findings/findings-v1.schema.json",
    "ledger": "ledger/ledger-v1.schema.json",
    "exceptions": "ledger/exceptions-v1.schema.json",
    "tracker": "ledger/tracker-v1.schema.json",
    "scorecard": "scorecard/scorecard-v1.schema.json",
    "scorecard-catalog": "scorecard/catalog-v1.schema.json",
    "attestations": "scorecard/attestations-v1.schema.json",
    "runner-config": "runner/runner-config-v1.schema.json",
    "runner-state": "runner/runner-state-v1.schema.json",
    "runner-status": "runner/runner-status-v1.schema.json",
    "cli-findings": "cli/findings-json-v1.schema.json",
    "metrics-registry": "metrics/registry.schema.json",
}


# ---- minimal JSON Schema (draft 2020-12 subset used by contracts/) ---------------------------------------------------
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}
DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, TYPES[t])


def schema_errors(doc, schema, root=None, path="$"):
    """Supported: $ref (#/...), type (str or list), enum, const, pattern, maxLength, minLength, format (date-time,
    date), minimum, maximum, required, properties, additionalProperties (bool|schema), patternProperties, items,
    minItems, anyOf, oneOf, allOf. Unknown keywords are ignored (annotations)."""
    root = root if root is not None else schema
    if schema is True or schema == {}:
        return []
    if schema is False:
        return [f"{path}: not allowed"]
    out = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            return [f"{path}: unsupported $ref {ref}"]
        target = root
        for part in ref[2:].split("/"):
            target = target[part]
        out += schema_errors(doc, target, root, path)
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        if not any(_is_type(doc, x) for x in ts):
            return out + [f"{path}: expected {t}, got {type(doc).__name__}"]
    if "enum" in schema and doc not in schema["enum"]:
        out.append(f"{path}: {doc!r} not in {schema['enum']}")
    if "const" in schema and doc != schema["const"]:
        out.append(f"{path}: {doc!r} != {schema['const']!r}")
    if isinstance(doc, str):
        if "pattern" in schema and not re.search(schema["pattern"], doc):
            out.append(f"{path}: {doc!r} !~ {schema['pattern']}")
        if "maxLength" in schema and len(doc) > schema["maxLength"]:
            out.append(f"{path}: longer than {schema['maxLength']}")
        if "minLength" in schema and len(doc) < schema["minLength"]:
            out.append(f"{path}: shorter than {schema['minLength']}")
        fmt = schema.get("format")
        if fmt == "date-time" and not DATE_TIME.match(doc):
            out.append(f"{path}: {doc!r} is not an RFC 3339 date-time")
        if fmt == "date" and not DATE.match(doc):
            out.append(f"{path}: {doc!r} is not a date")
    if _is_type(doc, "number"):
        if "minimum" in schema and doc < schema["minimum"]:
            out.append(f"{path}: {doc} < {schema['minimum']}")
        if "maximum" in schema and doc > schema["maximum"]:
            out.append(f"{path}: {doc} > {schema['maximum']}")
    if isinstance(doc, dict):
        for r in schema.get("required", []):
            if r not in doc:
                out.append(f"{path}: missing {r}")
        props = schema.get("properties", {})
        pprops = schema.get("patternProperties", {})
        for k, v in doc.items():
            matched = False
            if k in props:
                matched = True
                out += schema_errors(v, props[k], root, f"{path}.{k}")
            for pat, sub in pprops.items():
                if re.search(pat, k):
                    matched = True
                    out += schema_errors(v, sub, root, f"{path}.{k}")
            if not matched and "additionalProperties" in schema:
                out += schema_errors(v, schema["additionalProperties"], root, f"{path}.{k}")
    if isinstance(doc, list):
        if "items" in schema:
            for i, v in enumerate(doc):
                out += schema_errors(v, schema["items"], root, f"{path}[{i}]")
        if "minItems" in schema and len(doc) < schema["minItems"]:
            out.append(f"{path}: fewer than {schema['minItems']} items")
    for k in ("anyOf", "oneOf"):
        if k in schema:
            ok = [s for s in schema[k] if not schema_errors(doc, s, root, path)]
            if not ok or (k == "oneOf" and len(ok) != 1):
                out.append(f"{path}: does not match {'exactly one' if k == 'oneOf' else 'any'} of {k}")
    for s in schema.get("allOf", []):
        out += schema_errors(doc, s, root, path)
    return out


def load_schema(name):
    p = os.path.join(CONTRACTS, SCHEMAS.get(name, name))
    with open(p) as f:
        return json.load(f)


# ---- golden subsets ---------------------------------------------------------------------------------------------------
def subset_errors(actual, expected, path="$"):
    """`expected` is a subset of `actual`: extra keys in actual are fine (unknown fields are ignored by contract).
    Operators (a dict with exactly one key starting with '$'):
      {"$absent": true}            key must not exist          {"$null_or_absent": true}   missing or null
      {"$any": true}               key must exist (any value)  {"$type": "string"|...}     JSON type
      {"$regex": "..."}            string matches               {"$approx": [value, tol]}   number within tol
      {"$ge": n} / {"$le": n}      number bounds                {"$len": n}                 list/dict/str length
      {"$contains": [subsets]}     list has, for each subset, an element matching it (any order)
      {"$not_contains": [subsets]} list has no element matching any of them
      {"$unordered": [subsets]}    list has exactly these elements, any order
    Lists without an operator are compared element by element and must have the same length."""
    if isinstance(expected, dict) and len(expected) == 1 and next(iter(expected)).startswith("$"):
        op, arg = next(iter(expected.items()))
        if op == "$any":
            return []
        if op == "$type":
            return [] if _is_type(actual, arg) else [f"{path}: expected type {arg}, got {actual!r}"]
        if op == "$regex":
            return [] if isinstance(actual, str) and re.search(arg, actual) else [f"{path}: {actual!r} !~ {arg}"]
        if op == "$approx":
            ok = _is_type(actual, "number") and abs(actual - arg[0]) <= arg[1]
            return [] if ok else [f"{path}: {actual!r} not within {arg[1]} of {arg[0]}"]
        if op == "$ge":
            return [] if _is_type(actual, "number") and actual >= arg else [f"{path}: {actual!r} < {arg}"]
        if op == "$le":
            return [] if _is_type(actual, "number") and actual <= arg else [f"{path}: {actual!r} > {arg}"]
        if op == "$len":
            return [] if hasattr(actual, "__len__") and len(actual) == arg else [f"{path}: length {len(actual) if hasattr(actual, '__len__') else '?'} != {arg}"]
        if op == "$contains":
            if not isinstance(actual, list):
                return [f"{path}: expected a list"]
            return [f"{path}: no element matches {e!r}" for e in arg if not any(not subset_errors(a, e) for a in actual)]
        if op == "$not_contains":
            if not isinstance(actual, list):
                return [f"{path}: expected a list"]
            return [f"{path}: an element matches {e!r}" for e in arg if any(not subset_errors(a, e) for a in actual)]
        if op == "$unordered":
            if not isinstance(actual, list) or len(actual) != len(arg):
                return [f"{path}: expected {len(arg)} elements, got {actual!r}"[:300]]
            rest = list(actual)
            for e in arg:
                hit = next((i for i, a in enumerate(rest) if not subset_errors(a, e)), None)
                if hit is None:
                    return [f"{path}: no element matches {e!r}"]
                rest.pop(hit)
            return []
        if op in ("$absent", "$null_or_absent"):
            return [] if op == "$null_or_absent" and actual is None else [f"{path}: expected absent, got {actual!r}"]
        return [f"{path}: unknown operator {op}"]
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            return [f"{path}: expected an object, got {actual!r}"[:300]]
        out = []
        for k, v in expected.items():
            if k not in actual:
                if isinstance(v, dict) and len(v) == 1 and next(iter(v)) in ("$absent", "$null_or_absent"):
                    continue
                out.append(f"{path}.{k}: missing")
                continue
            out += subset_errors(actual[k], v, f"{path}.{k}")
        return out
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            return [f"{path}: expected {len(expected)} elements, got {json.dumps(actual)[:200]}"]
        out = []
        for i, (a, e) in enumerate(zip(actual, expected)):
            out += subset_errors(a, e, f"{path}[{i}]")
        return out
    if isinstance(expected, float) or isinstance(actual, float):
        return [] if _is_type(actual, "number") and abs(actual - expected) < 1e-9 else [f"{path}: {actual!r} != {expected!r}"]
    return [] if actual == expected and type(actual) is type(expected) else [f"{path}: {actual!r} != {expected!r}"]


# ---- Prometheus text format ---------------------------------------------------------------------------------------
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?\s+(\S+)(\s+\d+)?$')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_prom(text):
    """-> (samples [(name, labels, value)], types {name: type}, errors)."""
    samples, types, errs = [], {}, []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        if line.startswith("#"):
            p = line.split()
            if len(p) >= 4 and p[1] == "TYPE":
                types[p[2]] = p[3]
            continue
        m = SAMPLE.match(line)
        if not m:
            errs.append(f"line {n}: not a sample: {line[:120]}")
            continue
        labels = dict(LABEL.findall(m.group(3) or ""))
        try:
            v = float(m.group(4))
        except ValueError:
            errs.append(f"line {n}: bad value {m.group(4)}")
            continue
        samples.append((m.group(1), labels, v))
    return samples, types, errs


# ---- running a case -----------------------------------------------------------------------------------------------
class CaseError(Exception):
    pass


PROTOCOL_ENV = {"SP_DATA", "SP_INSTANCE", "SP_RUN_DIR", "SP_INPUT_DIR", "SP_INSTANCE_NAME", "SP_COLLECTOR_NAME"}
# {sandbox} {case} {python} {path} {now_epoch} {fake_jwt} {fake_key} {svc_<name>} {epoch:+-N} {utc:+-N}; anything else in braces is left alone
TEMPLATE = re.compile(r"\{(sandbox|case|python|path|now_epoch|fake_jwt|fake_key|svc_[a-z0-9_]+|epoch:[+-]?\d+|utc:[+-]?\d+)\}")


def fake_jwt():
    """An unsigned, syntactically valid JWT (sub scanner, aud conformance, exp 2100) for identity-token fixtures and
    as a secret canary. Built here so that no token-shaped string is committed."""
    import base64
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256', 'kid': 'k'})}.{enc({'sub': 'scanner', 'aud': 'conformance', 'exp': 4102444800})}." + \
        base64.urlsafe_b64encode(b"signature-canary").rstrip(b"=").decode()


class Sandbox:
    def __init__(self, case_dir, keep):
        self.case_dir = case_dir
        self.root = tempfile.mkdtemp(prefix="spconf-")
        self.keep = keep
        self.vars = {"sandbox": self.root, "case": case_dir, "python": sys.executable, "path": os.environ.get("PATH", ""),
                     "now_epoch": str(int(time.time())), "fake_jwt": fake_jwt(),
                     "fake_key": "fake-private-key-" + os.urandom(8).hex()}
        self.services, self.background = [], {}

    def render(self, s):
        def rep(m):
            k = m.group(1)
            if k.startswith("epoch:"):          # {epoch:-2820} = the real clock now + offset (seconds)
                return str(int(time.time()) + int(k[6:]))
            if k.startswith("utc:"):            # {utc:-3600} = ISO time, real clock now + offset
                return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + int(k[4:])))
            if k in self.vars:
                return self.vars[k]
            raise CaseError(f"unknown template variable {{{k}}}")
        return TEMPLATE.sub(rep, s) if isinstance(s, str) else s

    def render_obj(self, o):
        if isinstance(o, str):
            return self.render(o)
        if isinstance(o, list):
            return [self.render_obj(x) for x in o]
        if isinstance(o, dict):
            return {k: self.render_obj(v) for k, v in o.items()}
        return o

    def path(self, rel):
        return os.path.join(self.root, self.render(rel))

    def stage(self, files):
        """{sandbox path: case file | {"text": "..."} | {"json": {...}} | {"dir": true}}; text files are rendered
        (templates), unless {"raw": "case file"}."""
        for dst, src in (files or {}).items():
            p = self.path(dst)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if isinstance(src, dict) and src.get("dir"):
                os.makedirs(p, exist_ok=True)
            elif isinstance(src, dict) and "text" in src:
                open(p, "w").write(self.render(src["text"]))
            elif isinstance(src, dict) and "json" in src:
                json.dump(self.render_obj(src["json"]), open(p, "w"), indent=1)
            elif isinstance(src, dict) and "raw" in src:
                shutil.copyfile(os.path.join(self.case_dir, src["raw"]), p)
            else:
                text = open(os.path.join(self.case_dir, src)).read()
                open(p, "w").write(self.render(text))
            if isinstance(src, dict) and src.get("mode"):
                os.chmod(p, int(src["mode"], 8))

    def start_services(self, services):
        for s in services or []:
            pf = os.path.join(self.root, f".svc-{s['name']}.port")
            argv = [self.render(x) for x in s["argv"]] + ["--port-file", pf]
            p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            self.services.append(p)
            for _ in range(100):
                if os.path.exists(pf) and open(pf).read().strip():
                    break
                time.sleep(0.05)
            else:
                raise CaseError(f"service {s['name']} did not start")
            self.vars[f"svc_{s['name']}"] = f"http://127.0.0.1:{open(pf).read().strip()}"

    def close(self):
        for p in self.services + [b["proc"] for b in self.background.values()]:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            p.wait()
        if not self.keep:
            shutil.rmtree(self.root, ignore_errors=True)


def snapshot(root, ignore):
    out = {}
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        if any(rel == i or rel.startswith(i + os.sep) for i in ignore):
            dirs[:] = []
            continue
        for f in files:
            p = os.path.join(d, f)
            try:
                st = os.stat(p)
                out[os.path.relpath(p, root)] = (st.st_size, st.st_mtime_ns)
            except OSError:
                pass
    return out


def check(sb, exp, res):
    """One assertion -> list of error strings."""
    errs = []
    if "json" in exp or "jsonl" in exp:
        key = "json" if "json" in exp else "jsonl"
        p = sb.path(exp[key])
        if not os.path.exists(p):
            return [f"{exp[key]}: missing"]
        try:
            text = open(p).read()
            doc = json.loads(text) if key == "json" else [json.loads(x) for x in text.splitlines() if x.strip()]
        except ValueError as e:
            return [f"{exp[key]}: not JSON: {e}"]
        if exp.get("schema"):
            s = load_schema(exp["schema"])
            for i, d in enumerate(doc if key == "jsonl" else [doc]):
                errs += [f"{exp[key]} schema {exp['schema']}: {x}" for x in schema_errors(d, s)][:10]
        if "subset" in exp:
            want = exp["subset"]
            if isinstance(want, str):
                want = json.load(open(os.path.join(sb.case_dir, want)))
            errs += [f"{exp[key]}: {x}" for x in subset_errors(doc, sb.render_obj(want))][:15]
        if exp.get("findings_ids"):        # every finding id = sha1("layer|asset|check")[:12]
            import hashlib
            for f in doc.get("findings", []):
                want = hashlib.sha1(f"{f.get('layer')}|{f.get('asset')}|{f.get('check')}".encode()).hexdigest()[:12]
                if f.get("id") != want:
                    errs.append(f"{exp[key]}: finding id {f.get('id')} != sha1(layer|asset|check)[:12] {want}")
        return errs
    if "prom" in exp:
        p = sb.path(exp["prom"])
        if not os.path.exists(p):
            return [f"{exp['prom']}: missing"]
        samples, types, perrs = parse_prom(open(p).read())
        errs += [f"{exp['prom']}: {x}" for x in perrs[:5]]
        for fam in exp.get("families", []):
            if not any(n == fam for n, _, _ in samples):
                errs.append(f"{exp['prom']}: no sample of {fam}")
        for h in sb.render_obj(exp.get("has", [])):
            hits = [(n, lab, v) for n, lab, v in samples if n == h["name"]
                    and all(lab.get(k) == str(val) for k, val in (h.get("labels") or {}).items())]
            if h.get("exact_labels"):
                hits = [x for x in hits if set(x[1]) == set(h["labels"])]
            if not hits:
                errs.append(f"{exp['prom']}: no sample {h['name']}{h.get('labels') or ''}")
            elif "value" in h and not any(abs(v - float(h["value"])) < 1e-9 for _, _, v in hits):
                errs.append(f"{exp['prom']}: {h['name']}{h.get('labels') or ''} = {[v for _, _, v in hits]}, want {h['value']}")
        for h in exp.get("absent", []):
            if any(n == h["name"] and all(lab.get(k) == str(v) for k, v in (h.get("labels") or {}).items())
                   for n, lab, _ in samples):
                errs.append(f"{exp['prom']}: unexpected sample {h['name']}{h.get('labels') or ''}")
        for n, t in exp.get("types", {}).items():
            if types.get(n) != t:
                errs.append(f"{exp['prom']}: TYPE of {n} is {types.get(n)}, want {t}")
        for n, lab, _ in samples:
            bad = set(lab) & set(exp.get("forbidden_labels", []))
            if bad:
                errs.append(f"{exp['prom']}: {n} carries forbidden label(s) {sorted(bad)}")
        return errs
    if "stdout" in exp or "stderr" in exp:
        key = "stdout" if "stdout" in exp else "stderr"
        text, spec = res[key], exp[key]
        for r in spec.get("regex", []):
            if not re.search(r, text, re.M | (re.I if spec.get("ignore_case") else 0)):
                errs.append(f"{key}: no match for /{r}/ in:\n{text[-1500:]}")
        for r in spec.get("not_regex", []):
            m = re.search(r, text, re.M | (re.I if spec.get("ignore_case") else 0))
            if m:
                errs.append(f"{key}: unexpected match /{r}/: {m.group(0)[:200]}")
        for s in sb.render_obj(spec.get("not_contains", [])):
            if s in text:
                errs.append(f"{key}: must not contain {s!r}")
        if "json" in spec or "schema" in spec:
            try:
                doc = json.loads(text)
            except ValueError as e:
                return errs + [f"{key}: not JSON: {e}: {text[:300]}"]
            if spec.get("schema"):
                errs += [f"{key} schema {spec['schema']}: {x}" for x in schema_errors(doc, load_schema(spec["schema"]))][:10]
            if "json" in spec:
                errs += [f"{key}: {x}" for x in subset_errors(doc, sb.render_obj(spec["json"]))][:15]
        if "lines" in spec:
            got = [x for x in text.splitlines() if x.strip()]
            want = sb.render_obj(spec["lines"])
            if got != want:
                errs.append(f"{key}: lines {got} != {want}")
        return errs
    if "file" in exp:
        p = sb.path(exp["file"])
        if not os.path.exists(p):
            return [f"{exp['file']}: missing"]
        text = open(p, errors="replace").read()
        for r in sb.render_obj(exp.get("regex", [])):
            if not re.search(r, text, re.M):
                errs.append(f"{exp['file']}: no match for /{r}/ in:\n{text[-1500:]}")
        for r in sb.render_obj(exp.get("not_regex", [])):
            m = re.search(r, text, re.M)
            if m:
                errs.append(f"{exp['file']}: unexpected match /{r}/: {m.group(0)[:200]}")
        if "lines" in exp and len([x for x in text.splitlines() if x.strip()]) != exp["lines"]:
            errs.append(f"{exp['file']}: {len(text.splitlines())} lines, want {exp['lines']}")
        return errs
    if "exists" in exp:
        return [] if os.path.exists(sb.path(exp["exists"])) else [f"{exp['exists']}: missing"]
    if "absent" in exp:
        return [f"{exp['absent']}: must not exist"] if os.path.exists(sb.path(exp["absent"])) else []
    if "glob" in exp:
        import glob as g
        n = len(g.glob(sb.path(exp["glob"])))
        want = exp.get("count")
        return [] if n == want else [f"{exp['glob']}: {n} match(es), want {want}"]
    if "writes_only_under" in exp:
        return res.get("write_errs", [])
    if "no_secret" in exp:
        canaries = sb.render_obj(exp["no_secret"])
        for d, _, files in os.walk(sb.path(exp.get("in", "."))):
            for f in files:
                p = os.path.join(d, f)
                try:
                    data = open(p, "rb").read()
                except OSError:
                    continue
                if os.path.relpath(p, sb.root).startswith(tuple(exp.get("except", []))):
                    continue
                errs += [f"secret canary {c[:6]}... found in {os.path.relpath(p, sb.root)}" for c in canaries if c.encode() in data]
        errs += [f"secret canary {c[:6]}... found in {k}" for c in canaries for k in ("stdout", "stderr") if c in res[k]]
        return errs
    if "duration_max" in exp:
        return [] if res["duration"] <= exp["duration_max"] else [f"took {res['duration']:.1f}s > {exp['duration_max']}s"]
    return [f"unknown assertion {exp}"]


def impl_cmd(component, impls):
    cmd = impls.get(component) or os.environ.get("SP_IMPL_" + component.upper().replace("-", "_"))
    if not cmd:
        return None
    argv = shlex.split(cmd)
    # cases run in a temporary directory: a relative program path means relative to where run.py was started
    if os.sep in argv[0] and not os.path.isabs(argv[0]):
        argv[0] = os.path.abspath(argv[0])
    return argv


def run_case(case_dir, case, impls, keep, verbose):
    """-> (status, messages). status: pass | fail | skip."""
    needed = sorted({s["exec"]["impl"] for s in case["steps"] if "exec" in s})
    missing = [c for c in needed if not impl_cmd(c, impls)]
    if missing:
        return "skip", [f"no implementation for {', '.join(missing)} (SP_IMPL_{missing[0].upper().replace('-', '_')})"]
    sb = Sandbox(case_dir, keep)
    msgs, info = [], []     # msgs: failures; info: verbose notes
    try:
        sb.start_services(case.get("services"))      # first: fixtures may name a service URL ({svc_<name>})
        sb.stage(case.get("files"))
        for i, step in enumerate(case["steps"]):
            name = step.get("name", f"step {i + 1}")
            sb.stage(step.get("files"))
            for rel in step.get("remove", []):
                p = sb.path(rel)
                shutil.rmtree(p) if os.path.isdir(p) else os.path.exists(p) and os.remove(p)
            if "sleep" in step:
                time.sleep(step["sleep"])
            res = {"stdout": "", "stderr": "", "duration": 0.0, "rc": None}
            if "wait" in step:
                b = sb.background.pop(step["wait"])
                out, err = b["proc"].communicate(timeout=step.get("timeout", 120))
                res.update(stdout=out, stderr=err, rc=b["proc"].returncode, duration=time.time() - b["t0"])
            if "exec" in step:
                ex = step["exec"]
                argv = impl_cmd(ex["impl"], impls) + [sb.render(a) for a in ex.get("args", [])]
                env = {k: v for k, v in os.environ.items() if k not in PROTOCOL_ENV}   # no leak from the caller's shell
                env.update({"TZ": "UTC", "LC_ALL": "C", "NO_COLOR": "1", "HOME": sb.path("home")})
                os.makedirs(sb.path("home"), exist_ok=True)
                env.update({k: sb.render(v) for k, v in (ex.get("env") or {}).items()})
                cwd = sb.path(ex.get("cwd", "."))
                watch = ex.get("writes_only_under")
                before = snapshot(sb.root, [sb.render(w) for w in watch]) if watch is not None else None
                t0 = time.time()
                p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, start_new_session=True)
                if ex.get("background"):
                    sb.background[name] = {"proc": p, "t0": t0}
                    continue
                try:
                    out, err = p.communicate(timeout=ex.get("timeout", 120))
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    out, err = p.communicate()
                    msgs.append(f"{name}: timed out after {ex.get('timeout', 120)}s")
                    return "fail", msgs + [f"stderr: {err[-800:]}"] + info
                res.update(stdout=out, stderr=err, rc=p.returncode, duration=time.time() - t0)
                if before is not None:
                    after = snapshot(sb.root, [sb.render(w) for w in watch])
                    changed = sorted(k for k in after if before.get(k) != after[k]) + sorted(k for k in before if k not in after)
                    res["write_errs"] = [f"wrote outside {watch}: {k}" for k in changed if not k.startswith(".svc-")]
            if res["rc"] is not None:
                want = step.get("exit", 0)
                ok = (res["rc"] in want["in"]) if isinstance(want, dict) and "in" in want else \
                     (res["rc"] != want["not"]) if isinstance(want, dict) and "not" in want else res["rc"] == want
                if not ok:
                    msgs.append(f"{name}: exit code {res['rc']}, want {want}\n  stderr: {res['stderr'][-800:]}")
            for exp in step.get("expect", []):
                msgs += [f"{name}: {e}" for e in check(sb, exp, res)]
            if verbose and res["rc"] is not None:
                info.append(f"{name}: rc={res['rc']} {res['duration']:.1f}s")
        return ("fail" if msgs else "pass"), msgs + info
    except CaseError as e:
        return "fail", msgs + [f"case error: {e}"] + info
    finally:
        if keep:
            print(f"      sandbox kept: {sb.root}", flush=True)
        sb.close()


def load_cases(components, globs):
    out = []
    for comp in sorted(os.listdir(CASES)):
        if components and comp not in components:
            continue
        for name in sorted(os.listdir(os.path.join(CASES, comp))):
            d = os.path.join(CASES, comp, name)
            cid = f"{comp}/{name}"
            if not os.path.isfile(os.path.join(d, "case.json")):
                continue
            if globs and not any(fnmatch.fnmatch(cid, g) for g in globs):
                continue
            out.append((cid, d, json.load(open(os.path.join(d, "case.json")))))
    return out


def load_expected(path):
    out = {}
    if not path:
        return out
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if line:
            out[line.split()[0]] = line
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["validate"]:
        if len(argv) < 3:
            print("usage: run.py validate SCHEMA FILE...", file=sys.stderr)
            return 2
        s, rc = load_schema(argv[1]), 0
        for f in argv[2:]:
            errs = schema_errors(json.load(open(f)), s)
            print(f"{'ok  ' if not errs else 'FAIL'} {f}" + "".join(f"\n     {e}" for e in errs[:20]))
            rc |= bool(errs)
        return rc
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--impl", action="append", default=[], metavar="COMPONENT=COMMAND")
    ap.add_argument("--component", action="append", default=[])
    ap.add_argument("--case", action="append", default=[], metavar="GLOB")
    ap.add_argument("--expected-failures", metavar="FILE", help="case ids this implementation is allowed to fail")
    ap.add_argument("--require-all", action="store_true", help="a component without an implementation is a failure")
    ap.add_argument("--keep", action="store_true", help="keep the sandboxes (printed)")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)
    impls = {}
    for x in a.impl:
        k, _, v = x.partition("=")
        if not v:
            ap.error(f"--impl {x!r}: COMPONENT=COMMAND")
        impls[k] = v
    cases = load_cases(a.component, a.case)
    if a.list:
        for cid, _, c in cases:
            print(f"{cid:58} {c.get('contract', ''):24} {('deviation ' + c['deviation']) if c.get('deviation') else ''}")
        return 0
    xfail = load_expected(a.expected_failures)
    counts = {"pass": 0, "fail": 0, "skip": 0, "xfail": 0, "xpass": 0}
    per_comp = {}
    for cid, d, c in cases:
        t0 = time.time()
        st, msgs = run_case(d, c, impls, a.keep, a.verbose)
        if st == "skip" and a.require_all:
            st = "fail"
        if cid in xfail and st == "fail":
            st = "xfail"
        elif cid in xfail and st == "pass":
            st = "xpass"
            msgs = [f"listed in {a.expected_failures} but passes now: the deviation is fixed, remove the line"] + msgs
        counts[st] += 1
        per_comp.setdefault(cid.split("/")[0], {}).setdefault(st, 0)
        per_comp[cid.split("/")[0]][st] += 1
        label = {"pass": "PASS ", "fail": "FAIL ", "skip": "SKIP ", "xfail": "XFAIL", "xpass": "XPASS"}[st]
        dev = f" [{c['deviation']}]" if c.get("deviation") else ""
        print(f"{label} {cid}{dev} ({time.time() - t0:.1f}s)", flush=True)
        if st in ("fail", "xpass", "skip") or (a.verbose and msgs):
            for m in msgs:
                print("      " + m.replace("\n", "\n      "))
    print("\n" + "  ".join(f"{k}={v}" for k, v in counts.items()))
    for comp, cs in sorted(per_comp.items()):
        print(f"  {comp:28} " + " ".join(f"{k}={v}" for k, v in sorted(cs.items())))
    unknown = sorted(set(xfail) - {cid for cid, _, _ in load_cases(None, None)})
    if unknown:
        print(f"expected-failures lists unknown case ids: {', '.join(unknown)}")
        return 1
    return 1 if counts["fail"] or counts["xpass"] else 0


if __name__ == "__main__":
    sys.exit(main())
