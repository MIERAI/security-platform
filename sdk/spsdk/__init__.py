"""security-platform collector SDK (component `sdk`, see sdk/VERSION).

Collectors use it to build ONE findings document per run (schema findings/v1) plus a Prometheus text file.
Consumers never import collectors; they only read the documents. See docs/design.md section 4-5.
"""
import hashlib
import json
import os
import sys
import time

SCHEMA_VERSION = "1.2"
SEVERITIES = ["critical", "high", "medium", "low", "info"]
LAYERS = ["identity", "network", "host", "workload", "supply-chain", "data-secrets", "ai-agents", "detection"]


def now_iso(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def fid(layer, asset, check):
    return hashlib.sha1(f"{layer}|{asset}|{check}".encode()).hexdigest()[:12]


def load_instance():
    """Instance config (private, environment-specific). Path from SP_INSTANCE."""
    p = os.environ.get("SP_INSTANCE")
    if not p:
        sys.exit("SP_INSTANCE not set (path to the private instance.yaml)")
    return load_config(p)


def load_config(p):
    """YAML when PyYAML is available; JSON (a subset of YAML) otherwise, so minimal hosts need only python3."""
    with open(os.path.expanduser(p)) as f:
        text = f.read()
    try:
        import yaml
    except ImportError:
        return json.loads(text)
    return yaml.safe_load(text)


def asset_scope(inst, name):
    """Per-asset scope (instance `scope:` list): [{names: [..], scope: [collector, ...], offline: gap|expected,
    reason}]. Returns the matching entry or None (= every collector, offline is a gap). Matching is by any of the
    names (the same device may be `dorm-router` in `hosts` and its overlay-network host name in discovery)."""
    for s in (inst or {}).get("scope") or []:
        if name in (s.get("names") or []):
            return s
    return None


def in_scope(inst, name, collector):
    """False when the instance limits this asset to other collectors (it is then skipped: not a gap)."""
    s = asset_scope(inst, name)
    return s is None or collector in (s.get("scope") or [])


class Collector:
    def __init__(self, name, version):
        # SP_COLLECTOR_NAME: the same collector deployed twice with different scopes (e.g. in-cluster and from a
        # workstation) reports under distinct names, so each one only ever resolves (fixes) its own findings
        self.name, self.version = os.environ.get("SP_COLLECTOR_NAME") or name, version
        self.started = now_iso()
        self.findings, self.metrics, self.coverage, self.tools = [], [], {}, {}
        self.out = os.environ.get("SP_RUN_DIR") or sys.exit("SP_RUN_DIR not set")
        os.makedirs(self.out, exist_ok=True)

    # evidence ------------------------------------------------------------
    def raw(self, name, obj):
        """Store evidence (already filtered: NEVER secret values). Returns the evidence pointer."""
        d = os.path.join(self.out, "raw", self.name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, name), "w") as f:
            f.write(obj if isinstance(obj, str) else json.dumps(obj, indent=1, sort_keys=True, default=str))
        return f"raw/{self.name}/{name}"

    # findings / coverage / metrics --------------------------------------
    def finding(self, layer, asset, check, title, severity, evidence, remediation, needs_human=False,
                owner=None, kind="compliance", refs=None, **attributes):
        assert layer in LAYERS and severity in SEVERITIES, (layer, severity)
        if any(x["id"] == fid(layer, asset, check) for x in self.findings):
            return  # same (layer, asset, check) already reported in this run
        f = dict(id=fid(layer, asset, check), check=check, layer=layer, asset=asset, title=title[:300],
                 severity=severity, evidence=evidence, remediation=remediation, needs_human=bool(needs_human),
                 owner=owner or ("human" if needs_human else "platform"), observed_at=now_iso(), kind=kind)
        if refs:
            f["refs"] = refs
        if attributes:
            f["attributes"] = attributes
        self.findings.append(f)

    def ok(self, asset, complete_scope=None):
        """complete_scope: an asset prefix (e.g. "image:") this run inventoried COMPLETELY and authoritatively; the
        ledger then closes findings on assets under it that the run no longer lists (`asset_retired`). Declare it only
        when every source of the inventory was read successfully: a partial listing must not retire anything."""
        e = self.coverage.setdefault(asset, {"asset": asset, "status": "ok"})
        if complete_scope and e["status"] == "ok":
            e["complete_scope"] = complete_scope

    def gap(self, asset, reason, checks=None):
        """checks: a NARROW gap - only these checks (fnmatch patterns) could not be evaluated, on the asset this one is
        a part of (`<asset>/<part>`); the ledger then keeps their findings on `<asset>` unknown instead of fixed, while
        the asset itself stays covered (`ok`) for every other check."""
        self.coverage[asset] = {"asset": asset, "status": "gap", "reason": reason[:300]}
        if checks:
            assert "/" in asset, "a narrow gap is reported on <asset>/<part>"
            self.coverage[asset]["checks"] = sorted(checks)

    def metric(self, name, value, help_="", **labels):
        self.metrics.append(dict(name=name, value=float(value), labels={k: str(v) for k, v in labels.items()},
                                 help=help_))

    # output -------------------------------------------------------------
    def write(self):
        doc = {"schema_version": SCHEMA_VERSION,
               "collector": {"name": self.name, "version": self.version, "tools": self.tools},
               "run": {"started_at": self.started, "finished_at": now_iso(),
                       "instance": os.environ.get("SP_INSTANCE_NAME", "")},
               "coverage": list(self.coverage.values()), "findings": self.findings, "metrics": self.metrics}
        with open(os.path.join(self.out, f"{self.name}.findings.json"), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
        with open(os.path.join(self.out, f"{self.name}.prom"), "w") as f:
            f.write(to_prom(doc))
        gaps = sum(1 for c in self.coverage.values() if c["status"] == "gap")
        print(f"[{self.name} {self.version}] findings={len(self.findings)} assets={len(self.coverage)} gaps={gaps}",
              file=sys.stderr)


def to_prom(doc):
    """Generic metrics from any findings document (depends only on the schema)."""
    name = doc["collector"]["name"]
    counts = {}
    for x in doc["findings"]:
        k = (x["layer"], x["severity"])
        counts[k] = counts.get(k, 0) + 1
    series = [("security_collector_findings", {"collector": name, "layer": l, "severity": s}, v,
               "Findings reported by the latest run of a collector") for (l, s), v in sorted(counts.items())]
    gaps = sum(1 for c in doc["coverage"] if c["status"] == "gap")
    series += [("security_collector_gaps", {"collector": name}, gaps, "Assets the collector could not cover"),
               ("security_collector_assets", {"collector": name}, len(doc["coverage"]), "Assets in scope of the run"),
               ("security_collector_last_run_timestamp_seconds", {"collector": name},
                int(time.mktime(time.strptime(doc["run"]["finished_at"], "%Y-%m-%dT%H:%M:%SZ")) - time.timezone),
                "Heartbeat: when the collector last finished (no findings != secure)")]
    series += [(m["name"], dict(m.get("labels", {}), collector=name), m["value"], m.get("help", ""))
               for m in doc.get("metrics", [])]
    return render(series)


def render(series):
    lines, seen = [], set()
    for n, labels, v, h in series:
        if n not in seen:
            seen.add(n)
            if h:
                lines.append(f"# HELP {n} {h}")
            lines.append(f"# TYPE {n} {'counter' if n.endswith('_total') else 'gauge'}")
        lab = ",".join('{}="{}"'.format(k, str(val).replace("\\", "/").replace('"', "'").replace("\n", " "))
                       for k, val in sorted(labels.items()))
        lab = "{" + lab + "}" if lab else ""
        lines.append(f"{n}{lab} {v:g}" if isinstance(v, float) else f"{n}{lab} {v}")
    return "\n".join(lines) + "\n"
