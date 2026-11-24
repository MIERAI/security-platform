"""security-platform collector SDK (component `sdk`, see sdk/VERSION).

Collectors use it to build ONE findings document per run (schema findings/v1) plus a Prometheus text file.
Consumers never import collectors; they only read the documents. See docs/design.md section 4-5.
"""
import hashlib
import json
import os
import sys
import time

SCHEMA_VERSION = "1.0"
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
    import yaml  # provided by bin/run (uv --with pyyaml)
    with open(p) as f:
        return yaml.safe_load(f)


class Collector:
    def __init__(self, name, version):
        self.name, self.version = name, version
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

    def ok(self, asset):
        self.coverage.setdefault(asset, {"asset": asset, "status": "ok"})

    def gap(self, asset, reason):
        self.coverage[asset] = {"asset": asset, "status": "gap", "reason": reason[:300]}

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
            lines.append(f"# TYPE {n} gauge")
        lab = ",".join('{}="{}"'.format(k, str(val).replace('"', "'")) for k, val in sorted(labels.items()))
        lines.append(f"{n}{{{lab}}} {v:g}" if isinstance(v, float) else f"{n}{{{lab}}} {v}")
    return "\n".join(lines) + "\n"
