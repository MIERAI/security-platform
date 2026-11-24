#!/usr/bin/env python3
"""Collector `vuln-intel`: SBOM inventory x vulnerability intelligence -> prioritized findings. READ-ONLY.

Inputs (contracts, not other collectors' code):
  * inventory/v1 files in the run dir (e.g. inventory.k8s-images.json from the k8s collector)
  * instance config `intel: {feeds: [...], repos: [local checkout paths]}`
Steps: SBOM per image (trivy, CycloneDX, cached by digest) -> deterministic match against Trivy's DB
(GHSA/OSV/NVD/distro advisories) -> enrich with CISA KEV + EPSS feeds -> priority = intel x our exposure.
Registry credentials for private images: SP_REGISTRY_USER / SP_REGISTRY_TOKEN env (never logged).
"""
import concurrent.futures as cf
import glob
import hashlib
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import feeds  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
DATA = os.environ.get("SP_DATA", ".")
CACHE = os.path.join(DATA, "cache")
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def bump(sev, n=1):
    return SEV_ORDER[min(len(SEV_ORDER) - 1, SEV_ORDER.index(sev) + n)]


def trivy(args, env_extra=None, timeout=900):
    env = dict(os.environ, **(env_extra or {}))
    p = subprocess.run(["trivy", "--cache-dir", os.path.join(CACHE, "trivy"), "--quiet"] + args[:1] + (["--cache-backend", "memory"] if args[0] in ("image", "sbom", "fs") else []) + args[1:],
                       capture_output=True, text=True, timeout=timeout, env=env)
    return p.returncode, p.stdout, p.stderr


def scan_image(item):
    ref = item["image"]
    if item.get("image_id") and "@sha256:" in item["image_id"]:
        ref_scan = item["image_id"].split("://")[-1]  # pin to the digest actually running
        if "/" not in ref_scan.split("@")[0]:
            ref_scan = ref
    else:
        ref_scan = ref
    key = hashlib.sha1(ref_scan.encode()).hexdigest()[:16]
    sbom = os.path.join(DATA, "sbom", f"{key}.cdx.json")
    os.makedirs(os.path.dirname(sbom), exist_ok=True)
    env = {}
    if os.environ.get("SP_REGISTRY_TOKEN") and ref.startswith(os.environ.get("SP_REGISTRY_HOST", "ghcr.io")):
        env = {"TRIVY_USERNAME": os.environ.get("SP_REGISTRY_USER", ""), "TRIVY_PASSWORD": os.environ["SP_REGISTRY_TOKEN"]}
    if not os.path.exists(sbom):
        rc, out, err = trivy(["image", "--image-src", "remote", "--format", "cyclonedx", "--skip-db-update",
                              "--output", sbom, ref_scan], env)
        if rc != 0:
            return ref, None, f"sbom rc={rc}: {err.strip()[-160:]}"
    rc, out, err = trivy(["sbom", "--format", "json", "--skip-db-update", "--scanners", "vuln", sbom])
    if rc != 0:
        return ref, None, f"match rc={rc}: {err.strip()[-160:]}"
    return ref, json.loads(out), os.path.relpath(sbom, DATA)


def scan_repo(path):
    rc, out, err = trivy(["fs", "--format", "json", "--skip-db-update", "--scanners", "vuln", os.path.expanduser(path)])
    return path, (json.loads(out) if rc == 0 else None), err.strip()[-160:]


def vulns(report):
    for r in (report or {}).get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            yield r.get("Target", ""), v


def score(v):
    for src in ("nvd", "ghsa", "redhat"):
        s = ((v.get("CVSS") or {}).get(src) or {}).get("V3Score")
        if s:
            return s
    return None


def main():
    inst = spsdk.load_instance()
    cfg = inst.get("intel", {})
    c = spsdk.Collector("vuln-intel", VERSION)
    intel = {}
    for f in cfg.get("feeds", []):
        try:
            intel[f["type"]] = feeds.load(f, os.path.join(CACHE, "feeds"))
            c.ok(f"feed:{f['type']}")
            c.metric("security_intel_feed_age_seconds", int(time.time() - intel[f["type"]]["fetched_at"]),
                     "Age of the cached intel feed", feed=f["type"])
        except Exception as e:  # noqa: BLE001
            c.gap(f"feed:{f['type']}", f"{type(e).__name__}: {e}")
    kev = intel.get("cisa-kev", {}).get("index", {})
    epss = intel.get("epss", {}).get("index", {})
    rc, out, _ = trivy(["version", "--format", "json"])
    if rc == 0:
        tv = json.loads(out)
        c.tools["trivy"] = tv.get("Version", "")
        c.tools["trivy-db"] = (tv.get("VulnerabilityDB") or {}).get("UpdatedAt", "")
    # ---- inventory (contract inventory/v1) -> unique images ---------------------------------------------
    items = []
    for p in glob.glob(os.path.join(c.out, "inventory.*.json")):
        d = json.load(open(p))
        if d.get("schema") == "security-platform/inventory/v1" and d.get("kind") == "container-image":
            items += d["items"]
    images = {}
    for it in items:
        e = images.setdefault(it["image"], dict(it, clusters=set(), exposed=False, prod=False))
        e["clusters"].add(it["cluster"])
        e["exposed"] |= it["exposed"]
        e["prod"] |= it.get("prod", False)
    results = {}
    with cf.ThreadPoolExecutor(max_workers=4) as pool:
        for ref, rep, note in pool.map(scan_image, images.values()):
            results[ref] = rep
            if rep is None:
                c.gap(f"image:{ref}", note)
            else:
                c.ok(f"image:{ref}")
                images[ref]["sbom"] = note
    repos = {}
    for path, rep, note in map(scan_repo, cfg.get("repos", [])):
        repos[path] = rep
        (c.ok if rep is not None else (lambda a: c.gap(a, note)))(f"repo:{path}")
    # ---- match + prioritize ------------------------------------------------------------------------------
    now = time.time()
    oldest_fixable_crit = 0
    counts = {"critical": 0, "high": 0, "kev": 0}
    evidence = {}

    def handle(asset, meta, rep):
        nonlocal oldest_fixable_crit
        high_fixable = []
        for target, v in vulns(rep):
            cve, sev = v["VulnerabilityID"], v.get("Severity", "UNKNOWN").lower()
            in_kev = cve in kev
            ep = epss.get(cve)
            fixed = v.get("FixedVersion") or ""
            pub = v.get("PublishedDate") or ""
            if sev == "critical":
                counts["critical"] += 1
            elif sev == "high":
                counts["high"] += 1
            if in_kev:
                counts["kev"] += 1
            if sev == "critical" and fixed and pub:
                age = (now - time.mktime(time.strptime(pub[:10], "%Y-%m-%d"))) / 86400
                oldest_fixable_crit = max(oldest_fixable_crit, age)
            attrs = dict(cve=cve, package=v.get("PkgName"), installed=v.get("InstalledVersion"), fixed=fixed,
                         cvss=score(v), base_severity=sev, published_at=pub[:10], kev=in_kev,
                         kev_added=(kev.get(cve) or {}).get("date_added"), epss=ep,
                         exposed=meta.get("exposed", False), prod=meta.get("prod", False),
                         clusters=sorted(meta.get("clusters", [])), target=target)
            if in_kev or sev == "critical":
                if in_kev:
                    prio = "critical" if attrs["exposed"] else "high"
                else:
                    prio = "critical" if (attrs["exposed"] and fixed) else "high"
                if ep is not None and ep >= 0.5:
                    prio = bump(prio)
                if not attrs["prod"] and prio == "critical" and not in_kev:
                    prio = "high"
                ev_key = f"{asset}|{cve}"
                evidence[ev_key] = attrs
                c.finding("supply-chain", asset, f"vuln.{cve.lower()}",
                          f"{cve} in {v.get('PkgName')} {v.get('InstalledVersion')}"
                          + (f" (fix {fixed})" if fixed else " (no fix yet)") + (" [KEV]" if in_kev else ""),
                          prio, f"raw/vuln-intel/matches.json#{ev_key}",
                          f"update {v.get('PkgName')} to {fixed}" if fixed else "mitigate (reduce exposure) / watch for a fix",
                          kind="vulnerability", refs=[cve], **attrs)
            elif sev == "high" and fixed:
                high_fixable.append(cve)
        if high_fixable:
            c.finding("supply-chain", asset, "vuln.high_fixable_aggregate",
                      f"{len(set(high_fixable))} HIGH CVEs with available fixes", "medium" if meta.get("exposed") else "low",
                      f"raw/vuln-intel/high-aggregate.json#{asset}", "rebuild on a patched base / bump dependencies",
                      kind="vulnerability", count=len(set(high_fixable)))
            evidence.setdefault("_high", {})[asset] = sorted(set(high_fixable))

    for ref, meta in images.items():
        if results.get(ref):
            handle(f"image:{ref}", {k: v for k, v in meta.items() if k in ("exposed", "prod", "clusters")}, results[ref])
    for path, rep in repos.items():
        if rep:
            handle(f"repo:{os.path.basename(path.rstrip('/'))}", {"exposed": False, "prod": True, "clusters": []}, rep)
    high = evidence.pop("_high", {})
    c.raw("matches.json", evidence)
    c.raw("high-aggregate.json", high)
    c.raw("images.json", {k: dict(v, clusters=sorted(v["clusters"])) for k, v in images.items()})
    c.metric("security_vuln_oldest_fixable_critical_days", round(oldest_fixable_crit, 1),
             "Age (since publication) of the oldest CRITICAL CVE with a fix, in running images/repos")
    c.metric("security_vuln_matches", counts["critical"], "Vulnerability matches", severity="critical")
    c.metric("security_vuln_matches", counts["high"], "Vulnerability matches", severity="high")
    c.metric("security_vuln_kev_matches", counts["kev"], "Matches that are in CISA KEV")
    c.metric("security_sbom_images", sum(1 for r in results.values() if r), "Images with an SBOM")
    c.write()


if __name__ == "__main__":
    main()
