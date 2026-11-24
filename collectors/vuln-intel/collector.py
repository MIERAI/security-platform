#!/usr/bin/env python3
"""Collector `vuln-intel`: SBOM inventory x vulnerability intelligence -> prioritized findings. READ-ONLY.

Inputs (contracts, not other collectors' code):
  * inventory/v1 files in SP_INPUT_DIR (the runner's latest/) or the run dir (e.g. inventory.k8s-images.json)
  * instance config `intel: {feeds: [...], repos: [...], update_db: bool, sbom_max_age_days: 30,
                             registry_auth: [{host, username, token_file}]}`
Steps: SBOM per image (trivy, CycloneDX, cached by digest) -> deterministic match against Trivy's DB
(GHSA/OSV/NVD/distro advisories) -> enrich with CISA KEV + EPSS feeds -> priority = intel x our exposure.
Registry credentials for private images: a READ-ONLY token in a 0600 file (intel.registry_auth) or the env
SP_REGISTRY_USER / SP_REGISTRY_TOKEN; never logged. Without one, private images are coverage gaps (cached SBOMs of
already-seen digests are still matched).
Alerting attribute: `alertable` = affects our assets AND (in KEV OR (critical AND exposed)); the generated alert
rules page only on those, everything else goes to the weekly digest.
OSV (feed type osv): SBOM components are also matched directly against the OSV export (second, independent matcher,
with the advisory's publication date for time-to-know); findings only for KEV aliases or critical advisories.
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
sys.path[:0] = [HERE, os.path.join(ROOT, "sdk"), ROOT]
import osvmatch  # noqa: E402
import spsdk  # noqa: E402
from adapters import feeds  # noqa: E402
from adapters.sinks import read_secret_file  # noqa: E402

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


REG_AUTH = {}   # host -> (user, token); filled from the instance, never printed


def registry_env(ref):
    for host, (user, token) in REG_AUTH.items():
        if ref.startswith(host + "/"):
            return {"TRIVY_USERNAME": user, "TRIVY_PASSWORD": token}
    if os.environ.get("SP_REGISTRY_TOKEN") and ref.startswith(os.environ.get("SP_REGISTRY_HOST", "ghcr.io")):
        return {"TRIVY_USERNAME": os.environ.get("SP_REGISTRY_USER", ""), "TRIVY_PASSWORD": os.environ["SP_REGISTRY_TOKEN"]}
    return {}


SBOM_MAX_AGE_D = 30


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
    env = registry_env(ref)
    stale = os.path.exists(sbom) and time.time() - os.path.getmtime(sbom) > SBOM_MAX_AGE_D * 86400
    if not os.path.exists(sbom) or stale:
        rc, out, err = trivy(["image", "--image-src", "remote", "--format", "cyclonedx", "--skip-db-update",
                              "--output", sbom + ".tmp", ref_scan], env)
        if rc != 0:
            if not stale:   # a stale SBOM of the same digest is still matched; only a missing one is a gap
                hint = " (private image: no registry credential configured - coverage gap)" if not env and \
                    ("UNAUTHORIZED" in err or "unauthorized" in err or "DENIED" in err) else ""
                return ref, None, f"sbom rc={rc}{hint}: {err.strip()[-120:]}"
            if os.path.exists(sbom + ".tmp"):
                os.remove(sbom + ".tmp")
        else:
            os.replace(sbom + ".tmp", sbom)
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
    global SBOM_MAX_AGE_D
    inst = spsdk.load_instance()
    cfg = inst.get("intel", {})
    c = spsdk.Collector("vuln-intel", VERSION)
    SBOM_MAX_AGE_D = float(cfg.get("sbom_max_age_days", 30))
    for ra in cfg.get("registry_auth") or []:
        try:
            REG_AUTH[ra["host"]] = (ra.get("username", ""), read_secret_file(ra["token_file"]))
            c.ok(f"registry-auth:{ra['host']}")
        except (OSError, PermissionError) as e:
            c.gap(f"registry-auth:{ra['host']}", f"read-only registry credential unavailable ({type(e).__name__}): "
                  "private images not refreshed - create a read-only token file (see docs/runner.md)")
    if cfg.get("update_db"):
        rc, _, err = trivy(["image", "--download-db-only"], timeout=1800)
        (c.ok if rc == 0 else (lambda a: c.gap(a, f"trivy DB update rc={rc}: {err.strip()[-160:]}")))("feed:trivy-db")
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
        db_at = (tv.get("VulnerabilityDB") or {}).get("UpdatedAt", "")
        if db_at:
            c.metric("security_intel_feed_age_seconds", int(time.time() - time.mktime(time.strptime(db_at[:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone),
                     "Age of the cached intel feed", feed="trivy-db")
    # ---- inventory (contract inventory/v1) -> unique images ---------------------------------------------
    items = []
    for p in glob.glob(os.path.join(os.environ.get("SP_INPUT_DIR") or c.out, "inventory.*.json")):
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
                         clusters=sorted(meta.get("clusters", [])), target=target, matcher="trivy")
            attrs["alertable"] = bool(in_kev or (sev == "critical" and attrs["exposed"]))
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
    # ---- OSV: second matcher over the same SBOMs ------------------------------------------------------------
    osv_idx = intel.get("osv", {}).get("index", {})
    osv_hits = 0
    if osv_idx:
        for ref, meta in images.items():
            if not meta.get("sbom"):
                continue
            try:
                cdx = json.load(open(os.path.join(DATA, meta["sbom"])))
            except (OSError, ValueError):
                continue
            for eco, name, ver, adv in osvmatch.match(osvmatch.components(cdx), osv_idx):
                osv_hits += 1
                cves = [a for a in adv["aliases"] if a.startswith("CVE-")]
                in_kev = any(x in kev for x in cves)
                if not (in_kev or adv["severity"] == "critical"):
                    continue
                vid = cves[0] if cves else adv["id"]
                asset = f"image:{ref}"
                exposed = meta.get("exposed", False)
                prio = ("critical" if exposed else "high")
                fixed = osvmatch.fixed_version(adv)
                attrs = dict(cve=vid, osv_id=adv["id"], package=name, installed=ver, fixed=fixed, base_severity=adv["severity"] or "unknown",
                             published_at=adv["published"][:10], kev=in_kev,
                             kev_added=next(((kev.get(x) or {}).get("date_added") for x in cves if x in kev), None),
                             epss=max([epss.get(x) or 0 for x in cves] or [0]) or None, exposed=exposed, prod=meta.get("prod", False),
                             clusters=sorted(meta.get("clusters", [])), target=eco, matcher="osv")
                attrs["alertable"] = bool(in_kev or (adv["severity"] == "critical" and exposed))
                evidence[f"{asset}|{vid}"] = attrs
                c.finding("supply-chain", asset, f"vuln.{vid.lower()}",
                          f"{vid} in {name} {ver}" + (f" (fix {fixed})" if fixed else " (no fix yet)") + (" [KEV]" if in_kev else "") + " [OSV]",
                          prio, f"raw/vuln-intel/matches.json#{asset}|{vid}",
                          f"update {name} to {fixed}" if fixed else "mitigate (reduce exposure) / watch for a fix",
                          kind="vulnerability", refs=[vid, adv["id"]], **attrs)
        c.metric("security_vuln_osv_matches", osv_hits, "Component x advisory matches found by the OSV matcher")
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
    c.metric("security_vuln_alertable_matches", sum(1 for f in c.findings if (f.get("attributes") or {}).get("alertable")),
             "Matches that affect our assets AND (KEV OR critical+exposed): the only class that pages")
    c.write()


if __name__ == "__main__":
    main()
