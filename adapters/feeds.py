"""intel feed adapters: public vulnerability intelligence, cached, read-only.

  load(cfg, cache_dir) -> dict   (feed-specific index, e.g. {cve: {...}})

Implemented: cisa-kev (known exploited, JSON), epss (exploit probability, daily CSV), osv (OSV.dev per-ecosystem
export `all.zip`, e.g. Go / PyPI / npm: an independent second matcher next to Trivy's DB, with publication dates).
Every download is a conditional GET (ETag / Last-Modified kept next to the cache): an unchanged feed costs one 304.
`max_age_hours` (default 24) is how long a cached copy is used without asking at all.
Structured matching of distro packages is done by Trivy's DB (GHSA/OSV/NVD/distro advisories), wrapped by the
vuln-intel collector. Future adapters (interface only): nvd (CVSS details), vendor advisories (Kubernetes, Go, PostgreSQL, Ubuntu USN, Apple,
router vendors) - unstructured ones go through the AI advisor for EXTRACTION only, then human/deterministic
validation before they become matching rules (docs/design.md section 11).
Privacy: whole feeds are downloaded; our CVE list is never sent to a third party.
"""
import csv
import gzip
import io
import json
import os
import time
import urllib.error
import urllib.request
import zipfile

VERSION = "0.2.0"
SOURCES = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "osv": "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
}
STATS = {"downloads": 0, "not_modified": 0}


def fetch(url, path, max_age_h, timeout=300):
    """Cached conditional GET. -> (path, fetched_at). `fetched_at` = when the copy was last confirmed current."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mp = path + ".meta.json"
    meta = json.load(open(mp)) if os.path.exists(mp) and os.path.exists(path) else {}
    if meta and time.time() - meta.get("checked_at", 0) < max_age_h * 3600:
        return path, meta["checked_at"]
    req = urllib.request.Request(url, headers={"User-Agent": f"security-platform-feeds/{VERSION}"})
    if meta.get("etag"):
        req.add_header("If-None-Match", meta["etag"])
    if meta.get("last_modified"):
        req.add_header("If-Modified-Since", meta["last_modified"])
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read()
            meta = {"etag": r.headers.get("ETag"), "last_modified": r.headers.get("Last-Modified"), "url": url}
        with open(path + ".tmp", "wb") as f:
            f.write(data)
        os.replace(path + ".tmp", path)
        STATS["downloads"] += 1
    except urllib.error.HTTPError as e:
        if e.code != 304:
            raise
        STATS["not_modified"] += 1
    meta["checked_at"] = time.time()
    with open(mp + ".tmp", "w") as f:
        json.dump(meta, f)
    os.replace(mp + ".tmp", mp)
    return path, meta["checked_at"]


def _fetch(name, cache_dir, max_age_h):
    return fetch(SOURCES[name], os.path.join(cache_dir, os.path.basename(SOURCES[name])), max_age_h)


def kev(cfg, cache_dir):
    p, mt = _fetch("cisa-kev", cache_dir, cfg.get("max_age_hours", 24))
    d = json.load(open(p))
    return {"fetched_at": mt, "version": d.get("catalogVersion"),
            "index": {v["cveID"]: {"date_added": v["dateAdded"], "ransomware": v.get("knownRansomwareCampaignUse")}
                      for v in d["vulnerabilities"]}}


def epss(cfg, cache_dir):
    p, mt = _fetch("epss", cache_dir, cfg.get("max_age_hours", 24))
    raw = gzip.decompress(open(p, "rb").read()).decode()
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    idx = {r["cve"]: float(r["epss"]) for r in csv.DictReader(io.StringIO("\n".join(lines)))}
    return {"fetched_at": mt, "version": raw.splitlines()[0][:80], "index": idx}


def osv(cfg, cache_dir):
    """{ecosystems: [Go, PyPI, ...]} -> index {ecosystem: {package: [compact advisory]}}."""
    idx, fetched, versions = {}, [], []
    for eco in cfg.get("ecosystems", ["Go"]):
        p, mt = fetch(SOURCES["osv"].format(ecosystem=eco), os.path.join(cache_dir, "osv", eco, "all.zip"),
                      cfg.get("max_age_hours", 24))
        fetched.append(mt)
        pk = idx.setdefault(eco, {})
        with zipfile.ZipFile(p) as z:
            for n in z.namelist():
                v = json.loads(z.read(n))
                if v.get("withdrawn"):
                    continue
                sev = ((v.get("database_specific") or {}).get("severity") or "").lower()
                for a in v.get("affected") or []:
                    pkg = (a.get("package") or {})
                    if pkg.get("ecosystem", "").split(":")[0] != eco:
                        continue
                    pk.setdefault(pkg.get("name"), []).append({
                        "id": v["id"], "aliases": v.get("aliases") or [], "published": v.get("published", ""),
                        "modified": v.get("modified", ""), "severity": sev, "summary": (v.get("summary") or "")[:160],
                        "ranges": [{"type": r.get("type"), "events": r.get("events", [])} for r in a.get("ranges") or []],
                        "versions": a.get("versions") or []})
        versions.append(f"{eco}:{len(pk)} packages")
    return {"fetched_at": min(fetched) if fetched else time.time(), "version": ", ".join(versions), "index": idx}


def _future(cfg, cache_dir):
    raise NotImplementedError(f"feed {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"cisa-kev": kev, "epss": epss, "osv": osv, "nvd": _future, "vendor": _future}


def load(cfg, cache_dir):
    return ADAPTERS[cfg["type"]](cfg, cache_dir)
