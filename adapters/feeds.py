"""intel feed adapters: public vulnerability intelligence, cached, read-only.

  load(cfg, cache_dir) -> dict   (feed-specific index, e.g. {cve: {...}})

Implemented: cisa-kev (known exploited, JSON), epss (exploit probability, daily CSV).
Structured matching (package/version ranges from GHSA, OSV, NVD and distro advisories) is done by Trivy's DB,
wrapped by the vuln-intel collector. Future adapters (interface only): osv (direct API/ZIP export for
non-Trivy inventories), nvd (CVSS details), vendor advisories (Kubernetes, Go, PostgreSQL, Ubuntu USN, Apple,
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
import urllib.request

VERSION = "0.1.0"
SOURCES = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}


def _fetch(name, cache_dir, max_age_h):
    os.makedirs(cache_dir, exist_ok=True)
    p = os.path.join(cache_dir, os.path.basename(SOURCES[name]))
    if not os.path.exists(p) or time.time() - os.path.getmtime(p) > max_age_h * 3600:
        req = urllib.request.Request(SOURCES[name], headers={"User-Agent": "security-platform/0.1"})
        data = urllib.request.urlopen(req, timeout=120).read()
        with open(p + ".tmp", "wb") as f:
            f.write(data)
        os.replace(p + ".tmp", p)
    return p, os.path.getmtime(p)


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


def _future(cfg, cache_dir):
    raise NotImplementedError(f"feed {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"cisa-kev": kev, "epss": epss, "osv": _future, "nvd": _future, "vendor": _future}


def load(cfg, cache_dir):
    return ADAPTERS[cfg["type"]](cfg, cache_dir)
