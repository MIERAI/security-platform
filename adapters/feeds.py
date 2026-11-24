"""intel feed adapters: public vulnerability intelligence, cached, read-only.

  load(cfg, cache_dir) -> dict   (feed-specific index, e.g. {cve: {...}})

Implemented: cisa-kev (known exploited, JSON), epss (exploit probability, daily CSV), osv (OSV.dev per-ecosystem
export `all.zip`, e.g. Go / PyPI / npm: an independent second matcher next to Trivy's DB, with publication dates).
Platform advisories (structured or deterministically parsed; used by vuln-intel's host matcher):
  android-bulletins   Android Security Bulletins via the OSV `Android` export (per-entry security patch level `spl`)
  apple-security-releases  Apple's security releases index (release name, date, page); CVE ids of a release are read
                      from its page by regex, on demand (`apple_release_cves`)
  msrc-cvrf           Microsoft Security Response Center CVRF API: the last N monthly documents (product, fixed build,
                      KB, exploited flag)
  vendor-advisories   unstructured vendor pages (router / firmware vendors): only headline lines are extracted
                      (deterministic regex); they are CANDIDATES for a human or a deterministic check, never a verdict
Every download is a conditional GET (ETag / Last-Modified kept next to the cache): an unchanged feed costs one 304.
`max_age_hours` (default 24) is how long a cached copy is used without asking at all.
Structured matching of distro packages is done by Trivy's DB (GHSA/OSV/NVD/distro advisories), wrapped by the
vuln-intel collector. Future adapters (interface only): nvd (CVSS details), vendor advisories (Kubernetes, Go, PostgreSQL, Ubuntu USN, Apple,
router vendors) - unstructured ones go through the AI advisor for EXTRACTION only, then human/deterministic
validation before they become matching rules (docs/design.md section 11).
Privacy: whole feeds are downloaded; our CVE list is never sent to a third party.
"""
import csv
import hashlib
import re
import gzip
import io
import json
import os
import time
import urllib.error
import urllib.request
import zipfile

VERSION = "0.3.0"
SOURCES = {
    "cisa-kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "osv": "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip",
    "android-bulletins": "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip",
    "apple-security-releases": "https://support.apple.com/en-us/100100",
    "msrc-updates": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "msrc-cvrf": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}",
}
STATS = {"downloads": 0, "not_modified": 0}


def fetch(url, path, max_age_h, timeout=300, headers=None):
    """Cached conditional GET. -> (path, fetched_at). `fetched_at` = when the copy was last confirmed current."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mp = path + ".meta.json"
    meta = json.load(open(mp)) if os.path.exists(mp) and os.path.exists(path) else {}
    if meta and time.time() - meta.get("checked_at", 0) < max_age_h * 3600:
        return path, meta["checked_at"]
    req = urllib.request.Request(url, headers=dict({"User-Agent": f"security-platform-feeds/{VERSION}"}, **(headers or {})))
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
            "index": {v["cveID"]: {"date_added": v["dateAdded"], "ransomware": v.get("knownRansomwareCampaignUse"),
                                   "vendor": v.get("vendorProject"), "product": v.get("product")}
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


def android_bulletins(cfg, cache_dir):
    """-> index: [{id, aliases, spl, severity, versions, component}] (withdrawn and device-family-specific excluded)."""
    p, mt = fetch(SOURCES["android-bulletins"], os.path.join(cache_dir, "android", "all.zip"), cfg.get("max_age_hours", 24))
    out = []
    with zipfile.ZipFile(p) as z:
        for n in z.namelist():
            v = json.loads(z.read(n))
            if v.get("withdrawn"):
                continue
            for a in v.get("affected") or []:
                es = a.get("ecosystem_specific") or {}
                vers = a.get("versions") or []
                if not es.get("spl") or any("specific" in x.lower() for x in vers):
                    continue
                out.append({"id": v["id"], "aliases": v.get("aliases") or [], "spl": es["spl"][:10],
                            "severity": (es.get("severity") or "").lower(), "versions": vers,
                            "component": (a.get("package") or {}).get("name", "")})
    return {"fetched_at": mt, "version": f"{len(out)} entries", "index": out}


def _text(html):
    html = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    return re.sub(r"[ \t]+", " ", re.sub(r"(?s)<[^>]+>", "\n", html))


def apple_security_releases(cfg, cache_dir):
    """Apple's security releases table -> index: [{name, product, version, date, url}] (deterministic HTML parse)."""
    p, mt = fetch(SOURCES["apple-security-releases"], os.path.join(cache_dir, "apple", "index.html"), cfg.get("max_age_hours", 24))
    html = open(p, encoding="utf-8", errors="replace").read()
    rows = []
    for r in re.findall(r"(?s)<tr>(.*?)</tr>", html):
        cells = re.findall(r"(?s)<td[^>]*>(.*?)</td>", r)
        if len(cells) < 3:
            continue
        name = re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", cells[0])).strip()
        date = re.sub(r"(?s)<[^>]+>", "", cells[2]).strip()
        url = (re.findall(r'href="([^"]+)"', cells[0]) or [None])[0]
        m = re.match(r"(macOS|iOS|iPadOS|watchOS|tvOS|visionOS|Safari|Xcode)\b(?:\s+[A-Za-z][A-Za-z ]*?)?\s+(\d+(?:\.\d+)*)", name)
        try:
            d = time.strftime("%Y-%m-%d", time.strptime(date, "%d %b %Y"))
        except ValueError:
            continue
        rows.append({"name": name.split("This update")[0].strip()[:120], "product": m.group(1) if m else "",
                     "version": m.group(2) if m else "", "date": d, "url": url})
    if not rows:
        raise ValueError("apple security releases: no rows parsed (page layout changed?)")
    return {"fetched_at": mt, "version": f"{len(rows)} releases", "index": rows}


def apple_release_cves(url, cache_dir, max_age_h=168):
    """CVE ids listed on one Apple security release page (regex; cached a week)."""
    key = hashlib.sha1(url.encode()).hexdigest()[:16]
    p, _ = fetch(url, os.path.join(cache_dir, "apple", f"release-{key}.html"), max_age_h)
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", open(p, encoding="utf-8", errors="replace").read())))


def msrc_cvrf(cfg, cache_dir):
    """The last `months` (default 3) MSRC CVRF documents -> index: {releases: [{id, date}],
    products: {product name: [{release, cve, fixed_build, kb, exploited, severity}]}}."""
    h = {"Accept": "application/json"}
    p, mt = fetch(SOURCES["msrc-updates"], os.path.join(cache_dir, "msrc", "updates.json"), cfg.get("max_age_hours", 24), headers=h)
    ups = sorted(json.load(open(p))["value"], key=lambda x: x["InitialReleaseDate"])[-int(cfg.get("months", 3)):]
    products, releases = {}, []
    for u in ups:
        dp, _ = fetch(SOURCES["msrc-cvrf"].format(id=u["ID"]), os.path.join(cache_dir, "msrc", f"{u['ID']}.json"),
                      cfg.get("max_age_hours", 24), headers=h)
        d = json.load(open(dp))
        names = {x["ProductID"]: x["Value"] for x in d["ProductTree"].get("FullProductName") or []}
        releases.append({"id": u["ID"], "date": u["InitialReleaseDate"][:10]})
        for v in d.get("Vulnerability") or []:
            threats = " ".join((t.get("Description") or {}).get("Value", "") for t in v.get("Threats") or [] if t.get("Type") == 1)
            sev = next(((t.get("Description") or {}).get("Value", "").lower() for t in v.get("Threats") or [] if t.get("Type") == 3), "")
            for r in v.get("Remediations") or []:
                if not r.get("FixedBuild"):
                    continue
                kb = (r.get("Description") or {}).get("Value", "")
                for pid in r.get("ProductID") or []:
                    if pid in names:
                        products.setdefault(names[pid], []).append(
                            {"release": u["ID"], "date": u["InitialReleaseDate"][:10], "cve": v.get("CVE"),
                             "fixed_build": r["FixedBuild"], "kb": kb, "exploited": "Exploited:Yes" in threats, "severity": sev})
    return {"fetched_at": mt, "version": ", ".join(r["id"] for r in releases), "index": {"releases": releases, "products": products}}


def vendor_advisories(cfg, cache_dir):
    """Unstructured vendor pages -> candidate headlines. cfg: {sources: [{name, url, item_regex?, max_age_hours?}]}.
    index: {source name: [{id, text, date?, url}]}; errors: {source name: reason} (a source that cannot be read
    deterministically - bot challenge, JavaScript-only page - is an error, never silently "no advisories").
    Extraction only (regex); never a verdict. Bot protection is respected, never circumvented."""
    idx, fetched, errors = {}, [], {}
    for src in cfg.get("sources") or []:
        key = hashlib.sha1(src["url"].encode()).hexdigest()[:12]
        try:
            p, mt = fetch(src["url"], os.path.join(cache_dir, "vendor", f"{key}.html"),
                          src.get("max_age_hours", cfg.get("max_age_hours", 24)),
                          headers={"User-Agent": "Mozilla/5.0 (compatible; security-platform-feeds)"})
        except Exception as e:  # noqa: BLE001
            errors[src["name"]] = f"{type(e).__name__}: {str(e)[:120]}"
            continue
        fetched.append(mt)
        text = _text(open(p, encoding="utf-8", errors="replace").read())
        rx = re.compile(src.get("item_regex") or r"(CVE-\d{4}-\d+|[Ss]ecurity [Aa]dvisor|安全公告)")
        items, seen = [], set()
        for line in text.splitlines():
            line = line.strip()
            if 12 <= len(line) <= 300 and rx.search(line) and line not in seen:
                seen.add(line)
                dm = re.search(r"(\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2,8}\.? \d{1,2}, \d{4})", line)
                items.append({"id": hashlib.sha1(f"{src['name']}|{line}".encode()).hexdigest()[:10], "text": line,
                              "date": dm.group(1) if dm else None, "url": src["url"]})
        if not items:
            why = "bot challenge (not circumvented)" if re.search(r"(?i)not a bot|proof of work|captcha", text) else \
                "no advisory lines parsed (JavaScript-rendered page or layout change)"
            errors[src["name"]] = why
            continue
        idx[src["name"]] = items
    return {"fetched_at": min(fetched) if fetched else time.time(), "version": f"{sum(map(len, idx.values()))} items",
            "index": idx, "errors": errors}


def _future(cfg, cache_dir):
    raise NotImplementedError(f"feed {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"cisa-kev": kev, "epss": epss, "osv": osv, "android-bulletins": android_bulletins,
            "apple-security-releases": apple_security_releases, "msrc-cvrf": msrc_cvrf, "vendor-advisories": vendor_advisories,
            "nvd": _future, "vendor": _future}


def load(cfg, cache_dir):
    return ADAPTERS[cfg["type"]](cfg, cache_dir)
