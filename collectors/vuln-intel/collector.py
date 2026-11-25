#!/usr/bin/env python3
"""Collector `vuln-intel`: SBOM inventory x vulnerability intelligence -> prioritized findings. READ-ONLY.

Inputs (contracts, not other collectors' code):
  * inventory/v1 files in SP_INPUT_DIR (the runner's latest/) or the run dir (e.g. inventory.k8s-images.json)
  * instance config `intel: {feeds: [...], repos: [...], update_db: bool, sbom_max_age_days: 30,
                             registry_auth: [{host, username, token_file}]}`
Steps: SBOM per image (trivy, CycloneDX, cached by digest) -> deterministic match against Trivy's DB
(GHSA/OSV/NVD/distro advisories) -> enrich with CISA KEV + EPSS feeds -> priority = intel x our exposure.
Retired images: when every container-image inventory is complete (`complete: true`), the run declares the coverage
entry `inventory:container-image` with `complete_scope: "image:"`; the ledger then closes findings of images that are
no longer running (fixed, `asset_retired`). A partial inventory (a cluster failed) retires nothing.
Registry credentials for private images: a READ-ONLY token in a 0600 file (intel.registry_auth) or the env
SP_REGISTRY_USER / SP_REGISTRY_TOKEN; never logged. Without one, private images are coverage gaps (cached SBOMs of
already-seen digests are still matched).
Alerting attribute: `alertable` = affects our assets AND (in KEV OR (critical AND exposed)); the generated alert
rules page only on those, everything else goes to the weekly digest.
OSV (feed type osv): SBOM components are also matched directly against the OSV export (second, independent matcher,
with the advisory's publication date for time-to-know); findings only for KEV aliases or critical advisories.

Hosts (inventory host-package / host-platform, e.g. from the host-sbom collector):
  * distro packages (deb/apk/rpm) -> CycloneDX -> Trivy's DB (Ubuntu USN / Debian security tracker / Alpine secdb):
    same priority rules as images; the kernel is matched separately (only the RUNNING kernel counts; packages of
    other installed kernels are clean-up, not exposure) and aggregated into one finding per host;
  * language packages / Go binaries under `sbom_paths` (fs SBOM) -> Trivy + OSV;
  * platform advisories, one finding per missed release (so time-to-know is measured per advisory):
    Android Security Bulletins (patch level), Apple security releases (same major line), MSRC monthly updates
    (OS build), plus KEV entries of the firmware vendor added after the firmware build;
  * unstructured vendor advisories (feed vendor-advisories): new headlines become CANDIDATES (needs_human) for the
    hosts whose `firmware.vendor` matches the source's `vendors`; a human records the verdict in
    <data>/advisory-reviews.yaml ({id: {verdict: affected|not-affected|not-applicable, by, at}}). Neither this
    collector nor any advisor ever concludes "not affected"; the advisor (intel.advisor) may only add extracted
    candidates to the evidence, logged in decisions/.
  * ecosystems without a structured advisory source (termux, brew formulae, opkg, windows-program) are inventoried
    and counted (security_sbom_unmatched_packages), never reported as "no vulnerabilities".
"""
import concurrent.futures as cf
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [HERE, os.path.join(ROOT, "sdk"), ROOT]
import hostmatch  # noqa: E402
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


def code_repos(cfg, c):
    """The code host's repositories of an owner (contract: their default branch HEAD) -> {asset: (sbom relpath, sha)}.
    API use is minimal: ONE listing call per `list_max_age_hours` (default 24, cached); HEADs come from
    `git ls-remote` (git protocol, no API quota); a shallow clone + SBOM (trivy fs, CycloneDX) only when the HEAD
    changed (cached by commit). Credentials: the code host CLI's token for `gh_user`, passed to git in the
    environment (never on a command line, never logged). cfg: {type: github, owner, gh_user?, include_forks: false,
    include_archived: false, exclude: [names]}"""
    owner = cfg["owner"]
    base = os.path.join(DATA, "cache", "repos", owner)
    os.makedirs(base, exist_ok=True)
    lp = os.path.join(base, "list.json")
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    tok = ""
    if cfg.get("gh_user") or cfg.get("token_file"):
        if cfg.get("token_file"):
            tok = read_secret_file(cfg["token_file"])
        else:
            r = subprocess.run(["gh", "auth", "token", "--user", cfg["gh_user"]], capture_output=True, text=True, timeout=30)
            tok = r.stdout.strip() if r.returncode == 0 else ""
    if tok:
        import base64
        env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="http.https://github.com/.extraheader",
                   GIT_CONFIG_VALUE_0="AUTHORIZATION: basic " + base64.b64encode(f"x-access-token:{tok}".encode()).decode())
    fresh = os.path.exists(lp) and time.time() - os.path.getmtime(lp) < float(cfg.get("list_max_age_hours", 24)) * 3600
    if not fresh:
        genv = dict(os.environ, **({"GH_TOKEN": tok} if tok else {}))
        r = subprocess.run(["gh", "repo", "list", owner, "--limit", "1000", "--json", "name,isArchived,isFork,isPrivate,url"],
                           capture_output=True, text=True, timeout=120, env=genv)
        if r.returncode == 0:
            with open(lp + ".tmp", "w") as f:
                f.write(r.stdout)
            os.replace(lp + ".tmp", lp)
        elif not os.path.exists(lp):
            c.gap(f"codehost:github/{owner}/repos", f"repository listing failed: {r.stderr.strip()[-160:]}")
            return {}
    repos = [x for x in json.load(open(lp)) if (cfg.get("include_forks") or not x["isFork"])
             and (cfg.get("include_archived") or not x["isArchived"]) and x["name"] not in (cfg.get("exclude") or [])]
    c.metric("security_sbom_repos_in_scope", len(repos), "Code-host repositories in scope of dependency matching")
    out = {}
    for x in repos:
        asset = f"repo:github/{owner}/{x['name']}"
        url = x["url"] + ".git"
        r = subprocess.run(["git", "ls-remote", url, "HEAD"], capture_output=True, text=True, timeout=60, env=env)
        sha = (r.stdout.split() or [""])[0]
        if r.returncode != 0 or not sha:
            c.gap(asset, f"ls-remote failed: {r.stderr.strip()[-120:]}")
            continue
        sbom = os.path.join(DATA, "sbom", f"repo-{owner}-{x['name']}-{sha[:12]}.cdx.json")
        if not os.path.exists(sbom):
            wd = os.path.join(base, x["name"])
            shutil.rmtree(wd, ignore_errors=True)
            r = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--no-tags", url, wd], capture_output=True, text=True,
                               timeout=600, env=env)
            if r.returncode != 0:
                c.gap(asset, f"clone failed: {r.stderr.strip()[-120:]}")
                continue
            rc, sout, err = trivy(["fs", "--format", "cyclonedx", "--skip-db-update", "--scanners", "vuln", "--output", sbom + ".tmp", wd])
            shutil.rmtree(wd, ignore_errors=True)
            if rc != 0:
                c.gap(asset, f"sbom rc={rc}: {err.strip()[-120:]}")
                continue
            os.replace(sbom + ".tmp", sbom)
            for old in glob.glob(os.path.join(DATA, "sbom", f"repo-{owner}-{x['name']}-*.cdx.json")):
                if old != sbom:
                    os.remove(old)
        out[asset] = (os.path.relpath(sbom, DATA), sha)
    return out


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


def _date(s):
    for fmt in ("%Y-%m-%d", "%B %d, %Y", "%b %d, %Y", "%b. %d, %Y"):
        try:
            return time.strftime("%Y-%m-%d", time.strptime(s, fmt))
        except (TypeError, ValueError):
            pass
    return None


def vendor_state(feed, fcfg, c):
    """First sighting of each headline, kept in <data>/state/vendor-advisories.json. The first read of a source is a
    baseline (old headlines are not "new"), except headlines dated within `recent_days` (default 180). Optional
    advisor: may only EXTRACT candidates (package / version range) from a new headline into the evidence."""
    p = os.path.join(DATA, "state", "vendor-advisories.json")
    st = json.load(open(p)) if os.path.exists(p) else {}
    now = spsdk.now_iso()
    recent = time.strftime("%Y-%m-%d", time.gmtime(time.time() - float(fcfg.get("recent_days", 180)) * 86400))
    new = {}
    for src, items in feed["index"].items():
        first_read = src not in st
        seen = st.setdefault(src, {})
        for it in items:
            if it["id"] not in seen:
                d = _date(it.get("date"))
                seen[it["id"]] = {"first_seen": now, "baseline": first_read and not (d and d >= recent), "text": it["text"][:200]}
            rec = seen[it["id"]]
            if not rec["baseline"]:
                new.setdefault(src, []).append(dict(it, first_seen=rec["first_seen"]))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p + ".tmp", "w") as f:
        json.dump(st, f, indent=1, ensure_ascii=False)
    os.replace(p + ".tmp", p)
    feed["new"], feed["sources_cfg"] = new, fcfg.get("sources") or []
    for src, why in (feed.get("errors") or {}).items():
        c.metric("security_intel_source_unreadable", 1, "Vendor advisory source that cannot be read deterministically", feed=src)
    adv_cfg = fcfg.get("advisor")
    if adv_cfg and new:
        sys.path.insert(0, os.path.join(ROOT, "core"))
        import advisor as adv  # noqa: E402
        a = adv.advisor(adv_cfg)
        for src, items in new.items():
            for it in items:
                ctx = {"headline": it["text"], "url": it["url"]}
                prop = a.advise("extract-advisory-candidates", ctx)
                adv.log_decision(DATA, "extract-advisory-candidates", ctx, prop, getattr(a, "model", "?"))
                if prop:
                    it["advisor_candidates"] = prop   # evidence only; never changes severity or status


def image_inventory(paths):
    """inventory/v1 container-image files -> (items, complete, reasons it is partial). Complete = at least one file
    and EVERY file says `complete: true` (its producer listed all of its sources); a file without the field (an older
    producer) or with a failed source makes the whole image inventory partial."""
    items, n, partial = [], 0, []
    for p in sorted(paths):
        with open(p) as f:
            d = json.load(f)
        if d.get("schema") == "security-platform/inventory/v1" and d.get("kind") == "container-image":
            n += 1
            items += d["items"]
            if d.get("complete") is not True:
                bad = [f"{k} {v}" for k, v in sorted((d.get("sources") or {}).items()) if v != "complete"]
                partial.append(f"{os.path.basename(p)}: " + (", ".join(bad) if bad else "completeness not declared"))
    return items, n > 0 and not partial, partial


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
    if "vendor-advisories" in intel:
        vendor_state(intel["vendor-advisories"], next(f for f in cfg["feeds"] if f["type"] == "vendor-advisories"), c)
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
    items, complete, partial = image_inventory(glob.glob(os.path.join(os.environ.get("SP_INPUT_DIR") or c.out, "inventory.*.json")))
    if complete:
        # every image inventory is complete: an image no longer listed is no longer running, and the ledger closes
        # its findings (asset_retired). Partial or old-format inventories declare nothing (= unknown).
        c.ok("inventory:container-image", complete_scope="image:")
    elif partial:
        print(f"[vuln-intel] image inventory partial ({'; '.join(partial)[:300]}): findings of images no longer listed "
              "stay as they are", file=sys.stderr)
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
        (c.ok if rep is not None else (lambda a: c.gap(a, note)))(f"repo:{os.path.basename(path.rstrip('/'))}")
    remote_repos = {}
    for rc_cfg in cfg.get("code_repos") or []:
        remote_repos.update(code_repos(rc_cfg, c))
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
    repo_sboms = []
    for asset, (sbom_rel, sha) in sorted(remote_repos.items()):
        rc, out, err = trivy(["sbom", "--format", "json", "--skip-db-update", "--scanners", "vuln", os.path.join(DATA, sbom_rel)])
        if rc != 0:
            c.gap(asset, f"match rc={rc}: {err.strip()[-160:]}")
            continue
        c.ok(asset)
        meta = {"exposed": False, "prod": True, "clusters": [], "commit": sha}
        handle(asset, meta, json.loads(out))
        repo_sboms.append((asset, sbom_rel, meta))
    c.metric("security_sbom_repos", len(repo_sboms), "Code-host repositories with a dependency SBOM matched")

    # ---- hosts: distro packages, fs SBOMs, platform advisories --------------------------------------------
    inv_kinds = {}
    for p in glob.glob(os.path.join(os.environ.get("SP_INPUT_DIR") or c.out, "inventory.*.json")):
        d = json.load(open(p))
        if d.get("schema") == "security-platform/inventory/v1":
            inv_kinds.setdefault(d.get("kind"), []).extend(d.get("items") or [])
    plats = {p["host"]: p for p in inv_kinds.get("host-platform", [])}
    hpkgs = {}
    for x in inv_kinds.get("host-package", []):
        hpkgs.setdefault(x["host"], []).append(x)
    unmatched = {}
    host_sboms = []          # (asset, sbom relpath, meta) for the OSV matcher
    android_idx = (intel.get("android-bulletins") or {}).get("index")
    apple_idx = (intel.get("apple-security-releases") or {}).get("index")
    msrc_idx = (intel.get("msrc-cvrf") or {}).get("index")
    vend = intel.get("vendor-advisories") or {}
    hcov = {}

    def hgap(asset, part, reason):
        hcov[asset][part] = "gap: " + reason[:200]

    for host, plat in sorted(plats.items()):
        A = f"host:{host}"
        hcov[A] = {}
        meta = {"exposed": plat.get("exposed", False), "prod": plat.get("prod", True), "clusters": []}
        pk = hpkgs.get(host, [])
        for x in pk:
            if x["ecosystem"] not in ("deb", "apk", "rpm") or not hostmatch.DISTROS.get((plat.get("os_family") or "").lower()):
                unmatched[x["ecosystem"]] = unmatched.get(x["ecosystem"], 0) + 1
        cdx = hostmatch.os_sbom(plat, pk)
        if cdx:
            sp = os.path.join(DATA, "sbom", f"host-{host}-os.cdx.json")
            os.makedirs(os.path.dirname(sp), exist_ok=True)
            with open(sp, "w") as f:
                json.dump(cdx, f)
            rc, out, err = trivy(["sbom", "--format", "json", "--skip-db-update", "--scanners", "vuln", sp])
            if rc != 0:
                hgap(A, f"os-packages", f"match rc={rc}: {err.strip()[-160:]}")
            else:
                hcov[A]["os-packages"] = "ok"
                rep = json.loads(out)
                kern, rest = [], []
                src_of = {x["name"]: x.get("source_name") for x in pk}
                for r in rep.get("Results") or []:
                    keep = []
                    for v in r.get("Vulnerabilities") or []:
                        (kern if hostmatch.is_kernel_pkg(v.get("PkgName"), src_of.get(v.get("PkgName"))) else keep).append(v)
                    r["Vulnerabilities"] = keep
                    rest.append(r)
                handle(A, meta, {"Results": rest})
                running = [v for v in kern if hostmatch.kernel_running_pkg(v["PkgName"], plat.get("kernel_running"))]
                stale_pk = sorted({v["PkgName"] for v in kern} - {v["PkgName"] for v in running})
                fixable = {v["VulnerabilityID"]: v for v in running if v.get("FixedVersion")}
                if fixable:
                    kev_k = sorted(x for x in fixable if x in kev)
                    crit = sum(1 for v in fixable.values() if v.get("Severity") == "CRITICAL")
                    fixed_to = max((v["FixedVersion"] for v in fixable.values()), key=hostmatch.vtuple)
                    sev = "critical" if kev_k and meta["exposed"] else "high" if kev_k or crit else "medium"
                    ev_key = f"{A}|kernel"
                    evidence[ev_key] = dict(running=plat.get("kernel_running"), cves=len(fixable), critical=crit, kev=kev_k,
                                            fixed_in=fixed_to, other_installed_kernel_packages=stale_pk[:20])
                    c.finding("supply-chain", A, "vuln.kernel_fixes_available",
                              f"running kernel {plat.get('kernel_running')}: {len(fixable)} CVEs fixed in {fixed_to} "
                              f"({crit} critical{', KEV ' + ' '.join(kev_k) if kev_k else ''})", sev,
                              f"raw/vuln-intel/matches.json#{ev_key}",
                              "install the fixed kernel and reboot into it (planned maintenance)", kind="vulnerability",
                              refs=kev_k[:10], cve=(kev_k or [None])[0], kev=bool(kev_k), alertable=bool(kev_k),
                              exposed=meta["exposed"], prod=meta["prod"], base_severity="critical" if crit else "high",
                              published_at=min((v.get("PublishedDate") or "9999")[:10] for v in fixable.values()),
                              kev_added=max([kev[x]["date_added"] for x in kev_k] or [None]) if kev_k else None,
                              matcher="trivy")
                c.metric("security_host_kernel_cves_fixable", len(fixable), "CVEs of the running kernel fixed in a newer kernel", host=host)
        if plat.get("fs_sbom") and os.path.exists(os.path.join(DATA, plat["fs_sbom"])):
            rc, out, err = trivy(["sbom", "--format", "json", "--skip-db-update", "--scanners", "vuln", os.path.join(DATA, plat["fs_sbom"])])
            if rc == 0:
                hcov[A]["fs-packages"] = "ok"
                handle(A, meta, json.loads(out))
                host_sboms.append((A, plat["fs_sbom"], meta))
            else:
                hgap(A, f"fs-packages", f"match rc={rc}: {err.strip()[-160:]}")
        fam = (plat.get("os_family") or "").lower()
        if fam == "android":
            if android_idx is None:
                hgap(A, f"platform", "feed android-bulletins not configured or unavailable")
            else:
                missed = hostmatch.android_missed(plat, android_idx)
                if missed is None:
                    hgap(A, f"platform", "security patch level unknown")
                else:
                    hcov[A]["platform"] = "ok"
                    for b in missed:
                        es = b["entries"]
                        cves = sorted({a for e in es for a in e["aliases"] if a.startswith("CVE-")})
                        kev_c = [x for x in cves if x in kev]
                        crit = sum(1 for e in es if e["severity"] == "critical")
                        sev = "high" if kev_c or crit else "medium"
                        if kev_c and meta["exposed"]:
                            sev = "critical"
                        ev_key = f"{A}|asb-{b['spl']}"
                        evidence[ev_key] = dict(patch_level=plat.get("patch_level"), bulletin_spl=b["spl"], issues=len(es),
                                                critical=crit, kev=kev_c, cves=cves[:200])
                        c.finding("host", A, f"platform.android_bulletin.{b['spl']}",
                                  f"Android security patch level {plat.get('patch_level')} lacks bulletin {b['spl']}: {len(es)} issues "
                                  f"({crit} critical{', KEV ' + ' '.join(kev_c) if kev_c else ''})", sev,
                                  f"raw/vuln-intel/matches.json#{ev_key}",
                                  "install the vendor OTA with this patch level (if the vendor stopped updates: retire/isolate the device)",
                                  needs_human=True, kind="vulnerability", refs=kev_c[:10], advisory=f"android-bulletin-{b['spl']}",
                                  cve=(kev_c or [None])[0], kev=bool(kev_c), alertable=bool(kev_c), exposed=meta["exposed"],
                                  published_at=b["spl"], kev_added=max([kev[x]["date_added"] for x in kev_c] or [None]) if kev_c else None,
                                  base_severity="critical" if crit else "high", matcher="android-bulletins")
        elif fam == "macos":
            if apple_idx is None:
                hgap(A, f"platform", "feed apple-security-releases not configured or unavailable")
            else:
                hcov[A]["platform"] = "ok"
                for r in hostmatch.apple_missed(plat, apple_idx) or []:
                    try:
                        cves = feeds.apple_release_cves(r["url"], os.path.join(CACHE, "feeds")) if r.get("url") else []
                    except Exception as e:  # noqa: BLE001
                        cves = []
                        hgap(A, f"platform-cves", f"apple release page: {type(e).__name__}")
                    kev_c = [x for x in cves if x in kev]
                    sev = ("critical" if meta["exposed"] else "high") if kev_c else "medium"
                    ev_key = f"{A}|{r['name']}"
                    evidence[ev_key] = dict(installed=plat.get("os_version"), release=r, cves=cves, kev=kev_c)
                    c.finding("host", A, f"platform.apple_release.{r['version']}",
                              f"{r['name']} ({r['date']}) not installed (host {plat.get('os_version')}): {len(cves)} CVEs"
                              + (f", KEV {' '.join(kev_c)}" if kev_c else ""), sev, f"raw/vuln-intel/matches.json#{ev_key}",
                              f"install {r['name']}", needs_human=True, kind="vulnerability", refs=kev_c[:10] + [r.get("url") or ""],
                              advisory=r["name"], cve=(kev_c or [None])[0], kev=bool(kev_c), alertable=bool(kev_c),
                              exposed=meta["exposed"], published_at=r["date"],
                              kev_added=max([kev[x]["date_added"] for x in kev_c] or [None]) if kev_c else None,
                              base_severity="high", matcher="apple-security-releases")
        elif fam == "windows":
            missed, prod = hostmatch.windows_missed(plat, msrc_idx) if msrc_idx is not None else (None, None)
            if msrc_idx is None:
                hgap(A, f"platform", "feed msrc-cvrf not configured or unavailable")
            elif missed is None:
                hgap(A, f"platform", f"product {prod!r} not found in the MSRC documents")
            else:
                hcov[A]["platform"] = "ok"
                for m in missed:
                    cves = sorted({i["cve"] for i in m["items"] if i.get("cve")})
                    kev_c = sorted({x for x in cves if x in kev} | {i["cve"] for i in m["items"] if i.get("exploited")})
                    crit = sum(1 for i in m["items"] if i.get("severity") == "critical")
                    sev = ("critical" if meta["exposed"] else "high") if kev_c else ("high" if crit else "medium")
                    ev_key = f"{A}|{m['release']}"
                    evidence[ev_key] = dict(build=plat.get("os_build"), product=prod, release=m["release"], cves=cves,
                                            kev_or_exploited=kev_c, kbs=sorted({i["kb"] for i in m["items"]}),
                                            fixed_builds=sorted({i["fixed_build"] for i in m["items"]}))
                    c.finding("host", A, f"platform.windows_update.{m['release'].lower()}",
                              f"{m['release']} security update not installed (build {plat.get('os_build')}): {len(cves)} CVEs "
                              f"({crit} critical{', exploited ' + ' '.join(kev_c) if kev_c else ''})", sev,
                              f"raw/vuln-intel/matches.json#{ev_key}", "run Windows Update (cumulative update)", needs_human=True,
                              kind="vulnerability", refs=kev_c[:10], advisory=f"msrc-{m['release']}", cve=(kev_c or [None])[0],
                              kev=bool(kev_c), alertable=bool(kev_c), exposed=meta["exposed"], published_at=m["date"],
                              base_severity="critical" if crit else "high", matcher="msrc-cvrf")
        fw = plat.get("firmware") or {}
        if fw.get("vendor"):
            hcov[A]["firmware-kev"] = "ok"
            names = (cfg.get("firmware_vendors") or {}).get(fw["vendor"], [fw["vendor"]])
            for k in hostmatch.vendor_kev(plat, kev, names):
                ev_key = f"{A}|{k['cve']}"
                evidence[ev_key] = dict(firmware=fw, kev=k)
                c.finding("host", A, f"vuln.{k['cve'].lower()}",
                          f"{k['cve']} (KEV, {k.get('vendor')} {k.get('product')}) added {k['date_added']} after the firmware "
                          f"build {fw.get('build_date')}: CANDIDATE - verify the model/version against the vendor advisory",
                          "critical" if meta["exposed"] else "high", f"raw/vuln-intel/matches.json#{ev_key}",
                          "check the vendor advisory for this model; update firmware or isolate", needs_human=True,
                          kind="vulnerability", refs=[k["cve"]], cve=k["cve"], kev=True, kev_added=k["date_added"],
                          published_at=k["date_added"], alertable=True, exposed=meta["exposed"], candidate=True,
                          matcher="kev-vendor")
            srcs = [s for s in (vend.get("sources_cfg") or []) if fw["vendor"] in (s.get("vendors") or [])]
            reviews = spsdk.load_config(os.path.join(DATA, "advisory-reviews.yaml")) if os.path.exists(os.path.join(DATA, "advisory-reviews.yaml")) else {}
            reviews = (reviews or {}).get("reviews") or {}
            for s in srcs:
                if s["name"] in (vend.get("errors") or {}):
                    hgap(A, f"vendor-advisories:{s['name']}", vend["errors"][s["name"]])
                    continue
                hcov[A][f"vendor-advisories:{s['name']}"] = "ok"
                for it in (vend.get("new") or {}).get(s["name"], []):
                    rv = reviews.get(it["id"]) or {}
                    if rv.get("verdict") in ("not-affected", "not-applicable") and rv.get("by"):
                        continue   # a HUMAN's verdict; the platform never concludes this itself
                    affected = rv.get("verdict") == "affected"
                    mentions = [w for w in [fw.get("model"), fw.get("version")] + [x["name"] for x in pk if len(x["name"]) > 4]
                                if w and re.search(r"(?<![\w-])" + re.escape(w) + r"(?![\w-])", it["text"])]
                    ev_key = f"{A}|advisory-{it['id']}"
                    evidence[ev_key] = dict(item=it, mentions=mentions[:10], review=rv or None)
                    c.finding("host", A, f"advisory.vendor.{it['id']}",
                              ("AFFECTED (human review): " if affected else "Unreviewed vendor advisory (candidate): ")
                              + it["text"][:200], "high" if affected else ("medium" if mentions else "low"),
                              f"raw/vuln-intel/matches.json#{ev_key}",
                              f"read {it['url']} and record a verdict in advisory-reviews.yaml (id {it['id']})", needs_human=True,
                              kind="vulnerability", advisory=f"{s['name']}:{it['id']}", published_at=it.get("first_seen", "")[:10],
                              candidate=not affected, matcher="vendor-advisories")
    readable = {v for src in (vend.get("sources_cfg") or []) if src["name"] not in (vend.get("errors") or {})
                for v in src.get("vendors") or []}
    fw_vendors = {(p.get("firmware") or {}).get("vendor") for p in plats.values()} - {None}
    c.metric("security_intel_firmware_vendors_without_source", len(fw_vendors - readable),
             "Firmware vendors in scope without a readable advisory source (only KEV covers them)")
    # coverage per HOST (findings live on host:<name>): ok only when every applicable matcher covered it, so a
    # partial run never marks a finding fixed; the per-matcher detail is evidence
    for A, parts in hcov.items():
        bad = {k: v for k, v in parts.items() if v != "ok"}
        if not parts:
            c.gap(A, "no matcher applies (no distro packages, fs SBOM, platform feed or firmware vendor)")
        elif bad:
            c.gap(A, "partial: " + "; ".join(f"{k} {v}" for k, v in bad.items()))
        else:
            c.ok(A)
    c.raw("host-coverage.json", hcov)
    # ---- OSV: second matcher over the same SBOMs ------------------------------------------------------------
    osv_idx = intel.get("osv", {}).get("index", {})
    osv_hits = 0
    if osv_idx:
        targets = [(f"image:{ref}", meta["sbom"], meta) for ref, meta in images.items() if meta.get("sbom")] + host_sboms + repo_sboms
        for asset, sbom_rel, meta in targets:
            try:
                cdx = json.load(open(os.path.join(DATA, sbom_rel)))
            except (OSError, ValueError):
                continue
            for eco, name, ver, adv in osvmatch.match(osvmatch.components(cdx), osv_idx):
                osv_hits += 1
                cves = [a for a in adv["aliases"] if a.startswith("CVE-")]
                in_kev = any(x in kev for x in cves)
                if not (in_kev or adv["severity"] == "critical"):
                    continue
                vid = cves[0] if cves else adv["id"]
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
    for k, v in sorted(unmatched.items()):
        c.metric("security_sbom_unmatched_packages", v, "Inventoried host packages without a structured advisory source", kind=k)
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
