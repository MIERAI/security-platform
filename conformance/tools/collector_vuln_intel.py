"""Conformance cases of the `vuln-intel` collector (collector-protocol/1.0, findings/1.2): a fake trivy on PATH answers
from recorded SBOMs and vulnerabilities (fakes/fake_trivy.py); feeds are either pre-seeded fresh caches (no network:
the reference runs them too) or served by a fake mirror (fakes/mock_feeds.py, target behaviour). Imported by
gen_cases.py, which passes its helpers (write_case, collector_env, protocol_checks)."""
import hashlib
import io
import json
import os
import struct
import zipfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
C = "collector-protocol/1.0 / findings/1.2"
TOKEN = "registry-conformance-token-5e2a"     # a registry credential: never in any output, log or argument
NO_PROXY_OUT = "http://127.0.0.1:9"            # the reference has no feed URL option: its requests must go nowhere
INV = "security-platform/inventory/v1"
FRESH = '{"checked_at": {now_epoch}, "etag": "\\"v1\\"", "last_modified": null, "url": "x"}'


def gzip_stored(data):
    """gzip with stored (uncompressed) deflate blocks and a fixed header: the same bytes from every Python/zlib."""
    co = zlib.compressobj(0, zlib.DEFLATED, -15)
    body = co.compress(data) + co.flush()
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + body + struct.pack("<II", zlib.crc32(data), len(data) & 0xFFFFFFFF)


def zip_stored(entries):
    """A zip archive (stored entries, fixed times and attributes): the same bytes from every Python."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        for name, obj in entries:
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            zi.create_system, zi.external_attr = 3, 0o644 << 16
            z.writestr(zi, json.dumps(obj, sort_keys=True))
    return buf.getvalue()


# ---- feeds --------------------------------------------------------------------------------------------------------
def kev_entry(cve, vendor, product, added):
    return {"cveID": cve, "vendorProject": vendor, "product": product, "dateAdded": added,
            "knownRansomwareCampaignUse": "Unknown", "shortDescription": "conformance fixture"}


KEV = {"catalogVersion": "2026.11.24", "vulnerabilities": [
    kev_entry("CVE-2099-0002", "zlib", "zlib", "2026-02-01"),
    kev_entry("CVE-2099-0202", "Linux", "Kernel", "2026-03-01"),
    kev_entry("CVE-2099-0302", "Android", "Framework", "2026-03-05"),
    kev_entry("CVE-2099-0402", "Apple", "macOS", "2026-04-01"),
    kev_entry("CVE-2099-0500", "ExampleVendor", "EX router", "2025-12-01"),
    kev_entry("CVE-2099-0501", "ExampleVendor", "EX router", "2026-05-01")]}
EPSS = b"#model_version:v2025.03.14,score_date:2026-11-24T00:00:00+0000\ncve,epss,percentile\n" \
       b"CVE-2099-0003,0.73000,0.99100\nCVE-2099-0001,0.01200,0.51000\nCVE-2099-0101,0.33000,0.90000\n"


def osv_adv(i, sev, aliases, rtype, events, published="2026-03-01T00:00:00Z", **kw):
    a = {"id": f"GO-2099-000{i}", "aliases": aliases, "published": published, "modified": "2026-03-02T00:00:00Z",
         "summary": f"conformance advisory {i}", "affected": [{"package": {"ecosystem": "Go", "name": "example.com/lib"},
                                                             "ranges": [{"type": rtype, "events": events}]}]}
    if sev:
        a["database_specific"] = {"severity": sev}
    a.update(kw)
    return a


OSV_GO = zip_stored([
    ("GO-2099-0001.json", osv_adv(1, "CRITICAL", ["CVE-2099-0101"], "SEMVER", [{"introduced": "0"}, {"fixed": "1.4.2"}])),
    ("GO-2099-0002.json", osv_adv(2, "", ["CVE-2099-0002", "GHSA-xxxx"], "ECOSYSTEM", [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}])),
    ("GO-2099-0003.json", osv_adv(3, "MODERATE", ["CVE-2099-0103"], "SEMVER", [{"introduced": "1.2.0"}, {"last_affected": "1.3.0"}])),
    ("GO-2099-0004.json", osv_adv(4, "CRITICAL", ["CVE-2099-0104"], "SEMVER", [{"introduced": "0"}], withdrawn="2026-04-01T00:00:00Z"))])


def asb(i, spl, sev, versions, aliases):
    return {"id": f"ASB-A-2099-000{i}", "aliases": aliases, "published": spl + "T00:00:00Z",
            "affected": [{"package": {"ecosystem": "Android", "name": "Framework"},
                          "ecosystem_specific": {"spl": spl, "severity": sev}, "versions": versions}]}


ANDROID = zip_stored([
    ("ASB-A-2099-0001.json", asb(1, "2026-09-01", "Critical", ["16", "16-qpr1"], ["CVE-2099-0301"])),
    ("ASB-A-2099-0002.json", asb(2, "2026-09-05", "High", ["16"], ["CVE-2099-0302"])),
    ("ASB-A-2099-0003.json", asb(3, "2026-07-01", "Critical", ["16"], ["CVE-2099-0303"])),
    ("ASB-A-2099-0004.json", asb(4, "2026-10-01", "High", ["14"], ["CVE-2099-0304"])),
    ("ASB-A-2099-0005.json", asb(5, "2026-10-01", "High", ["Device specific"], ["CVE-2099-0305"]))])
APPLE_1, APPLE_2 = "https://support.example.invalid/apple/120001", "https://support.example.invalid/apple/120002"
APPLE_INDEX = (
    "<html><body><table><tr><th>Name</th><th>Available for</th><th>Release date</th></tr>\n"
    f'<tr><td><a href="{APPLE_1}">macOS Tahoe 26.7</a></td><td>macOS Tahoe</td><td>15 Sep 2026</td></tr>\n'
    f'<tr><td><a href="{APPLE_2}">macOS Tahoe 26.6.3</a></td><td>macOS Tahoe</td><td>1 Aug 2026</td></tr>\n'
    "<tr><td>macOS Sequoia 15.7</td><td>macOS Sequoia</td><td>15 Sep 2026</td></tr>\n"
    '<tr><td><a href="https://support.example.invalid/apple/120003">iOS 26.7 and iPadOS 26.7</a></td><td>iPhone</td>'
    "<td>15 Sep 2026</td></tr>\n"
    "<tr><td>Safari 26.1This update has no published CVE entries.</td><td>macOS</td><td>01 Oct 2026</td></tr>\n"
    "</table></body></html>\n")
PROD_ID, PROD_NAME = "12345", "Windows 11 Version 25H2 for x64-based Systems"


def cvrf(cve, build, kb, exploited, sev):
    return {"ProductTree": {"FullProductName": [{"ProductID": PROD_ID, "Value": PROD_NAME},
                                                {"ProductID": "999", "Value": "Windows Server 2025"}]},
            "Vulnerability": [{"CVE": cve, "Threats": [{"Type": 1, "Description": {"Value": "Exploited:" + exploited}},
                                                       {"Type": 3, "Description": {"Value": sev}}],
                               "Remediations": [{"FixedBuild": build, "ProductID": [PROD_ID, "999"], "Description": {"Value": kb}},
                                                {"Description": {"Value": "workaround"}, "ProductID": [PROD_ID]}]}]}


MSRC = {"updates.json": {"value": [{"ID": "2026-Oct", "InitialReleaseDate": "2026-10-14T07:00:00Z"},
                                   {"ID": "2026-Aug", "InitialReleaseDate": "2026-08-12T07:00:00Z"},
                                   {"ID": "2026-Sep", "InitialReleaseDate": "2026-09-09T07:00:00Z"},
                                   {"ID": "2026-Jul", "InitialReleaseDate": "2026-07-08T07:00:00Z"}]},
        "2026-Aug.json": cvrf("CVE-2099-0600", "10.0.26200.150", "5040000", "No", "Important"),
        "2026-Sep.json": cvrf("CVE-2099-0601", "10.0.26200.300", "5040001", "Yes", "Critical"),
        "2026-Oct.json": cvrf("CVE-2099-0602", "10.0.26200.400", "5040002", "No", "Important")}


def cached(rel, content, files, case_files, raw=False):
    """A feed file in <data>/cache/feeds/<rel>, confirmed current right now (the collector asks nobody)."""
    name = "feed-" + rel.replace("/", "-")
    case_files[name] = content
    files[f"data/cache/feeds/{rel}"] = {"raw": name} if raw else name
    files[f"data/cache/feeds/{rel}.meta.json"] = {"text": FRESH}


# ---- trivy ----------------------------------------------------------------------------------------------------------
def cdx(name, comps):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "metadata": {"component": {"name": name, "type": "container"}},
            "components": [dict({"type": "library", "name": n, "version": v}, **({"purl": p} if p else {})) for n, v, p in comps]}


def vuln(cve, sev, fixed=None, published="2026-03-01T00:00:00Z", cvss=None):
    v = {"VulnerabilityID": cve, "Severity": sev, "PublishedDate": published, "Title": "conformance"}
    if fixed:
        v["FixedVersion"] = fixed
    if cvss:
        v["CVSS"] = cvss
    return v


WEB_DIGEST = "registry.example/web@sha256:" + "a" * 64
TRIVY = {
    "version": {"Version": "0.99.1", "VulnerabilityDB": {"Version": 2, "UpdatedAt": "2026-11-24T06:12:00.123456789Z"}},
    "images": {
        WEB_DIGEST: {"sbom": cdx("registry.example/web:1.4", [
            ("openssl", "3.0.1", None), ("zlib", "1.2.11", None), ("curl", "7.0", None), ("libpng", "1.6", None),
            ("example.com/lib", "v1.3.0", "pkg:golang/example.com/lib@v1.3.0")])},
        "registry.example/batch:2": {"sbom": cdx("registry.example/batch:2", [("openssl", "3.0.1", None)])},
        "registry.example/tool:1": {"sbom": cdx("registry.example/tool:1", [("busybox", "1.0", None)])},
        "busybox:1.36": {"sbom": cdx("busybox:1.36", [])},
        "registry.private.example/app:1": {"auth": True, "sbom": cdx("registry.private.example/app:1", [("openssl", "3.0.1", None)])},
        "registry.other.example/app:2": {"auth": True, "sbom": cdx("x", [])},
        "registry.loose.example/x:1": {"auth": True, "sbom": cdx("x", [])},
        "registry.example/a:1": {"sbom": cdx("a", [])}, "registry.example/b:1": {"sbom": cdx("b", [])}},
    "fs": {"app": cdx("app", [("lodash", "4.17.0", "pkg:npm/lodash@4.17.0")])},
    "vulns": {
        "openssl@3.0.1": [vuln("CVE-2099-0001", "CRITICAL", "3.0.9", "2026-01-15T00:00:00Z", {"nvd": {"V3Score": 9.8}})],
        "zlib@1.2.11": [vuln("CVE-2099-0002", "HIGH", "1.2.12", cvss={"ghsa": {"V3Score": 7}})],
        "curl@7.0": [vuln("CVE-2099-0003", "CRITICAL", None, cvss={"nvd": {"V3Score": 0}, "redhat": {"V3Score": 9.1}})],
        "libpng@1.6": [vuln("CVE-2099-0004", "HIGH", "1.6.9"), vuln("CVE-2099-0005", "HIGH", "1.6.9"),
                       vuln("CVE-2099-0004", "HIGH", "1.6.9"), vuln("CVE-2099-0007", "MEDIUM", "1.6.9")],
        "busybox@1.0": [vuln("CVE-2099-0006", "CRITICAL", "1.1", "2026-05-01T00:00:00Z")],
        "lodash@4.17.0": [vuln("CVE-2099-0008", "CRITICAL", "4.17.21", "2026-02-02T00:00:00Z")],
        "openssl@3.0.13-0ubuntu3.4": [vuln("CVE-2099-0204", "CRITICAL", "3.0.13-0ubuntu3.5")],
        "linux-image-6.8.0-40-generic@6.8.0-40.40": [
            vuln("CVE-2099-0202", "CRITICAL", "6.8.0-52.53", "2026-03-01T00:00:00Z"),
            vuln("CVE-2099-0205", "HIGH", "6.8.0-50.51", "2026-02-01T00:00:00Z"), vuln("CVE-2099-0206", "HIGH")],
        "linux-image-6.8.0-45-generic@6.8.0-45.45": [vuln("CVE-2099-0207", "HIGH", "6.8.0-50.51")]}}


def item(cluster, image, exposed, prod, image_id=""):
    return {"cluster": cluster, "image": image, "image_id": image_id, "namespaces": ["apps"],
            "workloads": [f"k8s-workload:{cluster}/apps/Deployment/{image.split('/')[-1].split(':')[0]}"],
            "exposed": exposed, "prod": prod}


def inventory(items, complete=True, sources=None, kind="container-image"):
    d = {"schema": INV, "kind": kind, "items": items}
    if complete is not None:
        d["complete"] = complete
        d["sources"] = sources or {"k8s-cluster:prod": "complete"}
    return d


def base_files(extra=None):
    f = {"instance.json": "instance.json", "data/.keep": {"text": ""}, "fake_trivy.json": "trivy.json",
         "bin/trivy": {"text": "#!/bin/sh\nexec \"{python}\" \"{case}/fake_trivy.py\" \"$@\"\n", "mode": "0755"}}
    f.update(extra or {})
    return f


def env(h, extra=None):
    return h.collector_env(dict({"PATH": "{sandbox}/bin:{path}", "FAKE_TRIVY_DATA": "{sandbox}/fake_trivy.json",
                                 "FAKE_TRIVY_LOG": "{sandbox}/.svc-trivy.calls", "https_proxy": NO_PROXY_OUT,
                                 "HTTPS_PROXY": NO_PROXY_OUT, "http_proxy": NO_PROXY_OUT, "HTTP_PROXY": NO_PROXY_OUT,
                                 "no_proxy": "", "NO_PROXY": ""}, **(extra or {})))


def case_files(extra=None):
    d = {"fake_trivy.py": open(os.path.join(HERE, "fakes", "fake_trivy.py")).read(), "trivy.json": TRIVY}
    d.update(extra or {})
    return d


WRITES = ["run", "data/cache", "data/sbom"]


def F(cve, asset, severity, **kw):
    return dict({"check": f"vuln.{cve.lower()}", "asset": asset, "severity": severity}, **kw)


def images_case(h):
    files, cf = base_files(), case_files()
    cached("known_exploited_vulnerabilities.json", KEV, files, cf)
    cached("epss_scores-current.csv.gz", gzip_stored(EPSS), files, cf, raw=True)
    cached("osv/Go/all.zip", OSV_GO, files, cf, raw=True)
    files["data/latest/inventory.k8s-images.json"] = "inventory.json"
    files["src/app/go.mod"] = {"text": "module app\n"}
    cf["inventory.json"] = inventory([
        item("prod", "registry.example/web:1.4", True, True, "docker-pullable://" + WEB_DIGEST),
        item("lab", "registry.example/web:1.4", False, False, "docker-pullable://" + WEB_DIGEST),
        item("prod", "registry.example/batch:2", False, True),
        item("lab", "registry.example/tool:1", True, False, "sha256:" + "b" * 64),
        item("lab", "busybox:1.36", False, False, "docker-pullable://busybox@sha256:" + "c" * 64)],
        sources={"k8s-cluster:prod": "complete", "k8s-cluster:lab": "complete"})
    cf["instance.json"] = {"name": "conformance", "intel": {
        "feeds": [{"type": "cisa-kev"}, {"type": "epss"}, {"type": "osv", "ecosystems": ["Go"]}, {"type": "nvd"}],
        "repos": ["{sandbox}/src/app"]}}
    web = "image:registry.example/web:1.4"
    findings = [
        F("CVE-2099-0001", web, "critical", layer="supply-chain", kind="vulnerability", refs=["CVE-2099-0001"],
          title="CVE-2099-0001 in openssl 3.0.1 (fix 3.0.9)", evidence=f"raw/vuln-intel/matches.json#{web}|CVE-2099-0001",
          remediation="update openssl to 3.0.9",
          attributes={"cve": "CVE-2099-0001", "package": "openssl", "installed": "3.0.1", "fixed": "3.0.9", "cvss": 9.8,
                      "base_severity": "critical", "published_at": "2026-01-15", "kev": False, "kev_added": None,
                      "epss": 0.012, "exposed": True, "prod": True, "clusters": ["lab", "prod"],
                      "target": "registry.example/web:1.4", "matcher": "trivy", "alertable": True}),
        F("CVE-2099-0002", web, "critical", title="CVE-2099-0002 in zlib 1.2.11 (fix 1.2.12) [KEV]",
          attributes={"kev": True, "kev_added": "2026-02-01", "cvss": 7, "epss": None, "alertable": True, "matcher": "trivy"}),
        F("CVE-2099-0003", web, "critical", title="CVE-2099-0003 in curl 7.0 (no fix yet)",
          remediation="mitigate (reduce exposure) / watch for a fix", attributes={"cvss": 9.1, "epss": 0.73, "fixed": ""}),
        {"check": "vuln.high_fixable_aggregate", "asset": web, "severity": "medium",
         "title": "2 HIGH CVEs with available fixes", "evidence": f"raw/vuln-intel/high-aggregate.json#{web}",
         "attributes": {"count": 2}},
        F("CVE-2099-0001", "image:registry.example/batch:2", "high", attributes={"exposed": False, "alertable": False}),
        F("CVE-2099-0006", "image:registry.example/tool:1", "high", attributes={"prod": False, "alertable": True}),
        F("CVE-2099-0008", "repo:app", "high", attributes={"clusters": [], "prod": True, "exposed": False}),
        F("CVE-2099-0101", web, "critical", title="CVE-2099-0101 in example.com/lib v1.3.0 (fix 1.4.2) [OSV]",
          refs=["CVE-2099-0101", "GO-2099-0001"],
          attributes={"osv_id": "GO-2099-0001", "matcher": "osv", "target": "Go", "epss": 0.33, "base_severity": "critical"})]
    h.write_case("collector-vuln-intel", "images-kev-epss-osv-complete-inventory", {
        "title": "Running images x trivy (fake) x cached KEV / EPSS / OSV feeds: priority from intel and exposure (KEV, "
                 "EPSS >= 0.5 raises one step, outside prod at most high), HIGH fixes aggregated, OSV as a second "
                 "matcher, a local repository, the complete image inventory declared with complete_scope image:, a "
                 "future feed is a gap. Fresh caches: no feed is fetched",
        "contract": C, "origin": "collectors/vuln-intel/collector.py; tests/test_intel.py; tests/test_retired.py",
        "files": files,
        "steps": [{"name": "collect", "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
                   "expect": h.protocol_checks("vuln-intel") + [
                       {"json": "run/vuln-intel.findings.json", "subset": {
                           "collector": {"tools": {"trivy": "0.99.1", "trivy-db": "2026-11-24T06:12:00.123456789Z"}},
                           "coverage": [
                               {"asset": "feed:cisa-kev", "status": "ok"}, {"asset": "feed:epss", "status": "ok"},
                               {"asset": "feed:osv", "status": "ok"},
                               {"asset": "feed:nvd", "status": "gap",
                                "reason": "NotImplementedError: feed 'nvd' is a documented future adapter"},
                               {"asset": "inventory:container-image", "status": "ok", "complete_scope": "image:"},
                               {"asset": web, "status": "ok"}, {"asset": "image:registry.example/batch:2", "status": "ok"},
                               {"asset": "image:registry.example/tool:1", "status": "ok"},
                               {"asset": "image:busybox:1.36", "status": "ok"}, {"asset": "repo:app", "status": "ok"}],
                           "findings": {"$unordered": findings}}},
                       {"json": "run/raw/vuln-intel/images.json", "subset": {"registry.example/web:1.4": {
                           "clusters": ["lab", "prod"], "exposed": True, "prod": True, "sbom": {"$regex": r"^sbom/[0-9a-f]{16}\.cdx\.json$"}}}},
                       {"json": "run/raw/vuln-intel/matches.json", "subset": {f"{web}|CVE-2099-0002": {"matcher": "osv"}}},
                       {"prom": "run/vuln-intel.prom", "has": [
                           {"name": "security_vuln_matches", "labels": {"severity": "critical"}, "value": 5},
                           {"name": "security_vuln_matches", "labels": {"severity": "high"}, "value": 4},
                           {"name": "security_vuln_kev_matches", "value": 1},
                           {"name": "security_vuln_alertable_matches", "value": 5},
                           {"name": "security_vuln_osv_matches", "value": 3},
                           {"name": "security_sbom_images", "value": 4},
                           {"name": "security_intel_feed_age_seconds", "labels": {"feed": "trivy-db"}}]},
                       {"file": ".svc-trivy.calls", "regex": [
                           "^version --format json auth=no$",
                           r"^image --cache-backend memory --image-src remote --format cyclonedx --skip-db-update --output \S+/data/sbom/[0-9a-f]{16}\.cdx\.json\.tmp registry\.example/web@sha256:a{64} auth=no$",
                           r"^image .* registry\.example/tool:1 auth=no$", r"^image .* busybox:1\.36 auth=no$",
                           r"^sbom --cache-backend memory --format json --skip-db-update --scanners vuln \S+\.cdx\.json auth=no$",
                           r"^fs --cache-backend memory --format json --skip-db-update --scanners vuln \S+/src/app auth=no$"]}]},
                  {"name": "second run: SBOMs are cached by digest, only matched again", "remove": ["run", ".svc-trivy.calls"],
                   "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
                   "expect": [{"json": "run/vuln-intel.findings.json", "schema": "findings",
                               "subset": {"findings": {"$len": len(findings)}}},
                              {"file": ".svc-trivy.calls", "not_regex": ["^image "]}]}]},
        cf)


def partial_case(h):
    files, cf = base_files(), case_files()
    files.update({"data/latest/inventory.a-images.json": "a.json", "data/latest/inventory.b-images.json": "b.json",
                  "data/latest/inventory.old-images.json": "old.json"})
    cf.update({"a.json": inventory([item("a", "registry.example/a:1", False, True)], sources={"k8s-cluster:a": "complete"}),
               "b.json": inventory([item("b", "registry.example/b:1", False, True)], complete=False,
                                   sources={"k8s-cluster:b": "failed: RuntimeError", "k8s-cluster:b2": "complete"}),
               "old.json": inventory([item("old", "registry.example/a:1", True, False)], complete=None),
               "instance.json": {"name": "conformance", "intel": {"feeds": []}}})
    h.write_case("collector-vuln-intel", "partial-inventory-retires-nothing", {
        "title": "One image inventory that is partial (a failed cluster) or that does not declare completeness (an older "
                 "producer) makes the whole image inventory partial: no complete_scope, so the ledger retires nothing",
        "contract": C, "origin": "tests/test_retired.py::VulnIntelInventory::test_complete_only_when_every_inventory_is",
        "files": files,
        "steps": [{"name": "collect", "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
                   "expect": h.protocol_checks("vuln-intel") + [
                       {"json": "run/vuln-intel.findings.json", "subset": {"coverage": {"$unordered": [
                           {"asset": "image:registry.example/a:1", "status": "ok"},
                           {"asset": "image:registry.example/b:1", "status": "ok"}]}}},
                       {"json": "run/raw/vuln-intel/images.json", "subset": {"registry.example/a:1": {
                           "clusters": ["a", "old"], "exposed": True, "prod": True}}},
                       {"stderr": {"regex": [r"image inventory partial \(inventory\.b-images\.json: k8s-cluster:b failed: "
                                             r"RuntimeError; inventory\.old-images\.json: completeness not declared\)"]}}]}]},
        cf)


def registry_case(h):
    files, cf = base_files({"secrets/registry.token": {"text": TOKEN + "\n", "mode": "0600"},
                            "secrets/loose.token": {"text": TOKEN + "\n", "mode": "0644"},
                            "data/latest/inventory.k8s-images.json": "inventory.json"}), case_files()
    cf["inventory.json"] = inventory([item("prod", "registry.private.example/app:1", False, True),
                                      item("prod", "registry.other.example/app:2", False, True),
                                      item("prod", "registry.loose.example/x:1", False, True)])
    cf["instance.json"] = {"name": "conformance", "intel": {"feeds": [], "registry_auth": [
        {"host": "registry.private.example", "username": "reader", "token_file": "{sandbox}/secrets/registry.token"},
        {"host": "registry.loose.example", "username": "reader", "token_file": "{sandbox}/secrets/loose.token"}]}}
    hint = r"^sbom rc=1 \(private image: no registry credential configured - coverage gap\): UNAUTHORIZED"
    h.write_case("collector-vuln-intel", "private-registry-credential", {
        "title": "A read-only registry credential from a 0600 token file reaches trivy in its environment only (never an "
                 "argument, a log or an output); a token file readable by others is refused (gap); a private image "
                 "without a credential is a gap that says so",
        "contract": C, "origin": "docs/threat-model.md (registry token); collectors/vuln-intel/collector.py registry_env",
        "files": files,
        "steps": [{"name": "collect", "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
                   "expect": h.protocol_checks("vuln-intel", canaries=[TOKEN]) + [
                       {"json": "run/vuln-intel.findings.json", "subset": {
                           "coverage": [
                               {"asset": "registry-auth:registry.private.example", "status": "ok"},
                               {"asset": "registry-auth:registry.loose.example", "status": "gap",
                                "reason": {"$regex": r"^read-only registry credential unavailable \(PermissionError\)"}},
                               {"asset": "inventory:container-image", "status": "ok", "complete_scope": "image:"},
                               {"asset": "image:registry.private.example/app:1", "status": "ok"},
                               {"asset": "image:registry.other.example/app:2", "status": "gap", "reason": {"$regex": hint}},
                               {"asset": "image:registry.loose.example/x:1", "status": "gap", "reason": {"$regex": hint}}],
                           "findings": [F("CVE-2099-0001", "image:registry.private.example/app:1", "high")]}},
                       {"no_secret": [TOKEN], "in": ".", "except": ["secrets"]},
                       {"file": ".svc-trivy.calls", "regex": [r"^image .* registry\.private\.example/app:1 auth=yes$",
                                                              r"^image .* registry\.other\.example/app:2 auth=no$"]}]}]},
        cf)


def hosts_case(h):
    files, cf = base_files(), case_files()
    cached("known_exploited_vulnerabilities.json", KEV, files, cf)
    cached("osv/Go/all.zip", OSV_GO, files, cf, raw=True)
    cached("android/all.zip", ANDROID, files, cf, raw=True)
    cached("apple/index.html", APPLE_INDEX, files, cf)
    for url, cves in ((APPLE_1, "CVE-2099-0402 and CVE-2099-0401, CVE-2099-0401"), (APPLE_2, "CVE-2099-0403")):
        cached(f"apple/release-{hashlib.sha1(url.encode()).hexdigest()[:16]}.html",
               f"<html><body><p>Impact: {cves}</p></body></html>\n", files, cf)
    for name, doc in MSRC.items():
        cached(f"msrc/{name}", doc, files, cf)
    files["data/latest/inventory.host-sbom-platform.json"] = "platform.json"
    files["data/latest/inventory.host-sbom-packages.json"] = "packages.json"
    files["data/sbom/host-web1-fs.cdx.json"] = "web1-fs.json"
    cf["web1-fs.json"] = cdx("web1 /opt", [("example.com/lib", "v1.3.0", "pkg:golang/example.com/lib@v1.3.0")])
    cf["platform.json"] = inventory([
        {"host": "web1", "os_family": "ubuntu", "os_version": "24.04", "kernel_running": "6.8.0-40-generic",
         "exposed": True, "prod": True, "fs_sbom": "sbom/host-web1-fs.cdx.json"},
        {"host": "phone", "os_family": "android", "os_version": "16", "patch_level": "2026-08-01", "exposed": False},
        {"host": "laptop", "os_family": "macOS", "os_version": "26.6.2"},
        {"host": "pc", "os_family": "windows", "os_version": "25H2", "os_build": "10.0.26200.200", "arch": "AMD64"},
        {"host": "router", "os_family": "openwrt", "exposed": True,
         "firmware": {"vendor": "ExampleVendor", "model": "EX-100", "version": "1.2", "build_date": "2026-01-10"}},
        {"host": "nas", "os_family": "freebsd"}], complete=None, kind="host-platform")

    def pkg(host, eco, name, version, src=None):
        p = {"host": host, "ecosystem": eco, "name": name, "version": version}
        if src:
            p.update(source_name=src, source_version=version, arch="amd64")
        return p
    cf["packages.json"] = inventory([
        pkg("web1", "deb", "openssl", "3.0.13-0ubuntu3.4", "openssl"),
        pkg("web1", "deb", "libssl3t64", "3.0.13-0ubuntu3.4", "openssl"),
        pkg("web1", "deb", "linux-image-6.8.0-40-generic", "6.8.0-40.40", "linux-signed"),
        pkg("web1", "deb", "linux-image-6.8.0-45-generic", "6.8.0-45.45", "linux-signed"),
        pkg("router", "opkg", "dropbear", "2022.82"), pkg("laptop", "brew", "wget", "1.21.4")],
        complete=None, kind="host-package")
    cf["instance.json"] = {"name": "conformance", "intel": {"feeds": [
        {"type": "cisa-kev"}, {"type": "osv", "ecosystems": ["Go"]}, {"type": "android-bulletins"},
        {"type": "apple-security-releases"}, {"type": "msrc-cvrf"}]}}
    findings = [
        F("CVE-2099-0204", "host:web1", "critical", attributes={"matcher": "trivy", "target": "host", "clusters": []}),
        {"check": "vuln.kernel_fixes_available", "asset": "host:web1", "severity": "critical", "layer": "supply-chain",
         "title": "running kernel 6.8.0-40-generic: 2 CVEs fixed in 6.8.0-52.53 (1 critical, KEV CVE-2099-0202)",
         "refs": ["CVE-2099-0202"], "attributes": {"published_at": "2026-02-01", "kev_added": "2026-03-01", "cve": "CVE-2099-0202"}},
        F("CVE-2099-0101", "host:web1", "critical", attributes={"matcher": "osv", "clusters": []}),
        F("CVE-2099-0002", "host:web1", "critical", attributes={"matcher": "osv", "kev": True}),
        {"check": "platform.android_bulletin.2026-09-01", "asset": "host:phone", "severity": "high", "layer": "host",
         "title": "Android security patch level 2026-08-01 lacks bulletin 2026-09-01: 1 issues (1 critical)",
         "attributes": {"cve": None, "kev": False, "advisory": "android-bulletin-2026-09-01"}},
        {"check": "platform.android_bulletin.2026-09-05", "asset": "host:phone", "severity": "high",
         "refs": ["CVE-2099-0302"], "attributes": {"kev_added": "2026-03-05", "alertable": True}},
        {"check": "platform.apple_release.26.6.3", "asset": "host:laptop", "severity": "medium",
         "title": "macOS Tahoe 26.6.3 (2026-08-01) not installed (host 26.6.2): 1 CVEs", "refs": [APPLE_2]},
        {"check": "platform.apple_release.26.7", "asset": "host:laptop", "severity": "high",
         "title": "macOS Tahoe 26.7 (2026-09-15) not installed (host 26.6.2): 2 CVEs, KEV CVE-2099-0402",
         "refs": ["CVE-2099-0402", APPLE_1]},
        {"check": "platform.windows_update.2026-sep", "asset": "host:pc", "severity": "high",
         "title": "2026-Sep security update not installed (build 10.0.26200.200): 1 CVEs (1 critical, exploited CVE-2099-0601)"},
        {"check": "platform.windows_update.2026-oct", "asset": "host:pc", "severity": "medium"},
        F("CVE-2099-0501", "host:router", "critical", layer="host", needs_human=True,
          attributes={"candidate": True, "matcher": "kev-vendor"})]
    h.write_case("collector-vuln-intel", "hosts-kernel-platforms-firmware", {
        "title": "Host inventories: distro packages through a CycloneDX SBOM and trivy (the running kernel aggregated, "
                 "other installed kernels only evidence), an fs SBOM also through OSV, Android bulletins newer than the "
                 "patch level, Apple releases of the same major line, MSRC monthly updates by build, KEV entries of the "
                 "firmware vendor after the build date; a host no matcher applies to is a gap. Cached feeds only",
        "contract": C, "origin": "tests/test_hostintel.py; collectors/vuln-intel/hostmatch.py",
        "files": files,
        "steps": [{"name": "collect", "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
                   "expect": h.protocol_checks("vuln-intel") + [
                       {"json": "run/vuln-intel.findings.json", "subset": {
                           "coverage": {"$contains": [
                               {"asset": "host:web1", "status": "ok"}, {"asset": "host:phone", "status": "ok"},
                               {"asset": "host:laptop", "status": "ok"}, {"asset": "host:pc", "status": "ok"},
                               {"asset": "host:router", "status": "ok"},
                               {"asset": "host:nas", "status": "gap", "reason": {"$regex": "^no matcher applies"}}]},
                           "findings": {"$unordered": findings}}},
                       {"json": "run/raw/vuln-intel/matches.json", "subset": {"host:web1|kernel": {
                           "other_installed_kernel_packages": ["linux-image-6.8.0-45-generic"], "fixed_in": "6.8.0-52.53"}}},
                       {"prom": "run/vuln-intel.prom", "has": [
                           {"name": "security_host_kernel_cves_fixable", "labels": {"host": "web1"}, "value": 2},
                           {"name": "security_sbom_unmatched_packages", "labels": {"kind": "opkg"}, "value": 1},
                           {"name": "security_sbom_unmatched_packages", "labels": {"kind": "brew"}, "value": 1},
                           {"name": "security_intel_firmware_vendors_without_source", "value": 1}]}]}]},
        cf)


# ---- target behaviour: the feed mirror (VULN-D*) -------------------------------------------------------------------
def mirror_case(h, name, title, deviation, routes, feeds, stale, expect, steps2=None):
    files, cf = base_files({"data/latest/inventory.k8s-images.json": "inventory.json"}), case_files()
    cf["inventory.json"] = inventory([item("prod", "registry.example/web:1.4", True, True, "docker-pullable://" + WEB_DIGEST)])
    cf["instance.json"] = {"name": "conformance", "intel": {"feeds": feeds}}
    cf["routes.json"] = routes
    cf["mirror-kev.json"] = KEV
    cf["mirror-epss.csv.gz"] = gzip_stored(EPSS)
    cf["mock_feeds.py"] = open(os.path.join(HERE, "fakes", "mock_feeds.py")).read()
    for rel, (content, raw, etag) in stale.items():      # copies confirmed long ago: revalidated on this run
        nm = "stale-" + rel.replace("/", "-")
        cf[nm] = content
        files[f"data/cache/feeds/{rel}"] = {"raw": nm} if raw else nm
        files[f"data/cache/feeds/{rel}.meta.json"] = {"json": {"etag": etag, "last_modified": None, "url": "x", "checked_at": 1000}}
    steps = [{"name": "collect", "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
              "expect": h.protocol_checks("vuln-intel") + expect + [{"file": ".svc-feeds.calls", "not_regex": ["^(?!GET ).+"]}]}]
    h.write_case("collector-vuln-intel", name, {
        "title": title, "contract": C, "deviation": deviation,
        "origin": "adapters/feeds.py fetch(): fixed source URLs, cache replaced before the payload is read",
        "services": [{"name": "feeds", "argv": ["{python}", "{case}/mock_feeds.py", "--routes", "{case}/routes.json",
                                                "--log", "{sandbox}/.svc-feeds.calls"]}],
        "files": files, "steps": steps + (steps2 or [])}, cf)


def deviation_cases(h):
    kev_finding = {"json": "run/vuln-intel.findings.json", "subset": {"findings": {"$contains": [
        F("CVE-2099-0002", "image:registry.example/web:1.4", "critical", title={"$regex": r"\[KEV\]$"})]}}}
    mirror_case(
        h, "feed-mirror-conditional-get",
        "A feed can be read from a configured mirror (`url`): a cached copy is revalidated with If-None-Match and a "
        "304 keeps it (KEV enrichment applies), a new feed is downloaded and cached with its ETag, and a fresh copy "
        "is not asked for again. Only GET requests", "VULN-D1",
        {"/kev.json": {"file": "mirror-kev.json", "etag": '"kev-1"'}, "/epss.csv.gz": {"file": "mirror-epss.csv.gz", "etag": '"epss-7"'}},
        [{"type": "cisa-kev", "url": "{svc_feeds}/kev.json", "max_age_hours": 0}, {"type": "epss", "url": "{svc_feeds}/epss.csv.gz"}],
        {"known_exploited_vulnerabilities.json": (KEV, False, '"kev-1"')},
        [{"json": "run/vuln-intel.findings.json", "subset": {"coverage": {"$contains": [
            {"asset": "feed:cisa-kev", "status": "ok"}, {"asset": "feed:epss", "status": "ok"}]}}},
         kev_finding,
         {"file": "data/cache/feeds/epss_scores-current.csv.gz.meta.json", "regex": ['"\\\\"epss-7\\\\""']},
         {"file": ".svc-feeds.calls", "regex": ['^GET /kev.json inm="kev-1"$', "^GET /epss.csv.gz inm=-$"], "lines": 2}],
        [{"name": "again: KEV revalidated (max_age_hours 0), EPSS still fresh", "remove": ["run"],
          "exec": {"impl": "collector-vuln-intel", "env": env(h), "writes_only_under": WRITES},
          "expect": [kev_finding, {"file": ".svc-feeds.calls", "lines": 3, "regex": ['inm=-\\nGET /kev.json inm="kev-1"$']}]}])
    mirror_case(
        h, "corrupt-feed-keeps-last-good-copy",
        "A download that does not parse (an HTML error page) or exceeds the feed's size limit never replaces the last "
        "good cached copy: the copy stays in use (KEV enrichment applies) and the feed is a coverage gap that says so",
        "VULN-D2",
        {"/kev.json": {"body": "<html>maintenance</html>", "etag": '"kev-2"'}, "/epss.csv.gz": {"file": "mirror-epss.csv.gz", "etag": '"epss-8"'}},
        [{"type": "cisa-kev", "url": "{svc_feeds}/kev.json"}, {"type": "epss", "url": "{svc_feeds}/epss.csv.gz", "max_bytes": 64}],
        {"known_exploited_vulnerabilities.json": (KEV, False, '"kev-1"'), "epss_scores-current.csv.gz": (gzip_stored(EPSS), True, '"epss-1"')},
        [{"json": "run/vuln-intel.findings.json", "subset": {"coverage": {"$contains": [
            {"asset": "feed:cisa-kev", "status": "gap", "reason": {"$regex": "rejected.*using the copy confirmed at 1970-01-01T00:16:40Z"}},
            {"asset": "feed:epss", "status": "gap", "reason": {"$regex": "rejected.*64 bytes"}}]}}},
         kev_finding,
         {"file": "data/cache/feeds/known_exploited_vulnerabilities.json", "regex": ["CVE-2099-0002"], "not_regex": ["maintenance"]},
         {"file": "data/cache/feeds/known_exploited_vulnerabilities.json.meta.json", "regex": ["kev-1"], "not_regex": ["kev-2"]}])
    mirror_case(
        h, "feed-outage-uses-cached-copy",
        "When a feed cannot be refreshed (HTTP 503), a cached copy is still used (KEV enrichment applies) and the feed "
        "is a gap that says since when the copy is confirmed, with its real age; without a copy the feed is a plain gap",
        "VULN-D3",
        {"/kev.json": {"status": 503}, "/epss.csv.gz": {"status": 503}},
        [{"type": "cisa-kev", "url": "{svc_feeds}/kev.json"}, {"type": "epss", "url": "{svc_feeds}/epss.csv.gz"}],
        {"known_exploited_vulnerabilities.json": (KEV, False, '"kev-1"')},
        [{"json": "run/vuln-intel.findings.json", "subset": {"coverage": {"$contains": [
            {"asset": "feed:cisa-kev", "status": "gap",
             "reason": {"$regex": "refresh failed: HTTP 503.*using the copy confirmed at 1970-01-01T00:16:40Z"}},
            {"asset": "feed:epss", "status": "gap", "reason": {"$regex": "HTTP 503"}}]}}},
         kev_finding,
         {"prom": "run/vuln-intel.prom", "has": [{"name": "security_intel_feed_age_seconds", "labels": {"feed": "cisa-kev"}}],
          "absent": [{"name": "security_intel_feed_age_seconds", "labels": {"feed": "epss"}}]}])


def cases(h):
    images_case(h)
    partial_case(h)
    registry_case(h)
    hosts_case(h)
    deviation_cases(h)
