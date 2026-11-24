"""Deterministic OSV range matching for SBOM components (CycloneDX purls). Stdlib only.

Ranges of type SEMVER (and ECOSYSTEM for Go, whose versions are semver) are evaluated; other ecosystems match only
on the explicit `versions` list (exact), so an unknown version scheme never produces a guess.
"""
import re

PURL_ECO = {"golang": "Go", "pypi": "PyPI", "npm": "npm", "maven": "Maven", "cargo": "crates.io", "gem": "RubyGems",
            "nuget": "NuGet"}


def semver_key(v):
    v = v.lstrip("v")
    if v in ("0", ""):
        return ((0,), (1,))
    main, _, pre = v.partition("-")
    main = main.split("+")[0]
    nums = tuple(int(x) if x.isdigit() else 0 for x in main.split("."))
    nums = nums + (0,) * (3 - len(nums))
    if not pre:
        return (nums, (1,))
    return (nums, (0,) + tuple((0, int(p)) if p.isdigit() else (1, p) for p in re.split(r"[.]", pre)))


def in_range(version, events):
    key = semver_key(version)
    affected = False
    evs = []
    for e in events:
        for k, v in e.items():
            evs.append((semver_key(v), k))
    order = {"introduced": 0, "fixed": 1, "last_affected": 2, "limit": 3}
    for vk, kind in sorted(evs, key=lambda x: (x[0], order.get(x[1], 9))):
        if kind == "introduced" and vk <= key:
            affected = True
        elif kind == "fixed" and vk <= key:
            affected = False
        elif kind == "last_affected" and vk < key:
            affected = False
        elif kind == "limit" and vk <= key:
            affected = False
    return affected


def fixed_version(adv):
    for r in adv["ranges"]:
        for e in r["events"]:
            if "fixed" in e:
                return e["fixed"]
    return ""


def components(cdx):
    """CycloneDX document -> [(ecosystem, name, version)]."""
    out = []
    for c in cdx.get("components") or []:
        purl = c.get("purl") or ""
        m = re.match(r"pkg:([a-z]+)/(.+)@([^?#]+)", purl)
        if not m or m.group(1) not in PURL_ECO:
            continue
        name = m.group(2).replace("%2F", "/").replace("%40", "@")
        if m.group(1) == "maven":
            name = name.replace("/", ":", 1)
        out.append((PURL_ECO[m.group(1)], name, m.group(3)))
    return out


def match(comps, index):
    """-> [(ecosystem, name, version, advisory)]"""
    hits = []
    for eco, name, ver in comps:
        for adv in (index.get(eco) or {}).get(name, []):
            hit = ver in adv["versions"] or ver.lstrip("v") in adv["versions"]
            if not hit:
                for r in adv["ranges"]:
                    if r["type"] == "SEMVER" or (r["type"] == "ECOSYSTEM" and eco == "Go"):
                        if in_range(ver, r["events"]):
                            hit = True
                            break
            if hit:
                hits.append((eco, name, ver, adv))
    return hits
