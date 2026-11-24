"""Deterministic host / platform matching (stdlib only). Inputs are contracts (inventory host-package / host-platform)
and feed indexes (adapters/feeds.py); outputs are plain dicts the collector turns into findings.

  os_sbom(platform, packages)        -> CycloneDX for distro packages (deb/apk/rpm) that Trivy's DB can match
                                        (Ubuntu USN / Debian security tracker / Alpine secdb / ...), or None
  is_kernel_pkg(name, src)           -> kernel binary packages (matched separately: running vs installed kernel)
  android_missed(platform, entries)  -> [{spl, entries}] bulletins newer than the device's security patch level
  apple_missed(platform, releases)   -> [release] security releases of the same major line newer than the host's OS
  windows_missed(platform, msrc)     -> [{release, date, product, items}] monthly updates whose fixed build > host build
  vendor_kev(platform, kev, names)   -> KEV entries of the firmware vendor added after the firmware build date

Unstructured vendor advisories are NOT matched here: they are candidates for a human (see vuln-intel).
"""
import re
import urllib.parse

DISTROS = {"ubuntu": "ubuntu", "debian": "debian", "raspbian": "debian", "alpine": "alpine", "rocky": "rocky",
           "almalinux": "alma", "rhel": "redhat", "centos": "centos", "fedora": "fedora", "amzn": "amazon"}
OS_ECOS = {"deb": "deb", "apk": "apk", "rpm": "rpm"}
KERNEL_RX = re.compile(r"^linux-(image|modules|headers|tools|buildinfo|cloud-tools|objects|signatures)(-extra)?-\d")


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def os_sbom(platform, packages):
    distro = DISTROS.get((platform.get("os_family") or "").lower())
    pk = [p for p in packages if p["ecosystem"] in OS_ECOS]
    if not distro or not pk:
        return None
    ver = platform.get("os_version") or ""
    comps = [{"bom-ref": "os", "type": "operating-system", "name": distro, "version": ver}]
    refs = []
    for p in pk:
        q = urllib.parse.quote(p["version"], safe="")
        purl = f"pkg:{OS_ECOS[p['ecosystem']]}/{distro}/{urllib.parse.quote(p['name'], safe='')}@{q}?distro={distro}-{ver}"
        if p.get("arch"):
            purl += f"&arch={p['arch']}"
        if purl in refs:
            continue
        props = [{"name": "aquasecurity:trivy:SrcName", "value": p.get("source_name") or p["name"]},
                 {"name": "aquasecurity:trivy:SrcVersion", "value": p.get("source_version") or p["version"]},
                 {"name": "aquasecurity:trivy:PkgType", "value": distro}]
        comps.append({"bom-ref": purl, "type": "library", "name": p["name"], "version": p["version"], "purl": purl,
                      "properties": props})
        refs.append(purl)
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"bom-ref": "host", "type": "application", "name": "host"}},
            "components": comps, "dependencies": [{"ref": "host", "dependsOn": ["os"]}, {"ref": "os", "dependsOn": refs}]}


KERNEL_SRC_RX = re.compile(r"^linux(-signed|-meta|-hwe|-oem|-lowlatency|-generic|-aws|-azure|-gcp|-oracle|-raspi|-kvm"
                           r"|-restricted-modules|-lts)?([-.][0-9a-z.]+)*$")


def is_kernel_pkg(name, source=None):
    """Binary packages built from a kernel source (images, modules, headers, tools, bpftool, libc-dev ...): their CVEs
    are kernel CVEs and only the RUNNING kernel's matter (see kernel_running_pkg)."""
    return bool(KERNEL_RX.match(name or "")) or bool(source and source != "linux-firmware" and KERNEL_SRC_RX.match(source))


def kernel_running_pkg(name, kernel_running):
    """A kernel binary package belongs to the RUNNING kernel when its name carries the running release
    (e.g. linux-image-7.0.0-31-generic / linux-headers-7.0.0-31 for 7.0.0-31-generic)."""
    base = re.sub(r"-(generic|lowlatency|aws|azure|gcp|oracle|raspi|kvm)$", "", kernel_running or "")
    return bool(base) and (kernel_running in name or name.endswith(base) or f"{base}-" in name)


def android_missed(platform, entries):
    spl = (platform.get("patch_level") or "")[:10]
    rel = (platform.get("os_version") or "").split(".")[0]
    if not re.match(r"\d{4}-\d{2}-\d{2}", spl):
        return None
    by = {}
    for e in entries:
        if e["spl"] <= spl:
            continue
        vers = e.get("versions") or []
        numeric = [v for v in vers if re.match(r"^\d", v)]
        if numeric and not any(v == rel or v.startswith(rel + "-") for v in numeric):
            continue   # a platform release other than the device's
        by.setdefault(e["spl"], []).append(e)
    return [{"spl": k, "entries": v} for k, v in sorted(by.items())]


def apple_missed(platform, releases, product="macOS"):
    cur = vtuple(platform.get("os_version"))
    if not cur:
        return None
    out = []
    for r in releases:
        if r.get("product") != product or not r.get("version"):
            continue
        v = vtuple(r["version"])
        if v[:1] == cur[:1] and v > cur:
            out.append(r)
    return sorted(out, key=lambda r: vtuple(r["version"]))


def windows_product(platform):
    b = vtuple(platform.get("os_build"))
    if len(b) < 3:
        return None
    gen = "11" if b[2] >= 22000 else "10"
    arch = {"AMD64": "x64", "ARM64": "ARM64", "X86": "32-bit"}.get((platform.get("arch") or "").upper(), "x64")
    return f"Windows {gen} Version {platform.get('os_version')} for {arch}-based Systems"


def windows_missed(platform, msrc):
    prod = windows_product(platform)
    items = ((msrc or {}).get("products") or {}).get(prod) if prod else None
    if items is None:
        return None, prod
    cur = vtuple(platform.get("os_build"))
    by = {}
    for it in items:
        fb = vtuple(it["fixed_build"])
        if len(fb) == len(cur) and fb[:3] == cur[:3] and fb > cur:
            by.setdefault(it["release"], []).append(it)
    return [{"release": k, "date": v[0]["date"], "product": prod, "items": v} for k, v in sorted(by.items(), key=lambda x: x[1][0]["date"])], prod


def vendor_kev(platform, kev, vendor_names):
    fw = platform.get("firmware") or {}
    since = fw.get("build_date") or "0000-00-00"
    names = [n.lower() for n in vendor_names or []]
    return [dict(cve=c, **v) for c, v in kev.items()
            if (v.get("vendor") or "").lower() in names and (v.get("date_added") or "") >= since]
