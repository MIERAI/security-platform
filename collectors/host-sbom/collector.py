#!/usr/bin/env python3
"""Collector `host-sbom`: software inventory (SBOM) of every host, READ-ONLY, through an exec adapter + an OS profile.

Instance config: the same `hosts: [{name, exec, profile, ...}]` list as the `host` collector, plus optional per host
  sbom: false                       skip this host
  exposed: true|false               the host is reachable from outside its trust zone (priority input for vuln-intel)
  prod: true|false                  (default true)
  sbom_paths: [dir, ...]            local hosts only: language packages / Go binaries under these directories, via
                                    `trivy rootfs` (CycloneDX, kept in <data>/sbom/host-<name>-fs.cdx.json)
A profile prints `key=value` platform facts and `pkg<TAB>ecosystem<TAB>name<TAB>version<TAB>src<TAB>srcver<TAB>arch`
lines. New OSes are new profiles; consumers only read the contracts below.

Outputs (contract inventory/v1, read by vuln-intel):
  inventory.host-packages.json   kind host-package: {host, ecosystem, name, version, source_name, source_version, arch}
  inventory.host-platforms.json  kind host-platform: {host, profile, os_family, os_version, os_build, kernel_running,
                                 patch_level, device, firmware{vendor, model, version, build_date}, exposed, prod,
                                 fs_sbom, package_count}
Ecosystems: deb, apk, rpm, termux, brew, brew-cask, opkg, windows-kb, windows-program.
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import exec as ex  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
DATA = os.environ.get("SP_DATA", ".")
SCHEMA = "security-platform/inventory/v1"


def collect(h):
    prof = h["profile"]
    script = open(os.path.join(HERE, "profiles", prof + (".ps1" if prof == "windows" else ".sh"))).read()
    e = ex.executor(h["exec"])
    if prof == "windows":
        return ex.powershell(e, script, timeout=300)
    return e.run(["sh", "-s"], stdin=script, timeout=300)


def parse(out):
    kv, pkgs = {}, []
    for line in out.splitlines():
        line = line.rstrip("\r")
        if line.startswith("pkg\t"):
            f = (line.split("\t") + [""] * 7)[1:7]
            if f[1] and f[2]:
                pkgs.append(dict(ecosystem=f[0], name=f[1], version=f[2], source_name=f[3] or f[1],
                                 source_version=f[4] or f[2], arch=f[5]))
        elif "=" in line and not line.startswith(("#", " ")):
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv, pkgs


def platform(h, kv, pkgs):
    fw = {k: kv.get(f"firmware.{k}") for k in ("vendor", "model", "version", "channel")}
    ts = kv.get("firmware.build_ts")
    if ts and ts.isdigit():
        fw["build_date"] = time.strftime("%Y-%m-%d", time.gmtime(int(ts)))
    return dict(host=h["name"], profile=h["profile"], os_family=kv.get("os.family", ""), os_version=kv.get("os.version", ""),
                os_build=kv.get("os.build", ""), os_name=kv.get("os.name", ""), os_product=kv.get("os.product", ""),
                os_edition=kv.get("os.edition", ""), os_codename=kv.get("os.codename", ""), arch=kv.get("arch", ""),
                kernel_running=kv.get("kernel.running", ""), patch_level=kv.get("platform.patch_level", ""),
                vendor_patch_level=kv.get("platform.vendor_patch_level", ""), rsr=kv.get("os.rsr", ""),
                device=" ".join(x for x in (kv.get("device.manufacturer"), kv.get("device.model")) if x),
                firmware={k: v for k, v in fw.items() if v} or None, exposed=bool(h.get("exposed", False)),
                prod=bool(h.get("prod", True)), package_count=len(pkgs))


def fs_sbom(h, c):
    """Language packages and Go binaries under local directories (trivy rootfs, CycloneDX). Local exec only."""
    if not h.get("sbom_paths"):
        return None
    if (h.get("exec") or {}).get("type", "local") != "local":
        c.gap(f"host:{h['name']}/fs-sbom", "sbom_paths needs a local exec adapter (trivy runs on the hub)")
        return None
    out = os.path.join(DATA, "sbom", f"host-{h['name']}-fs.cdx.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    merged = None
    for p in h["sbom_paths"]:
        p = os.path.expanduser(p)
        if not os.path.isdir(p):
            continue
        r = subprocess.run(["trivy", "--cache-dir", os.path.join(DATA, "cache", "trivy"), "--quiet", "rootfs",
                            "--cache-backend", "memory", "--skip-db-update", "--scanners", "vuln", "--format", "cyclonedx", p],
                           capture_output=True, text=True, timeout=900)
        if r.returncode != 0:
            c.gap(f"host:{h['name']}/fs-sbom", f"trivy rootfs rc={r.returncode}: {r.stderr.strip()[-160:]}")
            return None
        doc = json.loads(r.stdout)
        if merged is None:
            merged = doc
        else:
            merged.setdefault("components", []).extend(doc.get("components") or [])
    if merged is None:
        return None
    with open(out + ".tmp", "w") as f:
        json.dump(merged, f)
    os.replace(out + ".tmp", out)
    return os.path.relpath(out, DATA)


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("host-sbom", VERSION)
    pkgs_all, plats = [], []
    for h in inst.get("hosts", []):
        if h.get("sbom") is False:
            continue
        a = f"host:{h['name']}"
        if not spsdk.in_scope(inst, h["name"], "host-sbom"):
            continue   # instance scope: another collector covers this asset (not a gap)
        if not h.get("exec"):
            c.gap(a, h.get("gap", "no exec adapter configured"))
            continue
        rc, out, err = collect(h)
        kv, pkgs = parse(out)
        if not kv.get("os.family"):
            c.gap(a, f"inventory failed rc={rc}: {err.strip()[-160:]}")
            continue
        c.ok(a)
        p = platform(h, kv, pkgs)
        p["fs_sbom"] = fs_sbom(h, c)
        plats.append(p)
        pkgs_all += [dict(x, host=h["name"]) for x in pkgs]
        c.raw(f"{h['name']}.json", {"platform": p, "packages": len(pkgs), "rc": rc})
        if not pkgs:
            c.finding("host", a, "sbom.no_packages", f"no package inventory for {h['profile']} host (package manager not found)",
                      "info", f"raw/host-sbom/{h['name']}.json", "check the profile / package manager")
    for kind, name, items in (("host-package", "host-packages", pkgs_all), ("host-platform", "host-platforms", plats)):
        with open(os.path.join(c.out, f"inventory.{name}.json"), "w") as f:
            json.dump({"schema": SCHEMA, "kind": kind, "generated_at": spsdk.now_iso(), "items": items}, f, indent=0)
    eco = {}
    for x in pkgs_all:
        eco[x["ecosystem"]] = eco.get(x["ecosystem"], 0) + 1
    for k, v in sorted(eco.items()):
        c.metric("security_sbom_host_packages", v, "Installed packages inventoried on hosts", kind=k)
    c.metric("security_sbom_hosts", len(plats), "Hosts with a software inventory")
    c.write()


if __name__ == "__main__":
    main()
