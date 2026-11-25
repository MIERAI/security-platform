#!/usr/bin/env python3
"""A fake `trivy` for the conformance suite: answers from recorded data instead of scanning. Test tool, stdlib only.
Started through a wrapper script on PATH (bin/trivy), so implementations run it like the real one.

  FAKE_TRIVY_DATA  JSON: {"version": {...}, "images": {"<ref as scanned>": {"sbom": {CycloneDX}} | {"error": "...",
                   "rc": N}}, "fs": {"<directory name>": {CycloneDX}},
                   ...}; an image with "auth": true fails as UNAUTHORIZED unless TRIVY_PASSWORD is set "vulns": {"<name>@<version>": [vulnerability]}}
  FAKE_TRIVY_LOG   every call is appended as one line: the arguments after the global options, then
                   "auth=yes|no" (whether TRIVY_PASSWORD is set; its value is never written anywhere)

`sbom FILE` and `fs DIR --format json` report, for every component of the SBOM, the recorded vulnerabilities of
"<name>@<version>" (PkgName / InstalledVersion filled in), in component order, as one Result whose Target is the
SBOM's metadata.component.name (else the file name).
"""
import json
import os
import sys


def fail(msg, rc=1):
    sys.stderr.write(msg + "\n")
    sys.exit(rc)


def report(cdx, target, data):
    vulns = []
    for c in cdx.get("components") or []:
        for v in data.get("vulns", {}).get(f"{c.get('name')}@{c.get('version')}", []):
            vulns.append(dict(v, PkgName=c.get("name"), InstalledVersion=c.get("version")))
    name = ((cdx.get("metadata") or {}).get("component") or {}).get("name") or target
    return {"SchemaVersion": 2, "ArtifactName": target, "Results": [{"Target": name, "Class": "lang-pkgs", "Vulnerabilities": vulns}]}


def opt(args, name):
    return args[args.index(name) + 1] if name in args else None


def main():
    args = sys.argv[1:]
    glob_opts = []
    while args and args[0] in ("--cache-dir", "--quiet"):
        glob_opts += args[:2] if args[0] == "--cache-dir" else args[:1]
        args = args[2:] if args[0] == "--cache-dir" else args[1:]
    if "--cache-dir" not in glob_opts or "--quiet" not in glob_opts:
        fail("fake trivy: expected the global options --cache-dir DIR --quiet first")
    log = os.environ.get("FAKE_TRIVY_LOG")
    if log:
        with open(log, "a") as f:
            f.write(" ".join(args) + " auth=" + ("yes" if os.environ.get("TRIVY_PASSWORD") else "no") + "\n")
    data = json.load(open(os.environ["FAKE_TRIVY_DATA"]))
    cmd = args[0] if args else ""
    if cmd == "version":
        print(json.dumps(data.get("version") or {}))
    elif cmd == "image" and "--download-db-only" in args:
        return
    elif cmd == "image":
        rec = data.get("images", {}).get(args[-1])
        if rec is None:
            fail(f"fake trivy: no recorded image {args[-1]}")
        if "error" in rec:
            fail(rec["error"], rec.get("rc", 1))
        if rec.get("auth") and not os.environ.get("TRIVY_PASSWORD"):
            fail("UNAUTHORIZED: authentication required")
        json.dump(rec["sbom"], open(opt(args, "--output"), "w"))
    elif cmd == "sbom":
        cdx = json.load(open(args[-1]))
        print(json.dumps(report(cdx, os.path.basename(args[-1]), data)))
    elif cmd == "fs":
        name = os.path.basename(args[-1].rstrip("/"))
        cdx = data.get("fs", {}).get(name)
        if cdx is None:
            fail(f"fake trivy: no recorded directory {name}")
        if opt(args, "--format") == "cyclonedx":
            json.dump(cdx, open(opt(args, "--output"), "w"))
        else:
            print(json.dumps(report(cdx, name, data)))
    else:
        fail(f"fake trivy: unknown command {cmd!r}")


if __name__ == "__main__":
    main()
