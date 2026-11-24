"""Hub snapshots (contract `security-platform/snapshot/v1`): a gzip tarball of the hub's private state (ledger, reports,
human-approved control files, remediation tracker) with a MANIFEST.json (schema, site, created_at, sha256 per file).

An in-cluster hub publishes it into ONE Secret of its own namespace (only the hub can write it; only the operator's
pull identity can read it, by name); the operator's workstation pulls it into its private data repository and
commits it (off-cluster copy + audit trail). Secrets, not ConfigMaps: findings are attacker intelligence.
"""
import base64
import hashlib
import io
import json
import os
import shutil
import tarfile
import time

SCHEMA = "security-platform/snapshot/v1"
KEY = "snapshot.tar.gz"
MAX = 900_000   # base64 bytes: a Secret holds 1 MiB


def pack(data, paths, site="hub", now=None):
    files = []
    for p in paths:
        full = os.path.join(data, p)
        if os.path.isfile(full):
            files.append(p)
        elif os.path.isdir(full):
            for root, _, names in os.walk(full):
                files += [os.path.relpath(os.path.join(root, n), data) for n in sorted(names)]
    files = sorted(f for f in files if not f.endswith(".tmp"))
    manifest = {"schema": SCHEMA, "site": site, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
                "files": {f: hashlib.sha256(open(os.path.join(data, f), "rb").read()).hexdigest() for f in files}}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        def add(name, blob):
            ti = tarfile.TarInfo(name)
            ti.size, ti.mtime, ti.mode = len(blob), int(now or time.time()), 0o600
            t.addfile(ti, io.BytesIO(blob))
        add("MANIFEST.json", json.dumps(manifest, indent=1, sort_keys=True).encode())
        for f in files:
            add(f, open(os.path.join(data, f), "rb").read())
    return buf.getvalue()


def unpack(blob, into):
    """Verify and extract into `into` (replaced as a whole). Only regular files named in the manifest, relative
    paths without '..', matching their sha256; anything else rejects the whole snapshot."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
        members = {m.name: m for m in t.getmembers()}
        if "MANIFEST.json" not in members:
            raise ValueError("snapshot without MANIFEST.json")
        manifest = json.load(t.extractfile(members["MANIFEST.json"]))
        if manifest.get("schema") != SCHEMA:
            raise ValueError(f"snapshot schema {manifest.get('schema')!r} != {SCHEMA}")
        want = manifest.get("files") or {}
        if set(members) != set(want) | {"MANIFEST.json"}:
            raise ValueError("snapshot members differ from its manifest")
        tmp = into.rstrip("/") + ".new"
        shutil.rmtree(tmp, ignore_errors=True)
        for name, digest in want.items():
            m = members[name]
            if not m.isfile() or name.startswith("/") or ".." in name.split("/"):
                raise ValueError(f"unsafe snapshot member {name!r}")
            blob_f = t.extractfile(m).read()
            if hashlib.sha256(blob_f).hexdigest() != digest:
                raise ValueError(f"{name}: checksum mismatch")
            dest = os.path.join(tmp, name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as f:
                f.write(blob_f)
        os.makedirs(tmp, exist_ok=True)
        with open(os.path.join(tmp, "MANIFEST.json"), "w") as f:
            json.dump(manifest, f, indent=1, sort_keys=True)
    old = into.rstrip("/") + ".old"
    shutil.rmtree(old, ignore_errors=True)
    if os.path.exists(into):
        os.rename(into, old)
    os.rename(tmp, into)
    shutil.rmtree(old, ignore_errors=True)
    return manifest


def put_secret(cfg, blob):
    from adapters import kubeapi
    data = base64.b64encode(blob).decode()
    if len(data) > MAX:
        raise ValueError(f"snapshot is {len(data)} bytes base64: too large for one Secret (trim `paths`)")
    api = kubeapi.client(cfg)
    ns = cfg.get("namespace") or api.namespace
    sec = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
           "metadata": {"name": cfg["name"], "namespace": ns,
                        "labels": {"app.kubernetes.io/part-of": "security-platform", "app.kubernetes.io/component": "snapshot"}},
           "data": {KEY: data}}
    api.request("PATCH", f"/api/v1/namespaces/{ns}/secrets/{cfg['name']}", body=sec,
                query={"fieldManager": "security-platform-runner", "force": "true"})


def get_secret(cfg):
    from adapters import kubeapi
    api = kubeapi.client(cfg)
    ns = cfg.get("namespace") or api.namespace
    sec = api.request("GET", f"/api/v1/namespaces/{ns}/secrets/{cfg['name']}")
    return base64.b64decode(sec["data"][KEY])
