"""discovery adapter interface: find assets.

  discover(cfg) -> [ {name, address, os, online, attrs{}} ]

Implemented: tailscale (local `tailscale status --json`), static (addresses and/or CIDR ranges listed in the instance
config: `targets: [{name, address, os?}]`, `cidrs: ["10.0.0.0/28", ...]`, `exclude: [addresses]`; a CIDR expands to
its host addresses, at most `max_hosts` (default 1024) per config so a typo cannot start a /8 scan; CIDR-derived
assets carry `attrs.cidr`, and a collector may treat "nothing answers" there as "no host", not as a coverage gap),
file (a JSON list in the same shape, e.g. exported by a hub for a site that cannot discover by itself; `max_age`
seconds: older = error, so a stale list becomes a coverage gap instead of a silent scan of the wrong hosts),
gcp (Compute Engine VM instances of one or more projects, READ-ONLY: Cloud Asset API `searchAllResources` by default,
or `compute` aggregated instances.list; authenticates exactly like a GCP account of adapters/cloud.py, i.e. short-lived
service-account credentials via workload identity federation or the operator's ADC + impersonation, and refuses an
over-privileged identity like the cloud collector does).
Future (interface only): aws-vpc (ec2:DescribeInstances), azure, cmdb.
"""
import json
import subprocess
import urllib.parse

VERSION = "0.5.0"


def tailscale(cfg):
    out = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=30).stdout
    st = json.loads(out)
    res = []
    for p, is_self in [(v, False) for v in st.get("Peer", {}).values()] + [(st.get("Self", {}), True)]:
        ip = next((a for a in p.get("TailscaleIPs", []) if "." in a), None)
        res.append(dict(name=p.get("HostName"), address=ip, os=p.get("OS"), online=bool(p.get("Online")) or is_self,
                        attrs=dict(self=is_self, exit_node_option=bool(p.get("ExitNodeOption")),
                                   online_verified=True,   # the control plane saw it (static targets are assumed)
                                   key_expiry_disabled=p.get("KeyExpiry") is None and not is_self)))
    return res


def static(cfg):
    import ipaddress
    res = [dict(name=t.get("name", t["address"]), address=t["address"], os=t.get("os", ""), online=True, attrs={})
           for t in cfg.get("targets", [])]
    seen = {r["address"] for r in res} | set(cfg.get("exclude", []))
    limit = int(cfg.get("max_hosts", 1024))
    for c in cfg.get("cidrs", []):
        net = ipaddress.ip_network(c, strict=False)
        if net.num_addresses > limit + 2:
            raise ValueError(f"CIDR {c} has {net.num_addresses} addresses (max_hosts {limit})")
        for ip in (net.hosts() if net.num_addresses > 2 else net):
            a = str(ip)
            if a not in seen:
                seen.add(a)
                res.append(dict(name=a, address=a, os="", online=True, attrs={"cidr": str(net)}))
    return res


def file(cfg):
    import os
    import time
    p = os.path.expanduser(cfg["path"])
    age = time.time() - os.path.getmtime(p)
    if cfg.get("max_age") and age > float(cfg["max_age"]):
        raise RuntimeError(f"asset list is {int(age)}s old (max_age {cfg['max_age']})")
    return [dict(name=d["name"], address=d.get("address"), os=d.get("os", ""), online=bool(d.get("online", True)),
                 attrs=d.get("attrs", {})) for d in json.load(open(p))]


def _gcp_get(url, token):
    from adapters import cloud
    st, out = cloud.http("GET", url, None, {"Authorization": "Bearer " + token})
    if st != 200:
        api = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1].split(":")[-1] or "list"
        raise cloud.CloudAuthError(f"gcp discovery {api}: HTTP {st} {cloud._err_text(out)}")
    return json.loads(out)


def _gcp_instances_asset(base, project, token, limit):
    """Cloud Asset API searchAllResources (assetTypes=compute Instance) -> [(name, zone, status, internal, external)]."""
    out, page = [], None
    while True:
        q = {"assetTypes": "compute.googleapis.com/Instance", "pageSize": "500"}
        if page:
            q["pageToken"] = page
        d = _gcp_get(f"{base}/projects/{urllib.parse.quote(project)}:searchAllResources?{urllib.parse.urlencode(q)}", token)
        for r in d.get("results") or []:
            a = r.get("additionalAttributes") or {}
            out.append((r.get("displayName") or r.get("name", "").rsplit("/", 1)[-1], r.get("location", ""),
                        r.get("state", ""), list(a.get("internalIPs") or []), list(a.get("externalIPs") or [])))
        page = d.get("nextPageToken")
        if len(out) > limit:
            raise ValueError(f"gcp project {project} has more than {limit} instances (max_hosts)")
        if not page:
            return out


def _gcp_instances_compute(base, project, token, limit):
    """Compute Engine aggregated instances.list -> [(name, zone, status, internal, external)]."""
    out, page = [], None
    while True:
        q = {"maxResults": "500", "returnPartialSuccess": "true"}
        if page:
            q["pageToken"] = page
        d = _gcp_get(f"{base}/projects/{urllib.parse.quote(project)}/aggregated/instances?{urllib.parse.urlencode(q)}", token)
        for scope, v in sorted((d.get("items") or {}).items()):
            for i in v.get("instances") or []:
                nics = i.get("networkInterfaces") or []
                out.append((i.get("name", ""), scope.removeprefix("zones/"), i.get("status", ""),
                            [n["networkIP"] for n in nics if n.get("networkIP")],
                            [c["natIP"] for n in nics for c in n.get("accessConfigs") or [] if c.get("natIP")]))
        page = d.get("nextPageToken")
        if len(out) > limit:
            raise ValueError(f"gcp project {project} has more than {limit} instances (max_hosts)")
        if not page:
            return out


def gcp(cfg):
    """{type: gcp, project_id, project_ids?, api?: cloudasset|compute, address?: external|internal,
    include_stopped?: false, max_hosts?: 1024, refuse_over_privileged?: true, + the keys of a GCP cloud account
    (source, service_account, workload_identity_provider, identity_token, endpoint overrides)} -> VM instances.
    Read-only GET calls only. An instance without an address of the requested kind is listed with address None (the
    exposure collector then has nothing to probe for it); stopped instances are left out unless include_stopped."""
    from adapters import cloud
    prov = cloud.provider(dict(cfg, provider="gcp"))
    if cfg.get("refuse_over_privileged", True):
        perm = prov.permissions()
        if perm.get("write_capable"):
            raise cloud.CloudAuthError("refused: the discovery identity is over-privileged (read-only expected): "
                                       + ", ".join(perm["write_capable"])[:200])
    token = prov.credentials()["access_token"]
    api = cfg.get("api", "cloudasset")
    if api == "cloudasset":
        base = cfg.get("cloudasset_url", "https://cloudasset.googleapis.com/v1").rstrip("/")
        lister = _gcp_instances_asset
    elif api == "compute":
        base = cfg.get("compute_url", "https://compute.googleapis.com/compute/v1").rstrip("/")
        lister = _gcp_instances_compute
    else:
        raise ValueError(f"gcp discovery api {api!r} unknown (cloudasset, compute)")
    want = cfg.get("address", "external")
    if want not in ("external", "internal"):
        raise ValueError(f"gcp discovery address {want!r} unknown (external, internal)")
    limit = int(cfg.get("max_hosts", 1024))
    res = []
    for project in cfg.get("project_ids") or [prov.account]:
        for name, zone, status, internal, external in lister(base, project, token, limit):
            running = status == "RUNNING"
            if not running and not cfg.get("include_stopped"):
                continue
            addrs = external if want == "external" else internal
            res.append(dict(name=name, address=addrs[0] if addrs else None, os="", online=running,
                            attrs=dict(provider="gcp", project=project, zone=zone, status=status,
                                       online_verified=running,   # the control plane says RUNNING
                                       external=bool(external), asset=f"cloud:gcp/{project}/compute/{name}")))
    return res


def apply_scope(devices, scope):
    """Instance `scope:` entries (see spsdk.asset_scope): attach the asset's scope to attrs, and drop devices that
    are offline when `offline: expected` (scanned only when online; offline is not a coverage gap)."""
    out = []
    for d in devices:
        s = next((x for x in scope or [] if d.get("name") in (x.get("names") or [])), None)
        if s:
            d = dict(d, attrs=dict(d.get("attrs") or {}, scope=list(s.get("scope") or [])))
            if not d["online"] and s.get("offline") == "expected":
                continue
        out.append(d)
    return out


def _future(cfg):
    raise NotImplementedError(f"discovery adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"tailscale": tailscale, "static": static, "file": file, "gcp": gcp, "aws-vpc": _future, "azure": _future}


def discover(cfg):
    return ADAPTERS[cfg["type"]](cfg)
