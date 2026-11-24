"""discovery adapter interface: find assets.

  discover(cfg) -> [ {name, address, os, online, attrs{}} ]

Implemented: tailscale (local `tailscale status --json`), static (addresses and/or CIDR ranges listed in the instance
config: `targets: [{name, address, os?}]`, `cidrs: ["10.0.0.0/28", ...]`, `exclude: [addresses]`; a CIDR expands to
its host addresses, at most `max_hosts` (default 1024) per config so a typo cannot start a /8 scan; CIDR-derived
assets carry `attrs.cidr`, and a collector may treat "nothing answers" there as "no host", not as a coverage gap),
file (a JSON list in the same shape, e.g. exported by a hub for a site that cannot discover by itself; `max_age`
seconds: older = error, so a stale list becomes a coverage gap instead of a silent scan of the wrong hosts).
Future (interface only): aws-vpc (ec2:DescribeInstances), gcp (compute.instances.list), azure, cmdb.
"""
import json
import subprocess

VERSION = "0.3.0"


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


def _future(cfg):
    raise NotImplementedError(f"discovery adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"tailscale": tailscale, "static": static, "file": file, "aws-vpc": _future, "gcp": _future, "azure": _future}


def discover(cfg):
    return ADAPTERS[cfg["type"]](cfg)
