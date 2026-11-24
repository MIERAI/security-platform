"""discovery adapter interface: find assets.

  discover(cfg) -> [ {name, address, os, online, attrs{}} ]

Implemented: tailscale (local `tailscale status --json`), static (addresses/CIDRs listed in the instance config).
Future (interface only): aws-vpc (ec2:DescribeInstances), gcp (compute.instances.list), azure, cmdb.
"""
import json
import subprocess

VERSION = "0.1.0"


def tailscale(cfg):
    out = subprocess.run(["tailscale", "status", "--json"], capture_output=True, text=True, timeout=30).stdout
    st = json.loads(out)
    res = []
    for p, is_self in [(v, False) for v in st.get("Peer", {}).values()] + [(st.get("Self", {}), True)]:
        ip = next((a for a in p.get("TailscaleIPs", []) if "." in a), None)
        res.append(dict(name=p.get("HostName"), address=ip, os=p.get("OS"), online=bool(p.get("Online")) or is_self,
                        attrs=dict(self=is_self, exit_node_option=bool(p.get("ExitNodeOption")),
                                   key_expiry_disabled=p.get("KeyExpiry") is None and not is_self)))
    return res


def static(cfg):
    return [dict(name=t.get("name", t["address"]), address=t["address"], os=t.get("os", ""), online=True, attrs={})
            for t in cfg.get("targets", [])]


def _future(cfg):
    raise NotImplementedError(f"discovery adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"tailscale": tailscale, "static": static, "aws-vpc": _future, "gcp": _future, "azure": _future}


def discover(cfg):
    return ADAPTERS[cfg["type"]](cfg)
