#!/usr/bin/env python3
"""Collector `exposure`: what an outsider sees. Open TCP ports + which HTTP(S) services answer without auth.

Adapters (from the instance config, section `exposure`):
  discovery: [ {type: tailscale} | {type: static, targets: [{name, address}]} ]   -> targets
  vantage:   an exec adapter config for a host OUTSIDE the targets' trust zone (the role, not a device)
  extra_ports: "P,Q"   ports to scan on top of nmap top-1000 + the built-in known list
Classification is by response fingerprint (generic), not by the instance's port numbers.
SP_EXPOSURE_RAW=<file> re-classifies an existing probe result without scanning again.
"""
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import discovery, exec as ex  # noqa: E402

VERSION = open(os.path.join(os.path.dirname(__file__), "VERSION")).read().strip()


def st(e, p):
    return (e.get("paths", {}).get(p) or {}).get("status")


def ok2xx(e, p):
    r = e.get("paths", {}).get(p) or {}
    return bool(r.get("status")) and 200 <= r["status"] < 300 and not r.get("auth")


def snip(e, p):
    return (e.get("paths", {}).get(p) or {}).get("snippet", "")


def classify(port, e):
    """-> list of (check, severity, title, remediation). Fingerprints only; no port-number assumptions
    except for non-HTTP protocols, which nmap already names."""
    out = []
    svc = e.get("nmap_service", "")
    if "paths" not in e:
        if port == 23 or svc == "telnet":
            out.append(("telnet.open", "high", "telnet (cleartext remote login) is reachable",
                        "disable telnetd / firewall the port"))
        elif port in (5432, 55432, 3306, 6379, 27017, 9200, 2379) or svc in ("postgresql", "mysql", "redis", "mongodb"):
            out.append(("db.reachable", "medium", f"database port reachable from the vantage point ({svc or port})",
                        "bind to localhost / a private bridge; firewall it"))
        elif svc in ("netbios-ssn", "microsoft-ds"):
            out.append(("smb.reachable", "medium", f"SMB ({svc}) is reachable from the vantage point",
                        "bind SMB to the LAN only / disable guest access"))
        return out
    paths = e["paths"]
    two = [p for p in paths if ok2xx(e, p)]
    same_body = len({snip(e, p) for p in two}) == 1 and len(two) >= 6
    if same_body:  # SPA / catch-all: every path answers the same page -> cannot tell, flag for review
        out.append(("http.catch_all_unverified", "low",
                    "web app answers every path with the same page; login enforcement not verifiable by GET",
                    "verify login is required; ensure open sign-up is disabled"))
        return out
    authed_api = any(r.get("status") in (401, 403) or r.get("auth") for r in paths.values())
    if ok2xx(e, "/api/v2/status") and ("cluster" in snip(e, "/api/v2/status") or "config" in snip(e, "/api/v2/status")):
        out.append(("alertmanager.unauth", "high", "Alertmanager API without auth: anyone can create silences",
                    "put behind an auth proxy or expose only via port-forward"))
    elif ok2xx(e, "/api/v1/status/buildinfo") and "version" in snip(e, "/api/v1/status/buildinfo"):
        out.append(("prometheus.unauth_read", "medium",
                    "Prometheus query API without auth (topology, labels, targets disclosed)",
                    "auth proxy; keep the admin API disabled"))
    flags = (e.get("paths", {}).get("/api/v1/status/flags") or {}).get("fields") or {}
    if flags.get("web.enable-remote-write-receiver") == "true":
        out.append(("prometheus.unauth_remote_write", "high",
                    "Prometheus remote_write receiver accepts unauthenticated clients: metrics (incl. SLOs) can be forged",
                    "auth/mTLS on the receiver or an allowlist of writers"))
    if ok2xx(e, "/api/tags") and "models" in snip(e, "/api/tags"):
        out.append(("ollama.unauth", "high", "Ollama API without auth: anyone can run, pull or delete models",
                    "bind to localhost behind an authenticating proxy"))
    if flags.get("web.enable-admin-api") == "true":
        out.append(("prometheus.admin_api_unauth", "high", "Prometheus admin API enabled without auth (delete series)",
                    "disable --web.enable-admin-api or put behind auth"))
    if ok2xx(e, "/loki/api/v1/labels") and '"status":"success"' in snip(e, "/loki/api/v1/labels").replace(" ", ""):
        out.append(("loki.unauth", "high", "Loki without auth: all shipped logs readable and forgeable (query + push)",
                    "auth proxy / per-tenant auth"))
    if ok2xx(e, "/api/search") and "traces" in snip(e, "/api/search"):
        out.append(("tempo.unauth_read", "medium", "Tempo search API without auth: traces readable",
                    "auth proxy"))
    if st(e, "/v1/traces") == 405:
        out.append(("otlp.unauth_ingest", "low", "OTLP/HTTP ingest without auth: spans can be forged",
                    "allowlist senders"))
    if st(e, "/probe") == 400 and "target" in snip(e, "/probe").lower() or (
            st(e, "/probe") == 400 and "blackbox" in snip(e, "/").lower()):
        out.append(("blackbox.open_probe", "medium",
                    "blackbox_exporter /probe reachable: usable as an SSRF relay into the network",
                    "restrict callers to the monitoring server"))
    if not out and ok2xx(e, "/metrics"):
        out.append(("metrics.unauth", "low", "/metrics readable without auth (software versions, internals)",
                    "restrict to the scraper"))
    if not out and ok2xx(e, "/") and not authed_api:
        out.append(("http.unauth_root", "low", "HTTP service answers / without auth (purpose unknown)",
                    "identify the service; require auth or close"))
    return out


def main():
    inst = spsdk.load_instance()
    cfg = inst.get("exposure", {})
    c = spsdk.Collector("exposure", VERSION)
    devices = []
    for dcfg in cfg.get("discovery", []):
        try:
            devices += discovery.discover(dcfg)
        except Exception as err:  # noqa: BLE001
            c.gap(f"discovery:{dcfg.get('type')}", f"{type(err).__name__}: {err}")
    ev_dev = c.raw("devices.json", devices)
    targets, name_of, verified = [], {}, set()
    for d in devices:
        if not d.get("address"):
            continue
        name_of[d["address"]] = d["name"]
        if d["online"] and d["attrs"].get("online_verified"):
            verified.add(d["address"])
        if not d["online"]:
            c.gap(f"host:{d['name']}", "offline at scan time")
            continue
        targets.append(d["address"])
        c.ok(f"host:{d['name']}")   # covers exactly this asset (discovery facts), not its endpoints
        if d["attrs"].get("key_expiry_disabled"):
            c.finding("identity", f"host:{d['name']}", "overlay.node_key_expiry_disabled",
                      "overlay-network node key never expires", "low", ev_dev,
                      "enable key expiry, or record an exception for unattended servers", needs_human=True)
    targets = list(dict.fromkeys(targets))
    if os.environ.get("SP_EXPOSURE_RAW"):
        res = json.load(open(os.environ["SP_EXPOSURE_RAW"]))
    else:
        probe = open(os.path.join(os.path.dirname(__file__), "remote", "vantage_probe.py")).read()
        args = ["python", "-"] + (["--ports", cfg["extra_ports"]] if cfg.get("extra_ports") else []) + targets
        rc, out, err = ex.executor(cfg["vantage"]).run(args, stdin=probe, timeout=3600)
        if rc != 0:
            c.gap("vantage", f"probe failed rc={rc}: {err.strip()[-200:]}")
            c.write()
            return
        res = json.loads(out)
    c.tools.update(res.get("tools", {}))
    ev = c.raw("probe.json", res)
    unauth = open_ports = 0
    for ip, ports in res["hosts"].items():
        asset = f"net-endpoint:{name_of.get(ip, ip)}@{ip}"
        if not ports:
            if ip in verified:   # discovery saw it online at scan time: nothing open = fully filtered (the goal)
                c.ok(asset)
                continue
            # -Pn scan of an address nobody vouched for: down or filtered cannot be told apart -> no "fixed"
            c.gap(f"host:{name_of.get(ip, ip)}", "no open port seen from the vantage point (down or filtered)")
            continue
        c.ok(asset)
        open_ports += len(ports)
        for port_s, e in ports.items():
            for check, sev, title, fix in classify(int(port_s), e):
                if check not in ("metrics.unauth", "http.catch_all_unverified", "otlp.unauth_ingest"):
                    unauth += 1
                c.finding("network", f"{asset}:{port_s}", check, f"{title} ({ip}:{port_s})", sev,
                          f"{ev}#{ip}/{port_s}", fix, kind="detection")
    c.metric("security_exposure_open_ports", open_ports, "Open TCP ports seen from the vantage point (all targets)")
    c.metric("security_exposure_unauth_services", unauth,
             "Sensitive services answering without auth, seen from the vantage point")
    c.write()


if __name__ == "__main__":
    main()
