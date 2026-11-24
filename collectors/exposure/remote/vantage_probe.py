"""Runs ON THE VANTAGE HOST (any host outside the targets: a spare device, a cloud VM, a CI runner).
Needs only python3 + nmap. Gives the external / attacker view of the targets passed on the command line.

Read-only: TCP connect scan (nmap -sT, no root) at a gentle rate, then a handful of
GET requests per HTTP(S) port to see whether it answers without authentication.
No POST/PUT/DELETE, no credentials, no exploitation. Prints one JSON document on stdout.

usage: python vantage_probe.py [--ports P,Q,..] <ip> [<ip> ...]
"""
import json
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

KNOWN = ("22,53,80,139,443,445,2379,3000,3080,3100,3200,4317,4318,5335,5432,6443,8022,8080,8085,8384,8443,8770,"
         "8888,9090,9091,9093,9100,9115,9195,10250,10255,11434,11435,18080-18082,19090,30080-30090,30115")
# GET only. Write endpoints are detected by their 405 answer to GET (no data is ever sent).
PATHS = ["/", "/metrics", "/api/v1/status/buildinfo", "/api/v2/status", "/api/tags", "/api/v1/applications",
         "/api/search", "/status", "/api/v1/write", "/loki/api/v1/labels", "/loki/api/v1/push", "/v1/traces",
         "/probe", "/api/health", "/api/v1/status/flags"]
# fields kept from specific JSON answers (everything else is dropped)
KEEP = {"/api/v1/status/flags": ["web.enable-remote-write-receiver", "web.enable-admin-api", "web.enable-lifecycle"]}


def nmap(targets, ports_args):
    cmd = ["nmap", "-sT", "-Pn", "-n", "-T3", "--max-rate", "60", "--max-retries", "1", "--open", "-oX", "-"]
    cmd += ports_args + targets
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=1800).stdout
    res = {}
    for h in ET.fromstring(out).findall("host"):
        ip = h.find("address").get("addr")
        for p in h.findall("ports/port"):
            if p.find("state").get("state") == "open":
                svc = p.find("service")
                res.setdefault(ip, {})[int(p.get("portid"))] = svc.get("name") if svc is not None else ""
    return res


CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=CTX))


def get(url, keep=None):
    req = urllib.request.Request(url, headers={"User-Agent": "security-platform-probe/0"})
    try:
        r = OPENER.open(req, timeout=4)
        body = r.read(65536 if keep else 2048)
        if keep:
            try:
                data = json.loads(body).get("data", {})
                return dict(status=r.status, auth=False, fields={k: data.get(k) for k in keep})
            except Exception:  # noqa: BLE001
                pass
        return dict(status=r.status, auth=r.headers.get("WWW-Authenticate") is not None,
                    server=r.headers.get("Server", ""), ctype=r.headers.get("Content-Type", ""),
                    snippet=body[:160].decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return dict(status=e.code, auth=e.headers.get("WWW-Authenticate") is not None,
                    server=e.headers.get("Server", ""), location=e.headers.get("Location", ""))
    except Exception as e:  # not HTTP / refused / TLS mismatch
        return dict(error=type(e).__name__)


def is_http(ip, port):
    first = None
    for scheme in ("http", "https"):
        r = get(f"{scheme}://{ip}:{port}/")
        if "status" in r:
            if r["status"] == 400 and scheme == "http":   # "HTTP request sent to HTTPS port"
                first = first or (scheme, r)
                continue
            return scheme, r
    return first or (None, None)


def main(argv):
    ports = KNOWN
    if argv and argv[0] == "--ports":
        ports, argv = KNOWN + "," + argv[1], argv[2:]
    targets = argv
    top = nmap(targets, ["--top-ports", "1000"])
    known = nmap(targets, ["-p", ports])
    hosts = {}
    for d in (top, known):
        for ip, ports in d.items():
            hosts.setdefault(ip, {}).update(ports)
    ver = subprocess.run(["nmap", "--version"], capture_output=True, text=True).stdout.split("\n")[0]
    result = {"targets": targets, "hosts": {}, "tools": {"nmap": ver}}
    for ip in targets:
        ports = hosts.get(ip, {})
        entry = {}
        for port, svc in sorted(ports.items()):
            e = {"nmap_service": svc}
            if port not in (22, 8022, 53, 139, 445, 5432, 2379):
                scheme, root = is_http(ip, port)
                if scheme:
                    e["scheme"] = scheme
                    e["paths"] = {"/": root}
                    for p in PATHS[1:]:
                        e["paths"][p] = get(f"{scheme}://{ip}:{port}{p}", KEEP.get(p))
            entry[str(port)] = e
        result["hosts"][ip] = entry
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    main(sys.argv[1:])
