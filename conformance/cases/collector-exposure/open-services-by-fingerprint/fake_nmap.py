#!/usr/bin/env python3
"""A fake nmap for the exposure conformance cases (test tool, stdlib only): prints recorded XML for the scenario in
$FAKE_NMAP_SPEC instead of scanning anything.

  {"rc": 0, "stderr": "", "version": "Nmap version 7.95 ( https://nmap.org )",
   "hosts": {"127.0.0.1": {"status": "up", "timedout": false,
                           "ports": [["svc:web", "open", "http"], [8080, "filtered", "http-proxy"], ...]}}}

A port given as "svc:<name>" is the port of the harness service <name> (read from <sandbox>/.svc-<name>.port);
"svc:<name>:<extra>" reads <sandbox>/.svc-<name>.<extra> (a second socket of that service). A service name null
means a <service> element without a name; a target not in "hosts" is reported down. Every invocation's argv is
appended to <sandbox>/nmaplog/argv.log; an option nmap is never given by the probe (an argument injected through a
target string) creates <sandbox>/nmaplog/injected."""
import json
import os
import sys
from xml.sax.saxutils import quoteattr

WITH_VALUE = {"--max-rate", "--max-retries", "--top-ports", "-p", "-oX", "--host-timeout"}
FLAGS = {"-sT", "-Pn", "-n", "-T3", "--open"}


def port_of(spec, sandbox):
    if isinstance(spec, int):
        return spec
    _, name, *extra = spec.split(":")
    with open(os.path.join(sandbox, f".svc-{name}." + (extra[0] if extra else "port"))) as f:
        return int(f.read().strip())


def main(argv):
    spec_path = os.environ["FAKE_NMAP_SPEC"]
    sandbox = os.path.dirname(os.path.abspath(spec_path))
    spec = json.load(open(spec_path))
    logdir = os.path.join(sandbox, "nmaplog")
    os.makedirs(logdir, exist_ok=True)
    with open(os.path.join(logdir, "argv.log"), "a") as f:
        f.write(json.dumps(argv) + "\n")
    if argv == ["--version"]:
        print(spec.get("version", "Nmap version 7.95 ( https://nmap.org )"))
        print("Platform: fake")
        return 0
    targets, i = [], 0
    while i < len(argv):
        a = argv[i]
        if a in WITH_VALUE:
            i += 2
            continue
        if a in FLAGS:
            i += 1
            continue
        if a.startswith("-"):
            open(os.path.join(logdir, "injected"), "w").write(a + "\n")
        else:
            targets.append(a)
        i += 1
    if spec.get("rc"):
        sys.stderr.write(spec.get("stderr", "nmap: failed") + "\n")
        return spec["rc"]
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<!DOCTYPE nmaprun>",
           '<nmaprun scanner="nmap" args="nmap" version="7.95">']
    for t in targets:
        h = spec.get("hosts", {}).get(t, {"status": "down"})
        timed = ' timedout="true"' if h.get("timedout") else ""
        out.append(f'<host starttime="1" endtime="2"{timed}><status state="{h.get("status", "up")}" reason="user-set"/>')
        out.append(f'<address addr={quoteattr(t)} addrtype="ipv4"/><ports>')
        for p, state, svc in h.get("ports", []):
            service = "" if svc is False else ('<service method="table"/>' if svc is None else f'<service name={quoteattr(svc)} method="table"/>')
            out.append(f'<port protocol="tcp" portid="{port_of(p, sandbox)}"><state state="{state}" reason="syn-ack"/>{service}</port>')
        out.append("</ports></host>")
    out.append('<runstats><finished time="2"/></runstats></nmaprun>')
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
