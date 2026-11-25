#!/usr/bin/env python3
"""A fake kubectl for the detection collector's read-only checks: `kubectl [--kubeconfig K | --kubeconfig=K] get
daemonsets|prometheusrules -A -o json`. Test tool, stdlib only. The answers come from kubectl.json next to this
script: {"<kubeconfig basename or in-cluster>": {"daemonsets": [...], "prometheusrules": [...], "fail": "<stderr>"}}.
Anything else than `get ... -o json` (a write) exits 3 and is logged to $SP_FAKE_KUBECTL_LOG when set."""
import json
import os
import sys


def main(argv):
    kc, args = "in-cluster", []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--kubeconfig":
            kc, i = argv[i + 1], i + 2
            continue
        if a.startswith("--kubeconfig="):
            kc = a.split("=", 1)[1]
        else:
            args.append(a)
        i += 1
    if args[:1] != ["get"] or args[-2:] != ["-o", "json"]:
        if os.environ.get("SP_FAKE_KUBECTL_LOG"):
            with open(os.environ["SP_FAKE_KUBECTL_LOG"], "a") as f:
                f.write(" ".join(argv) + "\n")
        print("fake kubectl: read-only verbs only", file=sys.stderr)
        return 3
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "kubectl.json")) as f:
        clusters = json.load(f)
    c = clusters.get(os.path.basename(kc) if kc != "in-cluster" else kc)
    if c is None:
        print(f"error: kubeconfig {os.path.basename(kc)} not found", file=sys.stderr)
        return 1
    if c.get("fail"):
        print(c["fail"], file=sys.stderr)
        return 1
    print(json.dumps({"apiVersion": "v1", "kind": "List", "items": c.get(args[1], [])}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
