#!/usr/bin/env python3
"""A fake `kubectl` for the conformance suite: replays recorded API answers, one JSON file per cluster. Test tool,
stdlib only. Started through a wrapper script on PATH (bin/kubectl), so implementations run it like the real one.

  FAKE_KUBE_DIR   directory of <cluster>.json (cluster = the --kubeconfig file's name without extension;
                  "in-cluster" without --kubeconfig)
  FAKE_KUBE_LOG   every call is appended as one line "<cluster>: <arguments without --kubeconfig>"

<cluster>.json: {"unreachable": "message"} or {"resources": {"<resource>": [items] | {"error": "message"}},
                 "whoami": {userInfo} | {"error": "message"}}
Only read verbs exist here: `get` (-o json, or the custom-columns listing of secrets) and `auth whoami`. Anything
else is refused (exit 1) and logged, so a case can assert that an implementation never calls a mutating verb.
"""
import json
import os
import sys


def fail(msg):
    sys.stderr.write(msg + "\n")
    sys.exit(1)


def columns(items, spec):
    out = []
    for it in items:
        row = []
        for col in spec.split(","):
            path = col.split(":", 1)[1].lstrip(".").split(".")
            v = it
            for p in path:
                v = v.get(p) if isinstance(v, dict) else None
            row.append("<none>" if v is None else str(v))
        out.append("   ".join(row))
    return "\n".join(out) + ("\n" if out else "")


def get(cluster, args):
    res = args[1] if len(args) > 1 else ""
    items = cluster.get("resources", {}).get(res)
    if items is None:
        fail(f'error: the server doesn\'t have a resource type "{res.split(".")[0]}"')
    if isinstance(items, dict):
        fail(items["error"])
    if "-A" not in args and res not in ("namespaces", "clusterroles", "clusterrolebindings",
                                        "clusterpolicyreports.wgpolicyk8s.io"):
        items = [i for i in items if (i.get("metadata") or {}).get("namespace") == "default"]
    o = args[args.index("-o") + 1] if "-o" in args else ""
    if o.startswith("custom-columns="):
        sys.stdout.write(columns(items, o[len("custom-columns="):]))
        return
    if o != "json":
        fail("fake kubectl: only -o json and -o custom-columns are recorded")
    print(json.dumps({"apiVersion": "v1", "kind": "List", "items": items}))


def main():
    args = sys.argv[1:]
    name = "in-cluster"
    if "--kubeconfig" in args:
        i = args.index("--kubeconfig")
        name = os.path.splitext(os.path.basename(args[i + 1]))[0]
        del args[i:i + 2]
    log = os.environ.get("FAKE_KUBE_LOG")
    if log:
        with open(log, "a") as f:
            f.write(f"{name}: {' '.join(args)}\n")
    p = os.path.join(os.environ["FAKE_KUBE_DIR"], name + ".json")
    if not os.path.exists(p):
        fail(f"error: stat {name}: no such file or directory")
    cluster = json.load(open(p))
    if cluster.get("unreachable"):
        fail(cluster["unreachable"])
    if args[:1] == ["get"]:
        return get(cluster, args)
    if args[:2] == ["auth", "whoami"]:
        who = cluster.get("whoami") or {"error": "error: the server doesn't have a resource type \"selfsubjectreviews\""}
        if "error" in who:
            fail(who["error"])
        print(json.dumps({"kind": "SelfSubjectReview", "status": {"userInfo": who}}))
        return
    fail(f"fake kubectl: refused verb {' '.join(args[:2])!r} (collectors are read-only)")


if __name__ == "__main__":
    main()
