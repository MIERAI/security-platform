#!/usr/bin/env python3
"""A fake of the gh CLI, for the reference codehost-github collector in the conformance suite. Test tool, stdlib only.

  gh auth token --user U          prints the token in $FAKE_GH_TOKEN_FILE
  gh auth status                  prints $FAKE_GH_STATUS_FILE (the account list the real gh prints)
  gh api [-H H]... PATH [--paginate] [--jq EXPR]
                                  GET $FAKE_GH_API + PATH with "Authorization: token $GH_TOKEN"; --paginate follows
                                  Link rel="next" and concatenates arrays; --jq supports exactly the expressions the
                                  collector uses. On an HTTP error: "gh: <message> (HTTP <code>)" on stderr, the
                                  response body on stdout, exit 1 (as gh does).
"""
import json
import os
import re
import sys
import urllib.error
import urllib.request

JQ_SECRET_SCANNING = ("[.[] | .secret_type_display_name] | {count: length, types: (group_by(.) | map({(.[0]): length})"
                      " | add)}")
JQ_DEPENDABOT = "[.[] | .security_advisory.severity] | group_by(.) | map({(.[0]): length}) | add"
JQ_SECRETS = "[.secrets[] | {name, updated_at}]"


def grouped(values):
    if any(not isinstance(v, str) for v in values):
        raise ValueError("jq: error: Object keys must be strings")
    out = {}
    for v in sorted(values):
        out[v] = out.get(v, 0) + 1
    return out or None


def jq(expr, data):
    if expr == JQ_SECRET_SCANNING:
        names = [x.get("secret_type_display_name") for x in data]
        return {"count": len(names), "types": grouped(names)}
    if expr == JQ_DEPENDABOT:
        return grouped([(x.get("security_advisory") or {}).get("severity") for x in data])
    if expr == JQ_SECRETS:
        return [{"name": s.get("name"), "updated_at": s.get("updated_at")} for s in data["secrets"]]
    raise SystemExit(f"fake gh: unsupported --jq expression {expr!r}")


def get(url):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "Authorization": "token " + os.environ.get("GH_TOKEN", "")})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r), r.headers.get("Link", "")


def api(args):
    path, paginate, expr, i = None, False, None, 0
    while i < len(args):
        if args[i] == "-H":
            i += 2
            continue
        if args[i] == "--paginate":
            paginate = True
        elif args[i] == "--jq":
            expr = args[i + 1]
            i += 1
        else:
            path = args[i]
        i += 1
    url = os.environ["FAKE_GH_API"].rstrip("/") + path
    try:
        data, link = get(url)
        while paginate and isinstance(data, list):
            m = re.search(r'<([^>]+)>;\s*rel="next"', link)
            if not m:
                break
            more, link = get(m.group(1))
            data += more
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            msg = json.loads(body).get("message") or e.reason
        except ValueError:
            msg = e.reason
        print(body)
        print(f"gh: {msg} (HTTP {e.code})", file=sys.stderr)
        return 1
    if expr:
        try:
            out = jq(expr, data)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 5
        print(json.dumps(out))
    else:
        print(json.dumps(data))
    return 0


def main(argv):
    if argv[:2] == ["auth", "token"]:
        print(open(os.environ["FAKE_GH_TOKEN_FILE"]).read().strip())
        return 0
    if argv[:2] == ["auth", "status"]:
        sys.stdout.write(open(os.environ["FAKE_GH_STATUS_FILE"]).read())
        return 0
    if argv[:1] == ["api"]:
        return api(argv[1:])
    print(f"fake gh: unsupported command {argv}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
