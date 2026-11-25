#!/usr/bin/env python3
"""A fake `gh` (GitHub CLI) for the conformance suite: the two calls the Python identity adapter makes. Test tool,
stdlib only; started through a wrapper on PATH (bin/gh).

  gh auth token --user LOGIN      prints the conformance token (built here: no token-shaped string is committed)
  gh api -i -H H1 [-H H2] PATH    GET FAKE_GH_URL + PATH with those headers and GH_TOKEN, printed as `gh api -i`
                                  prints it: status line, headers, blank line, body; exit 1 when not 2xx

Every call is logged to FAKE_GH_LOG (argv only; the token never appears on a command line).
"""
import os
import sys
import urllib.error
import urllib.request

TOKEN = "gho_" + "conformanceCanary" + "0" * 19


def main():
    a = sys.argv[1:]
    if os.environ.get("FAKE_GH_LOG"):
        with open(os.environ["FAKE_GH_LOG"], "a") as f:
            f.write("gh " + " ".join(a) + "\n")
    if a[:2] == ["auth", "token"]:
        print(TOKEN)
        return 0
    if a[:1] != ["api"]:
        sys.stderr.write("fake gh: only `auth token` and `api` are recorded\n")
        return 1
    headers, i, path = {}, 1, None
    while i < len(a):
        if a[i] == "-H":
            k, _, v = a[i + 1].partition(":")
            headers[k.strip()] = v.strip()
            i += 2
        elif a[i] == "-i":
            i += 1
        else:
            path = a[i]
            i += 1
    headers["Authorization"] = "token " + os.environ.get("GH_TOKEN", "")
    req = urllib.request.Request(os.environ["FAKE_GH_URL"] + path, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        r = opener.open(req, timeout=30)
        status, reason, hdrs, body = r.status, r.reason, r.headers, r.read()
    except urllib.error.HTTPError as e:
        status, reason, hdrs, body = e.code, e.reason, e.headers, e.read()
    out = f"HTTP/2.0 {status} {reason}\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
    sys.stdout.write(out + body.decode())
    return 0 if 200 <= status < 300 else 1


if __name__ == "__main__":
    sys.exit(main())
