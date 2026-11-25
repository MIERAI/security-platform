#!/usr/bin/env python3
"""Writes golden.json: Python's answers for the inputs the Go package pytext must agree on (subprocess text
decoding, str.splitlines/strip, shlex.quote, subprocess.list2cmdline, fnmatch.fnmatchcase).
Re-run after adding inputs: python3 internal/collectors/pytext/testdata/gen_golden.py"""
import base64
import fnmatch
import json
import os
import shlex
import subprocess

RAW = [b"", b"a=1\nb=2\n", b"a=1\r\nb=2\r\n", b"x\ry\r\n\rz", b"caf\xe9=1", b"\xe2\x82", b"\xe2\x82(", b"\xf0\x9f\x98\x80",
       b"\xf0\x9f\x98", b"\xed\xa0\x80", b"\xc0\xaf", b"\xff\xfe", b"\xf4\x90\x80\x80", b"\xe0\x80\xaf", b"ok\xefend",
       b"\xef\xbf\xbd", b"\xf1\x80\x80", b"\xc2", b"tab\there\x00nul"]
TEXT = ["", "a\nb", "a\r\nb\r\n", "a\rb", "a\x0bb\x0cc", "a\x1cb\x1dc\x1ed", "a\x85b\u2028c\u2029d", "\n\n", "x\n",
        "  a = b  ", "\t\x1f x \xa0\u3000", "\u200bzero-width", "end\r"]
QUOTE = ["", "abc", "a b", "it's", "-n", "a$b", "x;y", "@%+=:,./-_", "\u00e9", "\n", "a'b'c", '{"roots": ["~"]}']
ARGV = [["a"], ["a b"], [""], ['a"b'], ["a\\b"], ["a\\"], ["a b\\"], ["a\\\\\"b"], ['x', 'y z', ''], ["tab\there"],
        ["C:\\Python312\\python.exe", "-c", "import sys", '{"roots": ["~"], "exclude": []}']]
MATCH = [("sshd.passwordauthentication", "sshd.*"), ("sshd", "sshd.*"), ("fw.profile_public", "fw.profile_*"),
         ("win.fw_profile_x", "win.fw_profile_*"), ("listen.db_wildcard.5432", "listen.db_wildcard.*"), ("a/b", "a*"),
         ("abc", "a?c"), ("ac", "a?c"), ("", "*"), ("", ""), ("x", ""), ("aXbXc", "a*b*c"), ("ab", "a*b*c"), ("**", "*"),
         ("pkg.upgradable", "pkg.upgradable"), ("pkg.upgradable2", "pkg.upgradable")]


def decode(b):
    return b.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")


out = {"decode": [[base64.b64encode(b).decode(), decode(b)] for b in RAW],
       "splitlines": [[t, t.splitlines()] for t in TEXT], "strip": [[t, t.strip()] for t in TEXT],
       "quote": [[q, shlex.quote(q)] for q in QUOTE], "cmdline": [[a, subprocess.list2cmdline(a)] for a in ARGV],
       "fnmatch": [[n, p, fnmatch.fnmatchcase(n, p)] for n, p in MATCH]}
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden.json"), "w") as f:
    json.dump(out, f, indent=1, ensure_ascii=True)
    f.write("\n")
