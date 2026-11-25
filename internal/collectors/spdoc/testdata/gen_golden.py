#!/usr/bin/env python3
"""Writes golden.json: json.dumps of each value with the options the collectors use (indent 1 + sort_keys for
documents and evidence, indent 0 for inventories, no indent for the scan settings and the merged SBOM).
Re-run after adding values: python3 internal/collectors/spdoc/testdata/gen_golden.py"""
import json
import os

VALUES = [None, True, 0, -12, 1.0, 0.1, 1e16, 1.5e-05, 123456789.125, "", "café", "tab\t\"q\"\\", "\U0001F600",
          "\x7f\x00\x1f", [], {}, [1, [2, []], {}], {"b": 1, "a": [True, None], "c": {"z": "", "y": 0.5}},
          {"schema": "s", "kind": "k", "generated_at": "2026-01-01T00:00:00Z", "items": [{"z": 1, "a": "x"}]},
          {"roots": ["~", "/etc/ssh"], "exclude": [], "maxdepth": 5}]
out = []
for v in VALUES:
    src = json.dumps(v)          # the Go test reads it back with pyvalue (key order kept)
    for indent, sort in ((1, True), (0, False), (None, False), (2, False)):
        out.append({"src": src, "indent": -1 if indent is None else indent, "sort": sort,
                    "out": json.dumps(v, indent=indent, sort_keys=sort)})
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden.json"), "w") as f:
    json.dump(out, f, indent=1)
    f.write("\n")
