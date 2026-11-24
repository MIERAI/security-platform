"""Minimal JSON-Schema validator (the subset used by schema/*.json): type, required, properties, enum,
pattern, items, maxLength, additionalProperties(schema). Stdlib only, so CI and air-gapped instances need nothing."""
import json
import os
import re

TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "number": (int, float), "integer": int}
SCHEMA_DIR = os.path.join(os.path.dirname(__file__), "..", "schema")
ACCEPTED_MAJORS = {"1": "findings-v1.schema.json"}   # two-step rule: add "2" here BEFORE any collector emits v2


def errors(doc, schema, path="$"):
    out = []
    t = schema.get("type")
    if t and not isinstance(doc, TYPES[t]) or (t in ("number", "integer") and isinstance(doc, bool)):
        return [f"{path}: expected {t}"]
    if "enum" in schema and doc not in schema["enum"]:
        out.append(f"{path}: {doc!r} not in {schema['enum']}")
    if isinstance(doc, str):
        if "pattern" in schema and not re.search(schema["pattern"], doc):
            out.append(f"{path}: {doc!r} !~ {schema['pattern']}")
        if "maxLength" in schema and len(doc) > schema["maxLength"]:
            out.append(f"{path}: longer than {schema['maxLength']}")
    if isinstance(doc, dict):
        for r in schema.get("required", []):
            if r not in doc:
                out.append(f"{path}: missing {r}")
        props = schema.get("properties", {})
        for k, v in doc.items():
            if k in props:
                out += errors(v, props[k], f"{path}.{k}")
            elif isinstance(schema.get("additionalProperties"), dict):
                out += errors(v, schema["additionalProperties"], f"{path}.{k}")
    if isinstance(doc, list) and "items" in schema:
        for i, v in enumerate(doc):
            out += errors(v, schema["items"], f"{path}[{i}]")
    return out


def validate_findings(doc):
    major = str(doc.get("schema_version", "")).split(".")[0]
    if major not in ACCEPTED_MAJORS:
        return [f"unsupported schema_version {doc.get('schema_version')!r} (core accepts {sorted(ACCEPTED_MAJORS)})"]
    schema = json.load(open(os.path.join(SCHEMA_DIR, ACCEPTED_MAJORS[major])))
    return errors(doc, schema)
