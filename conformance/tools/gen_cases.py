#!/usr/bin/env python3
"""Generates conformance/cases/<component>/<case>/ (case.json + fixtures). The generated files are the suite; this
script only keeps the shared fixture builders in one place. Re-run after editing: python3 conformance/tools/gen_cases.py
(it rewrites every case directory it owns and leaves others alone). Stdlib only; imports nothing from the product."""
import calendar
import hashlib
import importlib
import json
import os
import shutil
import sys
import time

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cases")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # collector_<name>.py next to this file
OWNED = []


def fid(layer, asset, check):
    return hashlib.sha1(f"{layer}|{asset}|{check}".encode()).hexdigest()[:12]


def epoch(s):
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))


def finding(asset, check, layer="host", severity="high", kind="compliance", observed="2026-11-01T08:00:00Z", **extra):
    f = {"id": fid(layer, asset, check), "check": check, "layer": layer, "asset": asset, "title": f"{check} on {asset}",
         "severity": severity, "evidence": f"raw/x/{check}.json", "remediation": f"fix {check}", "needs_human": False,
         "owner": "platform", "observed_at": observed, "kind": kind}
    if kind is None:
        del f["kind"]
    f.update(extra)
    return f


def doc(collector, findings, coverage, finished="2026-11-01T09:00:00Z", started=None, version="1.2", cver="1.0.0", **extra):
    d = {"schema_version": version, "collector": {"name": collector, "version": cver},
         "run": {"started_at": started or finished, "finished_at": finished, "instance": "conformance"},
         "coverage": coverage, "findings": findings}
    d.update(extra)
    return d


def ok(asset, **kw):
    return dict({"asset": asset, "status": "ok"}, **kw)


def gap(asset, reason="unreachable", **kw):
    return dict({"asset": asset, "status": "gap", "reason": reason}, **kw)


def write_case(component, name, case, files=None):
    d = os.path.join(CASES, component, name)
    if os.path.isdir(d):
        shutil.rmtree(d)
    os.makedirs(d)
    OWNED.append(f"{component}/{name}")
    case = dict({"component": component}, **case)
    with open(os.path.join(d, "case.json"), "w") as f:
        json.dump(case, f, indent=1, ensure_ascii=False)
        f.write("\n")
    for rel, content in (files or {}).items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        if isinstance(content, bytes):      # byte-exact fixtures (CRLF, legacy code pages, archives): {"raw": ...}
            with open(p, "wb") as f:
                f.write(content)
            continue
        with open(p, "w") as f:
            if isinstance(content, str):
                f.write(content)
            else:
                json.dump(content, f, indent=1, sort_keys=True)
                f.write("\n")
        if rel.endswith(".sh"):
            os.chmod(p, 0o755)


# ==================================================================================================================
# ledger (contract ledger/1.0): <impl> --run RUN --data DATA [--latest DIR]
# ==================================================================================================================
def merge(n, files, expect=None, exit_=0, name=None, latest=False, env=None, remove=None, extra=None):
    st = {"name": name or f"merge run{n}", "files": dict({f"run{n}/{k}": v for k, v in files.items()}, **(extra or {})),
          "exec": {"impl": "ledger", "args": ["--run", f"{{sandbox}}/run{n}", "--data", "{sandbox}/data"]
                   + (["--latest", "{sandbox}/latest"] if latest else [])},
          "exit": exit_, "expect": expect or []}
    if env:
        st["exec"]["env"] = env
    if remove:
        st["remove"] = remove
    return st


def L(subset, schema=True):
    e = {"json": "data/ledger.json", "subset": subset}
    if schema:
        e["schema"] = "ledger"
    return e


def ledger_cases():
    C = "ledger/1.0"
    h1 = finding("host:h1", "host.ssh_password_auth", severity="high")
    D1 = doc("host", [h1], [ok("host:h1")], finished="2026-11-01T09:00:00Z")
    DOC = "host.findings.json"

    write_case("ledger", "first-run-opens", {
        "title": "A finding seen for the first time is open; outputs and their schemas",
        "contract": C, "origin": "tests/test_ledger.py::test_lifecycle",
        "files": {"data/.keep": {"text": ""}},
        "steps": [merge(1, {DOC: "run1.json"}, [
            L({"schema": "security-platform/ledger/v1", "entries": {h1["id"]: {
                "status": "open", "first_seen": "2026-11-01T08:00:00Z", "last_seen": "2026-11-01T08:00:00Z",
                "fixed_at": None, "reopened_count": 0, "collector": "host", "collector_version": "1.0.0",
                "check": h1["check"], "layer": "host", "asset": "host:h1", "severity": "high", "kind": "compliance",
                "ttk_counted": False}},
               "collectors": {"host": {"last_run": "2026-11-01T09:00:00Z", "last_good_run": "2026-11-01T09:00:00Z"}},
               "runs": [{"collectors": {"host": "1.0.0"}, "invalid": {}, "run_dir": {"$regex": "run1$"}}]}),
            {"prom": "data/metrics/ledger.prom", "families": [
                "security_findings", "security_findings_reopened_total", "security_exceptions_active",
                "security_exceptions_expired", "security_time_to_fix_days", "security_contract_invalid_documents",
                "security_ledger_last_update_timestamp_seconds", "security_collector_last_good_run_timestamp_seconds",
                "security_sli", "security_sli_objective", "security_sli_ok", "security_sli_new_total"],
             "has": [{"name": "security_findings", "labels": {"layer": "host", "severity": "high", "status": "open"}, "value": 1},
                     {"name": "security_collector_last_good_run_timestamp_seconds", "labels": {"collector": "host"},
                      "value": epoch("2026-11-01T09:00:00Z")},
                     {"name": "security_contract_invalid_documents", "value": 0}],
             "types": {"security_findings_reopened_total": "counter", "security_findings": "gauge"},
             "forbidden_labels": ["asset", "id", "host", "instance_name"]},
            {"exists": "run1/sli.prom"},
            {"jsonl": "run1/ocsf.jsonl", "subset": [{"finding_info": {"uid": h1["id"]}, "status": "open"}]},
            {"exists": "data/reports/latest-auto.md"},
        ])]}, {"run1.json": D1})

    write_case("ledger", "fixed-only-when-covered", {
        "title": "A finding is fixed only by a run that covered its asset (not_observed), with time_to_fix_days",
        "contract": C, "origin": "tests/test_ledger.py::test_lifecycle",
        "steps": [merge(1, {DOC: "run1.json"}),
                  merge(2, {DOC: "run2.json"}, [L({"entries": {h1["id"]: {
                      "status": "fixed", "fixed_at": "2026-11-03T08:00:00Z", "fixed_reason": "not_observed",
                      "time_to_fix_days": 2.0, "first_seen": "2026-11-01T08:00:00Z"}}}),
                      {"prom": "data/metrics/ledger.prom", "has": [
                          {"name": "security_findings", "labels": {"layer": "host", "severity": "high", "status": "fixed"}, "value": 1},
                          {"name": "security_time_to_fix_days", "labels": {"quantile": "0.5"}, "value": 2},
                          {"name": "security_time_to_fix_days", "labels": {"quantile": "1"}, "value": 2}]}])]},
        {"run1.json": D1, "run2.json": doc("host", [], [ok("host:h1")], finished="2026-11-03T08:00:00Z")})

    write_case("ledger", "coverage-gap-never-fixes", {
        "title": "A run that could not cover the asset (gap) never fixes its findings: unknown keeps state",
        "contract": C, "origin": "incident: an offline host's findings must not disappear; tests/test_ledger.py::test_lifecycle",
        "steps": [merge(1, {DOC: "run1.json"}),
                  merge(2, {DOC: "run2.json"}, [L({"entries": {h1["id"]: {"status": "open", "fixed_at": None}}})]),
                  merge(3, {DOC: "run3.json"}, [L({"entries": {h1["id"]: {"status": "open", "fixed_at": None}}})],
                        name="run3: asset not mentioned at all")]},
        {"run1.json": D1, "run2.json": doc("host", [], [gap("host:h1", "ssh timeout")], finished="2026-11-02T09:00:00Z"),
         "run3.json": doc("host", [], [ok("host:h2")], finished="2026-11-03T09:00:00Z")})

    write_case("ledger", "regression-reopens", {
        "title": "A fixed finding that comes back is open again (reopened_count + 1, counter metric)",
        "contract": C, "origin": "tests/test_ledger.py::test_lifecycle",
        "steps": [merge(1, {DOC: "run1.json"}), merge(2, {DOC: "run2.json"}),
                  merge(3, {DOC: "run3.json"}, [
                      L({"entries": {h1["id"]: {"status": "open", "fixed_at": None, "fixed_reason": {"$null_or_absent": True},
                                                "time_to_fix_days": {"$null_or_absent": True}, "reopened_count": 1,
                                                "first_seen": "2026-11-01T08:00:00Z", "last_seen": "2026-11-05T08:00:00Z"}}}),
                      {"prom": "data/metrics/ledger.prom", "has": [{"name": "security_findings_reopened_total", "value": 1}]}])]},
        {"run1.json": D1, "run2.json": doc("host", [], [ok("host:h1")], finished="2026-11-03T08:00:00Z"),
         "run3.json": doc("host", [dict(h1, observed_at="2026-11-05T08:00:00Z")], [ok("host:h1")], finished="2026-11-05T09:00:00Z")})

    a, b, c_, d_ = (finding(f"host:h{i}", "host.firewall_off", severity="medium") for i in range(1, 5))
    exc_yaml = (f"exceptions:\n"
                f"  {a['id']}: {{approved_by: alice, reason: lab machine, expires: '2099-01-01'}}\n"
                f"  {b['id']}: {{reason: no approver, expires: '2099-01-01'}}\n"
                f"  {c_['id']}: {{approved_by: alice, reason: no expiry}}\n"
                f"  {d_['id']}:\n    approved_by: alice\n    reason: block style YAML\n    expires: 2099-01-01\n")
    write_case("ledger", "exceptions-need-human-and-expiry", {
        "title": "Only an exception with approved_by AND expires accepts a finding; YAML flow and block style",
        "contract": C, "origin": "tests/test_ledger.py::test_exceptions_need_human_and_expiry",
        "files": {"data/exceptions.yaml": "exceptions.yaml"},
        "steps": [merge(1, {DOC: "run1.json"}, [
            L({"entries": {a["id"]: {"status": "accepted", "exception": {"approved_by": "alice", "expires": {"$regex": "^2099-01-01"}}},
                           b["id"]: {"status": "open"}, c_["id"]: {"status": "open"},
                           d_["id"]: {"status": "accepted"}}}),
            {"prom": "data/metrics/ledger.prom", "has": [{"name": "security_exceptions_active", "value": 2}]}])]},
        {"exceptions.yaml": exc_yaml,
         "run1.json": doc("host", [a, b, c_, d_], [ok(f"host:h{i}") for i in range(1, 5)])})

    write_case("ledger", "exception-expiry-reopens", {
        "title": "An expired exception makes the finding open again, marked expired (counted)",
        "contract": C, "origin": "tests/test_ledger.py::test_exceptions_need_human_and_expiry; design §1",
        "files": {"data/exceptions.yaml": "valid.yaml"},
        "steps": [merge(1, {DOC: "run1.json"}, [L({"entries": {a["id"]: {"status": "accepted"}}})]),
                  dict(merge(2, {DOC: "run1.json"}, extra={"data/exceptions.yaml": "expired.yaml"}, expect=[
                      L({"entries": {a["id"]: {"status": "open", "exception": {"expired": True, "approved_by": "alice"}}}}),
                      {"prom": "data/metrics/ledger.prom", "has": [{"name": "security_exceptions_expired", "value": 1},
                                                                    {"name": "security_exceptions_active", "value": 0}]}]),
                       name="exception now expired")]},
        {"valid.yaml": f"exceptions:\n  {a['id']}: {{approved_by: alice, reason: lab, expires: '2099-01-01'}}\n",
         "expired.yaml": f"exceptions:\n  {a['id']}: {{approved_by: alice, reason: lab, expires: '2000-01-01'}}\n",
         "run1.json": doc("host", [a], [ok("host:h1")])})

    write_case("ledger", "accepted-finding-can-be-fixed", {
        "title": "An accepted finding that a covering run no longer reports is fixed (the exception no longer matters)",
        "contract": C, "origin": "tests/test_ledger.py::test_accepted_finding_can_be_fixed",
        "files": {"data/exceptions.yaml": "valid.yaml"},
        "steps": [merge(1, {DOC: "run1.json"}), merge(2, {DOC: "run2.json"}, [
            L({"entries": {a["id"]: {"status": "fixed", "fixed_reason": "not_observed"}}})])]},
        {"valid.yaml": f"exceptions:\n  {a['id']}: {{approved_by: alice, reason: lab, expires: '2099-01-01'}}\n",
         "run1.json": doc("host", [a], [ok("host:h1")]),
         "run2.json": doc("host", [], [ok("host:h1")], finished="2026-11-02T09:00:00Z")})

    # ---- retired assets (incident: a retired image kept its findings open forever) ----
    def vf(image, cve="cve-2099-0001", observed="2026-11-24T08:00:00Z"):
        return finding(f"image:{image}", f"vuln.{cve}", layer="supply-chain", severity="critical", kind="vulnerability",
                       observed=observed)
    COMPLETE = ok("inventory:container-image", complete_scope="image:")
    old, new = vf("registry.example/app:1.0"), vf("registry.example/app:1.1")
    write_case("ledger", "retired-image-closes", {
        "title": "A complete inventory (complete_scope) that no longer lists an asset closes its findings: asset_retired; "
                 "reappearance reopens",
        "contract": C, "origin": "incident: retired container image kept critical findings open; tests/test_retired.py",
        "steps": [
            merge(1, {"vuln-intel.findings.json": "run1.json"}),
            merge(2, {"vuln-intel.findings.json": "run2.json"}, [L({"entries": {
                old["id"]: {"status": "fixed", "fixed_reason": "asset_retired", "fixed_at": "2026-11-25T09:00:00Z"},
                new["id"]: {"status": "open"}}})]),
            merge(3, {"vuln-intel.findings.json": "run3.json"}, [L({"entries": {
                old["id"]: {"status": "open", "reopened_count": 1}}})], name="rollback: the old image is back")]},
        {"run1.json": doc("vuln-intel", [old], [ok(old["asset"]), COMPLETE], finished="2026-11-24T09:00:00Z"),
         "run2.json": doc("vuln-intel", [dict(new, observed_at="2026-11-25T08:00:00Z")], [ok(new["asset"]), COMPLETE],
                          finished="2026-11-25T09:00:00Z"),
         "run3.json": doc("vuln-intel", [dict(old, observed_at="2026-11-26T08:00:00Z")], [ok(old["asset"]), COMPLETE],
                          finished="2026-11-26T09:00:00Z")})

    REPO_F = finding("repo:acme/app", "vuln.cve-2099-0002", layer="supply-chain", severity="high", kind="vulnerability")
    write_case("ledger", "partial-inventory-retires-nothing", {
        "title": "Without complete_scope (partial or failed inventory) an unlisted asset is unknown: nothing closes; "
                 "a gap on the asset also blocks retirement; complete_scope only covers its own prefix",
        "contract": C, "origin": "tests/test_retired.py::test_partial_or_failed_inventory_does_not_close, test_scope_limits_retirement",
        "steps": [
            merge(1, {"vuln-intel.findings.json": "run1.json"}),
            merge(2, {"vuln-intel.findings.json": "run2.json"}, [L({"entries": {old["id"]: {"status": "open"}}})],
                  name="inventory without complete_scope"),
            merge(3, {"vuln-intel.findings.json": "run3.json"}, [L({"entries": {old["id"]: {"status": "open"},
                                                                                 REPO_F["id"]: {"status": "open"}}})],
                  name="complete_scope image: with a gap on the old image; repo: is outside the scope")]},
        {"run1.json": doc("vuln-intel", [old, REPO_F],
                          [ok(old["asset"]), ok("repo:acme/app")], finished="2026-11-24T09:00:00Z"),
         "run2.json": doc("vuln-intel", [], [ok(new["asset"]), ok("inventory:container-image")], finished="2026-11-25T09:00:00Z"),
         "run3.json": doc("vuln-intel", [], [ok(new["asset"]), gap(old["asset"], "pull failed"), COMPLETE],
                          finished="2026-11-26T09:00:00Z")})

    # ---- narrow gaps (incident: one timed-out host probe hid / closed every other check) ----
    upd = finding("host:laptop", "host.os_updates_pending", severity="medium")
    fw = finding("host:laptop", "host.firewall_off", severity="high")
    write_case("ledger", "timed-out-host-check-keeps-state", {
        "title": "A narrow gap (<asset>/<part> with checks) keeps only those checks' findings unknown; the asset's "
                 "other findings are judged normally",
        "contract": C, "origin": "incident: a slow OS-update probe timed out and its findings were marked fixed; CHANGELOG findings 1.2",
        "steps": [merge(1, {DOC: "run1.json"}),
                  merge(2, {DOC: "run2.json"}, [L({"entries": {upd["id"]: {"status": "open", "fixed_at": None},
                                                               fw["id"]: {"status": "fixed", "fixed_reason": "not_observed"}}})]),
                  merge(3, {DOC: "run3.json"}, [L({"entries": {upd["id"]: {"status": "fixed"}}})],
                        name="the probe works again and the update is installed")]},
        {"run1.json": doc("host", [upd, fw], [ok("host:laptop")]),
         "run2.json": doc("host", [], [ok("host:laptop"), gap("host:laptop/os-updates", "probe timed out after 60s",
                                                              checks=["host.os_update*"])], finished="2026-11-02T09:00:00Z"),
         "run3.json": doc("host", [], [ok("host:laptop")], finished="2026-11-03T09:00:00Z")})

    other = doc("exposure", [], [ok("host:h1")], finished="2026-11-02T09:00:00Z")
    write_case("ledger", "collector-isolation", {
        "title": "A run only resolves findings of its own collector name: another collector covering the asset fixes nothing",
        "contract": C, "origin": "runner `as:` (SP_COLLECTOR_NAME) design; ledger rule",
        "steps": [merge(1, {DOC: "run1.json"}),
                  merge(2, {"exposure.findings.json": "run2.json"}, [L({"entries": {h1["id"]: {"status": "open"}}})])]},
        {"run1.json": D1, "run2.json": other})

    sf = finding("secret-file:h1:/etc/app/key.pem", "secrets.private_key_readable", layer="data-secrets")
    wl = finding("k8s-workload:prod/ns1/deploy/web", "k8s.privileged", layer="workload")
    ep = finding("net-endpoint:h1@192.0.2.10:22", "exposure.ssh_open", layer="network")
    write_case("ledger", "umbrella-and-prefix-coverage", {
        "title": "Coverage matching: host:h covers secret-file:h:...; k8s-cluster:c covers k8s-workload:c/...; an entry "
                 "covers assets it prefixes up to ':' '/' '@'",
        "contract": C, "origin": "tests/test_ledger.py::test_coverage_rules",
        "steps": [merge(1, {"x.findings.json": "run1.json"}),
                  merge(2, {"x.findings.json": "run2.json"}, [L({"entries": {
                      sf["id"]: {"status": "fixed"}, wl["id"]: {"status": "fixed"}, ep["id"]: {"status": "fixed"}}})])]},
        {"run1.json": doc("x", [sf, wl, ep], [ok("host:h1"), ok("k8s-cluster:prod"), ok("net-endpoint:h1@192.0.2.10")]),
         "run2.json": doc("x", [], [ok("host:h1"), ok("k8s-cluster:prod"), ok("net-endpoint:h1@192.0.2.10")],
                          finished="2026-11-02T09:00:00Z")})

    # ---- time to know (incident: the first inventory of a new asset was counted as a detection delay) ----
    pub = "2026-10-01T00:00:00Z"
    v_a1 = finding("image:a", "vuln.cve-2099-1111", layer="supply-chain", severity="critical", kind="vulnerability",
                   observed="2026-11-10T08:00:00Z", attributes={"cve": "CVE-2099-1111", "published_at": pub})
    v_a2 = finding("image:a", "vuln.cve-2099-2222", layer="supply-chain", severity="critical", kind="vulnerability",
                   observed="2026-11-11T08:00:00Z", attributes={"cve": "CVE-2099-2222", "published_at": "2026-11-11T02:00:00Z"})
    v_b1 = finding("image:b", "vuln.cve-2099-1111", layer="supply-chain", severity="critical", kind="vulnerability",
                   observed="2026-11-11T08:00:00Z", attributes={"cve": "CVE-2099-1111", "published_at": pub})
    write_case("ledger", "first-inventory-not-detection-delay", {
        "title": "time_to_know is computed for advisories, but only counted (ttk_counted) on an asset the collector had "
                 "already covered: a first inventory is a baseline",
        "contract": C, "origin": "incident: adding a new image reported a 40-day time-to-know",
        "steps": [merge(1, {"vuln-intel.findings.json": "run1.json"}, [L({"entries": {v_a1["id"]: {
                      "ttk_counted": False, "disclosed_at": pub, "time_to_know_hours": {"$approx": [968.0, 0.05]}}}})]),
                  merge(2, {"vuln-intel.findings.json": "run2.json"}, [L({"entries": {
                      v_a2["id"]: {"ttk_counted": True, "time_to_know_hours": {"$approx": [6.0, 0.05]}},
                      v_b1["id"]: {"ttk_counted": False}}}),
                      {"json": "data/ledger.json", "subset": {"coverage_seen": {"vuln-intel": ["image:a", "image:b"]}}}])]},
        {"run1.json": doc("vuln-intel", [v_a1], [ok("image:a")], finished="2026-11-10T09:00:00Z"),
         "run2.json": doc("vuln-intel", [dict(v_a1, observed_at="2026-11-11T08:00:00Z"), v_a2, v_b1],
                          [ok("image:a"), ok("image:b")], finished="2026-11-11T09:00:00Z")})

    bad = doc("host", [h1], [ok("host:h1")], version="2.0")
    write_case("ledger", "invalid-document-rejected", {
        "title": "A document that fails the findings contract (unknown major, bad field) is not merged, is recorded, and "
                 "does not fail the merge of the valid ones",
        "contract": C, "origin": "tests/test_contract.py::test_unknown_major_rejected",
        "steps": [merge(1, {"host.findings.json": "bad.json", "k8s.findings.json": "badfield.json",
                            "exposure.findings.json": "good.json"}, [
            L({"entries": {"$len": 1}, "runs": [{"invalid": {"host.findings.json": {"$type": "array"},
                                                             "k8s.findings.json": {"$type": "array"}},
                                                 "collectors": {"exposure": "1.0.0"}}]}),
            {"prom": "data/metrics/ledger.prom", "has": [{"name": "security_contract_invalid_documents", "value": 2}]}])]},
        {"bad.json": bad,
         "badfield.json": doc("k8s", [dict(finding("k8s-cluster:c", "k8s.x", layer="workload"), severity="urgent")], [ok("k8s-cluster:c")]),
         "good.json": doc("exposure", [finding("net-endpoint:h@192.0.2.1:22", "exposure.ssh_open", layer="network")],
                          [ok("net-endpoint:h@192.0.2.1")])})

    fut = doc("host", [dict(h1, future_field=1)], [ok("host:h1", future=True)], version="1.9", future_field={"x": 1})
    write_case("ledger", "unknown-minor-and-fields-accepted", {
        "title": "A newer minor (1.9) with unknown fields is accepted (unknown fields are ignored, never fatal)",
        "contract": C, "origin": "tests/test_contract.py::test_minor_with_unknown_fields_accepted; docs/upgrade.md",
        "steps": [merge(1, {DOC: "run1.json"}, [L({"entries": {h1["id"]: {"status": "open"}}, "runs": [{"invalid": {}}]})])]},
        {"run1.json": fut})

    vul = finding("image:a", "vuln.cve-2099-1111", layer="supply-chain", severity="critical", kind="vulnerability",
                  attributes={"cve": "CVE-2099-1111", "kev": True, "cvss": 9.8, "epss": 0.5, "package": "libx",
                              "installed": "1.0", "fixed": "1.1"})
    det = finding("host:h1", "detection.ssh_burst", layer="detection", severity="low", kind="detection")
    cmp_ = finding("host:h1", "host.ssh_root_login", severity="medium", refs=["cis:5.2.10"])
    write_case("ledger", "ocsf-mapping", {
        "title": "<run>/ocsf.jsonl holds one OCSF 1.x finding event per ledger entry (class by kind, severity_id, status_id)",
        "contract": C + " + findings/1.2 OCSF mapping", "origin": "tests/test_contract.py::test_ocsf_mapping; core/ocsf.py",
        "steps": [merge(1, {"x.findings.json": "run1.json"}, [{"jsonl": "run1/ocsf.jsonl", "subset": {"$unordered": [
            {"class_uid": 2002, "class_name": "Vulnerability Finding", "category_uid": 2, "activity_id": 1, "severity_id": 5,
             "status_id": 1, "status": "open", "time": "2026-11-01T08:00:00Z",
             "metadata": {"version": {"$regex": "^1\\."}, "product": {"name": "security-platform/x", "version": "1.0.0"}},
             "finding_info": {"uid": vul["id"], "types": ["vuln.cve-2099-1111"], "first_seen_time": "2026-11-01T08:00:00Z"},
             "resources": [{"type": "image", "name": "a"}],
             "vulnerabilities": [{"cve": {"uid": "CVE-2099-1111", "cvss": [{"base_score": 9.8}], "epss": {"score": 0.5}},
                                  "is_exploit_available": True,
                                  "affected_packages": [{"name": "libx", "version": "1.0", "fixed_in_version": "1.1"}]}]},
            {"class_uid": 2004, "severity_id": 2, "finding_info": {"uid": det["id"]}},
            {"class_uid": 2003, "severity_id": 3, "compliance": {"control": "host.ssh_root_login", "standards": ["cis:5.2.10"]},
             "finding_info": {"uid": cmp_["id"]}}]}}])]},
        {"run1.json": doc("x", [vul, det, cmp_], [ok("image:a"), ok("host:h1")])})

    write_case("ledger", "coverage-gaps-from-latest", {
        "title": "With --latest, open coverage gaps per collector are counted from the newest document of every "
                 "collector; a human-approved unexpired coverage exception takes a gap out",
        "contract": C, "origin": "tests/test_coverage.py::test_gap_excepted_only_with_human_and_expiry",
        "files": {"latest/host.findings.json": "host-latest.json", "latest/k8s.findings.json": "k8s-latest.json",
                  "data/exceptions.yaml": "exceptions.yaml"},
        "steps": [merge(1, {"exposure.findings.json": "run1.json"}, latest=True, expect=[
            {"prom": "data/metrics/ledger.prom", "has": [
                {"name": "security_coverage_gaps_open", "labels": {"collector": "host"}, "value": 1},
                {"name": "security_coverage_gaps_open", "labels": {"collector": "k8s"}, "value": 0},
                {"name": "security_coverage_gaps_excepted", "value": 1}]}])]},
        {"host-latest.json": doc("host", [], [ok("host:a"), gap("host:phone", "offline"), gap("host:b", "ssh refused")]),
         "k8s-latest.json": doc("k8s", [], [ok("k8s-cluster:c")]),
         "exceptions.yaml": "coverage_exceptions:\n  host|host:phone: {approved_by: alice, reason: personal device, expires: '2099-01-01'}\n",
         "run1.json": doc("exposure", [], [ok("net-endpoint:h@192.0.2.1")])})

    # ---- known deviations: target behaviour; the reference implementation is listed as an expected failure ----
    write_case("ledger", "finding-without-kind", {
        "title": "TARGET: `kind` is optional in findings/1.x; a valid document without it is merged as kind=compliance",
        "contract": C, "deviation": "LEDGER-D1",
        "origin": "found while writing the contracts: core/ledger.py reads f['kind'] and exits 1 (KeyError)",
        "steps": [merge(1, {DOC: "run1.json"}, [L({"entries": {h1["id"]: {"status": "open", "kind": "compliance"}}})])]},
        {"run1.json": doc("host", [finding("host:h1", "host.ssh_password_auth", kind=None)], [ok("host:h1")])})

    crit = finding("host:h1", "host.critical_thing", severity="critical", observed="2026-11-01T08:00:00Z")
    write_case("ledger", "due-date-on-first-record", {
        "title": "TARGET: a finding has its remediation due date as soon as the ledger first records it "
                 "(entry due_at = first_seen + SLO of its class; default SLO critical 7d)",
        "contract": C, "deviation": "LEDGER-D2",
        "origin": "continuity test: a new finding showed DUE '-' for up to an hour, until the remediation job ran",
        "steps": [merge(1, {DOC: "run1.json"}, [L({"entries": {crit["id"]: {"status": "open", "due_at": "2026-11-08T08:00:00Z"}}})])]},
        {"run1.json": doc("host", [crit], [ok("host:h1")])})

    img = finding("image:registry.example/web:1", "vuln.cve-2099-3333", layer="supply-chain", severity="high", kind="vulnerability")
    write_case("ledger", "gap-matches-asset-not-substring", {
        "title": "TARGET: a gap protects the assets it covers (same matching rules as ok entries), not every asset whose "
                 "name contains the gap's name",
        "contract": C, "deviation": "LEDGER-D3",
        "origin": "found while writing the contracts: a gap `host:web` keeps `image:registry.example/web:1` from being fixed",
        "steps": [merge(1, {"vuln-intel.findings.json": "run1.json"}),
                  merge(2, {"vuln-intel.findings.json": "run2.json"}, [L({"entries": {img["id"]: {"status": "fixed"}}})])]},
        {"run1.json": doc("vuln-intel", [img], [ok(img["asset"])]),
         "run2.json": doc("vuln-intel", [], [ok(img["asset"]), gap("host:web", "sbom unreadable")], finished="2026-11-02T09:00:00Z")})

    write_case("ledger", "removed-exception-reopens", {
        "title": "TARGET: when a human removes an exception from exceptions.yaml, the accepted finding is open again "
                 "(acceptance exists only while a valid exception says so)",
        "contract": C, "deviation": "LEDGER-D5",
        "origin": "found while writing the contracts: only entries listed in exceptions.yaml are re-evaluated",
        "files": {"data/exceptions.yaml": "valid.yaml"},
        "steps": [merge(1, {DOC: "run1.json"}, [L({"entries": {a["id"]: {"status": "accepted"}}})]),
                  merge(2, {DOC: "run1.json"}, extra={"data/exceptions.yaml": "empty.yaml"}, name="exception removed",
                        expect=[L({"entries": {a["id"]: {"status": "open"}}})])]},
        {"valid.yaml": f"exceptions:\n  {a['id']}: {{approved_by: alice, reason: lab, expires: '2099-01-01'}}\n",
         "empty.yaml": "exceptions: {}\n", "run1.json": doc("host", [a], [ok("host:h1")])})

    s1 = finding("host:h1", "host.ssh_password_auth", observed="2026-03-20T12:00:00Z")
    write_case("ledger", "time-arithmetic-is-utc", {
        "title": "TARGET: durations are computed on UTC instants whatever the process time zone (a DST change between "
                 "first_seen and fixed_at does not change time_to_fix_days)",
        "contract": C, "deviation": "LEDGER-D4",
        "origin": "found while writing the contracts: timestamps are parsed with mktime (local time, DST) minus the standard offset",
        "steps": [merge(1, {DOC: "run1.json"}, env={"TZ": "Europe/Berlin"}),
                  merge(2, {DOC: "run2.json"}, env={"TZ": "Europe/Berlin"},
                        expect=[L({"entries": {s1["id"]: {"status": "fixed", "time_to_fix_days": 14.0}}})])]},
        {"run1.json": doc("host", [s1], [ok("host:h1")], finished="2026-03-20T12:00:00Z"),
         "run2.json": doc("host", [], [ok("host:h1")], finished="2026-04-03T12:00:00Z")})


# ==================================================================================================================
# remediation (contract ledger/1.0, tracker part): <impl> --data DATA [--instance F] [--now EPOCH]
# ==================================================================================================================
def entry(f, status="open", collector="host", **kw):
    e = dict(f, status=status, first_seen=f["observed_at"], last_seen=f["observed_at"], fixed_at=None, reopened_count=0,
             collector=collector, collector_version="1.0.0", refs=[], attributes=f.get("attributes", {}), ttk_counted=False)
    e.pop("observed_at")
    e.update(kw)
    return e


def ledger_doc(*entries):
    return {"schema": "security-platform/ledger/v1", "entries": {e["id"]: e for e in entries}, "runs": [],
            "updated_at": "2026-11-01T09:00:00Z"}


def track(now, expect, name=None, files=None, instance=True):
    st = {"name": name or f"track at {now}", "exec": {"impl": "remediation", "args": ["--data", "{sandbox}/data", "--now", str(epoch(now))]
                                                    + (["--instance", "{sandbox}/instance.json"] if instance else [])},
          "expect": expect}
    if files:
        st["files"] = files
    return st


def T(subset):
    return {"json": "data/tracker/items.json", "schema": "tracker", "subset": subset}


def remediation_cases():
    C = "ledger/1.0 (tracker)"
    inst = {"name": "conformance", "remediation": {"default_owner": "security-oncall",
                                                    "owners": [{"layer_in": ["workload"], "owner": "platform-team"},
                                                               {"asset_prefix": "repo:", "owner": "dev-team"}]}}
    cr = finding("host:h1", "host.crit", severity="critical", observed="2026-11-01T08:00:00Z")
    hi = finding("host:h1", "host.high", severity="high", observed="2026-11-01T08:00:00Z")
    inf = finding("host:h1", "host.info", severity="info", observed="2026-11-01T08:00:00Z")
    write_case("remediation", "due-date-and-overdue", {
        "title": "due_at = opened + SLO of the class (default critical 7d, high 30d); overdue only past it; info has no SLO",
        "contract": C, "origin": "tests/test_remediation.py::test_lifecycle_due_overdue_close_reopen",
        "files": {"data/ledger.json": "ledger.json", "instance.json": "instance.json"},
        "steps": [track("2026-11-05T00:00:00Z", [T({"schema": "security-platform/tracker/v1", "items": {
                      cr["id"]: {"status": "open", "opened_at": "2026-11-01T08:00:00Z", "due_at": "2026-11-08T08:00:00Z",
                                 "overdue": False, "slo_class": "critical", "owner": "security-oncall", "owner_source": "default"},
                      hi["id"]: {"due_at": "2026-12-01T08:00:00Z", "overdue": False},
                      inf["id"]: {"due_at": None, "overdue": False}}})]),
                  track("2026-11-09T00:00:00Z", [T({"items": {cr["id"]: {"overdue": True}, hi["id"]: {"overdue": False}}}),
                      {"prom": "data/metrics/remediation.prom", "has": [
                          {"name": "security_remediation_overdue", "labels": {"severity": "critical"}, "value": 1},
                          {"name": "security_remediation_open", "labels": {"severity": "high"}, "value": 1},
                          {"name": "security_remediation_slo_seconds", "labels": {"severity": "critical"}, "value": 604800},
                          {"name": "security_remediation_unassigned", "value": 0}],
                       "families": ["security_remediation_last_update_timestamp_seconds"]}])]},
        {"ledger.json": ledger_doc(entry(cr), entry(hi), entry(inf)), "instance.json": inst})

    write_case("remediation", "close-and-regression-restart-clock", {
        "title": "An item closes when the ledger says fixed (closed_at = fixed_at); a regression reopens it and the SLO "
                 "clock restarts at reopened_at",
        "contract": C, "origin": "tests/test_remediation.py::test_lifecycle_due_overdue_close_reopen",
        "files": {"data/ledger.json": "open.json", "instance.json": "instance.json"},
        "steps": [track("2026-11-02T00:00:00Z", []),
                  track("2026-11-04T00:00:00Z", [T({"items": {cr["id"]: {"status": "fixed", "closed_at": "2026-11-03T08:00:00Z",
                                                                         "time_to_remediate_days": 2.0, "overdue": False}}})],
                        files={"data/ledger.json": "fixed.json"}),
                  track("2026-11-10T00:00:00Z", [T({"items": {cr["id"]: {
                      "status": "open", "reopened_at": "2026-11-10T00:00:00Z", "reopen_reason": "regression",
                      "due_at": "2026-11-17T00:00:00Z", "closed_at": None, "overdue": False,
                      "history": {"$contains": [{"status": "fixed"}, {"status": "open", "at": "2026-11-10T00:00:00Z"}]}}}})],
                        files={"data/ledger.json": "reopened.json"})]},
        {"open.json": ledger_doc(entry(cr)), "instance.json": inst,
         "fixed.json": ledger_doc(entry(cr, status="fixed", fixed_at="2026-11-03T08:00:00Z", fixed_reason="not_observed")),
         "reopened.json": ledger_doc(entry(cr, reopened_count=1, last_seen="2026-11-10T00:00:00Z"))})

    write_case("remediation", "exception-expiry-reopens-item", {
        "title": "Accepted items are not overdue; when the ledger reopens one because its exception expired, the item "
                 "reopens with reason 'exception expired'",
        "contract": C, "origin": "tests/test_remediation.py::test_exception_accepts_then_expiry_reopens",
        "files": {"data/ledger.json": "accepted.json", "instance.json": "instance.json"},
        "steps": [track("2026-12-01T00:00:00Z", [T({"items": {cr["id"]: {"status": "accepted", "overdue": False,
                                                                         "exception": {"approved_by": "alice"}}}})]),
                  track("2026-12-02T00:00:00Z", [T({"items": {cr["id"]: {"status": "open", "reopen_reason": "exception expired",
                                                                         "reopened_at": "2026-12-02T00:00:00Z"}}})],
                        files={"data/ledger.json": "expired.json"})]},
        {"accepted.json": ledger_doc(entry(cr, status="accepted", exception={"approved_by": "alice", "reason": "lab", "expires": "2026-12-01"})),
         "expired.json": ledger_doc(entry(cr, exception={"approved_by": "alice", "reason": "lab", "expires": "2026-12-01", "expired": True})),
         "instance.json": inst})

    wl = finding("k8s-workload:c/ns/web", "k8s.privileged", layer="workload")
    rp = finding("repo:acme/app", "codehost.no_branch_protection", layer="supply-chain")
    tm = finding("host:h2", "host.x", owner="network-team")
    hint = finding("host:h3", "host.y", owner="human")
    write_case("remediation", "owner-rules", {
        "title": "owner: first matching rule, else the finding's own team owner (role hints platform/human do not count), "
                 "else default_owner, else unassigned (counted)",
        "contract": C, "origin": "tests/test_remediation.py::test_owner_rules; fix 9116aae",
        "files": {"data/ledger.json": "ledger.json", "instance.json": "instance.json"},
        "steps": [track("2026-11-02T00:00:00Z", [T({"items": {
            wl["id"]: {"owner": "platform-team", "owner_source": "rule"}, rp["id"]: {"owner": "dev-team", "owner_source": "rule"},
            tm["id"]: {"owner": "network-team", "owner_source": "finding"},
            hint["id"]: {"owner": "security-oncall", "owner_source": "default"}}})]),
            dict(track("2026-11-02T00:00:00Z", [T({"items": {hint["id"]: {"owner": "unassigned", "owner_source": "none"}}}),
                                                {"prom": "data/metrics/remediation.prom",
                                                 "has": [{"name": "security_remediation_unassigned", "value": 3}]}],
                       instance=False, name="no instance: no default owner"), remove=["data/tracker"])]},
        {"ledger.json": ledger_doc(entry(wl), entry(rp), entry(tm), entry(hint)), "instance.json": inst})


# ==================================================================================================================
# scorecard (contract scorecard/1.0): <impl> compute --data D --instance F --now EPOCH
# ==================================================================================================================
CATALOG = {
    "01-alpha.yaml": """schema: security-platform/scorecard-catalog/v1
dimension: {id: alpha, order: 1, title: Alpha, pillars: [network, device]}
controls:
  - {id: alpha.reviewed, title: Reviewed, csf: GV.OC, pillars: [network], check: attested, weight: 2, validity: 90d, question: "Was it reviewed?"}
  - id: alpha.no-critical
    title: No open critical finding
    csf: ID.RA
    pillars: [device]
    check: automated
    weight: 1
    source: {type: findings, severity_in: [critical]}
""",
    "02-beta.yaml": """schema: security-platform/scorecard-catalog/v1
dimension: {id: beta, order: 2, title: Beta, pillars: [people]}
controls:
  - {id: beta.trained, title: Trained, csf: PR.AT, pillars: [people], check: attested, weight: 2, validity: 365d, question: "Trained?", tags: [people]}
  - {id: beta.expired, title: Expired attestation, csf: PR.AA, pillars: [people], check: attested, weight: 1, validity: 30d, question: "Holds?"}
  - {id: beta.missing, title: Never attested, csf: PR.AA, pillars: [people], check: attested, weight: 1, validity: 30d, question: "Holds?"}
  - {id: beta.waived, title: Waived by a human, csf: PR.AA, pillars: [people], check: attested, weight: 5, validity: 30d, question: "Holds?"}
""",
    "03-gamma.yaml": """schema: security-platform/scorecard-catalog/v1
dimension: {id: gamma, order: 3, title: Gamma (cloud only), pillars: [software], applies_when: {instance: cloud.accounts}}
controls:
  - {id: gamma.thing, title: Thing, csf: PR.PS, pillars: [software], check: attested, weight: 1, validity: 30d, question: "Thing?"}
""",
}
ATTEST = """schema: security-platform/attestations/v1
attestations:
  alpha.reviewed: {attested_by: alice, at: '2030-01-01', expires: '2030-03-01'}
  beta.trained: {attested_by: bob, at: '2030-01-01', expires: '2031-01-01', value: true}
  beta.expired: {attested_by: bob, at: '2029-10-01', expires: '2029-11-01'}
  beta.waived: {attested_by: carol, at: '2030-01-01', expires: '2031-01-01', not_applicable: not used here}
"""
NOW = "2030-01-10T00:00:00Z"


def compute(now, expect, name=None, files=None):
    st = {"name": name or f"compute at {now}", "exec": {"impl": "scorecard", "args": [
        "compute", "--data", "{sandbox}/data", "--instance", "{sandbox}/instance.json", "--now", str(epoch(now))]},
        "expect": expect}
    if files:
        st["files"] = files
    return st


def SC(subset):
    return {"json": "data/reports/scorecard.json", "schema": "scorecard", "subset": subset}


def scorecard_cases():
    C = "scorecard/1.0"
    inst = {"name": "conformance", "scorecard": {"replace_catalog": True, "catalog_dirs": ["{sandbox}/catalog"]}}
    base_files = {f"catalog/{k}": f"catalog/{k}" for k in CATALOG}
    base_files.update({"instance.json": "instance.json", "data/attestations.yaml": "attestations.yaml",
                       "data/ledger.json": "ledger.json"})
    crit = finding("host:h1", "host.crit", severity="critical")
    files = {f"catalog/{k}": v for k, v in CATALOG.items()}
    files.update({"instance.json": inst, "attestations.yaml": ATTEST, "ledger.json": ledger_doc(entry(crit, status="fixed"))})
    write_case("scorecard", "weakest-link", {
        "title": "Score = weighted pass ratio per dimension; overall = the weakest dimension; FAIL when one dimension is "
                 "below the threshold; expired/unattested fail; human-approved not_applicable is excluded; a dimension "
                 "whose applies_when does not hold is not applicable (never a penalty)",
        "contract": C, "origin": "tests/test_scorecard.py::test_weakest_link_and_weights, test_attestations_expire_and_need_a_human",
        "files": base_files,
        "steps": [compute(NOW, [SC({
            "schema": "security-platform/scorecard/v1", "computed_at": NOW, "threshold": 75.0, "status": "FAIL",
            "overall": 50.0, "mean": 75.0, "weakest": "beta",
            "dimensions": {"alpha": {"score": 100.0, "status": "PASS", "weight_total": 3, "weight_passed": 3, "failing": []},
                           "beta": {"score": 50.0, "status": "FAIL", "weight_total": 4, "weight_passed": 2,
                                    "failing": {"$unordered": ["beta.expired", "beta.missing"]}},
                           "gamma": {"$absent": True}},
            "not_applicable": {"gamma": {"reason": {"$regex": "cloud.accounts"}}},
            "attestations": {"valid": 2, "expired": 1, "missing": 1, "expiring": 0},
            "controls": {"$contains": [{"id": "alpha.reviewed", "status": "pass", "expires": "2030-03-01"},
                                       {"id": "alpha.no-critical", "status": "pass"},
                                       {"id": "beta.expired", "status": "expired"},
                                       {"id": "beta.missing", "status": "unattested"},
                                       {"id": "beta.waived", "status": "na"},
                                       {"id": "gamma.thing", "status": "na"}]}}),
            {"prom": "data/metrics/scorecard.prom", "has": [
                {"name": "security_score", "labels": {"dimension": "alpha"}, "value": 100, "exact_labels": True},
                {"name": "security_score", "labels": {"dimension": "beta"}, "value": 50, "exact_labels": True},
                {"name": "security_score_overall", "value": 50}, {"name": "security_score_pass", "value": 0},
                {"name": "security_score_threshold", "value": 75},
                {"name": "security_score_controls", "labels": {"dimension": "beta", "status": "fail"}, "value": 2},
                {"name": "security_score_controls", "labels": {"dimension": "beta", "status": "na"}, "value": 1},
                {"name": "security_attestations", "labels": {"state": "expired"}, "value": 1},
                {"name": "security_scorecard_last_compute_timestamp_seconds", "value": epoch(NOW)}],
             "absent": [{"name": "security_score", "labels": {"dimension": "gamma"}}]},
            {"exists": "data/reports/scorecard.md"}])]}, files)

    write_case("scorecard", "automated-control-reads-ledger", {
        "title": "An automated `findings` control passes with no matching open entry and fails with one",
        "contract": C, "origin": "tests/test_scorecard.py::test_evaluators",
        "files": base_files,
        "steps": [compute(NOW, [SC({"controls": {"$contains": [{"id": "alpha.no-critical", "status": "pass"}]}})]),
                  compute(NOW, [SC({"controls": {"$contains": [{"id": "alpha.no-critical", "status": "fail"}]},
                                    "dimensions": {"alpha": {"score": 66.7, "status": "FAIL"}}, "overall": 50.0})],
                          name="an open critical appears", files={"data/ledger.json": "ledger-open.json"})]},
        dict(files, **{"ledger-open.json": ledger_doc(entry(crit))}))

    good = ATTEST.replace("beta.expired: {attested_by: bob, at: '2029-10-01', expires: '2029-11-01'}",
                          "beta.expired: {attested_by: bob, at: '2030-01-01', expires: '2031-01-01'}") + \
        "  beta.missing: {attested_by: bob, at: '2030-01-01', expires: '2031-01-01'}\n"
    write_case("scorecard", "regression-counter", {
        "title": "A dimension that drops below its threshold counts one regression (first sight = baseline); a standing "
                 "low score does not count again",
        "contract": C, "origin": "tests/test_scorecard.py::test_regression_counter_and_metrics_contract",
        "files": dict(base_files, **{"data/attestations.yaml": "good.yaml"}),
        "steps": [compute(NOW, [SC({"status": "PASS", "overall": 100.0, "regressions_total": {"alpha": 0, "beta": 0}})]),
                  compute(NOW, [SC({"status": "FAIL", "regressions_total": {"beta": 1}}),
                                {"prom": "data/metrics/scorecard.prom", "has": [
                                    {"name": "security_score_regressions_total", "labels": {"dimension": "beta"}, "value": 1}],
                                 "types": {"security_score_regressions_total": "counter"}}],
                          name="attestations expire", files={"data/attestations.yaml": "attestations.yaml"}),
                  compute(NOW, [SC({"regressions_total": {"beta": 1}})], name="still failing: no new regression")]},
        dict(files, **{"good.yaml": good}))

    inst_na = {"name": "conformance", "scorecard": {"replace_catalog": True, "catalog_dirs": ["{sandbox}/catalog"],
                                                    "threshold": 50, "not_applicable": {"tag:people": "no staff",
                                                                                        "beta.miss*": "not ours"}}}
    write_case("scorecard", "instance-scope-and-threshold", {
        "title": "The instance may declare controls not applicable (by id glob or tag:, with a reason) and set the "
                 "threshold; a reason is mandatory",
        "contract": C, "origin": "tests/test_scorecard.py::test_opt_outs_are_not_applicable, test_instance_keys_need_reasons",
        "files": dict(base_files, **{"instance.json": "instance-na.json"}),
        "steps": [compute(NOW, [SC({"threshold": 50.0, "dimensions": {"beta": {"score": 0.0, "status": "FAIL", "weight_total": 1}},
                                    "controls": {"$contains": [{"id": "beta.trained", "status": "na", "detail": {"$regex": "no staff"}},
                                                               {"id": "beta.missing", "status": "na"}]}})]),
                  dict(compute(NOW, [], name="a not_applicable entry without a reason is refused"),
                       files={"instance.json": "instance-noreason.json"}, exit={"not": 0})]},
        dict(files, **{"instance-na.json": inst_na,
                       "instance-noreason.json": dict(inst_na, scorecard=dict(inst_na["scorecard"], not_applicable={"beta.*": ""}))}))
    scorecard_scope_cases()
    scorecard_score_cases()
    scorecard_attestation_cases()
    scorecard_evaluator_cases()


SC_HEAD = "schema: security-platform/scorecard-catalog/v1\n"
PASSING_SRC = "{type: findings}"            # nothing open in the ledger: passes
FAILING_SRC = "{type: findings, max: -1}"   # 0 findings > -1: fails


def sc_inst(**sc):
    return {"name": "conformance", "scorecard": dict({"replace_catalog": True, "catalog_dirs": ["{sandbox}/catalog"]}, **sc)}


def sc_ledger(collectors=None, sli=None, entries=()):
    d = ledger_doc(*entries)
    if collectors is not None:
        d["collectors"] = collectors
    if sli is not None:
        d["sli"] = sli
    return d


def SCF(*regex):
    """The printed report: number formatting is part of the contract (SPEC §4, rounding and printing)."""
    return {"file": "data/reports/scorecard.json", "regex": list(regex)}


def controls_are(**status):
    return {"controls": {"$contains": [{"id": k.replace("__", ".").replace("_", "-"), "status": v} for k, v in status.items()]}}


def scorecard_scope_cases():
    C = "scorecard/1.1"
    catalog = SC_HEAD + """dimension: {id: scope, order: 1, title: Scope, pillars: [device]}
controls:
  - {id: scope.exact, title: Exact id, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.glob-a, title: Glob a, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.glob-b, title: Glob b, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.bracket1, title: Character class, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.tagged, title: Tagged, csf: PR.PS, check: automated, weight: 1, tags: [ai-agent], source: {type: findings}}
  - {id: scope.disabled, title: Disabled with a reason, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.disabled-flag, title: Disabled, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
  - {id: scope.needs-col, title: Needs k8s, csf: DE.CM, check: automated, weight: 1, source: {type: findings, require_collector: k8s}}
  - id: scope.nested-col
    title: Needs identity or cloud, nested
    csf: DE.CM
    check: automated
    weight: 1
    source: {type: all, of: [{type: findings, require_collector: [identity, cloud]}, {type: findings}]}
  - id: scope.col-fallback
    title: Needs k8s, or a human
    csf: DE.CM
    check: automated
    weight: 1
    validity: 30d
    question: Does it hold?
    source: {type: first_known, of: [{type: findings, require_collector: k8s}, {type: attestation}]}
  - {id: scope.col-job, title: Collector of a runner job, csf: DE.CM, check: automated, weight: 1, source: {type: findings, require_collector: vuln}}
  - {id: scope.col-ledger, title: Collector in the ledger, csf: DE.CM, check: automated, weight: 1, source: {type: findings, require_collector: host}}
  - {id: scope.star, title: Any collector, csf: DE.CM, check: automated, weight: 1, source: {type: findings, require_collector: "*"}}
  - {id: scope.plain, title: Plain, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
"""

    def instance(unconfigured=None):
        return ("""name: conformance
runner:
  jobs:
    scan: {type: collector, collector: vuln-intel, as: vuln}
    report: {type: export, as: k8s}
scorecard:
  replace_catalog: true
  catalog_dirs: ["{sandbox}/catalog"]
""" + (f"  unconfigured_collectors: {unconfigured}\n" if unconfigured else "") + """  not_applicable:
    scope.exact: an exact id
    "scope.glob-?": one character
    "scope.bracket[0-9]": a character class
    "tag:ai-agent": no AI coding agents in use
    "scope.tag*": never used (the tag above matches first)
  overrides:
    scope.disabled: {disabled: replaced by a manual check}
    scope.disabled-flag: {disabled: true}
""")
    write_case("scorecard", "not-applicable-scope", {
        "title": "Instance scope: not_applicable by exact id, glob (?, [..]) and tag: (the first matching entry gives the "
                 "reason), overrides.<id>.disabled, and unconfigured_collectors: not_applicable for controls that need a "
                 "collector this instance never ran (nested sources too; a control a human can attest is never excluded; "
                 "a non-collector job does not count); the default `unknown` counts them as failing",
        "contract": C, "origin": "tests/test_scorecard.py::test_opt_outs_are_not_applicable, test_unconfigured_collectors",
        "files": {"catalog/01-scope.yaml": "catalog/01-scope.yaml", "instance.yaml": "instance-na.yaml",
                  "data/ledger.json": "ledger.json"},
        "steps": [
            dict(compute(NOW, [SC({
                "status": "FAIL",
                "dimensions": {"scope": {"score": 60.0, "weight_total": 5, "weight_passed": 3, "controls": 14,
                                         "failing": ["scope.col-fallback", "scope.col-job"]}},
                "controls": {"$contains": [
                    {"id": "scope.exact", "status": "na", "detail": {"$regex": r"\(scope\.exact\): an exact id$"}},
                    {"id": "scope.glob-a", "status": "na", "detail": {"$regex": "one character$"}},
                    {"id": "scope.glob-b", "status": "na", "detail": {"$regex": "one character$"}},
                    {"id": "scope.bracket1", "status": "na", "detail": {"$regex": "a character class$"}},
                    {"id": "scope.tagged", "status": "na", "detail": {"$regex": r"\(tag:ai-agent\): no AI coding agents in use$"}},
                    {"id": "scope.disabled", "status": "na",
                     "detail": "not applicable: disabled by the instance: replaced by a manual check"},
                    {"id": "scope.disabled-flag", "status": "na", "detail": "not applicable: disabled by the instance"},
                    {"id": "scope.needs-col", "status": "na", "detail": "not applicable: collector not configured: k8s"},
                    {"id": "scope.nested-col", "status": "na",
                     "detail": "not applicable: collector not configured: cloud, identity"},
                    {"id": "scope.col-fallback", "status": "unattested", "attestable": True},
                    {"id": "scope.col-job", "status": "unknown", "detail": {"$regex": "vuln: never covered anything"}},
                    {"id": "scope.col-ledger", "status": "pass"},
                    {"id": "scope.star", "status": "pass", "detail": "0 matching finding(s) (max 0)"},
                    {"id": "scope.plain", "status": "pass", "detail": "0 matching finding(s) (max 0)"}]}}),
                {"prom": "data/metrics/scorecard.prom", "has": [
                    {"name": "security_score_controls", "labels": {"dimension": "scope", "status": "na"}, "value": 9},
                    {"name": "security_score_controls", "labels": {"dimension": "scope", "status": "fail"}, "value": 2},
                    {"name": "security_score_controls", "labels": {"dimension": "scope", "status": "pass"}, "value": 3}]},
                SCF(r'"score": 60\.0,')]), exec=_inst_exec("instance.yaml")),
            dict(compute(NOW, [SC({
                "dimensions": {"scope": {"score": 42.9, "weight_total": 7, "weight_passed": 3}},
                "controls": {"$contains": [
                    {"id": "scope.needs-col", "status": "unknown", "detail": {"$regex": "^no recent coverage \\(k8s: never"}},
                    {"id": "scope.nested-col", "status": "unknown"}]}})],
                name="default unconfigured_collectors: unknown (no data is not secure)",
                files={"instance.yaml": "instance-unknown.yaml"}), exec=_inst_exec("instance.yaml")),
            dict(compute(NOW, [], name="unconfigured_collectors must be unknown or not_applicable",
                         files={"instance.yaml": "instance-bad.yaml"}), exec=_inst_exec("instance.yaml"), exit={"not": 0}),
        ]},
        {"catalog/01-scope.yaml": catalog, "instance-na.yaml": instance("not_applicable"),
         "instance-unknown.yaml": instance(), "instance-bad.yaml": instance("sometimes"),
         "ledger.json": sc_ledger(collectors={"host": {"version": "1.0.0", "last_good_run": "2030-01-09T12:00:00Z"}})})

    base = SC_HEAD + """dimension: {id: base, order: 1, title: Base, pillars: [device]}
controls:
  - {id: base.ok, title: Ok, csf: PR.PS, check: automated, weight: 1, source: {type: findings}}
"""
    cloud = SC_HEAD + """dimension:
  id: cloud
  order: 12
  title: Cloud
  pillars: [software]
  applies_when: {any: [{instance: cloud.accounts}, {coverage_prefix: "cloud:"}]}
controls:
  - {id: cloud.logging, title: Audit logging, csf: DE.CM, check: automated, weight: 1, source: {type: findings}}
"""
    agents = SC_HEAD + """dimension: {id: agents, order: 13, title: Agents, pillars: [software]}
controls:
  - {id: agents.deny, title: Deny rules, csf: PR.PS, check: automated, weight: 1, tags: [ai-agent], source: {type: findings}}
"""
    inst = sc_inst(not_applicable={"tag:ai-agent": "no AI coding agents"})
    cloud_doc = doc("cloud", [], [gap("cloud:gcp/project-1", reason="no credentials")], finished="2030-01-09T00:00:00Z")
    write_case("scorecard", "cloud-dimension-not-applicable", {
        "title": "A dimension whose applies_when does not hold ({any: [{instance: cloud.accounts}, {coverage_prefix: "
                 "cloud:}]}) is listed under not_applicable and in no score; it applies once a newest document covered "
                 "(even as a gap) such an asset, or the instance has a non-empty value at the key; a dimension all of whose "
                 "controls are not applicable is not applicable too",
        "contract": C, "origin": "tests/test_scorecard.py::test_cloud_dimension_applies_only_with_cloud_accounts",
        "files": {"catalog/01-base.yaml": "catalog/01-base.yaml", "catalog/12-cloud.yaml": "catalog/12-cloud.yaml",
                  "catalog/13-agents.yaml": "catalog/13-agents.yaml", "instance.json": "instance.json",
                  "data/ledger.json": "ledger.json"},
        "steps": [
            compute(NOW, [SC({
                "status": "PASS", "overall": 100.0, "weakest": "base",
                "dimensions": {"base": {"score": 100.0}, "cloud": {"$absent": True}, "agents": {"$absent": True}},
                "not_applicable": {
                    "cloud": {"title": "Cloud", "order": 12, "controls": 1,
                              "reason": "instance has no cloud.accounts and no cloud:* asset in scope"},
                    "agents": {"reason": "every control is not applicable", "controls": 1}},
                "pillars": {"software": {"score": 0.0, "controls": 2, "status": "FAIL"}},
                "dimension_pillar": {"cloud|software": {"$absent": True}},
                "controls": {"$contains": [{"id": "cloud.logging", "status": "na",
                                            "detail": "not applicable: instance has no cloud.accounts and no cloud:* asset in scope"}]}}),
                {"prom": "data/metrics/scorecard.prom", "absent": [
                    {"name": "security_score", "labels": {"dimension": "cloud"}},
                    {"name": "security_score_controls", "labels": {"dimension": "cloud", "status": "na"}}]}]),
            compute(NOW, [SC({"dimensions": {"cloud": {"score": 100.0, "status": "PASS"}},
                              "not_applicable": {"cloud": {"$absent": True}},
                              "dimension_pillar": {"cloud|software": 100.0}})],
                    name="a cloud asset in the newest documents (a gap counts: the account exists)",
                    files={"data/latest/cloud.findings.json": "cloud.findings.json"}),
            dict(compute(NOW, [SC({"not_applicable": {"cloud": {"reason": {"$regex": "^instance has no cloud.accounts"}}}})],
                         name="an empty value does not count", files={"instance.json": "instance-empty.json"}),
                 remove=["data/latest/cloud.findings.json"]),
            compute(NOW, [SC({"dimensions": {"cloud": {"score": 100.0}}, "not_applicable": {"cloud": {"$absent": True}}})],
                    name="cloud accounts in the instance", files={"instance.json": "instance-cloud.json"}),
        ]},
        {"catalog/01-base.yaml": base, "catalog/12-cloud.yaml": cloud, "catalog/13-agents.yaml": agents,
         "instance.json": inst, "instance-empty.json": dict(inst, cloud={"accounts": []}),
         "instance-cloud.json": dict(inst, cloud={"accounts": [{"id": "project-1"}]}),
         "cloud.findings.json": cloud_doc, "ledger.json": sc_ledger()})


def _inst_exec(name):
    return {"impl": "scorecard", "args": ["compute", "--data", "{sandbox}/data", "--instance", f"{{sandbox}}/{name}",
                                          "--now", str(epoch(NOW))]}


def scorecard_score_cases():
    C = "scorecard/1.1"
    P, F = PASSING_SRC, FAILING_SRC
    cat = {
        "01-one.yaml": SC_HEAD + f"""dimension: {{id: one, order: 1, title: One, pillars: [network]}}
controls:
  - {{id: one.a, title: A, csf: GV.OC, pillars: [network], check: automated, weight: 1, source: {P}}}
  - {{id: one.b, title: B, csf: ID.AM, pillars: [network, device], check: automated, weight: 15, source: {F}}}
""",
        "02-two.yaml": SC_HEAD + f"""dimension: {{id: two, order: 2, title: Two, pillars: [device]}}
controls:
  - {{id: two.a, title: A, csf: PR.AA, check: automated, weight: 3, source: {P}}}
  - {{id: two.b, title: B, csf: PR.PS, check: automated, weight: 13, source: {F}}}
""",
        "03-three.yaml": SC_HEAD + f"""dimension: {{id: three, order: 3, title: Three, pillars: [software], threshold: 80}}
controls:
  - {{id: three.a, title: A, csf: DE.CM, check: automated, weight: 2.5, source: {P}}}
  - {{id: three.b, title: B, csf: RS.MA, check: automated, weight: 0.5, source: {F}}}
  - {{id: three.c, title: Declared only, csf: DE.AE, check: evidence, weight: 0, source: {{type: none, reason: later}}}}
""",
        "05-five.yaml": SC_HEAD + f"""dimension: {{id: five, order: 5, title: Five, pillars: [people]}}
controls:
  - {{id: five.a, title: A, csf: GV.RR, check: automated, weight: 1, source: {P}}}
  - {{id: five.b, title: B, csf: ID.RA, check: automated, weight: 15, source: {F}}}
""",
    }
    inst = sc_inst(threshold=75.5, pillars=["network", "device", "people", "software", "physical"])
    write_case("scorecard", "weights-rounding-and-weakest-link", {
        "title": "Weighted pass ratio rounded to one decimal, ties to even on the exact binary value (1/16 = 6.25 -> 6.2, "
                 "3/16 = 18.75 -> 18.8); float weights; weight 0; per-dimension threshold; overall = the minimum, weakest = "
                 "the first dimension (in catalog order) with it; mean; pillars (instance list, an empty pillar scores 0 and "
                 "fails), NIST CSF functions (all six, an empty one scores 0 and has no metric), dimension x pillar; "
                 "numbers printed as the contract says",
        "contract": C, "origin": "tests/test_scorecard.py::test_weakest_link_and_weights",
        "files": dict({f"catalog/{k}": f"catalog/{k}" for k in cat},
                      **{"instance.json": "instance.json", "data/ledger.json": "ledger.json"}),
        "steps": [compute(NOW, [
            SC({"threshold": 75.5, "status": "FAIL", "overall": 6.2, "weakest": "one", "mean": 28.6,
                "dimensions": {
                    "one": {"score": 6.2, "status": "FAIL", "weight_total": 16, "weight_passed": 1, "threshold": 75.5,
                            "pillars": ["device", "network"], "functions": ["GV", "ID"]},
                    "two": {"score": 18.8, "status": "FAIL", "weight_total": 16, "weight_passed": 3},
                    "three": {"score": 83.3, "status": "PASS", "threshold": 80.0, "weight_total": 3.0, "weight_passed": 2.5,
                              "failing": ["three.b", "three.c"], "controls": 3},
                    "five": {"score": 6.2, "status": "FAIL"}},
                "pillars": {"network": {"score": 6.2, "controls": 2, "status": "FAIL"},
                            "device": {"score": 9.7, "controls": 3},
                            "people": {"score": 6.2, "controls": 2},
                            "software": {"score": 83.3, "controls": 3, "status": "PASS"},
                            "physical": {"score": 0.0, "controls": 0, "status": "FAIL", "failing": []}},
                "functions": {"GV": {"title": "Govern", "score": 100.0, "controls": 2},
                              "ID": {"score": 0.0, "controls": 2}, "PR": {"score": 18.8, "controls": 2},
                              "DE": {"score": 100.0, "controls": 2}, "RS": {"score": 0.0, "controls": 1},
                              "RC": {"title": "Recover", "score": 0.0, "controls": 0}},
                "dimension_pillar": {"one|network": 6.2, "one|device": 0.0, "two|device": 18.8, "three|software": 83.3,
                                     "five|people": 6.2, "one|people": {"$absent": True}},
                "controls": {"$contains": [{"id": "three.c", "status": "not_implemented", "detail": "later", "weight": 0},
                                           {"id": "five.a", "pillars": ["people"], "function": "GV", "csf": "GV.RR"}]}}),
            SCF(r'"score": 6\.2,', r'"score": 18\.8,', r'"weight_total": 3\.0\n', r'"weight_passed": 2\.5,',
                r'"weight_total": 16\n', r'"mean": 28\.6,', r'"threshold": 75\.5,', r'"threshold": 80\.0,'),
            {"file": "data/metrics/scorecard.prom",
             "regex": [r'(?m)^security_score\{dimension="one"\} 6\.2$', r'(?m)^security_score\{dimension="two"\} 18\.8$',
                       r'(?m)^security_score\{function="GV"\} 100$', r'(?m)^security_score_threshold 75\.5$',
                       r'(?m)^security_score_overall 6\.2$', r'(?m)^security_score\{dimension="one",pillar="device"\} 0$',
                       r'(?m)^security_score_pass 0$']},
            {"prom": "data/metrics/scorecard.prom", "absent": [{"name": "security_score", "labels": {"function": "RC"}}],
             "has": [{"name": "security_score", "labels": {"pillar": "physical"}, "value": 0},
                     {"name": "security_score", "labels": {"dimension": "three", "pillar": "software"}, "value": 83.3}]},
        ])]},
        dict({f"catalog/{k}": v for k, v in cat.items()}, **{"instance.json": inst, "ledger.json": sc_ledger()}))

    # regression counter over several computes: recover, fail again, and a dimension that left the catalog
    reg = {
        "01-alpha.yaml": SC_HEAD + """dimension: {id: alpha, order: 1, title: Alpha, pillars: [device]}
controls:
  - {id: alpha.ok, title: Ok, csf: PR.PS, check: automated, weight: 1, source: {type: findings, severity_in: [critical]}}
""",
        "02-beta.yaml": SC_HEAD + """dimension: {id: beta, order: 2, title: Beta, pillars: [device]}
controls:
  - {id: beta.ok, title: Ok, csf: PR.PS, check: automated, weight: 1, source: {type: findings, check_in: [nothing]}}
""",
    }
    crit = finding("host:h1", "host.crit", severity="critical")
    clean, dirty = sc_ledger(), sc_ledger(entries=[entry(crit)])
    R = lambda alpha, beta=None: SC({"regressions_total": dict({"alpha": alpha}, **({"beta": beta} if beta is not None else {}))})
    write_case("scorecard", "regression-counter-recovers", {
        "title": "Every pass -> fail transition of a dimension adds one regression; recovering and failing again counts "
                 "again; the counter of a dimension that left the catalog is kept (a counter never goes back)",
        "contract": C, "origin": "tests/test_scorecard.py::test_regression_counter_and_metrics_contract",
        "files": dict({f"catalog/{k}": f"catalog/{k}" for k in reg},
                      **{"instance.json": "instance.json", "data/ledger.json": "clean.json"}),
        "steps": [
            compute(NOW, [R(0, 0), {"json": "data/state/scorecard.json",
                                    "subset": {"below": {"alpha": False, "beta": False}, "regressions_total": {"alpha": 0}}}],
                    name="baseline"),
            compute(NOW, [R(1, 0), {"json": "data/state/scorecard.json", "subset": {"below": {"alpha": True}}}],
                    name="alpha fails", files={"data/ledger.json": "dirty.json"}),
            compute(NOW, [R(1)], name="alpha still failing"),
            compute(NOW, [R(1)], name="alpha recovers", files={"data/ledger.json": "clean.json"}),
            compute(NOW, [R(2), {"prom": "data/metrics/scorecard.prom", "has": [
                {"name": "security_score_regressions_total", "labels": {"dimension": "alpha"}, "value": 2}],
                "types": {"security_score_regressions_total": "counter"}}],
                    name="alpha fails again", files={"data/ledger.json": "dirty.json"}),
            dict(compute(NOW, [SC({"regressions_total": {"alpha": 2, "beta": 0}, "dimensions": {"beta": {"$absent": True}}}),
                               {"prom": "data/metrics/scorecard.prom", "has": [
                                   {"name": "security_score_regressions_total", "labels": {"dimension": "beta"}, "value": 0}]}],
                         name="beta left the catalog: its counter stays"), remove=["catalog/02-beta.yaml"]),
        ]},
        dict({f"catalog/{k}": v for k, v in reg.items()},
             **{"instance.json": sc_inst(), "clean.json": clean, "dirty.json": dirty}))


def scorecard_attestation_cases():
    C = "scorecard/1.1"

    def att(name, extra=""):
        return (f"  - {{id: att.{name}, title: \"Attestation {name}\", csf: GV.OV, check: attested, weight: 1, validity: 30d, "
                f"question: \"Does {name} hold?\"{extra}}}\n")
    cat = SC_HEAD + "dimension: {id: att, order: 1, title: Attestations, pillars: [people]}\ncontrols:\n" + "".join(
        att(n) for n in ("valid", "expiring", "expired", "missing", "no-by", "no-date", "at-validity", "false",
                         "na-expired", "na-valid")) + """  - id: att.fallback-human
    title: API cannot tell, a human can
    csf: GV.OV
    check: automated
    weight: 1
    validity: 30d
    question: Holds?
    source: {type: first_known, of: [{type: sli, sli: missing}, {type: attestation}]}
  - id: att.fallback-api
    title: The API decides
    csf: GV.OV
    check: automated
    weight: 1
    validity: 30d
    question: Holds?
    source: {type: first_known, of: [{type: sli, sli: crit}, {type: attestation}]}
"""
    attest = """schema: security-platform/attestations/v1
attestations:
  att.valid: {attested_by: alice, at: 2030-01-01, expires: 2031-01-01}
  att.expiring: {attested_by: alice, at: '2030-01-01', expires: '2030-01-20'}
  att.expired: {attested_by: alice, at: '2029-11-01', expires: '2030-01-10'}
  att.no-by: {at: '2030-01-01', expires: '2031-01-01'}
  att.no-date: {attested_by: alice}
  att.at-validity: {attested_by: alice, at: '2030-01-05T12:00:00Z'}
  att.false: {attested_by: bob, at: '2030-01-01', expires: '2031-01-01', value: false, note: it does not hold}
  att.na-expired: {attested_by: carol, at: '2029-01-01', expires: '2029-06-01', not_applicable: no longer used}
  att.na-valid: {attested_by: carol, at: '2030-01-01', expires: '2030-06-01', not_applicable: not used here}
  att.fallback-human: {attested_by: dave, at: '2030-01-01', expires: '2030-03-01'}
  att.fallback-api: {attested_by: dave, at: '2030-01-01', expires: '2030-01-15'}
"""
    write_case("scorecard", "attestation-states", {
        "title": "Attestations: valid, expiring within 14 days, expired (expires <= now), missing (none, no attested_by, "
                 "no date); expires defaults to at + validity; value: false fails but is a current attestation; a "
                 "human not_applicable needs an unexpired expiry; an automated control with an attestation fallback "
                 "counts only when the human decided it; YAML dates may be unquoted",
        "contract": C, "origin": "tests/test_scorecard.py::test_attestations_expire_and_need_a_human",
        "files": {"catalog/01-att.yaml": "catalog/01-att.yaml", "instance.json": "instance.json",
                  "data/attestations.yaml": "attestations.yaml", "data/ledger.json": "ledger.json"},
        "steps": [compute(NOW, [SC({
            "attestations": {"valid": 4, "expiring": 1, "expired": 2, "missing": 3},
            "dimensions": {"att": {"score": 45.5, "weight_total": 11, "weight_passed": 5}},
            "controls": {"$contains": [
                {"id": "att.valid", "status": "pass", "expires": "2031-01-01", "needs_human": True, "attestable": True,
                 "detail": "attested by alice until 2031-01-01"},
                {"id": "att.expiring", "status": "pass", "expires": "2030-01-20",
                 "detail": "attested by alice until 2030-01-20 (expires within 14 days)"},
                {"id": "att.expired", "status": "expired", "detail": "attestation by alice expired 2030-01-10: re-attest"},
                {"id": "att.missing", "status": "unattested", "expires": None,
                 "detail": "not attested: a human answers \"Does missing hold?\" (scorecard.py attest)"},
                {"id": "att.no-by", "status": "unattested", "detail": "attestation without attested_by is ignored"},
                {"id": "att.no-date", "status": "unattested", "detail": "attestation without a date (at/expires) is ignored"},
                {"id": "att.at-validity", "status": "pass", "expires": "2030-02-04"},
                {"id": "att.false", "status": "fail", "detail": "attested as NOT holding by bob: it does not hold"},
                {"id": "att.na-expired", "status": "expired"},
                {"id": "att.na-valid", "status": "na", "detail": "not applicable (approved by carol): not used here"},
                {"id": "att.fallback-human", "status": "pass", "expires": "2030-03-01", "needs_human": False},
                {"id": "att.fallback-api", "status": "pass", "expires": None, "detail": {"$regex": "^SLI crit = 0 "}}]}}),
            {"prom": "data/metrics/scorecard.prom", "has": [
                {"name": "security_attestations", "labels": {"state": s}, "value": v}
                for s, v in (("valid", 4), ("expiring", 1), ("expired", 2), ("missing", 3))]}])]},
        {"catalog/01-att.yaml": cat, "attestations.yaml": attest, "instance.json": sc_inst(),
         "ledger.json": sc_ledger(sli={"crit": {"ok": True, "value": 0, "target": 0}})})

    summer = SC_HEAD + "dimension: {id: att, order: 1, title: Attestations, pillars: [people]}\ncontrols:\n" + att("summer")
    late_june = "2030-06-30T23:30:00Z"
    write_case("scorecard", "attestation-expiry-is-utc", {
        "title": "Dates are UTC whatever the local time zone: an attestation that expires on 2030-07-01 holds until "
                 "2030-07-01T00:00:00Z, also where daylight saving time is in effect",
        "contract": C, "origin": "SCORECARD-D1", "deviation": "SCORECARD-D1",
        "files": {"catalog/01-att.yaml": "catalog/01-att.yaml", "instance.json": "instance.json",
                  "data/attestations.yaml": "attestations.yaml", "data/ledger.json": "ledger.json"},
        "steps": [dict(compute(late_june, [SC({
            "attestations": {"expiring": 1, "expired": 0},
            "controls": {"$contains": [{"id": "att.summer", "status": "pass", "expires": "2030-07-01",
                                        "detail": "attested by alice until 2030-07-01 (expires within 14 days)"}]}})]),
                       exec=dict(compute(late_june, [])["exec"], env={"TZ": "Europe/Berlin"}))]},
        {"catalog/01-att.yaml": summer, "instance.json": sc_inst(), "ledger.json": sc_ledger(),
         "attestations.yaml": "schema: security-platform/attestations/v1\nattestations:\n"
                              "  att.summer: {attested_by: alice, at: '2030-06-01', expires: '2030-07-01'}\n"})

    sli_cat = SC_HEAD + """dimension: {id: sli, order: 1, title: SLIs, pillars: [software]}
controls:
  - {id: sli.crit, title: No open critical, csf: DE.CM, check: automated, weight: 1, source: {type: sli, sli: crit}}
  - {id: sli.ttr, title: Time to remediate, csf: RS.MI, check: automated, weight: 1, source: {type: sli, sli: ttr}}
  - {id: sli.gone, title: Not computed yet, csf: RS.MI, check: automated, weight: 1, source: {type: sli, sli: gone}}
  - {id: sli.broken, title: No SLI named, csf: RS.MI, check: automated, weight: 1, source: {type: sli}}
"""
    write_case("scorecard", "sli-objectives", {
        "title": "An `sli` control passes while the ledger's SLI meets its objective, fails when not, is unknown when "
                 "the SLI is not computed; a broken source is unknown (one broken control never hides the others)",
        "contract": C, "origin": "tests/test_scorecard.py::test_evaluators",
        "files": {"catalog/01-sli.yaml": "catalog/01-sli.yaml", "instance.json": "instance.json",
                  "data/ledger.json": "ledger.json"},
        "steps": [compute(NOW, [SC({
            "dimensions": {"sli": {"score": 25.0, "failing": ["sli.broken", "sli.gone", "sli.ttr"]}},
            "controls": {"$contains": [
                {"id": "sli.crit", "status": "pass", "detail": "SLI crit = 0 (objective <= 0)"},
                {"id": "sli.ttr", "status": "fail", "detail": "SLI ttr = 3.5 (objective <= 1)"},
                {"id": "sli.gone", "status": "unknown", "detail": "SLI gone not computed yet"},
                {"id": "sli.broken", "status": "unknown", "detail": {"$regex": "^evaluator error: "}}]}})])]},
        {"catalog/01-sli.yaml": sli_cat, "instance.json": sc_inst(),
         "ledger.json": sc_ledger(sli={"crit": {"ok": True, "value": 0, "target": 0},
                                       "ttr": {"ok": False, "value": 3.5, "target": 1}})})


def scorecard_evaluator_cases():
    C = "scorecard/1.1"
    now = epoch(NOW)
    cat = SC_HEAD + """dimension: {id: ev, order: 1, title: Evaluators, pillars: [software]}
controls:
  - {id: ev.metric-age, title: Metric age, csf: DE.CM, check: automated, weight: 1,
     source: {type: metric, name: security_collector_last_run_timestamp_seconds, match: {collector: host}, age: true, value: 2h}}
  - {id: ev.metric-old, title: Metric too old, csf: DE.CM, check: automated, weight: 1,
     source: {type: metric, name: security_collector_last_run_timestamp_seconds, match: {collector: "k8.*"}, age: true, value: 1d}}
  - {id: ev.metric-count, title: Metric count, csf: DE.CM, check: automated, weight: 1,
     source: {type: metric, name: security_collector_last_run_timestamp_seconds, agg: count, op: ">=", value: 2}}
  - {id: ev.metric-sum, title: Metric sum, csf: DE.CM, check: automated, weight: 1,
     source: {type: metric, name: security_sli, agg: sum, op: "<", value: 4}}
  - {id: ev.metric-absent, title: Metric absent, csf: DE.CM, check: automated, weight: 1, source: {type: metric, name: nope}}
  - {id: ev.metric-absent-ok, title: Absent is fine, csf: DE.CM, check: automated, weight: 1, source: {type: metric, name: nope, absent: pass}}
  - {id: ev.metric-own, title: Own scores are ignored, csf: DE.CM, check: automated, weight: 1, source: {type: metric, name: security_score_overall, absent: fail}}
  - {id: ev.job-ok, title: Job ok, csf: DE.CM, check: automated, weight: 1, source: {type: job, jobs: [scan]}}
  - {id: ev.job-rc, title: Job failed, csf: DE.CM, check: automated, weight: 1, source: {type: job, jobs: [broken]}}
  - {id: ev.job-site, title: Site job old, csf: DE.CM, check: automated, weight: 1, source: {type: job, jobs: [remote], max_age: 2d}}
  - {id: ev.job-all, title: Every job, csf: DE.CM, check: automated, weight: 1, source: {type: job}}
  - {id: ev.job-ghost, title: Never ran, csf: DE.CM, check: automated, weight: 1, source: {type: job, jobs: ghost}}
  - {id: ev.fresh, title: Host fresh, csf: DE.CM, check: automated, weight: 1, source: {type: collector_fresh, collectors: [host]}}
  - {id: ev.fresh-all, title: Every collector fresh, csf: DE.CM, check: automated, weight: 1, source: {type: collector_fresh, max_age: 2d}}
  - {id: ev.find-prefix, title: ssh findings, csf: PR.PS, check: automated, weight: 1, source: {type: findings, check_prefix: [ssh.], max: 1}}
  - {id: ev.find-sev, title: critical findings, csf: PR.PS, check: automated, weight: 1, source: {type: findings, severity_in: [critical, high]}}
  - {id: ev.find-status, title: accepted too, csf: PR.PS, check: automated, weight: 1, source: {type: findings, check_in: [tls.weak], status_in: [open, accepted]}}
  - {id: ev.find-asset, title: on h2, csf: PR.PS, check: automated, weight: 1, source: {type: findings, asset_contains: "${site}", layer_in: [host]}}
  - {id: ev.find-kind, title: vulnerabilities, csf: PR.PS, check: automated, weight: 1, source: {type: findings, kind: vulnerability, attr_true: kev}}
  - {id: ev.find-cov, title: needs host coverage, csf: PR.PS, check: automated, weight: 1, source: {type: findings, require_coverage: "host:", require_collector: host}}
  - {id: ev.find-nocov, title: needs k8s coverage, csf: PR.PS, check: automated, weight: 1, source: {type: findings, require_coverage: "k8s:"}}
  - {id: ev.var-missing, title: unset variable, csf: PR.PS, check: automated, weight: 1, source: {type: findings, asset_contains: "${nope}"}}
  - {id: ev.file-ok, title: policy, csf: GV.PO, check: evidence, weight: 1, source: {type: file, path: "${data}/policy.md", contains: "^## Scope", mode_max: "0644"}}
  - {id: ev.file-mode, title: secret mode, csf: GV.PO, check: evidence, weight: 1, source: {type: file, path: "${data}/policy.md", mode_max: "0600"}}
  - {id: ev.file-text, title: lacks text, csf: GV.PO, check: evidence, weight: 1, source: {type: file, path: "${data}/policy.md", contains: "^## Owner"}}
  - {id: ev.file-missing, title: missing, csf: GV.PO, check: evidence, weight: 1, source: {type: file, path: "${data}/nothing.md"}}
  - {id: ev.all-unknown, title: all with unknown, csf: ID.AM, check: automated, weight: 1, source: {type: all, of: [{type: findings, check_in: [nothing]}, {type: sli, sli: gone}]}}
  - {id: ev.all-fail, title: all with none, csf: ID.AM, check: automated, weight: 1, source: {type: all, of: [{type: findings, check_in: [nothing]}, {type: none}]}}
  - {id: ev.any-pass, title: any, csf: ID.AM, check: automated, weight: 1, source: {type: any, of: [{type: findings, check_in: [nothing], max: -1}, {type: findings, check_in: [nothing]}]}}
  - {id: ev.any-unknown, title: any unknown, csf: ID.AM, check: automated, weight: 1, source: {type: any, of: [{type: sli, sli: a}, {type: sli, sli: b}]}}
  - {id: ev.first-known, title: first known, csf: ID.AM, check: automated, weight: 1, source: {type: first_known, of: [{type: sli, sli: gone}, {type: findings, check_in: [nothing], max: -1}, {type: findings, check_in: [nothing]}]}}
  - {id: ev.none, title: declared, csf: RC.RP, check: automated, weight: 1, source: {type: none, reason: needs a restore drill}}
  - {id: ev.bogus, title: bogus type, csf: RC.RP, check: automated, weight: 1, source: {type: bogus}}
  - {id: ev.bad-builtin, title: bad builtin, csf: RC.RP, check: automated, weight: 1, source: {type: builtin, name: nothing}}
  - {id: ev.pillars, title: pillars covered, csf: GV.OV, check: automated, weight: 1, source: {type: builtin, name: pillars_covered}}
  - {id: ev.functions, title: functions covered, csf: GV.OV, check: automated, weight: 1, source: {type: builtin, name: functions_covered}}
  - {id: ev.current, title: attestations current, csf: GV.OV, check: automated, weight: 1, source: {type: builtin, name: attestations_current}}
  - {id: ev.replaced, title: product version, csf: GV.OV, check: automated, weight: 1, source: {type: findings, check_in: [nothing], max: -1}}
  - {id: ev.weighty, title: weight from the instance, csf: GV.OV, check: automated, weight: 1, source: {type: findings, check_in: [nothing]}}
"""
    extra = SC_HEAD + """dimension: {id: ev, order: 1, title: Evaluators, pillars: [software]}
controls:
  - {id: ev.replaced, title: organisation version, csf: GV.OV, check: automated, weight: 1, source: {type: findings, check_in: [nothing]}}
"""
    prom = f"""# HELP security_collector_last_run_timestamp_seconds Heartbeat
# TYPE security_collector_last_run_timestamp_seconds gauge
security_collector_last_run_timestamp_seconds{{collector="host"}} {now - 3600}
security_collector_last_run_timestamp_seconds{{collector="k8s"}} {now - 200000}
security_sli{{sli="a"}} 1.5
security_sli{{sli="b"}} 2
security_score_overall 100
"""
    def f(asset, check, sev="medium", kind="compliance", layer="host", **kw):
        return finding(asset, check, layer=layer, severity=sev, kind=kind, **kw)
    entries = [entry(f("host:h1", "ssh.root_login")), entry(f("host:h2", "ssh.password_auth_enabled")),
               entry(f("host:h1", "tls.weak", layer="network"), status="accepted"),
               entry(f("host:h3", "host.crit", sev="critical"), status="fixed"),
               entry(f("image:x", "CVE-1", kind="vulnerability", layer="image", attributes={"kev": True}))]
    inst = sc_inst(catalog_dirs=["{sandbox}/catalog", "{sandbox}/catalog-org"], vars={"site": "h2"},
                   overrides={"ev.weighty": {"weight": 4}})
    host_doc = doc("host", [], [ok("host:h1"), gap("host:h9")], finished="2030-01-09T00:00:00Z")
    st = lambda **kw: {"json": dict(kw)}
    expect = {
        "ev.metric-age": ("pass", "security_collector_last_run_timestamp_seconds age 1.0h (<= 2h)"),
        "ev.metric-old": ("fail", "security_collector_last_run_timestamp_seconds age 2.3d (<= 1d)"),
        "ev.metric-count": ("pass", "count(security_collector_last_run_timestamp_seconds) = 2 (>= 2)"),
        "ev.metric-sum": ("pass", "sum(security_sli) = 3.5 (< 4)"),
        "ev.metric-absent": ("unknown", "metric nope absent"),
        "ev.metric-absent-ok": ("pass", "metric nope absent"),
        "ev.metric-own": ("fail", "metric security_score_overall absent"),
        "ev.job-ok": ("pass", "1 job(s) healthy"),
        "ev.job-rc": ("fail", "broken: last run failed (rc=2)"),
        "ev.job-site": ("fail", "remote: no success within 2d"),
        "ev.job-all": ("fail", "broken: last run failed (rc=2); remote: no success within 2d"),
        "ev.job-ghost": ("fail", "ghost: never ran"),
        "ev.fresh": ("pass", "1 collector(s) fresh"),
        "ev.fresh-all": ("fail", "k8s: last good run 40.0d ago"),
        "ev.find-prefix": ("fail", "2 matching finding(s) (max 1): ssh.password_auth_enabled, ssh.root_login"),
        "ev.find-sev": ("pass", "0 matching finding(s) (max 0)"),
        "ev.find-status": ("fail", "1 matching finding(s) (max 0): tls.weak"),
        "ev.find-asset": ("fail", "1 matching finding(s) (max 0): ssh.password_auth_enabled"),
        "ev.find-kind": ("fail", "1 matching finding(s) (max 0): CVE-1"),
        "ev.find-cov": ("fail", "3 matching finding(s) (max 0): CVE-1, ssh.password_auth_enabled, ssh.root_login"),
        "ev.find-nocov": ("unknown", "nothing covered k8s:* (adapter not configured or failing)"),
        "ev.var-missing": ("unknown", "configure scorecard.vars: nope"),
        "ev.file-ok": ("pass", None),
        "ev.file-mode": ("fail", None),
        "ev.file-text": ("fail", None),
        "ev.file-missing": ("fail", None),
        "ev.all-unknown": ("unknown", "SLI gone not computed yet"),
        "ev.all-fail": ("fail", "not implemented yet"),
        "ev.any-pass": ("pass", "0 matching finding(s) (max 0)"),
        "ev.any-unknown": ("unknown", "SLI a not computed yet; SLI b not computed yet"),
        "ev.first-known": ("fail", "0 matching finding(s) (max -1)"),
        "ev.none": ("not_implemented", "needs a restore drill"),
        "ev.bogus": ("unknown", "unknown source type 'bogus'"),
        "ev.bad-builtin": ("unknown", "evaluator error: ValueError: unknown builtin 'nothing'"),
        "ev.pillars": ("fail", "no passing automated control for: network, device, people"),
        "ev.functions": ("fail", None),
        "ev.current": ("pass", "0 attested controls, none expired"),
        "ev.replaced": ("pass", None),
        "ev.weighty": ("pass", None),
    }
    ctls = []
    for cid, (s, d) in expect.items():
        x = {"id": cid, "status": s}
        if d is not None:
            x["detail"] = d
        ctls.append(x)
    ctls.append({"id": "ev.replaced", "title": "organisation version"})
    ctls.append({"id": "ev.weighty", "weight": 4})
    write_case("scorecard", "evaluators", {
        "title": "Every evaluator type (metric incl. age/agg/match/absent and the scorecard's own series ignored, job incl. "
                 "site states, collector_fresh, findings selectors with require_collector/require_coverage/status_in, "
                 "file, all/any/first_known, builtin, none), ${var} substitution, a later catalog directory replacing a "
                 "control, an instance override, details as specified",
        "contract": C, "origin": "tests/test_scorecard.py::test_evaluators",
        "files": {"catalog/01-ev.yaml": "catalog/01-ev.yaml", "catalog-org/01-ev.yaml": "catalog-org/01-ev.yaml",
                  "instance.json": "instance.json", "data/ledger.json": "ledger.json",
                  "data/metrics/security-platform.prom": "security-platform.prom",
                  "data/latest/host.findings.json": "host.findings.json",
                  "data/state/runner/scan.json": st(last_success=now - 3600, last_rc=0),
                  "data/state/runner/broken.json": st(last_success=now - 3600, last_rc=2),
                  "data/state/runner/sinks.json": st(failing=True),
                  "data/state/sites/site-1.json": st(jobs={"remote": {"last_success": now - 10 * 86400, "last_rc": 0},
                                                           "scan": {"last_success": 1, "last_rc": 1}}),
                  "data/policy.md": {"text": "# Policy\n\n## Scope\n\nEverything.\n", "mode": "0644"}},
        "steps": [compute(NOW, [SC({"controls": {"$contains": ctls}}),
                                {"exists": "data/reports/scorecard.md"}])]},
        {"catalog/01-ev.yaml": cat, "catalog-org/01-ev.yaml": extra, "instance.json": inst,
         "security-platform.prom": prom, "host.findings.json": host_doc,
         "ledger.json": sc_ledger(entries=entries, collectors={
             "host": {"version": "1.0.0", "last_good_run": "2030-01-09T00:00:00Z"},
             "k8s": {"version": "1.0.0", "last_good_run": "2029-12-01T00:00:00Z"}})})

    write_case("scorecard", "catalog-errors", {
        "title": "A catalog file without the catalog schema is a configuration error: non-zero exit, no report",
        "contract": C, "origin": "tests/test_scorecard.py::test_catalog_schema_required",
        "files": {"catalog/01-x.yaml": {"text": "schema: something/else\ndimension: {id: x, order: 1, title: X}\n"},
                  "instance.json": {"json": sc_inst()}, "data/ledger.json": {"json": sc_ledger()}},
        "steps": [dict(compute(NOW, [{"absent": "data/reports/scorecard.json"}]), exit={"not": 0})]})


# ==================================================================================================================
# runner (contract runner/1.0): <impl> tick|run|status --instance F --data D [--now EPOCH] [JOB ...]
# ==================================================================================================================
EMIT = """#!/bin/sh
# a fake collector: copies a fixture findings document into the run directory (collector-protocol output)
set -e
[ -n "$EMIT_SLEEP" ] && sleep "$EMIT_SLEEP"
[ -n "$EMIT_MARK" ] && echo "$SP_RUN_DIR" >> "$EMIT_MARK"
[ -n "$EMIT_ENV" ] && env | grep -E '^(SP_|MY_)' | sort > "$EMIT_ENV"
[ -n "$EMIT_ENV_ALL" ] && env | sort > "$EMIT_ENV_ALL"
[ -n "$EMIT_FAIL" ] && exit "$EMIT_FAIL"
cp "$EMIT_DOC" "$SP_RUN_DIR/${EMIT_AS:-host}.findings.json"
"""


def rjob(schedule, doc="{case}/host.json", **kw):
    env = {"EMIT_DOC": doc, "EMIT_MARK": "{sandbox}/runs.log"}
    env.update(kw.pop("env", {}))
    return dict({"type": "command", "collector": "host", "schedule": schedule, "argv": ["/bin/sh", "{case}/emit.sh"], "env": env}, **kw)


def rinst(jobs, role="site", **cfg):
    r = {"site": "s1" if role == "site" else "hub", "role": role, "jobs": jobs}
    if role == "site":
        r["outbox"] = {"type": "local", "dir": "{sandbox}/outbox"}
    r.update(cfg)
    return {"name": "conformance", "runner": r}


def tick(now, name=None, expect=None, jobs=None, background=False, cmd="tick", exit_=0, files=None, env=None):
    st = {"name": name or f"{cmd} at {now}", "exec": {"impl": "runner", "args": [cmd, "--instance", "{sandbox}/instance.json",
                                                                              "--data", "{sandbox}/data"]
                                                     + (["--now", str(epoch(now))] if now else []) + (jobs or [])},
          "exit": exit_, "expect": expect or []}
    if env:
        st["exec"]["env"] = env
    if background:
        st["exec"]["background"] = True
        st.pop("exit")
        st.pop("expect")
    if files:
        st["files"] = files
    return st


def S(job, subset):
    return {"json": f"data/state/runner/{job}.json", "schema": "runner-state", "subset": subset}


def runner_cases():
    C = "runner/1.0"
    hostdoc = doc("host", [finding("host:h1", "host.ssh_password_auth")], [ok("host:h1")])
    base = {"emit.sh": EMIT, "host.json": hostdoc}

    write_case("runner", "catch-up-once-after-downtime", {
        "title": "After downtime the newest missed slot runs exactly once (not once per missed slot); the same slot never "
                 "runs twice; the trigger's exit code is 0",
        "contract": C, "origin": "tests/test_runner.py::test_catch_up_jitter_retry_max_delay; docs/runner.md",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("hourly", {"runs_total": 1, "done_slot": epoch("2030-01-07T12:00:00Z"),
                                                                     "last_rc": 0, "failures_total": 0})]),
                  tick("2030-01-07T12:45:00Z", expect=[S("hourly", {"runs_total": 1})], name="same slot: nothing to do"),
                  tick("2030-01-07T17:10:00Z", expect=[S("hourly", {"runs_total": 2, "done_slot": epoch("2030-01-07T17:00:00Z")})],
                       name="after 4h off: one catch-up run for the newest slot"),
                  tick("2030-01-07T17:20:00Z", expect=[S("hourly", {"runs_total": 2})])]},
        dict(base, **{"instance.json": rinst({"hourly": rjob("0 * * * *")})}))

    write_case("runner", "max-delay-skips-old-slot", {
        "title": "max_delay: a slot older than this is skipped (not run late); the next slot runs",
        "contract": C, "origin": "tests/test_runner.py::test_catch_up_jitter_retry_max_delay",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:00:00Z", expect=[{"absent": "runs.log"}]),
                  tick("2030-01-07T12:00:00Z", cmd="status", expect=[{"stdout": {"schema": "runner-status",
                                                                                  "json": {"nightly": {"due": "missed (older than max_delay)",
                                                                                                       "schedule": "30 3 * * *"}}}}]),
                  tick("2030-01-08T04:00:00Z", expect=[S("nightly", {"runs_total": 1, "done_slot": epoch("2030-01-08T03:30:00Z")})])]},
        dict(base, **{"instance.json": rinst({"nightly": rjob("30 3 * * *", max_delay="3h")})}))

    write_case("runner", "retries-then-give-up", {
        "title": "A failed slot is retried `retries` times at least retry_delay apart, then given up until the next slot",
        "contract": C, "origin": "tests/test_runner.py::test_catch_up_jitter_retry_max_delay",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T03:30:00Z", expect=[S("flaky", {"runs_total": 1, "failures_total": 1, "attempts": 1,
                                                                    "slot": epoch("2030-01-07T03:30:00Z"), "last_rc": 3})]),
                  tick("2030-01-07T03:51:00Z", expect=[S("flaky", {"runs_total": 2, "attempts": 2,
                                                                    "done_slot": epoch("2030-01-07T03:30:00Z")})],
                       name="retry after retry_delay"),
                  tick("2030-01-07T04:12:00Z", expect=[S("flaky", {"runs_total": 2})], name="retries exhausted"),
                  tick("2030-01-07T04:12:00Z", cmd="status", expect=[{"stdout": {"json": {"flaky": {"due": "done"}}}}]),
                  tick("2030-01-08T03:31:00Z", expect=[S("flaky", {"runs_total": 3, "attempts": 1})], name="next slot tries again")]},
        dict(base, **{"instance.json": rinst({"flaky": rjob("30 3 * * *", retries=1, retry_delay="20m", env={"EMIT_FAIL": "3"})})}))

    write_case("runner", "retry-waits-for-retry-delay", {
        "title": "TARGET: with --now, a retry waits retry_delay measured on the same clock (the scheduling clock), "
                 "not on the wall clock",
        "contract": C, "deviation": "RUNNER-D1",
        "origin": "found while writing the contracts: last_attempt is written from the wall clock while `due` uses --now",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T03:30:00Z", expect=[S("flaky", {"runs_total": 1})]),
                  tick("2030-01-07T03:35:00Z", expect=[S("flaky", {"runs_total": 1})], name="5 minutes later: waiting to retry"),
                  tick("2030-01-07T03:35:00Z", cmd="status", expect=[{"stdout": {"json": {"flaky": {"due": "waiting to retry"}}}}])]},
        dict(base, **{"instance.json": rinst({"flaky": rjob("30 3 * * *", retries=1, retry_delay="20m", env={"EMIT_FAIL": "3"})})}))

    write_case("runner", "no-overlap", {
        "title": "A tick while another tick (or the same job) is still running does not start the job again and exits 0",
        "contract": C, "origin": "tests/test_runner.py::test_lock_prevents_overlap; docs/runner.md locking",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", name="long tick", background=True),
                  {"name": "let it start", "sleep": 1.5},
                  tick("2030-01-07T12:30:00Z", name="overlapping tick", expect=[{"duration_max": 2.5}]),
                  {"name": "wait for the long tick", "wait": "long tick", "exit": 0},
                  {"name": "one run only", "expect": [S("slow", {"runs_total": 1, "last_rc": 0}),
                                                      {"file": "runs.log", "lines": 1}]}]},
        dict(base, **{"instance.json": rinst({"slow": rjob("0 * * * *", env={"EMIT_SLEEP": "4"})})}))

    write_case("runner", "timeout-kills-job", {
        "title": "A job that exceeds `timeout` is killed (its process group) and recorded as exit 124",
        "contract": C, "origin": "tests/test_runner.py::test_failure_timeout_and_contract",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("slow", {"last_rc": 124, "failures_total": 1}), {"duration_max": 40}])]},
        dict(base, **{"instance.json": rinst({"slow": rjob("0 * * * *", timeout="1s", env={"EMIT_SLEEP": "60"})})}))

    write_case("runner", "contract-violation-not-promoted", {
        "title": "A job whose document fails the findings contract is a failure (65); nothing reaches latest/ or the outbox",
        "contract": C, "origin": "tests/test_runner.py::test_failure_timeout_and_contract",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("bad", {"last_rc": 65, "failures_total": 1}),
                                                       {"absent": "data/latest/host.findings.json"},
                                                       {"glob": "outbox/*.findings.json", "count": 0}])]},
        dict(base, **{"bad.json": {"schema_version": "9.0"},
                      "instance.json": rinst({"bad": rjob("0 * * * *", doc="{case}/bad.json")})}))

    write_case("runner", "missing-document-is-failure", {
        "title": "Exit 0 without a findings document is a failure (no document != secure)",
        "contract": C, "origin": "runner job_collector: `rc != 0 or not document`",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("empty", {"last_rc": {"$ge": 1}, "failures_total": 1})])]},
        dict(base, **{"instance.json": rinst({"empty": rjob("0 * * * *", doc="/nonexistent/doc.json")})}))

    write_case("runner", "site-success-promotes-and-queues", {
        "title": "Role site: a valid document is promoted to latest/ and queued in the outbox; no ledger is kept",
        "contract": C, "origin": "tests/test_runner.py::test_site_role_fills_outbox_and_hub_ingests",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("host", {"last_rc": 0, "last_success": {"$type": "integer"},
                                                                   "last_run_dir": {"$regex": "^runs/"}}),
                                                       {"json": "data/latest/host.findings.json", "schema": "findings"},
                                                       {"glob": "outbox/*.findings.json", "count": 1},
                                                       {"absent": "data/ledger.json"}])]},
        dict(base, **{"instance.json": rinst({"host": rjob("0 * * * *")})}))

    write_case("runner", "job-environment", {
        "title": "A collector job gets SP_RUN_DIR (fresh, under DATA/runs/), SP_DATA, SP_INSTANCE, SP_INPUT_DIR "
                 "(DATA/latest), SP_INSTANCE_NAME, its `env`, and SP_COLLECTOR_NAME when `as:` is set",
        "contract": C + " / collector-protocol/1.0", "origin": "runner env(); docs/adapters.md collector section",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[S("renamed", {"last_rc": 0}), {"file": "env.txt", "regex": [
                      r"^SP_RUN_DIR={sandbox}/data/runs/.+", r"^SP_DATA={sandbox}/data$", r"^SP_INSTANCE={sandbox}/instance.json$",
                      r"^SP_INPUT_DIR={sandbox}/data/latest$", r"^SP_INSTANCE_NAME=conformance$", r"^SP_COLLECTOR_NAME=host-b$",
                      r"^MY_SETTING=x$"]}, {"exists": "data/latest/host-b.findings.json"}])]},
        dict(base, **{"instance.json": rinst({"renamed": rjob("0 * * * *", **{"as": "host-b"},
                                                               env={"EMIT_ENV": "{sandbox}/env.txt", "EMIT_AS": "host-b",
                                                                    "MY_SETTING": "x"})})}))

    hub = rinst({"host": rjob("0 * * * *")}, role="hub", sinks=[{"type": "textfile", "path": "{sandbox}/sink/m.prom"}],
                tick_stale_after="2h")
    write_case("runner", "hub-merges-and-publishes", {
        "title": "Role hub: a successful job is merged into the ledger and the metrics are published to every sink, "
                 "with the runner's own families and labels",
        "contract": C + " / metrics/1.0", "origin": "tests/test_runner.py::test_tick_runs_command_job_promotes_merges_and_publishes",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", expect=[
            S("host", {"last_rc": 0}), {"json": "data/ledger.json", "schema": "ledger", "subset": {"entries": {"$len": 1}}},
            {"prom": "sink/m.prom", "has": [
                {"name": "security_runner_job_last_success_timestamp_seconds", "labels": {"site": "hub", "job": "host"}},
                {"name": "security_runner_job_runs_total", "labels": {"site": "hub", "job": "host"}, "value": 1},
                {"name": "security_runner_job_failures_total", "labels": {"site": "hub", "job": "host"}, "value": 0},
                {"name": "security_runner_job_last_exit_code", "labels": {"site": "hub", "job": "host"}, "value": 0},
                {"name": "security_runner_job_expected_interval_seconds", "labels": {"site": "hub", "job": "host"}, "value": 3600},
                {"name": "security_collector_expected_interval_seconds", "labels": {"collector": "host"}, "value": 3600},
                {"name": "security_runner_tick_max_gap_seconds", "labels": {"site": "hub"}, "value": 7200},
                {"name": "security_runner_info", "labels": {"site": "hub"}, "value": 1},
                {"name": "security_collector_last_run_timestamp_seconds", "labels": {"collector": "host"}},
                {"name": "security_findings", "labels": {"status": "open"}}],
             "families": ["security_runner_tick_timestamp_seconds", "security_metrics_published_timestamp_seconds",
                          "security_ledger_last_update_timestamp_seconds", "security_runner_job_duration_seconds",
                          "security_runner_job_last_attempt_timestamp_seconds"],
             "types": {"security_runner_job_runs_total": "counter"}},
            {"prom": "data/metrics/security-platform.prom", "families": ["security_runner_tick_timestamp_seconds"]}])]},
        dict(base, **{"instance.json": hub}))

    blocker_inst = rinst({}, role="hub", sinks=[{"type": "textfile", "path": "{sandbox}/blocker/m.prom"},
                                                {"type": "textfile", "path": "{sandbox}/good.prom"}])
    write_case("runner", "failing-sink-never-fails-tick", {
        "title": "A failing sink is counted (consecutive and total) and retried on every tick; other sinks still get the "
                 "metrics; the tick exits 0",
        "contract": C, "origin": "tests/test_runner.py::test_failing_sink_is_retried_counted_and_never_fails_the_tick",
        "files": {"instance.json": "instance.json", "blocker": {"text": "a regular file: every write under it fails"}},
        "steps": [tick("2030-01-07T12:30:00Z"),
                  tick("2030-01-07T12:45:00Z", expect=[{"prom": "data/metrics/security-platform.prom", "has": [
                      {"name": "security_runner_sink_consecutive_failures", "labels": {"site": "hub", "sink": "0-textfile"}, "value": 2},
                      {"name": "security_runner_sink_failures_total", "labels": {"site": "hub", "sink": "0-textfile"}, "value": 2},
                      {"name": "security_runner_sink_consecutive_failures", "labels": {"site": "hub", "sink": "1-textfile"}, "value": 0}]},
                      {"exists": "good.prom"}])]},
        {"instance.json": blocker_inst})

    write_case("runner", "missed-slot-is-visible", {
        "title": "TARGET: a slot that will never run (skipped by max_delay, or given up after retries) is counted in "
                 "security_runner_job_missed_slots_total{site,job}",
        "contract": C + " / metrics/1.0", "deviation": "RUNNER-D2",
        "origin": "continuity test: after downtime nothing showed that a scheduled run had been missed",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:00:00Z", expect=[{"prom": "data/metrics/security-platform.prom", "has": [
            {"name": "security_runner_job_missed_slots_total", "labels": {"site": "hub", "job": "nightly"}, "value": 1}]}])]},
        dict(base, **{"instance.json": rinst({"nightly": rjob("30 3 * * *", max_delay="3h")}, role="hub")}))

    berlin = {"TZ": "Europe/Berlin"}
    write_case("runner", "dst-spring-forward-gap-runs-once", {
        "title": "DST, spring forward (Europe/Berlin): a daily slot whose wall-clock time does not exist (02:30 on "
                 "2030-03-31) fires once, at the end of the gap (03:00 CEST), not skipped for the day",
        "contract": C, "deviation": "RUNNER-D4",
        "origin": "contract §3.1 (DST); the reference's cron matches local times per epoch second and never sees 02:30",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-03-30T01:40:00Z", env=berlin, expect=[S("daily", {"runs_total": 1,
                                                                              "done_slot": epoch("2030-03-30T01:30:00Z")})],
                       name="Saturday 02:40 CET: the normal slot"),
                  tick("2030-03-31T01:10:00Z", env=berlin, expect=[S("daily", {"runs_total": 2,
                                                                              "done_slot": epoch("2030-03-31T01:00:00Z")})],
                       name="Sunday 03:10 CEST: the 02:30 slot fired at the gap's end, 03:00 CEST"),
                  tick("2030-03-31T01:40:00Z", env=berlin, expect=[S("daily", {"runs_total": 2})], name="once only")]},
        dict(base, **{"instance.json": rinst({"daily": rjob("30 2 * * *")})}))

    write_case("runner", "dst-fall-back-runs-once", {
        "title": "DST, fall back (Europe/Berlin): a wall-clock time that occurs twice (02:30 on 2030-10-27) is one "
                 "slot, its first occurrence; an hourly job does not run again in the repeated hour",
        "contract": C, "deviation": "RUNNER-D5",
        "origin": "contract §3.1 (DST); the reference runs both occurrences",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-10-27T00:40:00Z", env=berlin, expect=[
                      S("daily", {"runs_total": 1, "done_slot": epoch("2030-10-27T00:30:00Z")}),
                      S("hourly", {"runs_total": 1, "done_slot": epoch("2030-10-27T00:00:00Z")})],
                       name="02:40 CEST, first occurrence"),
                  tick("2030-10-27T01:40:00Z", env=berlin, expect=[S("daily", {"runs_total": 1}), S("hourly", {"runs_total": 1})],
                       name="02:40 CET, the repeated hour: nothing new"),
                  tick("2030-10-27T02:05:00Z", env=berlin, expect=[S("hourly", {"runs_total": 2,
                                                                               "done_slot": epoch("2030-10-27T02:00:00Z")})],
                       name="03:05 CET: the next hour")]},
        dict(base, **{"instance.json": rinst({"daily": rjob("30 2 * * *"), "hourly": rjob("0 * * * *")})}))

    write_case("runner", "dst-catch-up-across-spring-forward", {
        "title": "DST, spring forward (Europe/Berlin): a weekly slot just before midnight (Saturday 23:30) that was missed "
                 "is caught up on the Sunday of the change as that slot, not as the previous week's",
        "contract": C, "deviation": "RUNNER-D6",
        "origin": "contract §3.1 (DST); the reference's day jump assumes 24-hour days and lands an hour early",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-03-31T03:00:00Z", env=berlin, expect=[S("weekly", {"runs_total": 1,
                                                                               "done_slot": epoch("2030-03-30T22:30:00Z")})],
                       name="Sunday 05:00 CEST, machine was off at Saturday 23:30 CET")]},
        dict(base, **{"instance.json": rinst({"weekly": rjob("30 23 * * 6")})}))

    write_case("runner", "job-environment-allow-list", {
        "title": "A job gets an allow-listed environment: PATH and the like, SP_*, its `env`, and what "
                 "runner.env_passthrough names; other variables of the runner (ambient credentials) never reach it",
        "contract": C, "deviation": "RUNNER-D7",
        "origin": "contract §4 (Environment); the reference passes its whole environment to every job",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", env={"AWS_SECRET_ACCESS_KEY": "canary-ambient-credential-0123456789",
                                                    "MY_PASSED": "granted"},
                       expect=[S("renamed", {"last_rc": 0}),
                               {"file": "env-all.txt", "regex": [r"^PATH=", r"^MY_PASSED=granted$", r"^MY_SETTING=x$",
                                                                 r"^SP_RUN_DIR="]},
                               {"no_secret": ["canary-ambient-credential-0123456789"], "in": "."}])]},
        dict(base, **{"instance.json": rinst({"renamed": rjob("0 * * * *", env={"EMIT_ENV_ALL": "{sandbox}/env-all.txt",
                                                                                 "MY_SETTING": "x"})},
                                             env_passthrough=["MY_PASSED"])}))

    write_case("runner", "status-json", {
        "title": "`status` prints one JSON object: per job its state, `due` (why it would or would not run now) and schedule",
        "contract": C, "origin": "runner.py status; docs/runner.md",
        "files": {"instance.json": "instance.json"},
        "steps": [tick("2030-01-07T12:30:00Z", cmd="status", expect=[{"stdout": {"schema": "runner-status", "json": {
                      "a": {"due": "due", "schedule": "0 * * * *", "runs_total": 0}, "b": {"due": "due"}}}}]),
                  tick("2030-01-07T12:30:00Z", jobs=["a"]),
                  tick("2030-01-07T12:31:00Z", cmd="status", expect=[{"stdout": {"schema": "runner-status", "json": {
                      "a": {"due": "done", "runs_total": 1, "last_rc": 0}, "b": {"due": "due", "runs_total": 0}}}}])]},
        dict(base, **{"instance.json": rinst({"a": rjob("0 * * * *"), "b": rjob("0 * * * *")})}))


# ==================================================================================================================
# cli (contract cli/1.1): sp <command> --data D [--instance F]
# ==================================================================================================================
def sp(args, expect, exit_=0, name=None, env=None, files=None):
    st = {"name": name or "sp " + " ".join(args), "exec": {"impl": "cli", "args": args}, "exit": exit_, "expect": expect}
    if env:
        st["exec"]["env"] = env
    if files:
        st["files"] = files
    return st


def cli_cases():
    C = "cli/1.1"
    cr = finding("host:web-1", "host.ssh_password_auth", severity="critical", observed="2026-11-01T08:00:00Z")
    hi = finding("image:registry.example/app:1.0", "vuln.cve-2099-0001", layer="supply-chain", severity="high", kind="vulnerability")
    lo = finding("host:web-1", "host.motd_missing", severity="low")
    fx = finding("host:web-2", "host.firewall_off", severity="high")
    led = ledger_doc(entry(cr), entry(hi), entry(lo), entry(fx, status="fixed", fixed_at="2026-11-02T09:00:00Z", fixed_reason="not_observed"))
    items = {"schema": "security-platform/tracker/v1", "items": {
        cr["id"]: {"id": cr["id"], "status": "open", "due_at": "2026-11-08T08:00:00Z", "overdue": True, "owner": "ops",
                   "severity": "critical"},
        hi["id"]: {"id": hi["id"], "status": "open", "due_at": "2099-12-01T08:00:00Z", "overdue": False, "owner": "ops",
                   "severity": "high"}}}
    inst = {"name": "conformance", "runner": {"site": "hub", "role": "hub", "jobs": {
        "host": {"schedule": "15 2 * * *"}, "remediation": {"type": "remediation", "schedule": "50 * * * *"}}}}
    files = {"ledger.json": led, "items.json": items, "instance.json": inst}
    data = {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json", "data/instance.json": "instance.json"}
    D = ["--data", "{sandbox}/data"]

    write_case("cli", "findings-json", {
        "title": "`sp findings --json` prints the matching ledger entries as a JSON array, worst first; filters combine",
        "contract": C, "origin": "tests/test_cli.py::test_findings_filters",
        "files": data,
        "steps": [sp(["findings", "--json"] + D, [{"stdout": {"schema": "cli-findings", "json": {"$len": 4}}}]),
                  sp(["findings", "--open", "--json"] + D, [{"stdout": {"json": [{"id": cr["id"], "severity": "critical"},
                                                                                  {"id": hi["id"]}, {"id": lo["id"]}]}}]),
                  sp(["findings", "--open", "--severity", "high", "--json"] + D,
                     [{"stdout": {"json": {"$unordered": [{"id": cr["id"]}, {"id": hi["id"]}]}}}]),
                  sp(["findings", "--layer", "supply-chain", "--json"] + D, [{"stdout": {"json": [{"id": hi["id"]}]}}]),
                  sp(["findings", "--check", "host.ssh", "--json"] + D, [{"stdout": {"json": [{"id": cr["id"]}]}}]),
                  sp(["findings", "--overdue", "--json"] + D, [{"stdout": {"json": [{"id": cr["id"]}]}}])]}, files)

    write_case("cli", "findings-ids-and-table", {
        "title": "`--ids` prints one id per line (for scripts); the table shows the due date or OVERDUE",
        "contract": C, "origin": "cli/sp.py cmd_findings",
        "files": data,
        "steps": [sp(["findings", "--open", "--ids"] + D, [{"stdout": {"lines": [cr["id"], hi["id"], lo["id"]]}}]),
                  sp(["findings", "--open"] + D, [{"stdout": {"regex": [rf"^{cr['id']}\s+critical\s+open\s+OVERDUE",
                                                                        rf"^{hi['id']}\s+high\s+open\s+2099-12-01",
                                                                        rf"^{lo['id']}\s+low\s+open\s+-\s"]}}]),
                  sp(["findings", "--check", "nothing.matches"] + D, [{"stdout": {"regex": ["no matching findings"]}}])]}, files)

    write_case("cli", "explain", {
        "title": "`sp explain ID` (or a unique prefix) explains one finding and prints the exception snippet; an unknown "
                 "id exits 2",
        "contract": C, "origin": "tests/test_cli.py::test_explain_plain_language_and_exception_snippet",
        "files": data,
        "steps": [sp(["explain", cr["id"][:6]] + D, [{"stdout": {"regex": [rf"id {cr['id']}", "How to fix", "How to verify",
                                                                             "exceptions:", rf"{cr['id']}:", "approved_by:", "expires:"]}}]),
                  sp(["explain", "ffffffffffff"] + D, [{"stderr": {"regex": ["^sp: no finding ffffffffffff"]}}], exit_=2)]}, files)

    write_case("cli", "usage-errors", {
        "title": "No data directory, or a missing one: exit 2 with a one-line `sp: ...` message on stderr",
        "contract": C, "origin": "cli/sp.py Ctx/die",
        "steps": [sp(["status"], [{"stderr": {"regex": ["^sp: .*SP_DATA"]}}], exit_=2),
                  sp(["findings", "--data", "{sandbox}/nope"], [{"stderr": {"regex": ["^sp: .*does not exist"]}}], exit_=2)]})

    write_case("cli", "status", {
        "title": "`sp status` before any scan says so; with data it shows open findings, overdue fixes and every job",
        "contract": C, "origin": "tests/test_cli.py::test_status",
        "files": {"empty/instance.json": "instance.json"},
        "steps": [sp(["status", "--data", "{sandbox}/empty"], [{"stdout": {"regex": ["no scan yet"]}}]),
                  dict(sp(["status"] + D, [{"stdout": {"regex": [r"Open findings: .*critical 1", r"Overdue fixes: 1",
                                                                 r"^\s+never\s+host", r"^\s+never\s+remediation"]}}]),
                       files=data)]}, files)

    write_case("cli", "digest-has-no-asset-details", {
        "title": "`sp digest` (what notifiers send) carries aggregates only: never an asset name",
        "contract": C, "origin": "tests/test_cli.py::test_digest_has_no_asset_details",
        "files": data,
        "steps": [sp(["digest", "--days", "30"] + D, [{"stdout": {"regex": ["^Security ", "^Open: "],
                                                                  "not_contains": ["web-1", "web-2", "registry.example"]}}])]}, files)

    write_case("cli", "version", {
        "title": "`sp --version` prints `sp <cli version> (security-platform <release>)`",
        "contract": C, "origin": "cli/sp.py; docs/upgrade.md",
        "steps": [sp(["--version"], [{"stdout": {"regex": [r"^sp \d+\.\d+\.\d+ \(security-platform \S+\)$"]}}])]})

    write_case("cli", "init", {
        "title": "`sp init DIR` creates a private (0700) data directory with instance.yaml (0600) and exceptions.yaml; "
                 "it never overwrites an existing instance.yaml without --force",
        "contract": C, "origin": "tests/test_cli.py::test_init_and_doctor",
        "steps": [sp(["init", "{sandbox}/d", "--name", "lab"], [{"exists": "d/instance.yaml"}, {"exists": "d/exceptions.yaml"},
                                                                {"stdout": {"regex": ["wrote .*instance.yaml"]}}]),
                  sp(["init", "{sandbox}/d"], [{"stdout": {"regex": ["exists: left as it is"]}}])]})

    st_late = {"schema": "security-platform/runner-state/v1", "job": "remediation", "runs_total": 5, "failures_total": 0,
               "last_rc": 0, "last_success": "{epoch:-2820}", "last_attempt": "{epoch:-2820}", "done_slot": "{epoch:-2880}"}
    write_case("cli", "status-shows-missed-slot", {
        "title": "`sp status` marks a job whose newest scheduled slot has passed without a run (machine was off) "
                 "as late/missed, not just `ok, last good run 47m ago`",
        "contract": C,
        "origin": "continuity test: remediation due 07:50, machine off 07:46-08:06; status before the catch-up tick said ok "
                  "(was CLI-D1, fixed in cli 0.3.1)",
        "files": dict(data, **{"data/instance.json": "instance-every-10m.json", "data/state/runner/remediation.json": "state.json"}),
        "steps": [sp(["status"] + D, [{"stdout": {"regex": [r"^\s*\S+\s+remediation\b.*(missed|late|overdue|pending)"],
                                                  "ignore_case": True}}])]},
        dict(files, **{"instance-every-10m.json": dict(inst, runner=dict(inst["runner"], jobs={
            "remediation": {"type": "remediation", "schedule": "*/10 * * * *"}})),
            "state.json": json.dumps(st_late).replace('"{epoch:-2820}"', "{epoch:-2820}").replace('"{epoch:-2880}"', "{epoch:-2880}")}))
    cli_quickstart_case()
    cli_doctor_cases()
    cli_input_cases()
    cli_findings_cases(cr, hi, lo, fx)
    cli_status_cases()
    cli_digest_notify_cases()
    cli_run_cases()
    cli_init_cases()


EMIT_SH = """#!/bin/sh
# a fake collector: copies a fixture findings document into the run directory (collector-protocol output)
set -e
[ -n "$EMIT_FAIL" ] && { echo "emit: failing on purpose" >&2; exit "$EMIT_FAIL"; }
cp "$EMIT_DOC" "$SP_RUN_DIR/${SP_COLLECTOR_NAME:-host}.findings.json"
"""


def raw_json(obj, *templates):
    """JSON text in which each "{epoch:..}" string template becomes a bare number once rendered."""
    t = json.dumps(obj, indent=1)
    for x in templates:
        t = t.replace(f'"{x}"', x)
    return t


def cli_quickstart_case():
    C = "cli/1.1"
    crit = finding("host:lab-1", "host.ssh_password_auth", severity="critical", observed="2026-11-01T08:00:00Z")
    low = finding("host:lab-1", "host.motd_missing", severity="low", observed="2026-11-01T08:00:00Z")
    hdoc = doc("emit", [crit, low], [ok("host:lab-1"), gap("host:lab-2", "ssh: connection refused")])
    job = {"type": "command", "collector": "host", "as": "emit", "argv": ["/bin/sh", "{case}/emit.sh"],
           "schedule": "15 2 * * *", "env": {"EMIT_DOC": "{case}/emit.findings.json"}}
    qinst = {"name": "quick", "scorecard": {"enabled": False}, "runner": {"site": "hub", "role": "hub", "jobs": {
        "emit": job, "remediation": {"type": "remediation", "schedule": "50 * * * *"},
        "digest": {"type": "digest", "schedule": "0 9 * * 1"}}}}
    D = ["--data", "{sandbox}/data"]
    write_case("cli", "quickstart", {
        "title": "The documented first steps (docs/quickstart.md): init -> doctor -> run -> status -> findings -> explain, "
                 "each with the output a new user is told to look for",
        "contract": C, "origin": "docs/quickstart.md; tests/test_cli.py::test_init_and_doctor",
        "steps": [
            sp(["init", "{sandbox}/data", "--name", "quick"], [
                {"stdout": {"regex": [r"^wrote \S*/data/instance\.yaml$", r"sp doctor --data \S*data",
                                      r"sp run --data \S*data"]}},
                {"mode": "data", "is": "0700"}, {"mode": "data/instance.yaml", "is": "0600"},
                {"file": "data/instance.yaml", "regex": [r"^name: quick$", r"exec: \{type: local\}, profile: (linux|macos|windows|termux)\}"]},
                {"file": "data/exceptions.yaml", "regex": [r"^exceptions: \{\}$"]}]),
            sp(["doctor"] + D, [{"stdout": {"regex": [r"^config \S*/data/instance\.yaml$", r"^  ok    loads \(\d+ sections, name=quick\)$",
                                                      r"^  ok    data directory is private \(0700\)$", r"^ready: sp run$"],
                                            "not_regex": ["FIX"]}}], name="doctor on the starter config"),
            dict(sp(["run"] + D, [{"stdout": {"regex": [r"^running 2 job\(s\): emit, remediation  \(each job's log: \S*/data/runs/<date>/\)$",
                                                        r"^  ok  emit\s+\d+s", r"^  ok  remediation\s+\d+s",
                                                        r"^next: sp status"]}},
                                  {"json": "data/ledger.json", "schema": "ledger", "subset": {"entries": {"$len": 2}}}]),
                 files={"data/instance.yaml": "instance.json"}),
            sp(["status"] + D, [{"stdout": {"regex": [r"^security-platform status - quick$", r"^Open findings: critical 1, low 1$",
                                                      r"^  ok  emit\s+last good run (just now|\dm ago)$",
                                                      r"^Could not check 1 thing\(s\) \(no finding there does NOT mean safe\):$",
                                                      r"^  emit: ssh: connection refused$",
                                                      rf"^  {crit['id']}  critical ", r"^Top risks \(sp explain <id>\):$"]}}]),
            sp(["findings", "--open", "--ids"] + D, [{"stdout": {"lines": [crit["id"], low["id"]]}}]),
            sp(["findings", "--json"] + D, [{"stdout": {"schema": "cli-findings", "json": [
                {"id": crit["id"], "status": "open", "asset": "host:lab-1"}, {"id": low["id"]}]}}]),
            sp(["explain", crit["id"][:5]] + D, [{"stdout": {"regex": [rf"^id {crit['id']}   check host.ssh_password_auth   critical",
                                                                     r"^How to fix$", r"^How to verify$",
                                                                     rf"^    {crit['id']}:$"]}}])]},
        {"emit.sh": EMIT_SH, "emit.findings.json": hdoc, "instance.json": raw_json(qinst)})


def cli_doctor_cases():
    C = "cli/1.1"
    canary = "conformance-secret-canary-7f3a9c"
    inst = {"name": "doc", "hosts": [{"name": "h1", "exec": {"type": "ssh", "host": "h1"}}],
            "codehost": [{"type": "gitea", "url": "https://git.example.com", "token_file": "{sandbox}/secrets/gitea.token"}],
            "notify": [{"type": "telegram", "token_file": "{sandbox}/secrets/missing.token", "chat_id_file": "{sandbox}/secrets/chat"}],
            "runner": {"site": "hub", "role": "hub", "sinks": [
                {"type": "remote_write", "url": "https://metrics.example.com", "password_file": "{sandbox}/secrets/sink.pass",
                 "ca_file": "{sandbox}/secrets/no-such-ca.pem"}],
                "jobs": {"vi": {"collector": "vuln-intel"}, "nope": {"collector": "no-such-collector"},
                         "cmd": {"type": "command", "argv": ["true"]}}}}
    write_case("cli", "doctor-reports-problems", {
        "title": "`sp doctor` prints one line per check (`ok` / `FIX` with the fix), exits 1 when something must be fixed, "
                 "and never prints a secret: open data directory, missing tool, unknown collector, ssh without a client, "
                 "secret files missing or readable by others (ca_file is not a secret)",
        "contract": C, "origin": "cli/sp.py cmd_doctor",
        "files": {"data": {"dir": True, "mode": "0755"}, "data/instance.json": {"json": inst, "mode": "0600"},
                  "emptybin": {"dir": True},
                  "secrets/gitea.token": {"text": canary + "\n", "mode": "0644"},
                  "secrets/chat": {"text": "12345\n", "mode": "0600"},
                  "secrets/sink.pass": {"text": canary + "-sink\n", "mode": "0600"}},
        "steps": [sp(["doctor", "--data", "{sandbox}/data"], [
            {"stdout": {"regex": [r"^  FIX   data directory is readable by others \(mode 0o755\)$", r"^        -> chmod 700 \S*/data$",
                                  r"^  FIX   job vi: needs `trivy` - not found$", r"^        -> install trivy \(see docs/quickstart\.md\)$",
                                  r"^  FIX   job nope: unknown collector no-such-collector$",
                                  r"^        -> one of: agent-claude-code, cloud, codehost-gitea, codehost-github, exposure, host, "
                                  r"host-sbom, identity, k8s, secrets-files, vuln-intel$",
                                  r"^  FIX   hosts use ssh but `ssh` is not installed$",
                                  r"^  FIX   codehost: token_file \S*/secrets/gitea\.token is readable by others$",
                                  r"^        -> chmod 600 \S*/secrets/gitea\.token$",
                                  r"^  FIX   notify: token_file \S*/secrets/missing\.token does not exist$",
                                  r"^  ok    notify: chat_id_file is private$", r"^  ok    sink: password_file is private$",
                                  r"^6 thing\(s\) to fix$"],
                        "not_regex": ["ca_file", r"job cmd", "ready: sp run"]}},
            {"no_secret": [canary], "in": "data"}], exit_=1, env={"PATH": "{sandbox}/emptybin"})]})


def cli_input_cases():
    C = "cli/1.1"
    D = ["--data", "{sandbox}/data"]
    write_case("cli", "missing-instance", {
        "title": "A data directory without an instance config: commands that need it exit 2 with `sp: no instance config "
                 "at <path>`; findings and explain need only the ledger",
        "contract": C, "origin": "cli/sp.py Ctx.inst",
        "files": {"data/ledger.json": {"json": {"schema": "security-platform/ledger/v1", "entries": {}}}},
        "steps": [sp(["status"] + D, [{"stderr": {"regex": [r"^sp: no instance config at \S*/data/instance\.yaml"]}}], exit_=2),
                  sp(["doctor"] + D, [{"stderr": {"regex": [r"^sp: no instance config at "]}}], exit_=2),
                  sp(["digest"] + D + ["--instance", "{sandbox}/nope.yaml"],
                     [{"stderr": {"regex": [r"^sp: no instance config at \S*/nope\.yaml"]}}], exit_=2),
                  sp(["findings", "--ids"] + D, [{"stdout": {"lines": []}}])]})

    write_case("cli", "bad-input-is-one-line", {
        "title": "Unreadable input (a config that is not YAML, a config that is not a mapping, a corrupt ledger or tracker, "
                 "`sp init` onto a file) is reported as one line `sp: <path>: <why>` with exit 2, never a stack trace",
        "contract": C, "deviation": "CLI-D2", "origin": "cli/sp.py: exceptions escape as Python tracebacks (exit 1)",
        "files": {"yaml/instance.yaml": {"text": "name: [unclosed\nrunner: {\n"},
                  "list/instance.json": {"text": "[1, 2]\n"},
                  "ledger/instance.json": {"text": "{\"name\": \"x\"}\n"}, "ledger/ledger.json": {"text": "{\"entries\": "},
                  "items/instance.json": {"text": "{\"name\": \"x\"}\n"},
                  "items/ledger.json": {"text": "{\"entries\": {}}\n"}, "items/tracker/items.json": {"text": "not json"},
                  "afile": {"text": "x\n"}},
        "steps": [sp(["doctor", "--data", "{sandbox}/yaml"], [{"stderr": {"regex": [r"^sp: \S*/yaml/instance\.yaml: "],
                                                                           "not_regex": ["Traceback"]}}], exit_=2),
                  sp(["status", "--data", "{sandbox}/list"], [{"stderr": {"regex": [r"^sp: \S*/list/instance\.json: "],
                                                                           "not_regex": ["Traceback"]}}], exit_=2),
                  sp(["status", "--data", "{sandbox}/ledger"], [{"stderr": {"regex": [r"^sp: \S*/ledger/ledger\.json: "],
                                                                             "not_regex": ["Traceback"]}}], exit_=2),
                  sp(["findings", "--data", "{sandbox}/items"], [{"stderr": {"regex": [r"^sp: \S*/items/tracker/items\.json: "],
                                                                              "not_regex": ["Traceback"]}}], exit_=2),
                  sp(["init", "{sandbox}/afile"], [{"stderr": {"regex": [r"^sp: \S*/afile: "], "not_regex": ["Traceback"]}}],
                     exit_=2)]})

    write_case("cli", "locating-data", {
        "title": "Where the data and the instance config are: --data, else $SP_DATA (~ expanded); --instance, else "
                 "$SP_INSTANCE, else DATA/instance.yaml, instance.yml, instance.json (first that exists)",
        "contract": C, "origin": "contract cli §1; cli/sp.py Ctx",
        "files": {"a/instance.json": {"json": {"name": "from-a-json"}},
                  "b/instance.yml": {"text": "name: from-b-yml\n"}, "b/instance.json": {"json": {"name": "from-b-json"}},
                  "c/instance.yaml": {"text": "name: from-c-yaml\n"}, "c/instance.yml": {"text": "name: from-c-yml\n"},
                  "other.json": {"json": {"name": "from-sp-instance"}}, "flag.json": {"json": {"name": "from-flag"}},
                  "home/d/instance.json": {"json": {"name": "from-home"}}},
        "steps": [sp(["status"], [{"stdout": {"regex": [r"^security-platform status - from-a-json$"]}}], env={"SP_DATA": "{sandbox}/a"},
                     name="SP_DATA"),
                  sp(["status", "--data", "{sandbox}/b"], [{"stdout": {"regex": [r"^security-platform status - from-b-yml$"]}}],
                     env={"SP_DATA": "{sandbox}/a"}, name="--data wins over SP_DATA; instance.yml before instance.json"),
                  sp(["status", "--data", "{sandbox}/c"], [{"stdout": {"regex": [r"status - from-c-yaml$"]}}],
                     name="instance.yaml first"),
                  sp(["status", "--data", "{sandbox}/c"], [{"stdout": {"regex": [r"status - from-sp-instance$"]}}],
                     env={"SP_INSTANCE": "{sandbox}/other.json"}, name="SP_INSTANCE"),
                  sp(["status", "--data", "{sandbox}/c", "--instance", "{sandbox}/flag.json"],
                     [{"stdout": {"regex": [r"status - from-flag$"]}}], env={"SP_INSTANCE": "{sandbox}/other.json"},
                     name="--instance wins over SP_INSTANCE"),
                  sp(["status", "--data", "~/d"], [{"stdout": {"regex": [r"status - from-home$"]}}], name="~ is the home directory")]})

    write_case("cli", "argument-errors", {
        "title": "Command-line mistakes exit 2 with a message on stderr and nothing on stdout; -h/--help print usage and "
                 "exit 0; long options may be abbreviated and written --opt=value",
        "contract": C, "origin": "cli/sp.py main (argparse)",
        "files": {"data/instance.json": {"json": {"name": "x"}}, "data/ledger.json": {"json": {"entries": {}}}},
        "steps": [sp([], [{"stderr": {"regex": ["."]}}, {"stdout": {"not_regex": ["."]}}], exit_=2, name="no command"),
                  sp(["frobnicate"], [{"stderr": {"regex": ["frobnicate"]}}, {"stdout": {"not_regex": ["."]}}], exit_=2),
                  sp(["findings", "--severity", "bogus", "--data", "{sandbox}/data"],
                     [{"stderr": {"regex": ["bogus"]}}, {"stdout": {"not_regex": ["."]}}], exit_=2),
                  sp(["findings", "--no-such-option", "--data", "{sandbox}/data"], [{"stderr": {"regex": ["--no-such-option"]}}],
                     exit_=2),
                  sp(["explain", "--data", "{sandbox}/data"], [{"stderr": {"regex": ["."]}}], exit_=2, name="explain without an id"),
                  sp(["digest", "--days", "x", "--data", "{sandbox}/data"], [{"stderr": {"regex": ["."]}}], exit_=2),
                  sp(["init"], [{"stderr": {"regex": ["."]}}], exit_=2, name="init without a directory"),
                  sp(["--help"], [{"stdout": {"regex": ["init", "doctor", "findings", "explain", "digest", "notify"]}}]),
                  sp(["findings", "-h"], [{"stdout": {"regex": ["--severity", "--overdue", "--ids"]}}]),
                  sp(["findings", "--sev=critical", "--data={sandbox}/data", "--js"], [{"stdout": {"json": []}}],
                     name="abbreviated --opt=value")]})


def cli_findings_cases(cr, hi, lo, fx):
    C = "cli/1.1"
    long_asset = "host:" + "\u00e4" * 50
    lng = finding(long_asset, "host.title_" + "x" * 90, severity="medium", observed="2026-11-01T08:00:00Z")
    inf = finding("host:web-3", "host.banner", severity="info")
    led = ledger_doc(entry(cr), entry(hi), entry(lo), entry(fx, status="fixed", fixed_at="2026-11-02T09:00:00Z",
                                                             fixed_reason="not_observed"), entry(lng), entry(inf))
    items = {"schema": "security-platform/tracker/v1", "items": {
        cr["id"]: {"id": cr["id"], "status": "open", "due_at": "2026-11-08T08:00:00Z", "overdue": True, "owner": "ops"},
        hi["id"]: {"id": hi["id"], "status": "open", "due_at": "2099-12-01T08:00:00Z", "overdue": False, "owner": "ops"},
        lng["id"]: {"id": lng["id"], "status": "open", "due_at": "2030-01-31T23:30:00Z", "overdue": False, "owner": "ops"}}}
    SEVS = ["critical", "high", "medium", "low", "info"]
    ents = sorted(led["entries"].values(), key=lambda e: (SEVS.index(e["severity"]), e["layer"], e["asset"]))
    dues = {cr["id"]: "OVERDUE", hi["id"]: "2099-12-01", lng["id"]: "2030-01-31"}
    shown = [e for e in ents if e["severity"] != "info"]
    head = f"{'ID':<13}{'SEVERITY':<10}{'STATUS':<9}{'DUE':<12}{'LAYER':<13}{'ASSET':<38}WHAT"
    table = "\n".join([head] + [f"{e['id']:<13}{e['severity']:<10}{e['status']:<9}{dues.get(e['id'], '-'):<12}{e['layer']:<13}"
                                 f"{e['asset'][:37]:<38}{e['title'][:70]}" for e in shown]) + \
        f"\n\n{len(shown)} finding(s). Details and how to fix: sp explain <ID>\n"
    ids = lambda pred: [e["id"] for e in ents if pred(e)]  # noqa: E731
    D = ["--data", "{sandbox}/data"]
    write_case("cli", "findings-table-layout", {
        "title": "The `sp findings` table has fixed column widths (ID 13, SEVERITY 10, STATUS 9, DUE 12, LAYER 13, ASSET 38 "
                 "= the first 37 characters, WHAT = the first 70), DUE in local time, then a count line; `--severity S` "
                 "means S or worse, so `low` leaves out info",
        "contract": C, "origin": "cli/sp.py cmd_findings",
        "files": {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json"},
        "steps": [sp(["findings", "--severity", "low"] + D, [{"stdout": {"text": table}}]),
                  sp(["findings", "--severity", "medium", "--ids"] + D,
                     [{"stdout": {"lines": ids(lambda e: e["severity"] in ("critical", "high", "medium"))}}]),
                  sp(["findings", "--ids"] + D, [{"stdout": {"lines": ids(lambda e: True)}}]),
                  sp(["findings", "--json", "--check", "host.title_"] + D,
                     [{"stdout": {"schema": "cli-findings", "json": [dict(entry(lng))]}}], name="--json is the whole entry"),
                  sp(["findings", "--json", "--data", "{sandbox}/empty"], [{"stdout": {"json": []}}],
                     files={"empty/.keep": {"text": ""}}, name="no ledger yet: an empty array"),
                  sp(["findings", "--data", "{sandbox}/empty"], [{"stdout": {"text": "no matching findings\n"}}])]},
        {"ledger.json": led, "items.json": items})

    due = finding("host:web-9", "host.dst_due", severity="high")
    write_case("cli", "due-date-in-local-time", {
        "title": "A due date is a UTC instant shown as the local date: 2030-07-01T22:30:00Z is 2030-07-02 in Europe/Berlin "
                 "(summer time)",
        "contract": C, "deviation": "CLI-D3",
        "origin": "cli/sp.py ts(): time.mktime(...) - time.timezone is an hour off under daylight saving time",
        "files": {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json"},
        "steps": [sp(["findings"] + D, [{"stdout": {"regex": [rf"^{due['id']}\s+high\s+open\s+2030-07-02 "]}}],
                     env={"TZ": "Europe/Berlin"})]},
        {"ledger.json": ledger_doc(entry(due)), "items.json": {"items": {due["id"]: {
            "id": due["id"], "status": "open", "due_at": "2030-07-01T22:30:00Z", "overdue": False}}}})

    a = finding("host:web-1", "conformance.alpha", severity="high", needs_human=True, remediation="turn it off")
    e_a = entry(a, reopened_count=2, evidence="raw/host/web-1.json#k")
    others = [finding(f"host:n{i}", "conformance.beta", severity="low") for i in range(40)]
    clash = next(o for o in others if o["id"][0] == a["id"][0])
    write_case("cli", "explain-details", {
        "title": "`sp explain` shows owner, due date and OVERDUE from the tracker, regressions, the collector's own note, "
                 "whether a person is needed, the private evidence path and an exception snippet expiring in 90 days",
        "contract": C, "origin": "cli/sp.py cmd_explain",
        "files": {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json"},
        "steps": [sp(["explain", a["id"]] + D, [{"stdout": {"regex": [
            r"^conformance\.alpha on host:web-1$",
            rf"^id {a['id']}   check conformance\.alpha   high \(fix this week\)$",
            r"^where: host:web-1   area: host - the machine itself \(updates, firewall, disk\)$",
            r"^status: open   first seen 2026-11-01   last seen 2026-11-01   came back 2x$",
            r"^owner: ops   fix by: 2026-11-08   OVERDUE$",
            r"^How to fix$", r"^  \(collector's note: turn it off\)$", r"^How to verify$",
            r"^  This one needs a person ",
            r"^If you decide to accept the risk instead \(a human decision with an end date\), add to \S*/data/exceptions\.yaml:$",
            rf"^  exceptions:\n    {a['id']}:\n      approved_by: <your name>\n      reason: <why this is acceptable for now>\n"
            r"      expires: '({date:+7776000}|{date:+7779600})'$",
            r"^evidence \(private\): \S*/data/runs/\.\.\./raw/host/web-1\.json$"],
            "not_regex": ["What it means"]}}])]},
        {"ledger.json": ledger_doc(e_a, *[entry(o) for o in others]),
         "items.json": {"items": {a["id"]: {"id": a["id"], "status": "open", "due_at": "2026-11-08T08:00:00Z", "overdue": True,
                                             "owner": "ops"}}}})
    _ = clash

    write_case("cli", "explain-ambiguous-prefix", {
        "title": "`sp explain PREFIX` needs a unique prefix: one that matches several findings exits 2 and names them, "
                 "instead of explaining whichever comes first",
        "contract": C, "deviation": "CLI-D4", "origin": "cli/sp.py cmd_explain: next() over the ledger's order",
        "files": {"data/ledger.json": "ledger.json"},
        "steps": [sp(["explain", a["id"][0]] + D, [{"stderr": {"regex": [rf"^sp: .*{a['id'][0]}.*", a["id"], clash["id"]]}},
                                                   {"stdout": {"not_regex": ["."]}}], exit_=2),
                  sp(["explain", a["id"][:12]] + D, [{"stdout": {"regex": [rf"^id {a['id']} "]}}], name="the whole id")]},
        {"ledger.json": ledger_doc(e_a, *[entry(o) for o in others])})


def cli_status_cases():
    C = "cli/1.1"
    ents = [entry(finding(f"host:s{i}", f"conformance.check_{i}", severity=sev, observed=obs))
            for i, (sev, obs) in enumerate([("critical", "2026-11-03T00:00:00Z"), ("high", "2026-11-01T00:00:00Z"),
                                            ("critical", "2026-11-02T00:00:00Z"), ("medium", "2026-11-01T00:00:00Z"),
                                            ("low", "2026-11-01T00:00:00Z"), ("high", "2026-10-01T00:00:00Z")])]
    ents[1]["reopened_count"] = 1
    f7 = entry(finding("host:s9", "conformance.fixed_recently", severity="high"), status="fixed", fixed_at="{utc:-3600}")
    f30 = entry(finding("host:s8", "conformance.fixed_long_ago", severity="high"), status="fixed", fixed_at="2026-01-01T00:00:00Z")
    led = dict(ledger_doc(*ents, f7, f30), sli={"patch_latency": {"ok": True, "value": 2}, "mfa_coverage": {"ok": False, "value": 0.5}})
    items = {"items": {ents[0]["id"]: {"id": ents[0]["id"], "status": "open", "overdue": True, "owner": "ops"},
                       ents[1]["id"]: {"id": ents[1]["id"], "status": "open", "overdue": False, "owner": "unassigned"}}}
    sc = {"overall": 62.5, "status": "FAIL", "threshold": 75,
          "dimensions": {"network": {"score": 90}, "people": {"score": 62.5}, "devices": {"score": None}},
          "pillars": {"network": {"score": 80}, "people": 40}}
    jobs = {"host": {"schedule": "15 2 * * *"}, "flaky": {"schedule": "15 3 * * *"},
            "late": {"type": "remediation", "schedule": "*/10 * * * *"}, "fresh": {"schedule": "0 4 * * *"}}
    states = {
        "host": {"runs_total": 3, "failures_total": 0, "last_rc": 0, "last_success": "{epoch:-7300}", "done_slot": "{epoch:-7400}"},
        "flaky": {"runs_total": 4, "failures_total": 2, "last_rc": 3, "last_success": "{epoch:-90000}",
                  "last_note": "collector exited rc=3, document=no " + "z" * 100},
        "late": {"runs_total": 5, "failures_total": 0, "last_rc": 0, "last_success": "{epoch:-2820}", "done_slot": "{epoch:-2880}"}}
    reasons = ["r" * 130] + ["unreachable"] * 9
    gdoc = doc("host", [], [gap(f"host:g{i}", reasons[i]) for i in range(10)] + [ok("host:s0")])
    files = {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json", "data/instance.json": "instance.json",
             "data/scorecard/latest.json": "scorecard.json", "data/latest/host.findings.json": "host.findings.json"}
    for n in states:
        files[f"data/state/runner/{n}.json"] = f"state-{n}.json"
    fx = {"ledger.json": raw_json(led), "items.json": items, "instance.json": raw_json({"name": "conf", "runner": {"jobs": jobs}}),
          "scorecard.json": sc, "host.findings.json": gdoc}
    for n, s_ in states.items():
        fx[f"state-{n}.json"] = raw_json(dict({"schema": "security-platform/runner-state/v1", "job": n}, **s_),
                                         "{epoch:-7300}", "{epoch:-7400}", "{epoch:-90000}", "{epoch:-2820}", "{epoch:-2880}")
    top = sorted(range(6), key=lambda i: (["critical", "high", "medium", "low"].index(ents[i]["severity"]), ents[i]["first_seen"]))[:5]
    write_case("cli", "status-overview", {
        "title": "`sp status`: open findings by severity, overdue and unowned fixes, fixed in 7 days and regressions, the "
                 "scorecard (weakest dimensions, pillars), SLIs off target, every job (ok / FAILING / LATE / never), what "
                 "could not be checked (at most 8 lines, reasons cut at 100 characters) and the five worst findings",
        "contract": C, "origin": "cli/sp.py cmd_status; tests/test_cli.py::test_status",
        "files": files,
        "steps": [sp(["status", "--data", "{sandbox}/data"], [{"stdout": {"regex": [
            r"^security-platform status - conf$",
            r"^Open findings: critical 2, high 2, medium 1, low 1$",
            r"^Overdue fixes: 1 \(past their remediation SLO; `sp findings --overdue`\)$",
            r"^Without an owner: 1 \(set remediation\.default_owner\)$",
            r"^Fixed in the last 7 days: 1   Came back \(regressions\): 1$",
            r"^Scorecard: 62\.5/100   weakest: people 62\.5, network 90, devices None  \(FAIL, threshold 75\)$",
            r"^  pillars: network 80, people 40$",
            r"^Security SLIs: 1/2 on target: off target mfa_coverage=0\.5$",
            r"^Jobs:$",
            r"^  ok  host                 last good run 2h ago$",
            r"^  FAILING  flaky                last good run 1d ago  \(collector exited rc=3, document=no z{45}\)$",
            r"^  LATE    late                 slot \d{4}-\d\d-\d\d \d\d:\d\d not run yet \(\d+m late\); last good run 4\dm ago$",
            r"^  never   fresh$",
            r"^Could not check 10 thing\(s\) \(no finding there does NOT mean safe\):$",
            r"^  host: r{100}$",
            r"^Top risks \(sp explain <id>\):$"] + [rf"^  {ents[i]['id']}  {ents[i]['severity']:<8} " for i in top]
            + ["".join(rf"^  {ents[i]['id']}  .*\n" for i in top)],
            "not_regex": [r"^  host: r{101}", ents[[i for i in range(6) if i not in top][0]]["id"]]}},
            {"stdout": {"regex": [r"(?:^  host: \S+\n){8}\nTop risks"]}}])]}, fx)


def cli_digest_notify_cases():
    C = "cli/1.1"
    new_c = [finding(f"host:secret-{i}", "conformance.same_check", severity="critical", observed="{utc:-600}") for i in range(2)]
    new_h = finding("host:secret-9", "conformance.other_check", severity="high", observed="{utc:-1200}")
    old = finding("host:secret-8", "conformance.old_check", severity="low", observed="2026-01-01T00:00:00Z")
    back = finding("host:secret-7", "conformance.back_check", severity="low", observed="2026-01-01T00:00:00Z")
    fixed = finding("host:secret-6", "conformance.fixed_check", severity="high", observed="2026-01-01T00:00:00Z")
    led = ledger_doc(*[entry(f) for f in new_c], entry(new_h), entry(old), entry(back, reopened_count=1, last_seen="{utc:-60}"),
                     entry(fixed, status="fixed", fixed_at="{utc:-300}"))
    items = {"items": {old["id"]: {"id": old["id"], "status": "open", "overdue": True}}}
    inst = {"name": "conf", "runner": {"jobs": {"broken": {"schedule": "0 1 * * *"}}}}
    state = {"schema": "security-platform/runner-state/v1", "job": "broken", "runs_total": 2, "last_rc": 1, "last_success": None}
    files = {"data/ledger.json": "ledger.json", "data/tracker/items.json": "items.json", "data/instance.json": "instance.json",
             "data/state/runner/broken.json": "state.json",
             "data/scorecard.json": {"json": {"overall": 70, "dimensions": [{"id": "people", "score": 70}]}}}
    text = ("Security {date:+0} (conf)\nOpen: 2 critical, 1 high, 2 low\ntoday: 3 new, 1 fixed, 1 came back\n"
            "Overdue fixes: 1\nScorecard: 70/100   weakest: people 70\nJobs failing: 1 (sp status)\nNew and serious:\n"
            f"- critical: conformance.same_check (x2)  [sp explain {new_c[0]['id']}]\n"
            f"- high: conformance.other_check  [sp explain {new_h['id']}]\n")
    write_case("cli", "digest-content", {
        "title": "`sp digest`: the date and instance name, open counts above info, new / fixed / came back in the period, "
                 "overdue fixes, the scorecard, failing jobs, then the serious new findings once per check family with a "
                 "count and an id for `sp explain`; `All clear.` when there is nothing; never an asset",
        "contract": C, "origin": "cli/sp.py digest; tests/test_cli.py::test_digest_has_no_asset_details",
        "files": files,
        "steps": [sp(["digest", "--daily", "--data", "{sandbox}/data"], [{"stdout": {"text": text, "not_contains": ["secret-"]}}]),
                  sp(["digest", "--days", "400", "--data", "{sandbox}/data"],
                     [{"stdout": {"regex": [r"^last 400 days: 5 new, 1 fixed, 1 came back$"]}}]),
                  sp(["digest", "--data", "{sandbox}/clear"], [{"stdout": {"text": "Security {date:+0} (calm)\nOpen: nothing above info\n"
                                                                                     "today: 0 new, 0 fixed\nAll clear.\n"}}],
                     files={"clear/instance.json": {"json": {"name": "calm"}}}, name="nothing to report")]},
        {"ledger.json": raw_json(led), "items.json": items, "instance.json": inst, "state.json": raw_json(state)})

    canary = "conformance-bot-token-5d1e"
    notify = [{"type": "file", "path": "{sandbox}/out/latest.txt"},
              {"type": "webhook", "url_file": "{sandbox}/secrets/hook.url"},
              {"type": "webhook", "url_file": "{sandbox}/secrets/hook.url", "format": "json"},
              {"type": "webhook", "url_file": "{sandbox}/secrets/hook.url", "format": "text"},
              {"type": "telegram", "token_file": "{sandbox}/secrets/bot.token", "chat_id": 42, "api": "{svc_hook}"},
              {"type": "exec", "argv": ["/bin/sh", "-c", "cat > \"$0\"", "{sandbox}/out/exec.txt"]},
              {"type": "webhook", "url_file": "{sandbox}/secrets/fail.url"},
              {"type": "telegram", "token_file": "{sandbox}/secrets/open.token", "chat_id": 42, "api": "{svc_hook}"},
              {"type": "exec", "argv": ["/bin/sh", "-c", "echo boom >&2; exit 3"]}]
    nfiles = dict(files, **{"data/instance.json": {"json": {"name": "conf", "notify": notify}},
                            "secrets/hook.url": {"text": "{svc_hook}/hook\n", "mode": "0600"},
                            "secrets/fail.url": {"text": "{svc_hook}/fail\n", "mode": "0600"},
                            "secrets/bot.token": {"text": canary + "\n", "mode": "0600"},
                            "secrets/open.token": {"text": canary + "-open\n", "mode": "0644"}})
    write_case("cli", "notify-adapters", {
        "title": "`sp notify` sends the digest through every configured notifier (file, webhook slack/json/text, telegram, "
                 "exec); one failing does not stop the others and makes the exit 1; `--dry-run` sends nothing; secrets "
                 "(bot token, webhook URL) never reach the output; no notifier configured exits 1",
        "contract": C, "origin": "cli/sp.py cmd_notify; notifier/notifiers.py; tests/test_notifier.py",
        "services": [{"name": "hook", "argv": ["{python}", "{case}/mock_webhook.py", "--record", "{sandbox}/hook.jsonl"]}],
        "files": nfiles,
        "steps": [sp(["notify", "--dry-run", "--data", "{sandbox}/data"],
                     [{"stdout": {"regex": [r"^Security {date:+0} \(conf\)$", r"^\(dry run: 9 notifier\(s\) not called\)$"]}},
                      {"absent": "hook.jsonl"}, {"absent": "out/latest.txt"}]),
                  sp(["notify", "--data", "{sandbox}/data"], [
                      {"stdout": {"regex": [r"^sent via 0-file$", r"^sent via 1-webhook$", r"^sent via 2-webhook$",
                                            r"^sent via 3-webhook$", r"^sent via 4-telegram$", r"^sent via 5-exec$"],
                                  "not_regex": ["6-webhook", "7-telegram", "8-exec"]}},
                      {"stderr": {"regex": [r"^notifier 6-webhook failed: .*HTTP 500", r"^notifier 7-telegram failed: .*0600",
                                            r"^notifier 8-exec failed: .*rc=3: boom"], "not_regex": ["/fail", "/hook", "127\\.0\\.0\\.1"]}},
                      {"file": "out/latest.txt", "regex": [r"^Security {date:+0} \(conf\)$", r"^Open: 2 critical, 1 high, 2 low$"]},
                      {"file": "out/exec.txt", "regex": [r"^Security {date:+0} \(conf\)$"]},
                      {"jsonl": "hook.jsonl", "subset": [
                          {"path": "/hook", "content_type": "application/json", "user_agent": "security-platform",
                           "body": {"$regex": "^\\{\"text\": *\"Security "}},
                          {"path": "/hook", "content_type": "application/json", "body": {"$regex": "\"title\": *\"Security "}},
                          {"path": "/hook", "content_type": {"$regex": "^text/plain"}, "body": {"$regex": "^Security "}},
                          {"path": {"$regex": "^/bot.+/sendMessage$"}, "content_type": "application/x-www-form-urlencoded",
                           "body": {"$regex": "^chat_id=42&text=Security\\+.*&disable_web_page_preview=true$"}},
                          {"path": "/fail"}]},
                      {"no_secret": [canary], "in": "data"}], exit_=1),
                  sp(["notify", "--data", "{sandbox}/quiet"], [{"stderr": {"regex": [r"^sp: no notifiers configured"]}}], exit_=1,
                     files={"quiet/instance.json": {"json": {"name": "q"}}}, name="none configured")]},
        {"ledger.json": raw_json(led), "items.json": items, "state.json": raw_json(state),
         "mock_webhook.py": open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_webhook.py")).read()})


def cli_run_cases():
    C = "cli/1.1"
    f = finding("host:r1", "conformance.run_check", severity="medium")

    def cmd(**env):
        return {"type": "command", "collector": "host", "argv": ["/bin/sh", "{case}/emit.sh"], "schedule": "0 1 * * *",
                "env": dict({"EMIT_DOC": "{case}/emit.findings.json"}, **env)}
    inst = {"name": "runs", "scorecard": {"enabled": False}, "runner": {"site": "hub", "role": "hub", "jobs": {
        "remediation": {"type": "remediation", "schedule": "50 * * * *"}, "good": dict(cmd(), **{"as": "good"}),
        "bad": dict(cmd(EMIT_FAIL="3"), **{"as": "bad"}), "digest": {"type": "digest", "schedule": "0 9 * * 1"}}}}
    D = ["--data", "{sandbox}/data"]
    write_case("cli", "run-reports-each-job", {
        "title": "`sp run` runs every job except digest/notify/snapshot/push/pull-snapshot (collectors first), prints one "
                 "`ok` / `FAILED` line per job and exits with the runner's status; named jobs run as given; an unknown "
                 "job exits 2 naming the configured ones",
        "contract": C, "origin": "cli/sp.py cmd_run",
        "files": {"data/instance.json": "instance.json"},
        "steps": [sp(["run"] + D, [{"stdout": {"regex": [r"^running 3 job\(s\): good, bad, remediation  ",
                                                         r"^  ok  good\s+\d+s\s*$", r"^  FAILED  bad\s+\d+s  \S",
                                                         r"^  ok  remediation\s+\d+s\s*$", r"^next: sp status"]}},
                                   {"json": "data/state/runner/bad.json", "subset": {"last_rc": {"$type": "integer"}}}],
                     exit_={"not": 0}),
                  sp(["run", "good", "digest"] + D, [{"stdout": {"regex": [r"^running 2 job\(s\): good, digest  ",
                                                                           r"^  ok  good\s", r"^  ok  digest\s"]}}]),
                  sp(["run", "nope", "good"] + D, [{"stderr": {"regex": [
                      r"^sp: not in runner\.jobs: nope \(configured: remediation, good, bad, digest\)$"]}}], exit_=2)]},
        {"instance.json": raw_json(inst), "emit.sh": EMIT_SH, "emit.findings.json": doc("good", [f], [ok("host:r1")])})


def cli_init_cases():
    C = "cli/1.1"
    write_case("cli", "init-keeps-existing-files", {
        "title": "`sp init` on an existing directory makes it private (0700), keeps instance.yaml unless --force and keeps "
                 "exceptions.yaml and .gitignore always",
        "contract": C, "origin": "cli/sp.py cmd_init",
        "files": {"d": {"dir": True, "mode": "0755"}, "d/instance.yaml": {"text": "name: mine\n", "mode": "0600"},
                  "d/exceptions.yaml": {"text": "exceptions: {abc: {}}\n"}, "d/.gitignore": {"text": "mine/\n"}},
        "steps": [sp(["init", "{sandbox}/d"], [{"stdout": {"regex": [r"^\S*/d/instance\.yaml exists: left as it is \(--force overwrites\)$"],
                                                           "not_regex": ["^wrote"]}},
                                               {"mode": "d", "is": "0700"}, {"file": "d/instance.yaml", "text": "name: mine\n"}]),
                  sp(["init", "{sandbox}/d", "--force", "--name", "fresh"],
                     [{"stdout": {"regex": [r"^wrote \S*/d/instance\.yaml$"]}}, {"file": "d/instance.yaml", "regex": ["^name: fresh$"]},
                      {"mode": "d/instance.yaml", "is": "0600"},
                      {"file": "d/exceptions.yaml", "text": "exceptions: {abc: {}}\n"}, {"file": "d/.gitignore", "text": "mine/\n"}]),
                  sp(["init", "{sandbox}/new/nested"], [{"stdout": {"regex": [r"^wrote \S*/new/nested/instance\.yaml$"]}},
                                                         {"file": "new/nested/instance.yaml", "regex": [r"^name: nested$"]},
                                                         {"file": "new/nested/.gitignore", "text": "state/locks/\ncache/\n"}],
                     name="default name: the directory's")]})

    st = sp(["init", "{sandbox}/d"], [{"mode": "d", "is": "0700"}, {"mode": "d/instance.yaml", "is": "0600"},
                                      {"mode": "d/exceptions.yaml", "is": "0600"}, {"mode": "d/.gitignore", "is": "0600"}])
    st["exec"]["umask"] = "022"
    write_case("cli", "init-files-are-private", {
        "title": "Every file `sp init` creates is private to the user (0600), whatever the umask: the data directory holds "
                 "attacker-relevant information",
        "contract": C, "deviation": "CLI-D5",
        "origin": "cli/sp.py cmd_init: exceptions.yaml and .gitignore are created with the process umask (0644 under 022)",
        "steps": [st]})


# ==================================================================================================================
# collectors (contract collector-protocol/1.0): <impl> with SP_RUN_DIR, SP_INSTANCE, SP_DATA, ... set
# ==================================================================================================================
def collector_env(extra=None):
    e = {"SP_RUN_DIR": "{sandbox}/run", "SP_INSTANCE": "{sandbox}/instance.json", "SP_DATA": "{sandbox}/data",
         "SP_INPUT_DIR": "{sandbox}/data/latest", "SP_INSTANCE_NAME": "conformance"}
    e.update(extra or {})
    return e


def protocol_checks(name, canaries=()):
    out = [{"json": f"run/{name}.findings.json", "schema": "findings", "findings_ids": True,
            "subset": {"collector": {"name": name}}},
           {"writes_only_under": True}]
    if canaries:
        out.append({"no_secret": list(canaries), "in": "run"})
    return out


def collector_cases():
    C = "collector-protocol/1.0"
    tok = "{fake_jwt}"     # built by the harness at run time: no token-shaped string in the repository (secret scanners)
    acct = {"provider": "gcp", "workload_identity_provider": "projects/1/locations/global/workloadIdentityPools/p/providers/x",
            "service_account": "a@p.iam.gserviceaccount.com", "identity_token": {"type": "file", "path": "{sandbox}/token.jwt"},
            "sts_url": "{svc_gcp}/sts", "iamcredentials_url": "{svc_gcp}/iam", "resourcemanager_url": "{svc_gcp}/crm",
            "engines": []}
    inst = {"name": "conformance", "cloud": {"accounts": [dict(acct, project_id="cond"), dict(acct, project_id="cond-over")]}}
    MOCK = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "mock_gcp.py")).read()
    write_case("collector-cloud", "gcp-conditional-grant", {
        "title": "A time-bound (conditional) read-only GCP grant is judged by its real role: no over-privilege finding; a "
                 "conditional write role still is one. Credentials never reach the output",
        "contract": C + " / findings/1.2", "origin": "incident: a conditional Security Reviewer grant was refused as over-privileged; tests/test_cloud.py::test_gcp_flow",
        "files": {"instance.json": "instance.json", "token.jwt": {"text": tok}, "data/.keep": {"text": ""}},
        "services": [{"name": "gcp", "argv": ["{python}", "{case}/mock_gcp.py"]}],
        "steps": [{"name": "collect", "exec": {"impl": "collector-cloud", "env": collector_env(), "writes_only_under": ["run", "data/cache"]},
                   "expect": protocol_checks("cloud", canaries=[tok, "ya29.conformance-access-token"]) + [
                       {"json": "run/cloud.findings.json", "subset": {"findings": [
                           {"check": "cloud.platform_credential_over_privileged", "asset": "cloud:gcp/cond-over",
                            "title": {"$regex": "roles/editor"}, "severity": "high", "layer": "identity"}],
                           "coverage": {"$contains": [{"asset": "cloud:gcp/cond-over", "status": "gap",
                                                       "reason": {"$regex": "over-privileged"}}]}}}]}]},
        {"instance.json": inst, "mock_gcp.py": MOCK})

    write_case("collector-agent-claude-code", "settings-without-deny-rules", {
        "title": "Collector protocol on a hermetic input: one valid document named after the collector, ids derived "
                 "from (layer, asset, check), writes only into SP_RUN_DIR, no secret value copied",
        "contract": C, "origin": "tests/test_runner.py::test_as_renames_the_report_not_the_program; collector-protocol",
        "files": {"instance.json": "instance.json", "home/.claude/settings.json": "settings.json", "data/.keep": {"text": ""}},
        "steps": [{"name": "collect", "exec": {"impl": "collector-agent-claude-code", "env": collector_env(),
                                               "writes_only_under": ["run"]},
                   "expect": protocol_checks("agent-claude-code", canaries=["sk-conformance-canary-0123456789"]) + [
                       {"json": "run/agent-claude-code.findings.json", "subset": {
                           "coverage": {"$contains": [{"asset": "agent-guard:claude-code", "status": "ok"}]},
                           "findings": {"$contains": [{"check": "agent.no_credential_deny_rules", "layer": "ai-agents"}]}}}]},
                  {"name": "collect as another name (SP_COLLECTOR_NAME)", "remove": ["run"],
                   "exec": {"impl": "collector-agent-claude-code", "env": collector_env({"SP_COLLECTOR_NAME": "agent-b"})},
                   "expect": [{"json": "run/agent-b.findings.json", "schema": "findings", "subset": {"collector": {"name": "agent-b"}}},
                              {"absent": "run/agent-claude-code.findings.json"}]}]},
        {"instance.json": {"name": "conformance", "agents": [{"type": "claude-code", "settings": ["{sandbox}/home/.claude/settings.json"]}]},
         "settings.json": {"env": {"API_KEY": "sk-conformance-canary-0123456789"}, "permissions": {"allow": ["Bash(ls:*)"]}}})

    write_case("collector-example", "world-writable-file", {
        "title": "The POSIX sh example collector (contracts/collector-protocol/examples/collector.sh) honours the "
                 "protocol: a document per run, ok/gap coverage, stable ids, writes only into SP_RUN_DIR",
        "contract": C, "origin": "contracts/collector-protocol/examples/collector.sh",
        "files": {"target/open.conf": {"text": "x\n", "mode": "0666"}, "target/fine.conf": {"text": "x\n", "mode": "0644"}},
        "steps": [{"name": "collect", "exec": {"impl": "collector-example", "env": collector_env({
                      "EXAMPLE_FILES": "{sandbox}/target/open.conf:{sandbox}/target/fine.conf:{sandbox}/target/missing.conf",
                      "EXAMPLE_HOST": "lab"}), "writes_only_under": ["run"]},
                   "expect": protocol_checks("example-files") + [{"json": "run/example-files.findings.json", "subset": {
                       "coverage": {"$unordered": [{"asset": {"$regex": "^file:lab:.*/open.conf$"}, "status": "ok"},
                                                   {"asset": {"$regex": "^file:lab:.*/fine.conf$"}, "status": "ok"},
                                                   {"asset": {"$regex": "^file:lab:.*/missing.conf$"}, "status": "gap"}]},
                       "findings": [{"check": "example.world_writable_file", "asset": {"$regex": "open.conf$"}}]}}]}]})


# ==================================================================================================================
# exec-adapter collectors: host, host-sbom, secrets-files (collector-protocol/1.0). Targets are FAKE: fake_exec.sh,
# installed as {sandbox}/bin/ssh|sh|sudo, records argv + stdin under trace/ and replays replay/<target>.* (no real
# host, no network). PATH is fixed, so a program the case does not provide (powershell, trivy) is missing.
# ==================================================================================================================
FAKE_EXEC = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_exec.sh")).read()
SSH_BASE = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"]


def exec_env(extra=None):
    return collector_env(dict({"PATH": "{sandbox}/bin:/usr/bin:/bin", "FAKE_EXEC": "{sandbox}"}, **(extra or {})))


def fakes(*programs):
    """Case files: the fake installed under the given program names."""
    return {f"bin/{p}": {"raw": "fake_exec.sh", "mode": "0755"} for p in programs}


def replay(target, out=None, err=None, rc=None, sleep=None, raw=None):
    """Case files replaying one target. `raw`: the name of a byte-exact case file for stdout."""
    f = {}
    if raw:
        f[f"replay/{target}.out"] = {"raw": raw}
    elif out is not None:
        f[f"replay/{target}.out"] = {"text": out}
    for ext, v in (("err", err), ("rc", rc), ("sleep", sleep)):
        if v is not None:
            f[f"replay/{target}.{ext}"] = {"text": f"{v}\n" if ext != "err" else v}
    return f


def argv_regex(*argv):
    """A `file` regex: the trace holds exactly this argument vector, one argument per line."""
    import re
    return r"\A" + "".join(re.escape(a) + r"\n" for a in argv) + r"\Z"


def lines(*ls):
    return "".join(x + "\n" for x in ls)


def ssh(host, **kw):
    return dict({"type": "ssh", "host": host}, **kw)


def F(asset, check, severity, **kw):
    return dict({"asset": asset, "check": check, "severity": severity}, **kw)


def host_cases():
    C = "collector-protocol/1.0 / findings/1.2"
    files = {"fake_exec.sh": FAKE_EXEC}
    lin = lines("sshd.passwordauthentication=yes", "sshd.permitrootlogin=yes", "sshd.x11forwarding=yes",
                "sshd.pubkeyauthentication=yes", "os.name=Debian GNU/Linux 13 (trixie)", "os.kernel=6.12.0",
                "reboot_required=yes", "uptime_days=40", "fw.ufw=inactive", "fw.nft_input_policy=",
                "fw.iptables_input_policy=ACCEPT", "disk.crypt_devices=0", "audit.auditd=inactive",
                "listen=0.0.0.0:5432 postgres", "listen=127.0.0.1:6379 redis-server", "listen=[::]:22 sshd",
                "listen=*:9200 java", "pkg.auto_updates=no", "pkg.cache_mtime={epoch:-864000}", "pkg.count=512",
                "pkg.upgradable=12", "pkg.security_upgradable=3", "probe.end=1")
    mac = lines("os.name=macOS 26.1 (25B78)", "disk.filevault=off", "fw.app_firewall=off", "fw.stealth=off", "sip=on",
                "gatekeeper=off", "ssh.remote_login=off", "pkg.auto_install_os=unset", "pkg.auto_security=1",
                "uptime_days=3", "listen=127.0.0.1:5432 postgres", "pkg.brew_outdated=25", "pkg.os_updates_pending=2",
                "probe.end=1")
    router = lines("sshd.passwordauthentication=yes", "sshd.permitrootlogin=yes", "os.name=OpenWrt 24.10",
                   "os.kernel=6.6.0", "telnetd=1", "uptime_days=120", "fw.iptables_input_policy=ACCEPT",
                   "listen=0.0.0.0:53", "listen=0.0.0.0:6379", "probe.end=1")
    phone = lines("sshd.passwordauthentication=no", "os.name=Android 14 (patch 2020-01-05)", "os.security_patch=2020-01-05",
                  "uptime_days=9", "listen=00000000:8022", "listen=00000000:27017", "proc.secret_in_argv_suspects=1",
                  "pkg.cache_mtime=", "pkg.upgradable=4", "probe.end=1")
    inst = {"name": "conformance", "scope": [{"names": ["elsewhere"], "scope": ["k8s"]}], "hosts": [
        {"name": "lin", "profile": "linux", "probe_timeout": 7, "slow_probe_timeout": 30,
         "exec": ssh("lin.test", options=["-o", "StrictHostKeyChecking=no", "-F", "/dev/null"])},
        {"name": "mac", "profile": "macos", "exec": ssh("mac.test")},
        {"name": "router", "profile": "busybox", "exec": ssh("router.test")},
        {"name": "phone", "profile": "termux", "exec": ssh("phone.test")},
        {"name": "dormant", "profile": "linux", "exec": None, "gap": "powered off by design"},
        {"name": "elsewhere", "profile": "linux", "exec": ssh("elsewhere.test")}]}
    findings = [
        F("host:lin", "ssh.password_auth_enabled", "high", layer="identity", remediation="PasswordAuthentication no (keys only)"),
        F("host:lin", "ssh.root_login_password", "high", layer="identity"),
        F("host:lin", "ssh.x11_forwarding", "low", layer="host"),
        F("host:lin", "patch.security_pending", "medium", title="3 security updates pending"),
        F("host:lin", "patch.metadata_stale", "low", title={"$regex": "^package metadata 10 days old"}),
        F("host:lin", "patch.reboot_required", "medium", title={"$regex": r"\(uptime 40d\)$"}),
        F("host:lin", "patch.auto_updates_off", "low"),
        F("host:lin", "fw.host_firewall_off", "medium", layer="network"),
        F("host:lin", "listen.db_wildcard.5432", "medium", layer="network", evidence="raw/host/lin.json"),
        F("host:lin", "listen.db_wildcard.9200", "medium", title={"$regex": r"\(\*:9200 java\)$"}),
        F("host:mac", "macos.disk_filevault_off", "high", needs_human=True, owner="human"),
        F("host:mac", "macos.fw_app_firewall_off", "medium", needs_human=False, owner="platform"),
        F("host:mac", "macos.gatekeeper_off", "high", needs_human=True),
        F("host:mac", "macos.fw_stealth_off", "low"),
        F("host:mac", "patch.os_updates_pending", "medium", title="2 OS updates pending", needs_human=True),
        F("host:mac", "patch.brew_outdated", "low", title="25 Homebrew packages outdated"),
        F("host:router", "ssh.password_auth_enabled", "high"),
        F("host:router", "ssh.root_login_password", "high"),
        F("host:router", "telnet.daemon_running", "high", layer="network"),
        F("host:router", "listen.db_wildcard.6379", "medium"),
        F("host:phone", "patch.pending", "low", title="4 package updates pending"),
        F("host:phone", "patch.android_security_patch_old", "medium", needs_human=True),
        F("host:phone", "secret.in_process_argv", "medium", layer="data-secrets"),
        F("host:phone", "listen.db_wildcard.27017", "medium")]
    trace = {"file": "trace/lin.test.argv", "regex": [argv_regex(*SSH_BASE, "-o", "StrictHostKeyChecking=no", "-F", "/dev/null",
                                                                 "lin.test", "sh -s")]}
    write_case("collector-host", "ssh-targets-findings-and-protocol", {
        "title": "Probe output of linux, macOS, busybox and Termux hosts over ssh becomes the documented findings, "
                 "one coverage entry per configured host (a host without exec adapter is a gap with its configured "
                 "reason, a host scoped to another collector is skipped), ids from (layer, asset, check), the "
                 "wildcard-listener metric; ssh runs non-interactively with host-key checking that instance options "
                 "cannot weaken (first value wins) and the probe limits from the instance in the script",
        "contract": C, "origin": "collectors/host/collector.py; adapters/exec.py SSH.BASE; tests/test_host_probes.py",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": inst}, "data/.keep": {"text": ""}},
                      **replay("lin.test", lin), **replay("mac.test", mac), **replay("router.test", router),
                      **replay("phone.test", phone)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host") + [
                       {"json": "run/host.findings.json", "subset": {
                           "coverage": [{"asset": "host:lin", "status": "ok"}, {"asset": "host:mac", "status": "ok"},
                                        {"asset": "host:router", "status": "ok"}, {"asset": "host:phone", "status": "ok"},
                                        {"asset": "host:dormant", "status": "gap", "reason": "powered off by design"}],
                           "findings": {"$unordered": findings}}},
                       {"prom": "run/host.prom", "has": [
                           {"name": "security_host_wildcard_listeners", "labels": {"host": "lin"}, "value": 3},
                           {"name": "security_host_wildcard_listeners", "labels": {"host": "mac"}, "value": 0},
                           {"name": "security_host_wildcard_listeners", "labels": {"host": "phone"}, "value": 2},
                           {"name": "security_collector_findings", "labels": {"collector": "host", "layer": "network", "severity": "medium"},
                            "value": 5},
                           {"name": "security_collector_gaps", "labels": {"collector": "host"}, "value": 1}]},
                       {"json": "run/raw/host/lin.json", "subset": {"profile": "linux", "rc": 0, "unread": {},
                                                                   "listen": {"$len": 4}, "kv": {"pkg.count": "512"}}},
                       trace,
                       {"file": "trace/lin.test.stdin", "regex": [r"\ASP_PROBE_TIMEOUT=7\nSP_PROBE_SLOW_TIMEOUT=30\n",
                                                                  r"^sp_probe\(\) \{$", r"\necho probe\.end=1\n\Z"]},
                       {"file": "trace/mac.test.stdin", "regex": [r"\ASP_PROBE_TIMEOUT=20\nSP_PROBE_SLOW_TIMEOUT=90\n",
                                                                  "^# host profile: macOS"]},
                       {"absent": "trace/elsewhere.test.argv"}]},
                  {"name": "collect as another name (SP_COLLECTOR_NAME): document, evidence and pointers follow it",
                   "remove": ["run", "trace"],
                   "exec": {"impl": "collector-host", "env": exec_env({"SP_COLLECTOR_NAME": "host-b"})},
                   "expect": [{"json": "run/host-b.findings.json", "schema": "findings", "subset": {
                                  "collector": {"name": "host-b"},
                                  "findings": {"$contains": [{"asset": "host:lin", "check": "listen.db_wildcard.5432",
                                                              "evidence": "raw/host-b/lin.json"}]}}},
                              {"exists": "run/raw/host-b/lin.json"}, {"absent": "run/host.findings.json"}]}]}, files)

    mac_t = mac.replace("pkg.os_updates_pending=2\n", "pkg.os_updates_pending=unknown\nprobe.timeout=pkg.os_updates_pending\n") \
        .replace("fw.app_firewall=off", "fw.app_firewall=on").replace("fw.stealth=off", "fw.stealth=on") \
        .replace("gatekeeper=off", "gatekeeper=on").replace("pkg.brew_outdated=25", "pkg.brew_outdated=2")
    lin_t = lines("sshd.passwordauthentication=yes", "os.name=Debian", "reboot_required=no", "fw.ufw=inactive",
                  "fw.nft_input_policy=unknown", "probe.timeout=fw.nft_input_policy", "fw.iptables_input_policy=ACCEPT",
                  "probe.timeout=listen", "pkg.auto_updates=yes", "pkg.upgradable=0", "pkg.security_upgradable=0",
                  "probe.end=1")
    write_case("collector-host", "timed-out-probe-is-a-narrow-gap", {
        "title": "A probe that did not finish (probe.timeout=KEY) makes only the checks reading KEY unknown: a narrow gap "
                 "host:<name>/<part> listing those checks, the host itself stays covered and every other check reports; a "
                 "finding of a part with one unread key is dropped (a guess is not an observation); a timed-out listener "
                 "probe drops the wildcard-listener metric",
        "contract": C, "origin": "tests/test_host_probes.py::Collector; contracts/collector-protocol §5 (narrow gaps)",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "m", "profile": "macos", "exec": ssh("m.test")},
            {"name": "l", "profile": "linux", "exec": ssh("l.test")}]}}}, **replay("m.test", mac_t), **replay("l.test", lin_t)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host") + [
                       {"json": "run/host.findings.json", "subset": {
                           "coverage": [{"asset": "host:m", "status": "ok"},
                                        {"asset": "host:m/os-updates", "status": "gap", "checks": ["patch.os_updates_pending"],
                                         "reason": {"$regex": r"^m os-updates: could not check \(pkg\.os_updates_pending: did not finish"}},
                                        {"asset": "host:l", "status": "ok"},
                                        {"asset": "host:l/firewall", "status": "gap", "checks": ["fw.host_firewall_off"]},
                                        {"asset": "host:l/listeners", "status": "gap", "checks": ["listen.db_wildcard.*"]}],
                           "findings": {"$unordered": [F("host:m", "macos.disk_filevault_off", "high"),
                                                       F("host:l", "ssh.password_auth_enabled", "high")]}}},
                       {"json": "run/raw/host/m.json", "subset": {"unread": {"pkg.os_updates_pending": "did not finish within its time limit"},
                                                                 "kv": {"pkg.os_updates_pending": {"$absent": True}}}},
                       {"prom": "run/host.prom", "has": [{"name": "security_host_wildcard_listeners", "labels": {"host": "m"}, "value": 0}],
                        "absent": [{"name": "security_host_wildcard_listeners", "labels": {"host": "l"}}]}]}]}, files)

    partial = lines("os.name=macOS 26.1 (25B78)", "disk.filevault=off", "fw.app_firewall=off", "fw.stealth=on", "sip=on")
    write_case("collector-host", "script-timeout-keeps-partial-output", {
        "title": "A profile script stopped by its whole-script limit (script_timeout) keeps the lines it printed: their "
                 "checks report, every probe it never reached is a narrow gap (not reached: rc=124), the job is not "
                 "held up; a host that printed nothing before the limit is a host gap",
        "contract": C, "origin": "tests/test_host_probes.py::test_script_stopped_keeps_partial_output; adapters/exec.py partial",
        "files": dict(fakes("ssh", "sh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "local", "profile": "macos", "script_timeout": 5, "exec": {"type": "local"}},
            {"name": "silent", "profile": "linux", "script_timeout": 5, "exec": ssh("silent.test")}]}}},
            **replay("local-sh", partial, sleep=30), **replay("silent.test", sleep=30)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host", "env": exec_env(), "writes_only_under": ["run", "trace"],
                                               "timeout": 60},
                   "expect": protocol_checks("host") + [
                       {"duration_max": 25},
                       {"json": "run/host.findings.json", "subset": {
                           "coverage": [{"asset": "host:local", "status": "ok"},
                                        {"asset": "host:local/brew", "status": "gap", "checks": ["patch.brew_outdated"]},
                                        {"asset": "host:local/gatekeeper", "status": "gap", "checks": ["macos.gatekeeper_off"],
                                         "reason": {"$regex": r"gatekeeper: not reached: the script was stopped \(rc=124\)"}},
                                        {"asset": "host:local/listeners", "status": "gap", "checks": ["listen.db_wildcard.*"]},
                                        {"asset": "host:local/os-updates", "status": "gap", "checks": ["patch.os_updates_pending"]},
                                        {"asset": "host:silent", "status": "gap", "reason": {"$regex": "^exec failed rc=124: timeout"}}],
                           "findings": {"$unordered": [F("host:local", "macos.disk_filevault_off", "high"),
                                                       F("host:local", "macos.fw_app_firewall_off", "medium")]}}},
                       {"json": "run/raw/host/local.json", "subset": {"rc": 124, "unread": {"$len": 8}}},
                       {"file": "trace/local-sh.argv", "regex": [argv_regex("-s")]},
                       {"prom": "run/host.prom", "absent": [{"name": "security_host_wildcard_listeners"}]}]}]}, files)

    win = (b"sshd.passwordauthentication=yes(default)\r\nsshd.permitrootlogin=n/a\r\n"
           b"os.name=Microsoft Windows 11 Pro \xe9dition 10.0.26100\r\nuptime_days=2\r\nreboot_required=no\r\n"
           b"fw.profile_domain=on\r\nfw.profile_private=off\r\nfw.profile_public=off\r\nav.realtime=off\r\n"
           b"av.signature_age_days=12\r\ndisk.bitlocker=Off\r\nsmb.v1=True\r\nlisten=0.0.0.0:3306 mysqld\r\n"
           b"listen=127.0.0.1:5432 postgres\r\npkg.last_hotfix=2020-01-14\r\nprobe.end=1\r\n")
    write_case("collector-host", "windows-over-ssh", {
        "title": "The Windows profile runs through PowerShell over ssh to a cmd.exe login shell: a fixed -EncodedCommand "
                 "bootstrap reads the script (probe limits in front) from stdin; CRLF output is read as lines, bytes that "
                 "are not UTF-8 are replaced, not fatal; firewall profiles, Defender, BitLocker, SMB1, hotfix age and "
                 "listeners become findings",
        "contract": C, "origin": "adapters/exec.py powershell(); collectors/host/profiles/windows.ps1",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "win", "profile": "windows", "exec": ssh("win.test", shell="windows")}]}}},
            **replay("win.test", raw="win.out")),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host") + [
                       {"json": "run/host.findings.json", "subset": {
                           "coverage": [{"asset": "host:win", "status": "ok"}],
                           "findings": {"$unordered": [
                               F("host:win", "ssh.password_auth_enabled", "high"),
                               F("host:win", "win.fw_profile_private", "high", title="Windows firewall profile private is off"),
                               F("host:win", "win.fw_profile_public", "high", layer="network"),
                               F("host:win", "win.av_realtime_off", "high"),
                               F("host:win", "win.av_signatures_stale", "medium", title="AV signatures 12 days old"),
                               F("host:win", "win.disk_unencrypted", "medium", needs_human=True),
                               F("host:win", "win.smb1_enabled", "high"),
                               F("host:win", "patch.windows_stale", "medium", title="last Windows update installed 2020-01-14"),
                               F("host:win", "listen.db_wildcard.3306", "medium")]}}},
                       {"json": "run/raw/host/win.json", "subset": {"kv": {"os.name": "Microsoft Windows 11 Pro \ufffddition 10.0.26100",
                                                                          "smb.v1": "True"}}},
                       {"file": "trace/win.test.argv", "regex": [r"^powershell -NoProfile -NonInteractive -EncodedCommand [A-Za-z0-9+/]+=*\n\Z"]},
                       {"file": "trace/win.test.stdin", "regex": [r"\A\$SpProbeTimeout = 20\n\$SpProbeSlowTimeout = 90\n",
                                                                  r"\n'probe\.end=1'\n\Z"]}]}]},
        dict(files, **{"win.out": win}))

    bad = win.replace(b"pkg.last_hotfix=2020-01-14", b"pkg.last_hotfix=last Tuesday")
    write_case("collector-host", "one-host-never-fails-the-run", {
        "title": "A host the collector cannot fully evaluate never fails the run (collector-protocol §5): a probe value "
                 "that is not a date is a narrow gap for the checks reading it, a missing exec program (no powershell "
                 "on a local Windows profile) is a host gap; every other host and check still reports",
        "contract": C, "deviation": "COLLECTOR-D2",
        "origin": "collectors/host/collector.py: time.strptime ValueError and FileNotFoundError end the whole run (exit 1)",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "win", "profile": "windows", "exec": ssh("win.test", shell="windows")},
            {"name": "tab", "profile": "termux", "exec": ssh("tab.test")},
            {"name": "nops", "profile": "windows", "exec": {"type": "local"}},
            {"name": "fine", "profile": "busybox", "exec": ssh("fine.test")}]}}},
            **replay("win.test", raw="win.out"),
            **replay("tab.test", lines("os.security_patch=2026-13-45", "proc.secret_in_argv_suspects=1", "probe.end=1")),
            **replay("fine.test", router)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host") + [
                       {"json": "run/host.findings.json", "subset": {
                           "coverage": [{"asset": "host:win", "status": "ok"},
                                        {"asset": "host:win/windows-updates", "status": "gap", "checks": ["patch.windows_stale"],
                                         "reason": {"$regex": "could not check.*pkg.last_hotfix"}},
                                        {"asset": "host:tab", "status": "ok"},
                                        {"asset": "host:tab/android-patch", "status": "gap",
                                         "checks": ["patch.android_security_patch_old"]},
                                        {"asset": "host:nops", "status": "gap", "reason": {"$regex": "^exec failed"}},
                                        {"asset": "host:fine", "status": "ok"}],
                           "findings": {"$contains": [F("host:win", "win.smb1_enabled", "high"),
                                                      F("host:tab", "secret.in_process_argv", "medium"),
                                                      F("host:fine", "telnet.daemon_running", "high")]}}},
                       {"json": "run/host.findings.json", "subset": {"findings": {"$not_contains": [
                           {"check": "patch.windows_stale"}, {"check": "patch.android_security_patch_old"}]}}}]}]},
        dict(files, **{"win.out": bad}))


def sbom_cases():
    C = "collector-protocol/1.0 / inventory/v1"
    files = {"fake_exec.sh": FAKE_EXEC}
    deb = lines("os.family=debian", "os.version=13", "os.codename=trixie", "os.name=Debian GNU/Linux 13 (trixie)",
                "kernel.running=6.12.0-1-amd64", "arch=x86_64",
                "pkg\tdeb\topenssl\t3.5.1-1\topenssl\t3.5.1-1\tamd64",
                "pkg\tdeb\tlibssl3t64\t3.5.1-1\topenssl\t3.5.1-1\tamd64",
                "pkg\tdeb\tbash\t5.2.37-2\t\t\tamd64",
                "pkg\tdeb\t\t1.0\t\t\t", "pkg\tdeb\tshort", "# comment=ignored", " indented=ignored")
    mac = lines("os.family=macos", "os.version=26.1", "os.build=25B78", "os.name=macOS 26.1", "os.rsr=",
                "kernel.running=25.1.0", "arch=arm64", "brew.prefix=/opt/homebrew",
                "pkg\tbrew\tgit\t2.51.0\tgit\t2.51.0\t", "pkg\tbrew-cask\tfirefox\t145.0\tfirefox\t145.0\t")
    rtr = lines("os.family=openwrt", "os.version=24.10.0", "os.name=OpenWrt 24.10.0", "arch=aarch64_cortex-a53",
                "kernel.running=6.6.73", "firmware.vendor=gl-inet", "firmware.version=4.8.1", "firmware.model=GL-EXAMPLE",
                "firmware.build_ts=1700000000", "pkg\topkg\tdropbear\t2024.86-r1\tdropbear\t2024.86-r1\t")
    phone = lines("os.family=android", "os.version=14", "os.name=Android 14", "platform.patch_level=2025-10-01",
                  "platform.vendor_patch_level=2025-09-01", "device.manufacturer=Acme", "device.model=P1",
                  "os.build=AP1A.2510", "kernel.running=5.15.0", "arch=aarch64")
    win = ("os.family=windows\r\nos.name=Microsoft Windows 11 Pro\r\nos.product=Windows 10 Pro\r\nos.edition=Professional\r\n"
           "os.version=24H2\r\nos.build=10.0.26100.4652\r\narch=AMD64\r\n"
           "pkg\twindows-kb\tKB5062553\t2025-07-08\tSecurity Update\t\t\r\n"
           "pkg\twindows-program\t\u00c9diteur Example\t1.2.3\tExample Corp\t\t\r\n").encode()
    inst = {"name": "conformance", "scope": [{"names": ["elsewhere"], "scope": ["host"]}], "hosts": [
        {"name": "deb", "profile": "linux", "exec": ssh("deb.test"), "sbom_paths": ["/opt"]},
        {"name": "mac", "profile": "macos", "exec": ssh("mac.test"), "prod": False},
        {"name": "rtr", "profile": "busybox", "exec": ssh("rtr.test"), "exposed": True},
        {"name": "phone", "profile": "termux", "exec": ssh("phone.test")},
        {"name": "win", "profile": "windows", "exec": ssh("win.test", shell="windows")},
        {"name": "broken", "profile": "linux", "exec": ssh("broken.test")},
        {"name": "skipped", "profile": "linux", "exec": ssh("skipped.test"), "sbom": False},
        {"name": "dormant", "profile": "linux", "exec": None},
        {"name": "elsewhere", "profile": "linux", "exec": ssh("elsewhere.test")}]}
    pk = lambda host, eco, name, ver, src=None, srcver=None, arch="": {  # noqa: E731
        "host": host, "ecosystem": eco, "name": name, "version": ver, "source_name": src or name,
        "source_version": srcver or ver, "arch": arch}
    write_case("collector-host-sbom", "inventory-over-ssh", {
        "title": "Platform facts and package lines of linux, macOS, OpenWrt, Android and Windows hosts become the "
                 "inventory/v1 documents (host-packages, host-platforms) and per-ecosystem metrics; incomplete package "
                 "lines are skipped, a missing source defaults to the package, firmware build time becomes a UTC date; "
                 "no os.family is a gap, no package an info finding, sbom: false skips, sbom_paths needs a local exec "
                 "adapter (narrow fs-sbom gap)",
        "contract": C, "origin": "collectors/host-sbom/collector.py; docs/design.md (inventory/v1)",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": inst}}, **replay("deb.test", deb), **replay("mac.test", mac),
                      **replay("rtr.test", rtr), **replay("phone.test", phone), **replay("win.test", raw="win.out"),
                      **replay("broken.test", "no facts here\n", err="dpkg-query: permission denied\n")),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host-sbom", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host-sbom") + [
                       {"json": "run/host-sbom.findings.json", "subset": {
                           "coverage": [{"asset": "host:deb", "status": "ok"},
                                        {"asset": "host:deb/fs-sbom", "status": "gap", "reason": {"$regex": "local exec adapter"}},
                                        {"asset": "host:mac", "status": "ok"}, {"asset": "host:rtr", "status": "ok"},
                                        {"asset": "host:phone", "status": "ok"}, {"asset": "host:win", "status": "ok"},
                                        {"asset": "host:broken", "status": "gap",
                                         "reason": "inventory failed rc=0: dpkg-query: permission denied"},
                                        {"asset": "host:dormant", "status": "gap", "reason": "no exec adapter configured"}],
                           "findings": [{"check": "sbom.no_packages", "asset": "host:phone", "severity": "info",
                                         "evidence": "raw/host-sbom/phone.json"}]}},
                       {"json": "run/inventory.host-packages.json", "subset": {
                           "schema": "security-platform/inventory/v1", "kind": "host-package",
                           "generated_at": {"$regex": r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$"}, "items": [
                               pk("deb", "deb", "openssl", "3.5.1-1", arch="amd64"),
                               pk("deb", "deb", "libssl3t64", "3.5.1-1", "openssl", arch="amd64"),
                               pk("deb", "deb", "bash", "5.2.37-2", arch="amd64"),
                               pk("mac", "brew", "git", "2.51.0"), pk("mac", "brew-cask", "firefox", "145.0"),
                               pk("rtr", "opkg", "dropbear", "2024.86-r1"),
                               pk("win", "windows-kb", "KB5062553", "2025-07-08", "Security Update"),
                               pk("win", "windows-program", "\u00c9diteur Example", "1.2.3", "Example Corp")]}},
                       {"json": "run/inventory.host-platforms.json", "subset": {"kind": "host-platform", "items": [
                           {"host": "deb", "profile": "linux", "os_family": "debian", "os_codename": "trixie", "package_count": 3,
                            "fs_sbom": None, "firmware": None, "exposed": False, "prod": True, "device": ""},
                           {"host": "mac", "os_build": "25B78", "prod": False, "package_count": 2},
                           {"host": "rtr", "exposed": True, "firmware": {"vendor": "gl-inet", "model": "GL-EXAMPLE",
                                                                          "version": "4.8.1", "build_date": "2023-11-14"}},
                           {"host": "phone", "device": "Acme P1", "patch_level": "2025-10-01", "package_count": 0},
                           {"host": "win", "os_build": "10.0.26100.4652", "os_edition": "Professional", "package_count": 2}]}},
                       {"prom": "run/host-sbom.prom", "has": [
                           {"name": "security_sbom_host_packages", "labels": {"kind": "deb"}, "value": 3},
                           {"name": "security_sbom_host_packages", "labels": {"kind": "windows-program"}, "value": 1},
                           {"name": "security_sbom_hosts", "value": 5}]},
                       {"file": "trace/deb.test.argv", "regex": [argv_regex(*SSH_BASE, "deb.test", "sh -s")]},
                       {"file": "trace/deb.test.stdin", "regex": [r"\A# host-sbom profile: Linux"]},
                       {"absent": "trace/skipped.test.argv"}, {"absent": "trace/elsewhere.test.argv"}]}]},
        dict(files, **{"win.out": win}))

    write_case("collector-host-sbom", "missing-tool-is-a-gap", {
        "title": "A program the collector needs that is not installed never fails the run (collector-protocol §5): "
                 "no trivy for sbom_paths is a narrow fs-sbom gap next to the package inventory, no powershell for a "
                 "local Windows profile is a host gap",
        "contract": C, "deviation": "COLLECTOR-D3",
        "origin": "collectors/host-sbom/collector.py: FileNotFoundError from subprocess ends the whole run (exit 1)",
        "files": dict(fakes("sh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "l", "profile": "linux", "exec": {"type": "local"}, "sbom_paths": ["{sandbox}/apps"]},
            {"name": "w", "profile": "windows", "exec": {"type": "local"}}]}}, "apps/.keep": {"text": ""}},
            **replay("local-sh", deb)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host-sbom", "env": exec_env(), "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("host-sbom") + [
                       {"json": "run/host-sbom.findings.json", "subset": {"coverage": [
                           {"asset": "host:l", "status": "ok"},
                           {"asset": "host:l/fs-sbom", "status": "gap", "reason": {"$regex": "trivy"}},
                           {"asset": "host:w", "status": "gap", "reason": {"$regex": "^inventory failed"}}]}},
                       {"json": "run/inventory.host-platforms.json", "subset": {"items": [{"host": "l", "fs_sbom": None,
                                                                                         "package_count": 3}]}}]}]}, files)


    write_case("collector-host-sbom", "evidence-follows-collector-name", {
        "title": "Under SP_COLLECTOR_NAME the evidence is stored as raw/<that name>/... and every finding points there",
        "contract": C, "deviation": "COLLECTOR-D6",
        "origin": "collectors/host-sbom/collector.py: sbom.no_packages points to raw/host-sbom/<host>.json whatever the name",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "hosts": [
            {"name": "phone", "profile": "termux", "exec": ssh("phone.test")}]}}}, **replay("phone.test", phone)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-host-sbom", "env": exec_env({"SP_COLLECTOR_NAME": "sbom-b"}),
                                               "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("sbom-b") + [
                       {"exists": "run/raw/sbom-b/phone.json"},
                       {"json": "run/sbom-b.findings.json", "subset": {"findings": [
                           {"check": "sbom.no_packages", "asset": "host:phone", "evidence": "raw/sbom-b/phone.json"}]}}]}]},
        files)


def secrets_cases():
    C = "collector-protocol/1.0 / findings/1.2"
    files = {"fake_exec.sh": FAKE_EXEC}
    can = [f"conformance-canary-value-{i:02d}" for i in range(12)]
    home = {
        # the scan only reads the header: no closing line (secret scanners must not take a fixture for a key)
        "home/.ssh/id_conformance": ("-----BEGIN RSA PRIVATE " + "KEY-----\nProc-Type: 4,ENCRYPTED\n" + can[0] + "\n", "0644"),
        "home/work/.env": ("API_TOKEN=" + can[2] + "\nexport X=1\n", "0640"),
        "home/work/.env.example": ("API_TOKEN=\n", "0644"),
        "home/work/node_modules/pkg/.env": ("T=" + can[3] + "\n", "0644"),
        "home/skip/.env": ("T=" + can[3] + "\n", "0644"),
        "home/infra/terraform.tfstate": ('{"resources": [{"password": "' + can[4] + '"}]}\n', "0600"),
        "home/infra/.terraform/terraform.tfstate": ('{"backend": "' + can[4] + '"}\n', "0600"),
        "home/.docker/config.json": ('{"auths": {"registry.example": {"auth": "' + can[5] + '"}}}\n', "0600"),
        "home/.config/gh/hosts.yml": ("github.com:\n    oauth_token: " + can[6] + "\n", "0600"),
        "home/.config/rclone/rclone.conf": ("[remote]\ntype = s3\nsecret_access_key = " + can[7] + "\n", "0600"),
        "home/.kube/config": ("apiVersion: v1\nclusters:\n- cluster: {server: https://k.example}\nusers:\n- user:\n"
                              "    client-key-data: " + can[8] + "\n", "0644"),
        "home/notes/MEMORY.md": ("the db password: " + can[9] + "\nstored in the vault, value not written here\n", "0600"),
        "home/.netrc": ("machine example login u password " + can[10] + "\n", "0600"),
        "home/.secrets/db": (can[11] + "\n", "0600"),
    }
    fx = {k: {"text": t, "mode": m} for k, (t, m) in home.items()}
    write_case("collector-secrets-files", "metadata-only-local-scan", {
        "title": "Where secrets live, never what they are: a local scan of a fixture home records kind, mode, size and "
                 "properties of private keys, dotenv, Terraform state, docker/gh/rclone/kube configs, netrc, secret files "
                 "and credential-like notes (excluded directories and example files skipped), raises the documented "
                 "findings and metrics, and no byte of any file's content reaches the run directory or the output",
        "contract": C, "origin": "collectors/secrets-files/collector.py + remote/scan.py; docs/threat-model.md (values never stored)",
        "files": dict({"instance.json": {"json": {"name": "conformance", "secrets_files": [
            {"host": "lab", "exec": {"type": "local"}, "roots": ["~"], "exclude": ["~/skip"], "python": "{python}"}]}}}, **fx),
        "steps": [{"name": "collect", "exec": {"impl": "collector-secrets-files", "env": exec_env(), "writes_only_under": ["run"]},
                   "expect": protocol_checks("secrets-files", canaries=can) + [
                       {"json": "run/secrets-files.findings.json", "subset": {
                           "coverage": [{"asset": "host:lab", "status": "ok"}],
                           "findings": {"$unordered": [
                               F("secret-file:lab:~/.ssh/id_conformance", "secret.permissions_too_open", "high",
                                 title="private-key readable by group/others (mode 0o644)",
                                 evidence="raw/secrets-files/lab.json#~/.ssh/id_conformance"),
                               F("secret-file:lab:~/work/.env", "secret.permissions_too_open", "medium"),
                               F("secret-file:lab:~/infra/terraform.tfstate", "secret.tf_state_plaintext", "medium"),
                               F("secret-file:lab:~/.docker/config.json", "secret.docker_inline_auth", "medium"),
                               F("secret-file:lab:~/.config/gh/hosts.yml", "secret.gh_token_in_file", "medium"),
                               F("secret-file:lab:~/.config/rclone/rclone.conf", "secret.rclone_config_plaintext", "medium"),
                               F("secret-file:lab:~/.kube/config", "secret.permissions_too_open", "high"),
                               F("secret-file:lab:~/.kube/config", "secret.kubeconfig_embedded_client_key", "medium"),
                               F("secret-file:lab:~/notes/MEMORY.md", "secret.credential_in_notes", "high", layer="ai-agents",
                                 title={"$regex": "^1 line"})]}}},
                       {"json": "run/raw/secrets-files/lab.json", "subset": {"$contains": [
                           {"path": "~/work/.env", "kind": "dotenv", "mode": "0o640", "vars": 1},
                           {"path": "~/.ssh/id_conformance", "kind": "private-key", "passphrase": True, "format": "pem"},
                           {"path": "~/.secrets/db", "kind": "secret-file", "mode": "0o600"}]}},
                       {"json": "run/raw/secrets-files/lab.json", "subset": {"$not_contains": [
                           {"path": "~/skip/.env"}, {"path": "~/work/.env.example"}, {"path": "~/work/node_modules/pkg/.env"},
                           {"path": "~/infra/.terraform/terraform.tfstate"}]}},
                       {"prom": "run/secrets-files.prom", "has": [
                           {"name": "security_secrets_total", "labels": {"store": "files:lab"}, "value": 9},
                           {"name": "security_secrets_older_than_90d", "labels": {"store": "files:lab"}, "value": 0}]}]}]})

    write_case("collector-secrets-files", "sudo-refused-falls-back", {
        "title": "sudo: true runs the scan through `sudo -n` (never a prompt); when sudo refuses, the scan runs again "
                 "unprivileged and the privileged paths become a gap (host:<name>/privileged-paths); the scan settings go "
                 "to the target as one JSON argument and the scan program on stdin",
        "contract": C, "origin": "collectors/secrets-files/collector.py (sudo fallback)",
        "files": dict(fakes("sudo"), **{"instance.json": {"json": {"name": "conformance", "secrets_files": [
            {"host": "lab", "exec": {"type": "local"}, "roots": ["~/work"], "sudo": True, "maxdepth": 3,
             "python": "{python}"}]}},
            "home/work/.env": {"text": "A=" + can[2] + "\n", "mode": "0600"}},
            **replay("local-sudo", err="sudo: a password is required\n", rc=1)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-secrets-files", "env": exec_env(),
                                               "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("secrets-files", canaries=can[2:3]) + [
                       {"json": "run/secrets-files.findings.json", "subset": {"coverage": [
                           {"asset": "host:lab/privileged-paths", "status": "gap", "reason": "sudo -n not available; privileged paths skipped"},
                           {"asset": "host:lab", "status": "ok"}], "findings": []}},
                       {"file": "trace/local-sudo.argv", "regex": [
                           r"\A-n\n", r"^-c\nimport sys;exec\(sys\.stdin\.buffer\.read\(\)\.decode\('utf-8'\)\)\n"
                                      r'\{"roots": \["~/work"\], "exclude": \[\], "maxdepth": 3\}\n\Z']},
                       {"file": "trace/local-sudo.stdin", "regex": [r"\A\"\"\"Runs on the target host", r"^print\(json\.dumps"]}]}]},
        files)

    def item(path, kind, mode="0o600", age_days=1, **kw):
        return dict({"path": path, "kind": kind, "mode": mode, "uid": 1000, "size": 100,
                     "mtime": "{epoch:-%d}" % (age_days * 86400)}, **kw)

    def scan_json(home_dir, items):  # mtime templates become numbers once the harness renders the fixture
        return "warning: one line of noise before the result\n" + json.dumps({"home": home_dir, "items": items}).replace(
            '"{epoch:', "{epoch:").replace('}"', "}") + "\n"

    srv = [item("/home/u/.ssh/id_ed25519", "private-key", age_days=100, format="openssh", passphrase=False, type="ssh-ed25519"),
           item("/etc/ssh/ssh_host_ed25519_key", "private-key", age_days=400, uid=0, format="openssh", passphrase=False,
                type="ssh-ed25519"),
           item("/home/u/.kube/config", "kubeconfig", "0o644", embedded_client_key=False, token_auth=False),
           item("/home/u/.kube/admin.yaml", "kubeconfig", "0o644", embedded_client_key=False, token_auth=True),
           item("/home/u/.config/rclone/rclone.conf", "rclone-config", encrypted=True),
           item("/home/u/backup/.env.prod", "dotenv", "0o604", age_days=200, vars=3),
           item("/home/u/age/keys.txt", "age-key", "0o640"),
           item("/home/u/x.pem", "private-key", "0o640", format="pem", passphrase=True),
           item("/home/u/infra/prod.tfstate", "tf-state", "0o644", encrypted=True)]
    winitems = [item("C:\\Users\\u\\.ssh\\id_rsa", "private-key", "unknown", format="openssh", passphrase=True),
                item("C:\\Users\\u\\.aws\\deploy.token", "secret-file", "0o644", acl=["S-1-5-32-545"])]
    loader = "import sys;exec(sys.stdin.buffer.read().decode('utf-8'))"
    write_case("collector-secrets-files", "replay-over-ssh", {
        "title": "Scan results from remote POSIX and Windows targets (the last output line is the result): ~ for the "
                 "home, / separators, ages from mtime, severities from mode bits and properties (encrypted lowers, "
                 "world-readable raises), host keys exempt from the passphrase finding, unreadable permissions a "
                 "narrow gap, an unreachable target or one without exec adapter a host gap; argv quoted for the "
                 "remote POSIX shell or cmd.exe",
        "contract": C, "origin": "collectors/secrets-files/collector.py; adapters/exec.py SSH quoting",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance",
                                                                    "scope": [{"names": ["elsewhere"], "scope": ["host"]}],
                                                                    "secrets_files": [
            {"host": "srv", "exec": ssh("srv.test"), "roots": ["~", "/etc/ssh"], "exclude": ["~/old"], "sudo": True},
            {"host": "win", "exec": ssh("win.test", shell="windows"), "roots": ["~"], "python": "C:\\Python312\\python.exe"},
            {"host": "down", "exec": ssh("down.test"), "roots": ["~"]},
            {"host": "nox", "exec": None, "roots": ["~"]},
            {"host": "elsewhere", "exec": ssh("elsewhere.test"), "roots": ["~"]}]}}},
            **replay("srv.test.sudo", scan_json("/home/u", srv)), **replay("win.test", scan_json("C:\\Users\\u", winitems)),
            **replay("down.test", err="ssh: connect to host down.test port 22: Connection refused\n", rc=255)),
        "steps": [{"name": "collect", "exec": {"impl": "collector-secrets-files", "env": exec_env(),
                                               "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("secrets-files") + [
                       {"json": "run/secrets-files.findings.json", "subset": {
                           "coverage": [{"asset": "host:srv", "status": "ok"},
                                        {"asset": "host:win", "status": "ok"},
                                        {"asset": "secret-file:win:~/.ssh/id_rsa/permissions", "status": "gap",
                                         "reason": "file permissions could not be read"},
                                        {"asset": "host:down", "status": "gap",
                                         "reason": "scan failed rc=255: ssh: connect to host down.test port 22: Connection refused"},
                                        {"asset": "host:nox", "status": "gap", "reason": "no exec adapter"}],
                           "findings": {"$unordered": [
                               F("secret-file:srv:~/.ssh/id_ed25519", "secret.ssh_key_no_passphrase", "medium",
                                 title="private key without passphrase (ssh-ed25519, 100d old)", needs_human=True),
                               F("secret-file:srv:~/.ssh/id_ed25519", "secret.age_over_90d", "low",
                                 title="private-key unchanged for 100 days (rotation unknown)"),
                               F("secret-file:srv:/etc/ssh/ssh_host_ed25519_key", "secret.age_over_90d", "medium"),
                               F("secret-file:srv:~/.kube/admin.yaml", "secret.permissions_too_open", "high"),
                               F("secret-file:srv:~/backup/.env.prod", "secret.permissions_too_open", "high"),
                               F("secret-file:srv:~/backup/.env.prod", "secret.age_over_90d", "low"),
                               F("secret-file:srv:~/age/keys.txt", "secret.permissions_too_open", "medium"),
                               F("secret-file:srv:~/x.pem", "secret.permissions_too_open", "medium"),
                               F("secret-file:srv:~/infra/prod.tfstate", "secret.permissions_too_open", "low",
                                 title="tf-state (encrypted) readable by group/others (mode 0o644)"),
                               F("secret-file:win:~/.aws/deploy.token", "secret.permissions_too_open", "high",
                                 evidence="raw/secrets-files/win.json#~/.aws/deploy.token")]}}},
                       {"prom": "run/secrets-files.prom", "has": [
                           {"name": "security_secrets_total", "labels": {"store": "files:srv"}, "value": 9},
                           {"name": "security_secrets_older_than_90d", "labels": {"store": "files:srv"}, "value": 3},
                           {"name": "security_secrets_total", "labels": {"store": "files:win"}, "value": 2}],
                        "absent": [{"name": "security_secrets_total", "labels": {"store": "files:down"}}]},
                       {"file": "trace/srv.test.sudo.argv", "regex": [argv_regex(*SSH_BASE, "srv.test",
                           "sudo -n python3 -c '" + loader.replace("'", "'\"'\"'") + "' "
                           "'{\"roots\": [\"~\", \"/etc/ssh\"], \"exclude\": [\"~/old\"], \"maxdepth\": 5}'")]},
                       {"file": "trace/win.test.argv", "regex": [argv_regex(*SSH_BASE, "win.test",
                           'C:\\Python312\\python.exe -c "' + loader + '" '
                           '"{\\"roots\\": [\\"~\\"], \\"exclude\\": [], \\"maxdepth\\": 5}"')]},
                       {"absent": "trace/elsewhere.test.argv"}]}]}, files)

    good = [item("/home/u/.ssh/id_rsa", "private-key", "0o644", format="pem", passphrase=True)]
    write_case("collector-secrets-files", "unreadable-scan-output-is-a-gap", {
        "title": "A target whose scan cannot be read never fails the run (collector-protocol §5): output that is not "
                 "the scan result, no output at all, or an interpreter that does not exist is a gap for that host; the "
                 "other hosts report",
        "contract": C, "deviation": "COLLECTOR-D4",
        "origin": "collectors/secrets-files/collector.py: json.loads / IndexError / FileNotFoundError end the whole run (exit 1)",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "secrets_files": [
            {"host": "bad", "exec": ssh("bad.test"), "roots": ["~"]},
            {"host": "empty", "exec": ssh("empty.test"), "roots": ["~"]},
            {"host": "nopy", "exec": {"type": "local"}, "roots": ["~"], "python": "{sandbox}/missing/python3"},
            {"host": "good", "exec": ssh("good.test"), "roots": ["~"]}]}}},
            **replay("bad.test", "Traceback (most recent call last):\nSyntaxError: invalid syntax\n"),
            **replay("good.test", scan_json("/home/u", good))),
        "steps": [{"name": "collect", "exec": {"impl": "collector-secrets-files", "env": exec_env(),
                                               "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("secrets-files") + [
                       {"json": "run/secrets-files.findings.json", "subset": {
                           "coverage": [{"asset": "host:bad", "status": "gap", "reason": {"$regex": "^scan output unreadable"}},
                                        {"asset": "host:empty", "status": "gap", "reason": {"$regex": "^scan output unreadable"}},
                                        {"asset": "host:nopy", "status": "gap", "reason": {"$regex": "^scan failed"}},
                                        {"asset": "host:good", "status": "ok"}],
                           "findings": [F("secret-file:good:~/.ssh/id_rsa", "secret.permissions_too_open", "high")]}}]}]},
        files)

    pfx = [item("/home/u/.ssh/id_rsa", "private-key", "0o644", format="pem", passphrase=True),
           item("/backup/home/u/.ssh/id_rsa", "private-key", "0o644", format="pem", passphrase=True),
           item("/home/u2/.env", "dotenv", "0o644", vars=1)]
    write_case("collector-secrets-files", "home-replaced-only-as-prefix", {
        "title": "The target's home directory becomes ~ only where a path starts with it (whole path components): a "
                 "copy of the home elsewhere or a home whose name merely starts the same keeps its full path",
        "contract": C, "deviation": "COLLECTOR-D5",
        "origin": "collectors/secrets-files/collector.py: str.replace(home, '~', 1) replaces the first occurrence anywhere",
        "files": dict(fakes("ssh"), **{"instance.json": {"json": {"name": "conformance", "secrets_files": [
            {"host": "h", "exec": ssh("h.test"), "roots": ["/"]}]}}}, **replay("h.test", scan_json("/home/u", pfx))),
        "steps": [{"name": "collect", "exec": {"impl": "collector-secrets-files", "env": exec_env(),
                                               "writes_only_under": ["run", "trace"]},
                   "expect": protocol_checks("secrets-files") + [
                       {"json": "run/secrets-files.findings.json", "subset": {"findings": {"$unordered": [
                           F("secret-file:h:~/.ssh/id_rsa", "secret.permissions_too_open", "high"),
                           F("secret-file:h:/backup/home/u/.ssh/id_rsa", "secret.permissions_too_open", "high"),
                           F("secret-file:h:/home/u2/.env", "secret.permissions_too_open", "high")]}}}]}]}, files)

COLLECTOR_CASE_MODULES = ("collector_k8s", "collector_vuln_intel", "collector_identity")


def main(argv=None):
    import argparse
    global CASES
    ap = argparse.ArgumentParser(description="write the conformance cases")
    ap.add_argument("--out", default=CASES, help="cases directory (default: conformance/cases)")
    CASES = ap.parse_args(argv).out
    ledger_cases()
    remediation_cases()
    scorecard_cases()
    runner_cases()
    cli_cases()
    collector_cases()
    host_cases()
    sbom_cases()
    secrets_cases()
    import types
    helpers = types.SimpleNamespace(write_case=write_case, collector_env=collector_env, protocol_checks=protocol_checks)
    for module in COLLECTOR_CASE_MODULES:          # one module per collector: conformance/tools/collector_<name>.py
        importlib.import_module(module).cases(helpers)
    print(f"{len(OWNED)} cases written")


if __name__ == "__main__":
    main()
