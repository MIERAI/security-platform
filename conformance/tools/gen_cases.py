#!/usr/bin/env python3
"""Generates conformance/cases/<component>/<case>/ (case.json + fixtures). The generated files are the suite; this
script only keeps the shared fixture builders in one place. Re-run after editing: python3 conformance/tools/gen_cases.py
(it rewrites every case directory it owns and leaves others alone). Stdlib only; imports nothing from the product."""
import calendar
import hashlib
import json
import os
import shutil
import time

CASES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cases")
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
# cli (contract cli/1.0): sp <command> --data D [--instance F]
# ==================================================================================================================
def sp(args, expect, exit_=0, name=None, env=None):
    st = {"name": name or "sp " + " ".join(args), "exec": {"impl": "cli", "args": args}, "exit": exit_, "expect": expect}
    if env:
        st["exec"]["env"] = env
    return st


def cli_cases():
    C = "cli/1.0"
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
    print(f"{len(OWNED)} cases written")


if __name__ == "__main__":
    main()
