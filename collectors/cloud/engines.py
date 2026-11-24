"""Check engines and native-service importers of the `cloud` collector: one interface, many tools.

  ENGINES[name](prov, env, args, ecfg, workdir) -> Run      run an external scanner READ-ONLY, parse its output
  IMPORTERS[type](doc) -> [Result]                          parse an export of a provider's own posture service

A Result is one (resource, check) verdict in a tool-neutral shape:
  {source, provider, account, service, region, resource (canonical id: ARN / resource name / resource id), check
   (the tool's own id), control (generic id or None), status FAIL|PASS, severity, title, detail, refs, remediation}
The collector normalises the resource into an asset, maps the check onto a generic control (controls.py) and merges
equal (asset, control) pairs from different sources into one finding.

Engines are EXTERNAL PROCESSES only: Prowler (Apache-2.0), Steampipe (AGPL-3.0) and ScoutSuite (GPL-2.0) are never
imported, vendored or linked; this module only starts them and reads their documented output (docs/cloud.md).
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import controls  # noqa: E402
import steampipe_queries  # noqa: E402

SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info", "info": "info",
       "danger": "high", "warning": "medium", "moderate": "medium"}
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def seconds(v, default):
    if v is None:
        return default
    m = re.fullmatch(r"(\d+)([smhd]?)", str(v).strip())
    return int(m.group(1)) * UNITS.get(m.group(2) or "s", 1) if m else default


class Run:
    def __init__(self, engine):
        self.engine, self.results, self.errors, self.scope, self.ok, self.reason, self.version = engine, [], {}, set(), False, "", ""

    def error(self, service, msg):
        self.errors.setdefault(service, []).append(msg[:200])

    def gap_services(self):
        """Services that had errors AND gave no verdict at all: the listing itself failed (an error on a secondary
        call of a service that still returned verdicts is kept as evidence, not a gap)."""
        seen = {r["service"] for r in self.results}
        return {s: e for s, e in self.errors.items() if s not in seen and (not self.scope or s in self.scope)}


def _expand(p):
    return os.path.expanduser(str(p)) if p else p


def _run(argv, env, cwd, timeout):
    try:
        r = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{os.path.basename(argv[0])} not installed"
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"


def cis_refs(provider, compliance):
    """Prowler's `unmapped.compliance` {"CIS-3.0": ["5.2"], ...} -> ["cis-aws:3.0/5.2", ...] (CIS benchmarks only)."""
    out = []
    for fw, ids in sorted((compliance or {}).items()):
        m = re.fullmatch(r"CIS-([0-9.]+)", fw)
        if m:
            out += [f"cis-{provider}:{m.group(1)}/{i}" for i in ids]
    return out


# ---- Prowler ---------------------------------------------------------------------------------------------------
def parse_prowler_ocsf(doc, provider=None):
    """Prowler's json-ocsf output (a list of OCSF Detection Finding events) -> Results. MANUAL and muted are skipped."""
    out = []
    for x in doc:
        status = x.get("status_code")
        if status not in ("FAIL", "PASS") or x.get("status") == "Suppressed":
            continue
        res = (x.get("resources") or [{}])[0]
        cloud = x.get("cloud") or {}
        prov = provider or cloud.get("provider") or (x.get("unmapped") or {}).get("provider", "")
        check = (x.get("metadata") or {}).get("event_code") or (x.get("finding_info") or {}).get("uid", "")
        out.append({
            "source": "prowler", "provider": prov, "account": str((cloud.get("account") or {}).get("uid") or ""),
            "service": (res.get("group") or {}).get("name") or check.split("_")[0], "region": res.get("region") or "global",
            "resource": res.get("uid") or res.get("name") or "", "name": res.get("name") or "", "check": check,
            "control": controls.control_for("prowler", check), "status": status,
            "severity": SEV.get(str(x.get("severity", "")).lower(), "medium"),
            "title": (x.get("finding_info") or {}).get("title", check), "detail": x.get("status_detail") or x.get("message") or "",
            "refs": cis_refs(prov, (x.get("unmapped") or {}).get("compliance")),
            "remediation": ((x.get("remediation") or {}).get("desc") or "")[:300]})
    return out


def prowler_errors(log_text):
    """Prowler's --log-file (JSON lines) -> {service: [messages]} for errors raised by a service client."""
    errs = {}
    for line in log_text.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        mod = d.get("module", "")
        if d.get("level") in ("ERROR", "CRITICAL") and mod.endswith("_service"):
            errs.setdefault(mod[: -len("_service")], []).append(re.sub(r"\s+", " ", d.get("message", ""))[:200])
    return errs


def prowler(prov, env, args, ecfg, workdir):
    run = Run("prowler")
    out = os.path.join(workdir, "prowler")
    os.makedirs(out, exist_ok=True)
    argv = [_expand(ecfg.get("path", "prowler")), prov.kind]
    if prov.kind == "aws":
        argv += ["--profile", args["profile"], "--region", *args["regions"]]
    elif prov.kind == "gcp":
        argv += ["--project-id", *args["projects"]]
    elif prov.kind == "azure":
        argv += ["--managed-identity-auth", "--subscription-ids", *args["subscriptions"]]
    if ecfg.get("checks"):
        argv += ["--checks", *ecfg["checks"]]
        run.scope = {c.split("_")[0] for c in ecfg["checks"]}
    elif ecfg.get("services"):
        argv += ["--services", *ecfg["services"]]
        run.scope = set(ecfg["services"])
    if ecfg.get("excluded_checks"):
        argv += ["--excluded-checks", *ecfg["excluded_checks"]]
    if ecfg.get("scan_unused_services", True):
        argv += ["--scan-unused-services"]
    argv += ["--output-formats", "json-ocsf", "-o", out, "-F", "scan", "--no-banner", "--log-level", "ERROR",
             "--log-file", os.path.join(out, "prowler.log"), "--ignore-exit-code-3"] + list(ecfg.get("extra_args") or [])
    rc, so, se = _run(argv, env, workdir, seconds(ecfg.get("timeout"), 3 * 3600))
    p = os.path.join(out, "scan.ocsf.json")
    if rc != 0 or not os.path.exists(p):
        run.reason = f"prowler rc={rc}: " + (se.strip().splitlines() or so.strip().splitlines() or [""])[-1][:200]
        return run
    doc = json.load(open(p))
    run.results = parse_prowler_ocsf(doc, prov.kind)
    if doc:
        run.version = ((doc[0].get("metadata") or {}).get("product") or {}).get("version", "")
    lp = os.path.join(out, "prowler.log")
    run.errors = prowler_errors(open(lp).read()) if os.path.exists(lp) else {}
    run.ok = True
    return run


# ---- Steampipe -------------------------------------------------------------------------------------------------
def steampipe(prov, env, args, ecfg, workdir):
    """Our own query pack (steampipe_queries.py) through `steampipe query --output json --search-path sp_<provider>`.
    Steampipe v2 reads connections only from <install_dir>/config, so the run writes its connection
    (`security-platform-<provider>.spc`: profile name, regions, endpoint - no secret) there and removes it afterwards;
    the install dir is the platform's own (render.py tool-env). Credentials come from engine_env (credential_process)."""
    run = Run("steampipe")
    queries = steampipe_queries.QUERIES.get(prov.kind)
    if not queries:
        run.reason = f"steampipe: no query pack for {prov.kind}"
        return run
    if ecfg.get("queries"):
        queries = [q for q in queries if q["id"] in ecfg["queries"]]
    home = _expand(ecfg.get("install_dir") or "~/.steampipe")
    exe = _expand(ecfg.get("path", "steampipe"))
    region, conn_name = args["regions"][0], f"sp_{prov.kind}"
    conn = [f'connection "{conn_name}" {{', f'  plugin = "{ecfg.get("plugin", prov.kind)}"',
            f'  profile = "{args["profile"]}"', "  regions = [" + ", ".join(f'"{r}"' for r in args["regions"]) + "]",
            "  max_error_retry_attempts = 2"]
    if env.get("AWS_ENDPOINT_URL"):
        conn += [f'  endpoint_url = "{env["AWS_ENDPOINT_URL"]}"', "  s3_force_path_style = true"]
    spc = os.path.join(home, "config", f"security-platform-{prov.kind}.spc")
    env = dict(env, STEAMPIPE_INSTALL_DIR=home, STEAMPIPE_UPDATE_CHECK="false", STEAMPIPE_TELEMETRY="none")
    # its plugin manager talks over unix sockets in TMPDIR: a long TMPDIR exceeds the socket path limit (104 bytes on
    # macOS) and the plugin never starts. Use a short private directory for this run.
    short_tmp = None
    if len(env.get("TMPDIR", tempfile.gettempdir())) > 40:
        short_tmp = tempfile.mkdtemp(prefix="sp-sp-", dir="/tmp" if os.path.isdir("/tmp") else None)
        env["TMPDIR"] = short_tmp
    rc, so, se = _run([exe, "--version"], env, workdir, 60)
    if rc != 0:
        run.reason = f"steampipe unavailable: {(se or so).strip()[:160]}"
        if short_tmp:
            shutil.rmtree(short_tmp, ignore_errors=True)
        return run
    run.version = so.strip().split()[-1].lstrip("v") if so.strip() else ""
    run.scope = {q["service"] for q in queries}
    timeout = seconds(ecfg.get("timeout"), 600)
    failed = 0
    try:
        os.makedirs(os.path.dirname(spc), exist_ok=True)
        with open(spc, "w") as f:
            f.write("# written by security-platform for one run; removed afterwards\n" + "\n".join(conn + ["}"]) + "\n")
        for q in queries:
            rc, so, se = _run([exe, "query", "--output", "json", "--search-path", conn_name,
                               q["sql"].replace("{region}", region)], env, workdir, timeout)
            err = [ln for ln in (se + "\n" + so).splitlines() if ln.startswith(("Error:", "Warning: query"))]
            try:
                rows = json.loads(so[so.index("{"):]).get("rows") if "{" in so else None
            except ValueError:
                rows = None
            if rc != 0 or err or rows is None:
                run.error(q["service"], f"{q['id']}: " + (err[0] if err else f"rc={rc}")[:180])
                failed += 1
                continue
            run.results.append({"source": "steampipe", "provider": prov.kind, "account": prov.account,
                                "service": q["service"], "region": region, "resource": "", "check": q["id"],
                                "control": q["control"], "status": "PASS", "severity": "info", "title": q["id"],
                                "detail": "query ran", "refs": [], "remediation": "", "coverage_only": True})
            for r in rows or []:
                run.results.append({
                    "source": "steampipe", "provider": prov.kind, "account": str(r.get("account_id") or prov.account),
                    "service": q["service"], "region": r.get("region") or "global", "resource": r.get("arn") or "",
                    "name": "", "check": q["id"], "control": q["control"], "status": "FAIL", "severity": q["severity"],
                    "title": q["id"], "detail": str(r.get("detail") or ""), "refs": [], "remediation": ""})
    finally:
        try:
            os.remove(spc)
        except OSError:
            pass
        if short_tmp:
            shutil.rmtree(short_tmp, ignore_errors=True)
    run.ok = failed < len(queries)
    if not run.ok:
        run.reason = "steampipe: every query failed: " + "; ".join(e[0] for e in run.errors.values())[:200]
    return run


# ---- ScoutSuite -----------------------------------------------------------------------------------------------
ARN_TYPE = {"security_groups": "security-group", "volumes": "volume", "snapshots": "snapshot", "instances": "instance",
            "buckets": None, "users": "user", "roles": "role", "trails": "trail", "firewalls": None,
            "storage_accounts": None, "network_security_groups": None}


def scout_arn(provider, svc, region, account, coll, rid):
    """AWS: the ARN other engines report for the same resource (so findings merge); others: the resource id."""
    if provider != "aws" or coll not in ARN_TYPE:
        return rid
    if svc == "s3":
        return f"arn:aws:s3:::{rid}"
    if svc == "iam":
        return f"arn:aws:iam::{account}:{ARN_TYPE[coll]}/{rid}"
    return f"arn:aws:{svc}:{region if region != 'global' else ''}:{account}:{ARN_TYPE[coll]}/{rid}"


ITEM_ID = re.compile(r"^(?P<svc>[a-z0-9]+)\.(?:regions\.(?P<region>[^.]+)\.)?(?:.*\.)?(?P<coll>[a-z_]+)\.(?P<id>[^.]+)")


def _scout_resource(doc, parts):
    """The resource object an item path points into: services.<svc>....<collection>.<id> -> (collection, id, obj)."""
    node, coll = doc.get("services") or {}, None
    for i, p in enumerate(parts):
        if not isinstance(node, dict) or p not in node:
            break
        if p in ARN_TYPE and i + 1 < len(parts) and isinstance(node[p], dict) and parts[i + 1] in node[p]:
            return p, parts[i + 1], node[p][parts[i + 1]]
        node = node[p]
    return coll, parts[-1], {}


def parse_scoutsuite(doc, provider, account):
    """ScoutSuite's results object (scoutsuite_results_<provider>-<id>.js, `scoutsuite_results = {...}`): flagged
    items of every finding rule -> Results. Item paths point into the object (<service>.regions.<r>.<...>.<collection>.
    <internal id>); the resource's own `arn`/`name` there gives the canonical id other engines use."""
    out = []
    for svc, s in sorted((doc.get("services") or {}).items()):
        for rule, f in sorted((s.get("findings") or {}).items()):
            items = f.get("items") or []
            refs = [f"cis-{provider}:{c.get('version')}/{c.get('reference')}" for c in f.get("compliance") or []
                    if "CIS" in str(c.get("name", ""))]
            if not items and f.get("checked_items"):
                out.append({"source": "scoutsuite", "provider": provider, "account": account, "service": svc,
                            "region": "global", "resource": "", "check": rule, "control": controls.control_for("scoutsuite", rule),
                            "status": "PASS", "severity": "info", "title": f.get("description", rule), "detail": "",
                            "refs": refs, "remediation": "", "coverage_only": True})
            for it in items:
                m = ITEM_ID.match(it)
                parts = it.split(".")
                region = m.group("region") if m and m.group("region") else "global"
                coll, rid, obj = _scout_resource(doc, parts)
                name = obj.get("name") or rid
                arn = obj.get("arn") if str(obj.get("arn", "")).startswith("arn:") and svc != "s3" else None
                out.append({"source": "scoutsuite", "provider": provider, "account": account, "service": svc,
                            "region": region, "resource": arn or scout_arn(provider, svc, region, account, coll, name),
                            "name": name, "check": rule, "control": controls.control_for("scoutsuite", rule), "status": "FAIL",
                            "severity": SEV.get(str(f.get("level", "")).lower(), "medium"),
                            "title": f.get("description", rule), "detail": it[:200], "refs": refs,
                            "remediation": (f.get("remediation") or "")[:300]})
    return out


def scoutsuite_blind_services(doc):
    """Services in which ScoutSuite checked nothing at all (it could not list them; or they are empty)."""
    return sorted(svc for svc, s in (doc.get("services") or {}).items()
                  if (s.get("findings") or {}) and not any(f.get("checked_items") for f in s["findings"].values()))


def scoutsuite(prov, env, args, ecfg, workdir):
    run = Run("scoutsuite")
    out = os.path.join(workdir, "scoutsuite")
    argv = [_expand(ecfg.get("path", "scout")), prov.kind, "--no-browser", "--report-dir", out, "--force", "--quiet"]
    if prov.kind == "aws":
        argv += ["--profile", args["profile"], "--regions", *args["regions"]]
    elif prov.kind == "gcp":
        argv += ["--user-account", "--project-id", args["projects"][0]]     # application default = external account
    elif prov.kind == "azure":
        argv += ["--msi", "--subscriptions", *args["subscriptions"]]
    if ecfg.get("services"):
        argv += ["--services", *ecfg["services"]]
        run.scope = set(ecfg["services"])
    rc, so, se = _run(argv + list(ecfg.get("extra_args") or []), env, workdir, seconds(ecfg.get("timeout"), 3 * 3600))
    files = glob.glob(os.path.join(out, "scoutsuite-results", "scoutsuite_results_*.js"))
    if not files:
        run.reason = f"scoutsuite rc={rc}: " + ((se or so).strip().splitlines() or [""])[-1][:200]
        return run
    text = open(files[0]).read()
    doc = json.loads(text[text.index("{"):])
    run.results = parse_scoutsuite(doc, prov.kind, prov.account)
    run.version = str(doc.get("last_run", {}).get("version", ""))
    for svc in scoutsuite_blind_services(doc):
        run.error(svc, f"scoutsuite checked no {svc} resources")
    run.stderr_errors = sum(1 for ln in (se or "").splitlines() if " ERROR " in ln)   # evidence only
    run.ok = True
    return run


ENGINES = {"prowler": prowler, "steampipe": steampipe, "scoutsuite": scoutsuite}


# ---- native posture services (exports) -------------------------------------------------------------------------
def securityhub(doc):
    """AWS Security Hub findings in ASFF (`aws securityhub get-findings` output, or a list of findings)."""
    out = []
    for f in doc.get("Findings", doc) if isinstance(doc, dict) else doc:
        if f.get("RecordState") == "ARCHIVED" or (f.get("Workflow") or {}).get("Status") == "SUPPRESSED":
            continue
        comp = f.get("Compliance") or {}
        cid = comp.get("SecurityControlId") or (f.get("ProductFields") or {}).get("ControlId") or ""
        status = {"FAILED": "FAIL", "PASSED": "PASS"}.get(comp.get("Status"), "FAIL" if not comp else None)
        if status is None:
            continue
        res = (f.get("Resources") or [{}])[0]
        rid = res.get("Id", "")
        svc = rid.split(":")[2] if rid.startswith("arn:") else (res.get("Type", "").replace("Aws", "")[:20].lower() or "other")
        refs = []
        for req in comp.get("RelatedRequirements") or []:
            m = re.match(r"CIS AWS Foundations Benchmark v([0-9.]+)/([0-9.]+)", req)
            if m:
                refs.append(f"cis-aws:{m.group(1)}/{m.group(2)}")
        out.append({"source": "securityhub", "provider": "aws", "account": str(f.get("AwsAccountId", "")), "service": svc,
                    "region": res.get("Region") or f.get("Region") or "global", "resource": rid, "name": "",
                    "check": cid or f.get("GeneratorId", ""), "control": controls.control_for("securityhub", cid),
                    "status": status, "severity": SEV.get(str((f.get("Severity") or {}).get("Label", "")).lower(), "medium"),
                    "title": f.get("Title", cid), "detail": (f.get("Description") or "")[:200], "refs": refs,
                    "remediation": ((f.get("Remediation") or {}).get("Recommendation") or {}).get("Text", "")[:300]})
    return out


def scc(doc):
    """GCP Security Command Center findings (`gcloud scc findings list --format=json`: [{finding, resource}])."""
    out = []
    for row in doc.get("listFindingsResults", doc) if isinstance(doc, dict) else doc:
        f, res = row.get("finding", row), row.get("resource") or {}
        if f.get("state") not in ("ACTIVE", None) or f.get("mute") == "MUTED":
            continue
        cat = f.get("category", "")
        rname = f.get("resourceName", "")
        project = res.get("projectDisplayName") or res.get("project_display_name") or ""
        svc = rname.split("//", 1)[-1].split(".", 1)[0] if rname.startswith("//") else "other"
        refs = [f"cis-gcp:{c.get('version')}/{i}" for c in f.get("compliances") or [] if c.get("standard") == "cis"
                for i in c.get("ids") or []]
        out.append({"source": "scc", "provider": "gcp", "account": project, "service": svc, "region": res.get("location") or "global",
                    "resource": rname.split("/")[-1] if rname else "", "name": rname.split("/")[-1], "check": cat,
                    "control": controls.control_for("scc", cat), "status": "FAIL",
                    "severity": SEV.get(str(f.get("severity", "")).lower(), "medium"), "title": cat.replace("_", " ").lower(),
                    "detail": rname[:200], "refs": refs, "remediation": (f.get("nextSteps") or "")[:300]})
    return out


def defender(doc):
    """Microsoft Defender for Cloud assessments (Azure Resource Graph `securityresources | where type ==
    "microsoft.security/assessments"` export, or the REST list: {value: [..]})."""
    out = []
    rows = doc.get("data", doc.get("value", [])) if isinstance(doc, dict) else doc
    for a in rows:
        p = a.get("properties") or {}
        code = (p.get("status") or {}).get("code")
        if code not in ("Unhealthy", "Healthy"):
            continue
        rid = ((p.get("resourceDetails") or {}).get("Id") or (p.get("resourceDetails") or {}).get("ResourceId")
               or a.get("id", "").split("/providers/Microsoft.Security/")[0])
        m = re.match(r"(?i)/subscriptions/([^/]+)", rid)
        sub = m.group(1).lower() if m else ""
        pm = re.search(r"(?i)/providers/Microsoft\.([A-Za-z]+)/", rid)
        name = p.get("displayName", "")
        out.append({"source": "defender", "provider": "azure", "account": sub, "service": (pm.group(1).lower() if pm else "other"),
                    "region": "global", "resource": rid, "name": rid.rsplit("/", 1)[-1], "check": name,
                    "control": controls.control_for("defender", name), "status": "FAIL" if code == "Unhealthy" else "PASS",
                    "severity": SEV.get(str((p.get("metadata") or {}).get("severity", "")).lower(), "medium"),
                    "title": name, "detail": (p.get("status") or {}).get("description", "")[:200], "refs": [],
                    "remediation": ((p.get("metadata") or {}).get("remediationDescription") or "")[:300]})
    return out


IMPORTERS = {"securityhub": securityhub, "scc": scc, "defender": defender}
