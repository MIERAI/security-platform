# Changelog

Components are versioned independently (docs/design.md §5). Entries name the component and its new version.

## 2026-11-24 — continuous operation

- **runner 0.1.0** (new): `tick` / `run` / `status` / `metrics` / `serve-metrics`; per-job cron schedule with
  deterministic jitter, catch-up of missed slots (`max_delay` to keep heavy scans off-peak), timeout (process group),
  retries, per-job / ledger / tick locks; roles hub and site (outbox), `ingest` jobs pull sites into the ledger and
  publish asset lists to them; `command` jobs wrap any program that honours the findings contract; job heartbeat
  metrics `security_runner_*`, collector expected interval `security_collector_expected_interval_seconds`.
- **deploy 0.1.0** (new): trigger renderer (launchd, cron, systemd, termux-job, wrapper), `bin/sp-install` (versioned
  releases + `current`), Kubernetes metrics exporter (Deployment, Service, ServiceMonitor, NetworkPolicy), Dockerfile.
- **core 0.2.0**: a finding becomes `fixed` only if the run COVERED its asset (exact / prefix / umbrella match of an
  `ok` coverage entry; a gap always wins). 0.1.0 fixed everything that was not a gap, so a run with a smaller scope
  (e.g. vuln-intel without an inventory) "fixed" findings it never looked at. Ledger `--latest` (metrics and gaps from every collector's newest document, not just this run's);
  `security_sli_new_total` (findings entering an SLI's set; first sight = baseline), `security_sli_ok` (bool SLI),
  `security_collector_last_good_run_timestamp_seconds` (a blind run does not count); accepted findings can become
  fixed; new selectors `check_prefix`, `layer_in`, `kind_not`, `attr_any_true`; atomic writes;
  `<data>/metrics/ledger.prom`; **digest** (weekly summary of what did not page).
- **sdk 0.2.0**: `load_config` (YAML, or JSON without PyYAML); `*_total` typed as counters; empty label sets rendered
  without braces; label values sanitized.
- **generators 0.2.0**: alerts are regression-only (`alert.trigger: increase` in the catalog) and keep the `namespace`
  label; health alerts use per-collector expected intervals and the last *good* run; slo-platform SLO values (`age` per
  collector, `bool` per SLI, silent burns); dashboard with a namespace variable and runner/feed panels; ConfigMap form
  of the dashboard; `--instance`, `--runbook-url`. Catalog: new SLIs `vuln_alertable`, `critical_config_findings`.
- **collectors/exposure 0.2.0**: discovered online hosts are covered (`host:<name>`); a target with no open port is a coverage gap (with `-Pn` a down host looked
  "covered" and its findings were marked fixed); open ports reported as one aggregate (no per-host label).
- **collectors/vuln-intel 0.2.0**: repo coverage named like its findings (`repo:<basename>`); reads inventories from `SP_INPUT_DIR`; `update_db` refreshes Trivy's DB;
  `sbom_max_age_days`; read-only registry credentials from 0600 files (`registry_auth`), missing = coverage gap;
  attribute `alertable`; OSV matcher (second, independent, with publication dates); feed age for the Trivy DB.
- **adapters**: feeds 0.2.0 (conditional GET, `osv` adapter), discovery 0.2.0 (`file`), sinks 0.1.0 (textfile,
  kubernetes-configmap, remote_write), spool 0.1.0 (exec / local).
- **bin/check-residue**: `--history` (every commit, and commit messages), `.residue-ignore`.
- Tests: runner, sinks, intel, output contracts (metric labels, rules, SLO values, dashboard, digest).

## 2026-11-24 — phase 0

- schema findings/v1, sdk 0.1.0, core 0.1.0, generators 0.1.0, seven collectors 0.1.0, adapters, design.
