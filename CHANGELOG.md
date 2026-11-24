# Changelog

Components are versioned independently (docs/design.md §5). Entries name the component and its new version.

## 2026-11-24 — fixes

- **runner 0.4.1**: a job with `as:` runs `collectors/<collector>/` and reports under the `as` name (it looked for
  `collectors/<as>/` and exited 2: the in-cluster k8s collector never ran).

- **deploy 0.3.1**: the ClusterRoleBindings of the hub and the in-cluster site name their ServiceAccount in namespace
  `default`, which kustomize rewrites to the overlay's namespace (it left `security-platform` as it was, binding an
  account that does not exist: the read-only posture would have been denied).

## 2026-11-24 — remediation workflow

- **core 0.3.0**: `core/remediation.py`: one tracking item per open finding (contract `security-platform/tracker/v1`,
  `<data>/tracker/items.json`): owner rules (`remediation.owners`, `default_owner`, else `unassigned`), SLO class
  (`kev_exposed` or severity; defaults 1d / 7d / 30d / 90d / 180d), `due_at`, `overdue`, closure only when the
  ledger says fixed, reopen on regression or expired exception (SLO restarts), `time_to_remediate_days`; metrics
  `security_remediation_open|overdue{severity}`, `security_remediation_unassigned`, `security_time_to_remediate_days`,
  `security_remediation_slo_seconds` in `<data>/metrics/remediation.prom`. Advisor drafts (proposals only) under
  `tracker/drafts/`, logged in `decisions/`. Digest: "Overdue remediation" and "Time to remediate vs SLO".
  advisor 0.2.0: an adapter registry (`ADVISORS`).
- **adapters/trackers 0.1.0** (new): `files` (default: private markdown in the data dir), `github-issues` (off unless
  `enabled: true`; refuses any repository that is not private; issue state never feeds back).
- **runner 0.4.0**: job type `remediation`; publishes `remediation.prom` with `ledger.prom`; snapshot default paths include
  `tracker`.
- **generators 0.4.0**: `SecurityRemediationOverdue` (critical/high past SLO, ticket), runbook `remediation-overdue`,
  dashboard panels (overdue by severity, time to remediate).

## 2026-11-24 — in-cluster hub

- **deploy 0.3.0**: `deploy/kubernetes/hub/` — the hub as a CronJob (tick every 15 min) with its state on a PVC, a
  least-privilege ServiceAccount (cluster read-only without Secrets; in its namespace only the inbox, its snapshot
  Secret and its metrics ConfigMap), the inbox writer and snapshot reader Roles, a ValidatingAdmissionPolicy that binds
  an inbox document's `security-platform/site` label to the writer's ServiceAccount, a NetworkPolicy (no ingress;
  DNS + API only), example hub and site-identity configs.
- **runner 0.3.0**: `forward` (store and forward from a local spool to a remote one every tick; ack on delivery;
  reported as job `forward-<i>`); `outbox` and `state_outbox` may be lists, and a hub may have an `outbox` (a copy
  for another hub: parallel runs); job types `push` (human-approved control files to the outbox when they change),
  `pull-snapshot`; `snapshot` with `to:` publishes a `security-platform/snapshot/v1` tarball into a Secret; ingest
  `site_state` may be a spool, `accept_control: [exceptions, catalog-review]`; `retention` prunes `runs/`; job types
  with dashes dispatch.
- **adapters**: `kubeapi` 0.1.0 (new: stdlib Kubernetes API client — HTTPS + 0600 token file, in-cluster
  ServiceAccount, or kubectl with a kubeconfig); spool 0.3.0 (`kubernetes-secret` over kubeapi: `box`, `site`
  labels, newest-wins get, ack deletes every copy, writers need create only; legacy documents without a box are read
  as `outbox`); sinks 0.2.0 (`kubernetes-configmap` over kubeapi: server-side apply, namespace defaults to the pod's).
- Tests: `tests/test_hub.py` against an in-memory API with per-token permissions (inbox round trip, writers cannot
  read, private token files, site → forward → inbox → ingest → ledger → ConfigMap, offline queueing, control files only
  from trusted ingest jobs, snapshot publish/pull, unsafe or tampered snapshots rejected, RBAC promises).

## 2026-11-24 — offline-safe runner

- **deploy 0.2.0**: `render.py env` builds the runtime environment ONCE at deploy time from `deploy/requirements.lock`
  (exact versions + sha256 of every distribution; uv or venv+pip; `--find-links` for air-gapped hosts) and points
  `<install>/env` at it; the wrapper's default interpreter is that environment, it exports `PIP_NO_INDEX`/`UV_OFFLINE`
  and refuses a `--python` that resolves packages per run (`uv run --with …`, which made every tick fail while the
  host was offline). Errors go to the runner log: the wrapper logs a non-zero exit and a missing release; launchd,
  systemd and cron append the trigger's output to the same log (no more /dev/null). The image installs the same lock.
- **runner 0.2.0**: sinks are retried every tick and reported (`state/runner/sinks.json`,
  `security_runner_sink_last_success_timestamp_seconds`, `security_runner_sink_failures_total`,
  `security_runner_sink_consecutive_failures`; label `sink`); the local metrics file carries this tick's sink results;
  `security_runner_tick_max_gap_seconds` (`runner.tick_stale_after`, default 1h); a config that cannot load is logged
  (`cannot start`, rc 78) instead of a traceback; a publish error never crashes the tick.
- **generators 0.3.0**: `SecurityRunnerStale` (the tick heartbeat is overdue: trigger, environment, host or sink
  broken) and `SecurityMetricsSinkFailing`; runbook `runner-stale`.
- Tests: `tests/test_offline.py` (a tick with every socket blocked and package managers booby-trapped; errors in the
  log; the lock is exact and hashed; the environment is built once and used), sink retry/metrics.

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
- **collectors/k8s 0.2.0**: `parts` (workloads, rbac, secrets, policy, operator, cis), in-cluster kubectl
  (`kubeconfig: in-cluster`), one inventory file per collector instance.
- **sdk**: `SP_COLLECTOR_NAME` (runner job `as:`): the same collector in two scopes reports under two names.
- **deploy**: `deploy/kubernetes/cronjob` (in-cluster site: CronJob, read-only ClusterRole without secrets, outbox
  Role `create secrets`); **spool 0.2.0**: `kubernetes-secret`.
- Tests: runner, sinks, intel, output contracts (metric labels, rules, SLO values, dashboard, digest).

## 2026-11-24 — phase 0

- schema findings/v1, sdk 0.1.0, core 0.1.0, generators 0.1.0, seven collectors 0.1.0, adapters, design.
