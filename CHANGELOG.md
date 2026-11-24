# Changelog

Components are versioned independently (docs/design.md §5). Entries name the component and its new version.

## v0.2.0 — 2026-11-24

The first tagged product release: everything below this heading, tested together. Unit, contract and output tests,
`bin/check-residue --history`, and the second-environment test (`e2e/kind/run.sh --ref main`: PASSED, clone to first
findings 119 s, `e2e/kind/last-pass.json`). Each component is also tagged `<component>/vX.Y.Z`.

| component | version |
|---|---|
| `cli` | 0.1.0 |
| `collectors/agent-claude-code` | 0.2.0 |
| `collectors/codehost-gitea` | 0.1.0 |
| `collectors/codehost-github` | 0.1.1 |
| `collectors/detection` | 0.1.1 |
| `collectors/exposure` | 0.4.1 |
| `collectors/host-sbom` | 0.1.1 |
| `collectors/host` | 0.2.0 |
| `collectors/identity` | 0.1.0 |
| `collectors/k8s` | 0.2.0 |
| `collectors/secrets-files` | 0.2.1 |
| `collectors/vuln-intel` | 0.4.0 |
| `core` | 0.6.1 |
| `deploy` | 0.3.1 |
| `detections` | 0.2.1 |
| `events` | 0.1.1 |
| `generators` | 0.6.0 |
| `runner` | 0.7.1 |
| `scorecard` | 0.2.1 |
| `sdk` | 0.3.0 |

## 2026-11-24 — scorecard: generality and usability controls

- **scorecard catalog** (dimensions 9 and 10, data only): generality now needs evidence that a second, different
  environment ran the product within 45 days (`e2e/kind/last-pass.json`), alternative adapters (static CIDR
  discovery, a second code host), an install guide and configuration reference, an upgrade policy with two-step
  changes, contract tests, tagged releases, and a multi-architecture image (not implemented yet: counted as failing).
  Usability needs a measured clone-to-first-findings under 15 minutes, `sp` with plain-language explanations enforced
  by a test, a daily summary that reached a person (`notify` job), both dashboards, reference/FAQ/translations, plus the
  existing quick start, installer, weekly digest and the operator's attested review.

## 2026-11-24 — events heartbeat

- **events 0.1.1**: one `event=heartbeat` line per source and successful run, so a quiet host (no logins) is
  distinguishable from a broken shipper; no detection rule matches it.
- **collector detection 0.1.1**: auth sources must deliver (heartbeats included) within 1 day (was 7 days).
## 2026-11-25 — per-asset scope

- **sdk 0.3.0** `asset_scope` / `in_scope`; **discovery 0.4.0** `apply_scope`: instance `scope: [{names, scope:
  [collectors], offline: gap|expected, reason}]` limits an asset to some collectors (e.g. personal devices: exposure
  only). Other collectors skip it (no coverage gap); `offline: expected` = scanned only when online, offline is not
  a gap. Honoured by host 0.2.0, host-sbom 0.1.1, secrets-files 0.2.1, exposure 0.4.1 and the runner's
  `publish_assets` (runner 0.7.1, so sites running older code honour it too).

## 2026-11-25 — checks mapped to ATT&CK

- **scorecard**: `scorecard/attack-map.yaml` (check prefix -> MITRE ATT&CK Enterprise v17 techniques; detections
  already carry theirs); `tests/test_attack_map.py` fails when a collector emits an unmapped check; control
  `intel.attack-mapping` is now evidence (the map and the detection catalog).

## 2026-11-24 — install and operations docs, second-environment e2e test

- **docs**: `quickstart.md` (first findings in 15 minutes, starting with the local machine; add the environment one
  section at a time; keep it running; see it daily), `instance-reference.md` (every key and its default),
  `adapters.md` (writing a discovery/exec/sink/notifier adapter or a collector, with the rules every plugin follows),
  `upgrade.md` (versioning, upgrade and rollback, two-step breaking changes, compatibility promises), `faq.md`,
  summaries in Japanese (`summary.ja.md`) and Chinese (`summary.zh.md`); README quick start uses `sp`.
- **e2e/kind** (new): `e2e/kind/run.sh` installs the product from the public repository (or `--local` HEAD) into a
  fictional company's environment unlike the first instance: static CIDR discovery, plain ssh servers (one with
  password login), Gitea (no GitHub), kind + kube-prometheus-stack. It checks findings from every collector, no false
  coverage gaps, remediation owners, the scorecard, the daily summary (no asset details), the scheduled install
  (sp-install, render.py env/wrapper, a tick with a notify job), Prometheus scraping the exporter through its
  ServiceMonitor, and both Grafana dashboards; measures clone-to-first-findings; tears everything down; writes
  `e2e/kind/last-pass.json`. Gaps it found were fixed in the product (CIDR discovery, Gitea collector, default owner)
  or documented (kindnet and egress-deny NetworkPolicies; the published image is amd64 only).
- **image**: also ships the documents the scorecard reads as evidence (CHANGELOG, bin, dist, docs, examples, e2e,
  tests), so an in-cluster hub scores the same evidence controls as a host install. Nothing there is executed.

## 2026-11-24 — detections 0.2.1

- **detections 0.2.1**: in-cluster Falco detections fire on a rule's first match (Falco exports a rule counter only
  after it matched once: a new series counts, not only an increase); IPv6 loopback, ULA and link-local are expected
  outbound destinations (lab: pods talking to [::1] were reported).
- Log-store rules skip non-JSON lines (Falco start-up messages made the whole query fail), the Falco pod label is
  `k8s_pod` (it collided with the stream label `pod`), and the kubelet's fsGroup setgid on volume directories is not a
  setuid/setgid event.
## 2026-11-24 — overview dashboard

- **generators 0.6.0**: a second dashboard, **Security overview** (`dist/grafana-overview.json`, uid
  `security-platform-overview`; also a second key of the existing dashboard ConfigMap, so the Grafana sidecar picks it
  up with no deployment change): the security score, critical+high open, overdue fixes, new in 24h, regressions and
  "could not check" tiles; score by pillar and by dimension with failing controls; top risks (open critical/high by
  area), overdue fixes by severity, exposure/KEV SLIs; 30-day trend; job health; a plain-language "what to do" note.
  Aggregates only, every panel described in plain words.

## 2026-11-24 — fix: default owner

- **core 0.6.1**: `remediation.default_owner` applies to findings whose owner is only the SDK's role hint (`platform`
  or `human`); before, every real finding carried one of them, so the default owner was never used (found by the
  second-environment test).

## 2026-11-24 — a second kind of environment

- **adapters/discovery 0.3.0**: `static` takes CIDR ranges (`cidrs:`, `exclude:`, `max_hosts` default 1024 so a typo
  cannot start a /8 scan); range-derived assets carry `attrs.cidr`.
- **exposure 0.4.0**: an address from a CIDR range where nothing answers is "no host there", not a coverage gap.
- **codehost-gitea 0.1.0** (new): Gitea / Forgejo over the REST API (stdlib; token from a 0600 file): unprotected
  default branch, protection without approvals, write deploy keys, plain-http pull mirrors. Same check names as the
  GitHub collector where the meaning is the same.
- **codehost-github 0.1.1**: entries of another code-host type are left to their own collector (no false gap).
- Tests: `tests/test_adapters_generic.py` (CIDR expansion and limits; Gitea against an in-process fake API).

## 2026-11-24 — usability: the `sp` command line and notifiers

- **cli 0.1.0** (new): `bin/sp` (symlink it into PATH): `init` (a private data directory with a starter config whose
  first entry is the local machine, so the first run already shows findings), `doctor` (config, tools per configured
  collector, 0600 secret files), `run` (every job now, collectors first, then metrics), `status` (one screen: open by
  severity, overdue, fixed this week, SLIs, jobs, what could not be checked, top risks), `findings` (`--open
  --severity high --layer --check --overdue --json --ids`), `explain <id>` (what it means / why it matters / how to fix
  / how to verify, plus a ready-to-edit exception entry), `digest` and `notify`. `cli/explanations.py`: plain-language
  text for every check the collectors emit (a test fails when a new check has none).
- **notifier 0.1.0** (new): `notifier/notifiers.py`: `stdout`, `file`, `webhook` (slack / json / text: Slack,
  Mattermost, Teams workflows, ntfy-like), `telegram`, `exec` (pipe into a command, locally or through an exec
  adapter). The summary is aggregates only (it leaves the private boundary); secrets from 0600 files; errors carry
  a status code, never the URL or token.
- **runner 0.7.0**: job type `notify` (the daily summary to the instance's `notify:` adapters).
- **image**: also ships `cli/` and `notifier/` (an in-cluster hub can run the `notify` job).
- Tests: `tests/test_cli.py`, `tests/test_notifier.py`.

## 2026-11-24 — fix

## 2026-11-24 — detection and response (dimension 7)

- **detections 0.2.0**: every Falco detection also alerts in-cluster on Falco's per-rule counters
  (`engine=falco-metrics`), so runtime detection does not depend on the log store; the generic critical backstop is
  gone (it duplicated them). 0.1.0 (#13): catalog, curated Falco rules, node-logs, audit policy, runbooks, playbook.
- **collector detection 0.1.0** (new): the detection pipeline checked end to end from outside — scope (every
  `kubernetes:` cluster has a sensor and an audit source), sensors ready on every node, in-cluster backstop present,
  every expected source delivered logs (k8s-audit, auth, codehost, overlay-network), the ruler has every catalog
  rule, page alerts reach a notifying receiver; quality metrics: alert minutes per severity, false-positive ratio
  (human verdicts), drills (time to detect), rule-content age.
- **scorecard catalog 07-detection**: automated controls from the collector replace the placeholders (runtime,
  audit, auth, SaaS audit, rules deployed, backstop, page routing, drill + time to detect, false-positive rate,
  rule freshness, playbook evidence).
## 2026-11-24 — security events

- **events 0.1.0** (new): `events/ship.py` ships security events from hosts without a log agent and from SaaS control
  planes to a Loki push endpoint (log contract: `source`, `host`, structured metadata `event`/`user`/`src_ip`/`novel`,
  `actor`/`repo`); sources `command` (openssh, dropbear, sudo, macOS unified log parsers), `file-integrity`,
  `github-account`, `tailscale-audit`; at-least-once cursors, first-run baselines.
- **runner 0.6.0**: job type `events` (docs/runner.md "Security events").
## 2026-11-25 — coverage gaps closed (device and software pillars)

- **collector secrets-files 0.2.0**: Windows targets (exec `shell: windows`, script read as UTF-8 bytes, permissions
  from the ACL by SID, junctions not walked); an SSH server's host key is not "a key without passphrase".
- **collector vuln-intel 0.4.0**: `code_repos` — every repository of a code-host owner (one cached listing call per
  day; HEAD via `git ls-remote`; shallow clone + SBOM only when HEAD changed; token in the environment only),
  matched through Trivy's DB and OSV; metrics `security_sbom_repos{,_in_scope}`,
  `security_intel_firmware_vendors_without_source`.
- **collector exposure 0.3.0** / **discovery 0.3.0**: a host the discovery adapter saw online (`online_verified`) with
  no open port is covered (fully filtered), not a gap; unverified addresses stay gaps.
- **core 0.6.0**: coverage exceptions (`exceptions.yaml: coverage_exceptions`, human + expiry like finding
  exceptions) take a gap out of `collector_coverage_gaps`; `security_coverage_gaps_excepted`,
  `security_coverage_gaps_open{collector}`.
- **scorecard catalog**: coverage (host software inventory, secrets on every host, code dependencies, unmanaged
  devices attested, limitations documented) and intel (vendor advisories built, hosts matched, platform advisories
  fresh, time-to-know, code dependencies matched).

## 2026-11-24 — Tailscale OAuth client (read-only)

- **adapters/identity 0.2.0**: the `tailscale` provider takes an OAuth client (`oauth_client_id` +
  `oauth_client_secret_file`, 0600) and exchanges it for a short-lived token with only the client's scopes; preferred
  over `api_key_file` (an API key carries its user's full rights). Read-only scopes: `devices:core:read`,
  `users:read`, `policy_file:read`.

## 2026-11-25 — host software inventory and platform advisories

- **collector host-sbom 0.1.0** (new): software inventory of every host through the exec adapter + an OS profile
  (linux dpkg/apk/rpm, macOS Homebrew, Android/Termux, Windows KB + installed programs, OpenWrt opkg + firmware);
  contracts `inventory.host-packages.json` / `inventory.host-platforms.json`; optional `sbom_paths` (local hosts:
  Go binaries / PyPI / npm via `trivy rootfs`).
- **collector vuln-intel 0.3.0**: host matching — distro packages through Trivy's DB (Ubuntu USN / Debian tracker /
  Alpine), running-kernel aggregation, fs SBOMs through Trivy + OSV; platform advisories with one finding per missed
  release: Android bulletins (patch level), Apple security releases, MSRC monthly updates, firmware-vendor KEV
  entries (candidates); vendor advisory headlines as candidates with human verdicts (`advisory-reviews.yaml`),
  unreadable sources are gaps; optional advisor for extraction only. Coverage per host is ok only when every
  applicable matcher ran.
- **adapters**: feeds 0.3.0 (`android-bulletins`, `apple-security-releases`, `msrc-cvrf`, `vendor-advisories`; KEV
  index carries vendor/product); exec 0.2.0 (`shell: windows`, `powershell()` bootstrap through stdin).
- **core 0.5.0**: time-to-know baseline (`ttk_counted`: only findings on assets the collector had already covered),
  platform advisories count (`advisory`), `security_time_to_know_hours{asset_class,priority,quantile}`; SLI
  `time_to_know_hours` (objective 24h; disclosure dates are day-granular).

## 2026-11-24 — private outputs whatever the umask

- **core 0.5.1**: `ledger.json` is created 0600 regardless of the caller's umask (a manual `runner.py run` from a
  shell with umask 022 left it world-readable inside the 0700 directory).
- **scorecard 0.2.1**: report and metrics files are created 0600; `self.image-no-high-vulns` requires that the
  platform image was actually covered (`require_coverage: image:${self_image}`) - an image that is not running yet
  is `unknown`, not a pass.

## 2026-11-24 — platform self-security

- docs/threat-model.md (new): the platform's own threat model (assets, trust boundaries, STRIDE threats T1-T11 with
  controls and gaps), the secret-handling review, and the data-at-rest decision (full-disk encryption on every host
  holding the data; copies leaving the host encrypted separately).
- Scorecard catalog `self`: `self.image-ci-scan-sbom` (CI scan + SBOM through the shared build workflow);
  `self.image-signed` matches the workflow's `sign: true`.

## 2026-11-24 — people pillar (identity, AI agents as personnel)

- **adapters/identity 0.1.0** (new): `provider(cfg).collect()` normalises accounts (MFA true/false/unknown), orgs
  (2FA requirement), grants (collaborators, deploy keys, members), credentials (kind, scopes, created/expires, never
  a value) and policies (fork-PR approval, overlay ACL allow-all). `github` via gh with an ETag cache (304s cost no
  rate limit) and `orgs:` scoping (other organisations are never read); `tailscale` with a read-only API key file
  (0600) or the CLI; `local_credentials` (gh keyring dates, kubeconfig users incl. certificate expiry, SSH keys,
  Docker registries, token files). `google-workspace`, `okta`, `entra`, `gitlab`: documented interfaces (gaps).
- **collector identity 0.1.0** (new): provider-independent checks `identity.mfa_disabled`, `org_mfa_not_required`,
  `collaborator_unexpected`, `deploy_key_unused`, `fork_pr_approval_weak`, `overlay_acl_allow_all`,
  `token_age_over_90d`, `token_classic_full_repo`, `token_expiring_soon`, `credential_expired`,
  `ssh_key_age_over_365d`, `overlay_device_dormant`, `credential_file_readable`; MFA the API cannot tell is a coverage
  gap (`identity-mfa:`), answered by a human attestation in the scorecard. Metrics `security_identity_*`.
- **collector agent-claude-code 0.2.0**: memory files scanned for credential shapes (counts only; prose after a
  keyword is not a value), `agent.no_credential_deny_rules` (deny rules for credential paths), audit trail metadata
  (`agent.audit_trail_missing`: no transcript within 7 days or retention below `min_transcript_retention_days`),
  hooks inventory; coverage `agent-guard:`, `agent-memory:`, `agent-audit:`.
- **scorecard 0.2.0**: evaluators `first_known` (the API decides when it can tell, otherwise the next source) and
  `attestation` (the control's own human answer); `people.codehost-mfa` and `people.overlay-acl` use them;
  `attest` accepts controls with an attestation fallback; the digest lists every control a human must answer.

## 2026-11-24 — scorecard (weakest link)

- **scorecard 0.1.0** (new component): `scorecard/scorecard.py` (`compute`, `attest`, `lint`, `list`) and
  `scorecard/evaluators.py` (findings with `require_collector`/`require_coverage`, sli, metric, collector_fresh, job,
  file, all/any, builtin, none). Catalog `scorecard/catalog/<NN>-<dimension>.yaml`, one file per dimension (11
  dimensions, 99 seeded controls), each control mapped to pillars (network/device/people/software), a NIST CSF 2.0
  category and CIS Controls v8 safeguards; check types automated / evidence / attested (human, expires). Dimension
  score = weighted pass ratio; overall = the weakest dimension; FAIL when any dimension < 75. Outputs
  `reports/scorecard.{json,md}` (contract `security-platform/scorecard/v1`), `metrics/scorecard.prom`
  (`security_score{dimension|pillar|function}`, `security_score_regressions_total`, `security_attestations{state}`),
  regression state. Instance block `scorecard:` (threshold, catalog_dirs, replace_catalog, overrides, vars). docs/scorecard.md.
- **runner 0.5.0**: computes the scorecard on every publish and publishes `scorecard.prom`; control kind `attestations`
  (`push` / `accept_control`); snapshot default paths include `attestations.yaml`.
- **generators 0.5.0**: `SecurityScoreRegression` (ticket, regression-only), `SecurityAttestationExpired`,
  `SecurityScorecardStale`; dashboard row "Security scorecard" (overall, by dimension / pillar / CSF function,
  history, failing controls, attestations). Runbooks `score-regression`, `attestation-expired`.
- **core 0.4.0**: the weekly digest opens with the scorecard (weakest first, failing controls, attestations due).
- Image: `scorecard/` is copied into the runner image.

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
