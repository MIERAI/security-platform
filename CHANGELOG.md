# Changelog

Components are versioned independently (docs/design.md §5). Entries name the component and its new version.

## Unreleased

- **collectors/cloud 0.3.0**: a Go implementation, `sp cloud collect` (internal/collectors/cloud), behind the collector
  protocol: Prowler, Steampipe and ScoutSuite as external processes, Security Hub / SCC / Defender imports, the generic
  controls and the merge into one finding with N sources. Its findings document, evidence and metrics are
  byte-identical to the Python implementation's apart from times: the conformance case collector-cloud passes, the
  cloud e2e passes with it (`SP_CLOUD_E2E_IMPL=go`, every scan and failure scenario compared with the Python run) and
  parity tests pin the parsers, the merge and the control tables to the Python answers on the shared fixtures
  (`internal/collectors/cloud/testdata/golden.json`, kept current by tests/test_cloud.py). The Python collector is
  unchanged and stays the default; a `command` job selects the Go one (docs/cloud.md). Instance config: JSON only.
- **adapters/cloud.py 0.3.0, adapters/discovery.py 0.6.0**: their Go implementation, internal/cloud, on the providers'
  official SDKs instead of our own protocol code: aws-sdk-go-v2 (STS web identity + `AssumeRole` chain, IAM policy
  inspection with paging, SSO/shared-config profiles without the AWS CLI), golang.org/x/oauth2/google (STS token
  exchange, external-account config for engines, ADC refresh + impersonation; `getIamPolicy` at policy version 3) and
  the Azure SDK for Go (federated client assertion, ARM role assignments, resource-provider auto-registration off).
  Same keys, refusals and gap reasons; new optional `ca_file` per account (Go). `sp cloud discover` is `discovery: gcp`
  in Go. Dependencies and why each is needed: docs/go.md (google.golang.org/api considered and not used).
- **sp**: new Go subcommand `sp cloud` (collect, discover, and the engines' credential callbacks).
- **e2e/cloud-localstack**: `SP_CLOUD_E2E_IMPL=go`; `compare_impls.py`; the mock also serves the Entra/ARM endpoints
  over TLS (the Azure SDK for Go requires an https authority at the root of a host).
- **contracts 1.x** (new, documentation of existing behaviour; no component changed): `contracts/` defines every
  component boundary language-neutrally — findings 1.2 (incl. OCSF mapping), collector-protocol 1.0, ledger 1.0
  (merge + remediation tracking), scorecard 1.0, runner 1.0, metrics 1.0 (`registry.json`), cli 1.0 — each with JSON
  Schemas (2020-12), examples and a "Known deviations" table (LEDGER-D1…D5, RUNNER-D1…D3, CLI-D1, METRICS-D1,
  COLLECTOR-D1) that states the target behaviour.
- **conformance suite** (new): `conformance/run.py` runs any implementation of a component as a process
  (`SP_IMPL_<COMPONENT>`) against fixtures and golden subsets; `conformance/impl/python/run.sh` runs it against this
  implementation (in CI through `tests/test_conformance_reference.py`); the reference's known deviations are expected
  failures. How to implement a component in another language and replace it without stopping the platform:
  docs/contracts.md.
- **docs/quickstart.md**: the cron install line works under `set -e` when there is no crontab yet (it installed an empty
  crontab silently) and does not add a second tick line when run again.

## v0.3.0 — 2026-11-25

Everything between v0.2.0 and this heading, tested together: unit, contract and output tests, `bin/check-residue
--history`, the cloud end-to-end test (`e2e/cloud-localstack/run.sh`: PASSED) and the second-environment test
(`e2e/kind/run.sh --ref main`: PASSED, clone to first findings 123 s, `e2e/kind/last-pass.json`). Each component is also tagged
`<component>/vX.Y.Z`. Highlights: cloud posture (AWS, GCP, Azure; GCP `source: adc` and `discovery: gcp`), ticket and
SIEM exports, retired assets close their findings, one slow host check no longer hides the others, several hubs in
one cluster, release names from product tags only.

**Upgrade order** (contract findings/v1.2): upgrade every **hub** (core 0.9.0) before its **sites**. A site on host
0.3.0 reports a timed-out check as a narrow gap with `checks`; an older core does not know that field and would mark
the affected findings fixed. Install with this release's installer (`git checkout v0.3.0 && bin/sp-install DIR`); an
install of v0.2.0 named after a component tag is repaired by it (docs/upgrade.md).

| component | version |
|---|---|
| `cli` | 0.3.0 |
| `collectors/agent-claude-code` | 0.2.0 |
| `collectors/cloud` | 0.2.0 |
| `collectors/codehost-gitea` | 0.1.0 |
| `collectors/codehost-github` | 0.1.1 |
| `collectors/detection` | 0.1.1 |
| `collectors/exposure` | 0.4.1 |
| `collectors/host-sbom` | 0.1.1 |
| `collectors/host` | 0.3.0 |
| `collectors/identity` | 0.1.0 |
| `collectors/k8s` | 0.3.0 |
| `collectors/secrets-files` | 0.2.1 |
| `collectors/vuln-intel` | 0.5.0 |
| `core` | 0.9.0 |
| `deploy` | 0.5.0 |
| `detections` | 0.2.2 |
| `events` | 0.1.1 |
| `generators` | 0.7.0 |
| `runner` | 0.9.0 |
| `scorecard` | 0.4.0 |
| `sdk` | 0.5.0 |

## 2026-11-25 — one slow host check no longer hides the others

On macOS `softwareupdate -l` asks Apple's servers and can take from 90 s to several minutes. The host collector ran the
whole profile under one 180 s limit, so a first `sp run` could end with the entire host as a coverage gap
(`exec failed rc=124: timeout`), "Open findings: none" and a score of 0, although FileVault and the other checks had
already been measured. Now each probe has its own limit and only the check that timed out is "could not check".

- **collector host 0.3.0**: every probe of a profile runs under its own time limit (`profiles/probe.sh`: POSIX sh,
  background + watchdog, stops the command and its descendants; no `timeout` binary needed, so it works on macOS,
  dash, bash and busybox ash; `profiles/probe.ps1`: one runspace per probe on Windows). A probe that does not finish
  prints `probe.timeout=<key>` instead of a value. Its checks become a narrow coverage gap `host:<name>/<part>` (e.g.
  `host:my-laptop/os-updates`) carrying the checks it stands for; every other check reports normally, and a partly
  read part (e.g. one of three firewall keys) reports no guess. Network-dependent probes (`softwareupdate -l`,
  Homebrew, `apt list --upgradable`, the Windows hotfix list) run last with a generous limit. New host keys
  `probe_timeout` (20 s), `slow_probe_timeout` (90 s) and `script_timeout` (backstop, default 300 s): when the backstop
  fires, the lines printed so far are still used and the probes never reached become narrow gaps. The Windows profile
  now goes through stdin (`exec.powershell`), so its length is no longer bound by the 8191-character command line.
- **findings contract 1.2** (additive): a `gap` coverage entry may carry `checks: [patterns]` (a narrow gap on
  `<asset>/<part>`).
- **core 0.9.0**: a finding whose check is listed by a narrow gap on its asset keeps its state (unknown) instead of
  being marked fixed; the asset's other findings are judged as usual. Older cores ignore `checks` and would treat such a
  finding as fixed: upgrade the hub (core) first, as usual.
- **sdk 0.5.0**: `Collector.gap(asset, reason, checks=...)`; documents are written as `schema_version: "1.2"`.
- **adapter exec 0.3.0**: `run(..., partial=True)` returns the output printed before a timeout (default unchanged:
  nothing); a local command runs in its own session and the whole process group is stopped on timeout; a command
  without `stdin` reads `/dev/null` instead of inheriting the caller's stdin.
- **docs**: quickstart (the first macOS run can take a few minutes; a timed-out check is "could not check", not safe),
  instance-reference (`hosts` time limits), design §1 (narrow gaps).
## 2026-11-25 — release names from product tags only, everywhere

`git describe --tags` on a release commit prints a component tag (`collectors/codehost-gitea/v0.1.0` on `v0.2.0`):
all tags of a release are annotated and created in the same second, and describe prefers the newest. The installer
shipped **in v0.2.0** still used it, so `git checkout v0.2.0 && bin/sp-install` installed the product as
`releases/collectors/codehost-gitea/v0.1.0` (the earlier fix below only reached commits after v0.2.0). That fix also
fell back to an abbreviated hash or `vX.Y.Z-N-g<hash>` without saying so, and its pattern accepted any `v<digit>…` tag.

- **cli 0.3.0**: `cli/release.py` names the product version of a commit: the highest product tag
  (`vMAJOR.MINOR.PATCH[-PRERELEASE]`, strict) pointing at exactly that commit, annotated or lightweight, in any
  creation order; component tags are never used. No product tag: an error that says so (exit 2), or with `--dev` an
  explicit development name `dev-<nearest vX.Y.Z>-<n>-g<commit>`. `sp --version` prints the product release too:
  `sp 0.3.0 (security-platform v0.3.0)` (from the install's `RELEASE` file, or the checkout's tags).
- **bin/sp-install**: the release directory is `releases/<product version>/` with a `RELEASE` file (`version=`,
  `commit=`); an untagged commit is refused unless `--dev`; `--ref <tag>` installs another commit with this installer
  (re-install v0.2.0 correctly: `bin/sp-install --ref v0.2.0 <root>`). A release directory an older installer named
  after a component tag is reported, `current` moves to the correctly named one, and the old directory is **kept**
  (it may be the running one) with the `rm -rf` command printed.
- **runner 0.9.0**: `security_runner_info` gains the label `release` (the installed product version; empty in a
  checkout or the image). Additive (docs/upgrade.md: adding a label is a minor change).
- **e2e**: kind and cloud tests record the installed version through `cli/release.py --dev`; the kind test installs
  with `sp-install --dev` (it runs any `--ref`, a branch included).
- **docs**: upgrade.md: release naming, repairing an install named after a component tag, and the release procedure
  step by step (tags, checks, pushing the tags only).
- **tests**: `tests/test_release.py`: a temporary repository with a product tag and component tags on one commit
  (annotated and lightweight, every creation order), pre-releases, several product tags, untagged and component-only
  commits; the installer end to end including the migration of a component-named release.
- **Upgrade (existing installs)**: if `current` points at `releases/<component>/<…>/vX.Y.Z`, install again with a
  current installer (docs/upgrade.md); remove the old directory once a tick ran from the new `current`.


## 2026-11-25 — retired assets close their findings

A finding became `fixed` only when a run covered its asset again. An asset that no longer exists is never covered
again, so its findings stayed open forever (e.g. a critical CVE in `image:app:1.0` after the workload moved to
`app:1.1`). Now an authoritative, complete inventory retires them; a partial one still retires nothing.

- **findings contract 1.1** (additive; core and old collectors are unaffected): an `ok` coverage entry may carry
  `complete_scope: "<asset prefix>"` - "this run listed every existing asset under this prefix". Older cores ignore it.
- **core 0.8.0**: a finding of that collector on an asset under a declared `complete_scope` that the run listed neither
  as ok nor as gap is closed as fixed with `fixed_reason: asset_retired` (time to fix counted as usual); any gap that
  may concern it keeps it unknown. Regular fixes now record `fixed_reason: not_observed`. A retired asset that comes
  back reopens its findings (regression), and the reason is cleared.
- **sdk 0.4.0**: `Collector.ok(asset, complete_scope=...)`; documents are written as `schema_version: "1.1"`.
- **collector k8s 0.3.0**: the image inventory (`inventory/v1`) gains `complete` (true only when the pods of every
  configured cluster were listed) and `sources` (per cluster: `complete`, `failed: <error type>`, or not inventoried
  because `parts` excludes `workloads`).
- **collector vuln-intel 0.5.0**: declares `inventory:container-image` with `complete_scope: "image:"` only when every
  container-image inventory is complete; an inventory without `complete` (an older producer) or with a failed
  cluster declares nothing and is logged.
- **Upgrade**: no configuration change. Retirement starts once core, k8s and vuln-intel are all upgraded (any order;
  hub first as usual). The first complete run closes the backlog of findings on images that stopped running earlier,
  at once: expect a one-time drop in open supply-chain findings and a one-time rise of `security_time_to_fix_days`
  (their age is counted as time to fix).
- **docs**: design §1 (asset retirement) and §11.2 (inventory completeness), runner.md (vuln-intel), adapters.md
  (when a collector may declare `complete_scope`).

## 2026-11-25 — several hubs in one cluster

- **deploy 0.5.0**: component `deploy/kubernetes/unique-names` gives the cluster-scoped objects of a hub
  (ClusterRole/ClusterRoleBinding `security-platform-hub-read`, ValidatingAdmissionPolicy/Binding
  `security-platform-inbox-identity`) and of an in-cluster site (`security-platform-site-read`) the installation's
  name as a suffix, read from the ConfigMap `security-platform-installation` (key `name`) that the overlay generates;
  `roleRef` and `policyName` follow. Two installations in one cluster (one per environment / namespace) no longer
  overwrite each other's objects (a GitOps application stuck out of sync), and a combined render of several
  environments has no duplicate objects. Namespaced names are unchanged. Without the component nothing changes.
  Migration (docs/runner.md "Several hubs in one cluster"): add the component and the ConfigMap; the old
  unsuffixed objects are pruned by the GitOps tool, or deleted once by hand after every installation switched.
- **tests**: `tests/test_manifests.py` renders two environments (hub and site each) side by side with kustomize and
  fails on a colliding cluster-scoped name, a dangling `roleRef` / `policyName`, or a cluster-scoped object the
  component does not rename; the existing single-install render keeps its names.

## 2026-11-25 — detections 0.2.2: less audit noise

- **detections 0.2.2**: `k8s-audit/policy.yaml` drops `create` of `selfsubjectaccessreviews`, `subjectaccessreviews`,
  `localsubjectaccessreviews` and `selfsubjectrulesreviews` (authorization.k8s.io) by **service accounts**
  (`system:serviceaccounts`): controllers checking their own permissions (a policy engine's cleanup controller,
  admission webhooks, operators). On a real cluster with a policy engine these were about 35% of all audit lines; no
  detection uses them. The same reviews by a person (or anonymous) are still logged at Metadata (possible
  reconnaissance). The rule matches only these four resources and only `create`: tokens, exec, Secrets, RBAC and all
  other writes by service accounts are logged as before (tests). Trade-off: a stolen service account token asking
  what it may do is no longer logged; what it then does still is.
- **Action for instances**: the policy is a file on each control-plane node and is not deployed by the platform.
  Copy the updated `detections/k8s-audit/policy.yaml` to every control-plane node (where `--audit-policy-file`
  points) and restart the API server (static pod: touch or re-apply its manifest). Until then the old policy stays in
  effect (more volume, nothing missed).

## 2026-11-25 — team integrations: tickets, SIEM, instance scope in the scorecard

- **adapters/tickets.py 0.1.0** (new): one ticket per ledger finding in the team's issue tracker. Generic engine
  (`sync`) + backend interface (`check`, `list`, `create`, `update`, `comment`) so Jira can follow; backend `github`
  (REST, token from a 0600 file, GitHub Enterprise via `api_url`). Idempotent through a marker in the body (no local
  mapping; duplicates are closed); closes when the ledger marks the finding fixed (only after a run covered the
  asset), closes as not planned with `accepted-risk` for an approved exception, reopens with a comment on a
  regression or an expired exception; labels added by people are kept. Body minimal by default (control, asset,
  severity, first seen, evidence pointer; more with `fields`). Private repositories only. Rate-limit aware
  (`write_interval`, X-RateLimit-Reset / Retry-After up to `max_wait`, `max_writes` per run), `dry_run`.
- **adapters/siem.py 0.1.0** (new): ledger findings as OCSF 1.x Finding events (activity Create / Update / Close) to
  an HTTP collector (ndjson or JSON array, bearer token from a file, batching, retry with backoff), a file (JSON lines,
  0600, rotation) or stdout. Per-sink state advances only after a batch was accepted.
- **core 0.7.0**: `core/export.py` drives the instance's `export.tickets` / `export.siem`; every sink runs even if one
  fails; `metrics/export.prom` (`security_export_last_success_timestamp_seconds`, `_failures_total`,
  `_consecutive_failures`, `_items{sink,result}`).
- **runner 0.8.0**: job type `export` (`dry_run: true` plans only); `export.prom` is published with the other metrics.
- **generators 0.7.0**: alert `SecurityExportFailing` (3 failed runs in a row), runbook `export-failing`.
- **scorecard 0.4.0**: instance scope. `scorecard.not_applicable: {<control id | glob | tag:<tag>>: <reason>}` and
  `overrides.<id>.disabled` make controls not applicable (listed with the reason, excluded from every score);
  `unconfigured_collectors: not_applicable` (opt-in; default `unknown`) excludes controls over collectors the
  instance never runs (no job, no document) unless a human can attest them; a dimension whose every control is not
  applicable is itself not applicable. People catalog: tags `ai-agent` (the six AI agent controls) and
  `overlay-network`. Existing configurations: scores unchanged (dimensions, pillars, functions compared on the same
  data before and after); a control disabled by `overrides` is now listed as `na` with its reason instead of being
  dropped from the report.
- **cli 0.2.1**: `export` is a non-collector job in `sp` listings.
- **docs**: integrations.md (division of responsibility: detection and alerting in the SIEM / posture services,
  aggregation, de-duplication, ledger, scoring and remediation SLOs here; tickets; SIEM), instance-reference
  `export` and `scorecard` keys, scorecard instance scope and IdP/MDM evidence, adapters.

## 2026-11-25 — GCP scans with the operator's login; GCP discovery

- **adapters/cloud.py 0.2.0**: GCP `source: adc` (default stays `workload_identity`) for human-run / trial scans: the
  operator's gcloud Application Default Credentials (`authorized_user` only; `adc_file`, `GOOGLE_APPLICATION_CREDENTIALS`
  or gcloud's well-known file; mode 0600 required; a service-account key file is refused) -> refresh token -> user
  access token, used only for `generateAccessToken` of `service_account` (1 h). Nothing of the ADC is cached, logged or
  written; the same self-verification (refuse when over-privileged); evidence = service-account principal + `source`.
  Engines act as the service account, never as the operator: `engine_auth: access_token` (default; Prowler reads
  `CLOUDSDK_AUTH_ACCESS_TOKEN`, not refreshed) or `impersonate` (Prowler `--impersonate-service-account`); gcloud's
  config directory is an empty private one for the engine. Failures (ADC missing, `invalid_grant`, 403, 404) are
  coverage gaps with a reason. `oauth_token_url` configurable.
- **fix (GCP self-verification)**: the project IAM policy is read at policy version 3. A time-bound (conditional)
  grant was returned at version 1 as `<role>_withcond_<hash>`, unknown to the read-only allow-list, so a correctly
  scoped audit service account with an expiry was refused as over-privileged (found against a real project; the fakes
  now return conditional bindings like Google). The evidence lists conditional grants.
- **collector cloud 0.2.0**: Prowler `--impersonate-service-account` when asked; ScoutSuite is not run with GCP
  `source: adc` (it can only act as whoever `google.auth.default()` finds) - a gap of that engine with the reason; an
  engine-credential failure is a coverage gap instead of an exception.
- **adapters/discovery.py 0.5.0**: `gcp` discovery - Compute Engine VM instances of one or more projects (Cloud Asset
  `searchAllResources`, or `compute` aggregated `instances.list`), read-only, login and self-verification as a cloud
  GCP account, pagination, `max_hosts`, `address: external|internal`, `include_stopped`.
- **e2e/cloud-localstack**: `cloudmock.py` serves `oauth2.googleapis.com/token` (refresh-token grant; which user may
  impersonate which service account) and `cloudasset searchAllResources`; the run scans one project with `source: adc`,
  asserts the evidence and the six ADC failure modes, and lists instances with `discovery gcp`.
- **docs**: cloud.md (when to use `adc` vs workload identity, how engines authenticate), instance-reference, adapters.md.

## 2026-11-25 — scale benchmark

- **core 0.6.3**: the ledger indexes each document's coverage once (`ledger.Coverage`) instead of scanning every
  coverage entry for every finding that appeared or disappeared: a repeat run at 100k findings / 10k assets went from
  ~30 s to ~5 s. Same rules (tested against the linear rule on random inputs); no contract change.
- **bench/scale.py** (new): synthetic findings at chosen sizes, repeated runs with churn, gaps and exceptions; wall
  time and peak RSS of ledger, scorecard, digest and remediation. Smoke size runs in the unit tests; results and
  limits in docs/scale.md.

## 2026-11-25 — cloud security posture (AWS, GCP, Azure)

- **collector cloud 0.1.0** (new): cloud accounts as assets; engine-agnostic (`collectors/cloud/engines.py`): Prowler
  (json-ocsf), Steampipe (this product's own SQL query pack), ScoutSuite; native imports Security Hub (ASFF), Security
  Command Center, Defender for Cloud. Every result maps onto a generic control (`controls.py`: pillar, layer, CIS
  Foundations sections) and the same (resource, control) from several sources is ONE finding listing every source.
  Self-verification before each scan: a write-capable platform identity is `cloud.platform_credential_over_privileged`
  and the account is not scanned (`refuse_over_privileged`, default true). Failures (expired token, wrong audience,
  denied/missing role, unreachable API, engine missing, a service the engine could not list) are coverage gaps.
- **adapters/cloud.py 0.1.0** (new): short-lived credentials only - AWS `AssumeRoleWithWebIdentity` (+ `AssumeRole`
  chain, stdlib SigV4) or an SSO/role profile; GCP workload identity federation + service-account impersonation;
  Azure federated client assertion. In memory, refreshed 300 s before expiry; engines get no secret
  (`credential_process` callback, external-account config, workload-identity variables); long-lived keys refused;
  ambient cloud keys stripped from engine environments. Endpoints configurable (emulators, sovereign clouds).
- **deploy 0.4.0**: `render.py tool-env --tool prowler|steampipe|scoutsuite` builds a pinned external tool under
  `<install>/tools/<tool>/current` (`deploy/tools/prowler.lock` / `scoutsuite.lock` with hashes, `steampipe.json` with
  release SHA-256 and pinned plugin); separate from the runner's environment; ticks never download.
- **scorecard 0.3.0**: `applies_when` for dimensions and controls (`instance`, `coverage_prefix`, `any`): not
  applicable = excluded from every score and listed under `not_applicable`, never a penalty. New dimension 12
  `cloud` (CIS AWS v3.0 / GCP v2.0 / Azure v2.0 sections per control, `cis_benchmarks`), not applicable without cloud
  accounts, imports or covered cloud assets; `self.cloud-credential-read-only` (applies with cloud accounts).
  Existing instances without cloud: scores unchanged (verified on a live instance: every dimension, pillar and
  function identical).
- **core 0.6.2**: OCSF export lists `cis-<benchmark>:` references as compliance standards.
- **cli 0.2.0**: plain-language explanations for every cloud control (+ a `cloud.` family text); `sp doctor` knows
  the `cloud` job.
- **attack map**: cloud controls -> ATT&CK techniques.
- **e2e/cloud-localstack/run.sh** (new, local only): LocalStack community 4.14.0 + mock-oauth2-server + a GCP/Azure
  token mock; Prowler, Steampipe and ScoutSuite through OIDC federation into one ledger; failure modes; lifecycle; scorecard N/A;
  no credential on disk; tears down. What it does not prove: docs/cloud.md.
- **docs**: cloud.md (setup per provider, minimal permissions, data handling, validated-where, licences),
  instance-reference `cloud`, scorecard `applies_when`.

## 2026-11-24 — fix: release names with component tags

- **bin/sp-install**: names a release after the product tag only (`git describe --match 'v[0-9]*'`); with component
  tags (`runner/v0.7.1`, ...) on the same commit, the release directory would have been named after one of them.
  The e2e record uses the same rule.

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
