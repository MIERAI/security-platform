# instance.yaml reference

The instance config says **what to look at and when**. It is private (it describes your environment) and lives in
your data directory (`sp init` writes a starter). YAML, or JSON on hosts without PyYAML (JSON is valid YAML).

Rules that hold everywhere:

- **Every section is optional.** A missing section means "not used"; nothing fails because you do not have it.
- **Secrets never go in this file.** Every token, password or URL-with-a-token is a `*_file` key pointing at a file
  with mode 0600 (the platform refuses looser files). Paths may start with `~`.
- **Durations** are `30s`, `15m`, `2h`, `7d`. **Schedules** are cron expressions in the host's local time (`TZ`).
- Unknown keys are ignored, so a newer config works with an older release (and the other way round) — see
  [upgrade.md](upgrade.md).

A complete example: `examples/instance.example.yaml`. The end-to-end test's config (a company without an overlay
network or GitHub): `e2e/kind/instance.yaml`.

## Top level

| key | default | meaning |
|---|---|---|
| `name` | `""` | your organisation or environment name; appears in reports and the daily summary |
| `exposure` | — | external view: open ports and services answering without login |
| `hosts` | `[]` | machines checked through an exec adapter |
| `kubernetes` | `[]` | clusters (read-only) |
| `codehost` | `[]` | GitHub, Gitea, Forgejo organisations or users |
| `secrets_files` | `[]` | where secrets lie on disk (metadata only, never values) |
| `agents` | `[]` | AI coding assistants' permission settings |
| `cloud` | — | cloud accounts (AWS, GCP, Azure), check engines and native-service imports ([cloud.md](cloud.md)) |
| `intel` | — | advisories (CISA KEV, EPSS, OSV, Trivy DB) matched against your software inventory |
| `remediation` | owners `unassigned`, SLOs below | who fixes what, by when |
| `advisor` | `{type: none}` | optional AI that drafts text; never changes a status |
| `notify` | `[]` | where the daily summary goes |
| `export` | — | tickets in your issue tracker and OCSF events to your SIEM ([integrations.md](integrations.md)) |
| `scorecard` | enabled, threshold 75 | the programme scorecard ([scorecard.md](scorecard.md)) |
| `runner` | — | jobs, schedules, metrics sinks, multi-host topology |

## exposure

```yaml
exposure:
  discovery:                                   # one or more; results are merged
    - {type: static, targets: [{name: web-1, address: 192.0.2.10}], cidrs: ["192.0.2.0/28"], exclude: ["192.0.2.1"]}
  vantage: {type: ssh, host: scanner}          # where nmap runs: ideally OUTSIDE the scanned network
  extra_ports: "8443,9000-9010"                # on top of nmap's top 1000 and a built-in list
```

| key | default | meaning |
|---|---|---|
| `discovery[].type` | — | `static`, `tailscale`, `file`, `gcp` ([adapters.md](adapters.md)) |
| `static.targets` | `[]` | `{name, address, os?}` |
| `static.cidrs` | `[]` | ranges expanded to host addresses; an address where nothing answers is "no host", not a gap |
| `static.exclude` | `[]` | addresses to skip (e.g. the scanner itself) |
| `static.max_hosts` | `1024` | refuse larger ranges (a typo must not start a /8 scan) |
| `file.path`, `file.max_age` | —, none | a JSON list of `{name, address, os, online}`; older than `max_age` seconds = error |
| `gcp.project_id`, `gcp.project_ids` | —, `[project_id]` | Compute Engine VM instances of these projects (read-only); login keys as a [cloud](#cloud) GCP account (`source`, `service_account`, `workload_identity_provider`, `identity_token`, `adc_file`) |
| `gcp.api` | `cloudasset` | `cloudasset` (Cloud Asset `searchAllResources`, needs `roles/cloudasset.viewer` or `roles/viewer`) or `compute` (aggregated `instances.list`) |
| `gcp.address` | `external` | which address is the target: `external` (an instance without one is listed with no address) or `internal` |
| `gcp.include_stopped`, `gcp.max_hosts`, `gcp.refuse_over_privileged` | false, 1024, true | stopped instances; refuse more instances per project; refuse a write-capable identity |
| `gcp.cloudasset_url`, `gcp.compute_url` | Google's | endpoint overrides (tests, private endpoints) |
| `vantage` | — (required) | an exec adapter config (`{type: local}` or `{type: ssh, host}`); needs python3 + nmap there |
| `extra_ports` | none | nmap port list syntax |

## hosts

```yaml
hosts:
  - {name: web-1, exec: {type: ssh, host: web-1}, profile: linux}
  - {name: my-laptop, exec: {type: local}, profile: macos}
  - {name: printer, exec: null, gap: "no shell access"}      # known but not checkable: shows as a coverage gap
```

| key | default | meaning |
|---|---|---|
| `name` | — | asset name `host:<name>` |
| `exec` | — | `{type: local}` or `{type: ssh, host: <ssh alias or address>, options: [ssh options]}`; ssh runs with BatchMode (no prompts) and StrictHostKeyChecking=yes (put the host keys in known_hosts first) |
| `profile` | — | `linux`, `macos`, `windows` (over OpenSSH, PowerShell), `busybox`, `termux` |
| `gap` | "no exec adapter configured" | the reason shown when `exec` is null |
| `probe_timeout` | `20` | seconds each probe (one command of the profile) may take |
| `slow_probe_timeout` | `90` | seconds for network-dependent probes, which run last: `softwareupdate -l` (macOS), package lists (`apt list --upgradable`, Homebrew), the hotfix list (Windows) |
| `script_timeout` | `max(300, 2 × slow_probe_timeout + 120)` | backstop for the whole profile script; the lines printed before it fires are still used |

A probe that does not finish in time is reported as "could not check" for the checks that read it (a coverage gap
`host:<name>/<part>`, e.g. `host:my-laptop/os-updates`), never as a pass; every other check of the host reports as
usual. Raise `slow_probe_timeout` for hosts whose update check is slow every time.

The account needs key login and `sudo -n` (no password) for read-only commands such as `sshd -T`, `ss -tlnp`,
`ufw status`. Without sudo the checks that need it are skipped and reported.

## kubernetes

```yaml
kubernetes:
  - {name: prod, kubeconfig: ~/.kube/prod-readonly.yaml, role: prod, parts: [workloads, rbac, policy, operator]}
```

| key | default | meaning |
|---|---|---|
| `name` | — | the `cluster` label and asset prefix |
| `kubeconfig` | `""` | a file, or `""`/`in-cluster` for the pod's ServiceAccount |
| `role` | — | free text (`prod` makes image vulnerabilities on exposed workloads rank higher) |
| `parts` | all | `workloads`, `rbac`, `secrets` (metadata; needs list secrets), `policy` (PolicyReports), `operator` (the credential used), `cis` (kube-bench, needs `host_exec`) |
| `host_exec`, `kube_bench` | — | `cis` only: an exec adapter to a node and `{benchmark, tarball}` |

Give it a read-only identity (`deploy/kubernetes/hub/rbac.yaml` has one). An admin kubeconfig works but is itself
reported (`k8s.operator_cred_system_masters`).

The Go implementation (`sp k8s collect`, [go.md](go.md)) reads the same keys. It also lists namespaced Roles (K8S-D4;
the RBAC files above already allow it), and a part it cannot read is a gap of that part only — `k8s-identity:<name>`
(rbac), `k8s-cluster:<name>/secrets`, `k8s-cluster:<name>/policy`, `k8s-cluster:<name>/cis`, ... — while the cluster
stays covered (contracts/collector-protocol/SPEC.md, K8S-D1..D3).

## codehost

```yaml
codehost:
  - {type: github, owner: your-org, gh_user: security-bot}
  - {type: gitea, url: https://git.example.com, owner: your-org, token_file: ~/.config/security-platform/gitea.token}
```

| type | keys | collector job |
|---|---|---|
| `github` | `owner`, `gh_user` (an account logged in with `gh auth login`) | `codehost-github` |
| `gitea`, `forgejo` | `url`, `owner` (org or user), `token_file` (scopes `read:repository,read:organization,read:user`), `ca_file?`, `include_private` (default true) | `codehost-gitea` |

## secrets_files, agents

```yaml
secrets_files:
  - {host: web-1, exec: {type: ssh, host: web-1}, roots: ["~", "/etc"], sudo: true, maxdepth: 5, exclude: ["~/src"]}
agents:
  - {type: claude-code, settings: ["~/.claude/settings.json"]}
```

`secrets_files` reports where credentials lie, their permissions and ages — never their content. Defaults:
`maxdepth: 5`, `exclude: []`, `sudo: false`.

## intel

```yaml
intel:
  feeds: [{type: cisa-kev}, {type: epss}, {type: osv, ecosystems: [Go, PyPI]}]   # max_age_hours: 24 each
  update_db: true                    # refresh Trivy's database first
  sbom_max_age_days: 30
  registry_auth: [{host: ghcr.io, username: bot, token_file: ~/.config/security-platform/registry.token}]
  repos: ["~/src/service-a"]         # local checkouts whose dependencies are matched too
```

Defaults: `feeds: []`, OSV `ecosystems: [Go]`, `max_age_hours: 24`, `sbom_max_age_days: 30`, `repos: []`.

The Go implementation (`sp vuln-intel collect`, [go.md](go.md)) reads the same keys and the same cache files, plus per
feed: `url` (a mirror; `osv` a template with `{ecosystem}`, `msrc-cvrf` also `cvrf_url` with `{id}`; https only,
plain http only to a loopback address) and `max_bytes` (download limit; default 64 MiB, larger for OSV/Android
archives). A download that does not parse never replaces the cached copy, and a failed refresh keeps using it (a gap
says so; VULN-D1..D3). It refuses (exit 2) instances with feed `vendor-advisories` or `code_repos`: keep the Python
collector for those.

## identity

```yaml
identity:
  providers:
    - {type: github, api_url: https://api.github.com, accounts: [{gh_user: octo}, {token_file: ~/.config/security-platform/gh.token}],
       orgs: [example-org], repos_owner: octo, expected_collaborators: [a-friend]}
    - {type: tailscale, api_key_file: ~/.config/security-platform/tailscale-api.key}   # or oauth_client_id + oauth_client_secret_file
  credentials: {kubeconfigs: [~/.kube/*.yaml], ssh_dirs: [~/.ssh], docker_configs: [~/.docker/config.json], token_files: []}
  max_token_age_days: 90
```

Accounts take their token from `gh_user` (`gh auth token --user`), `token_file` (mode 0600, else refused) or
`token_env` (the name of an environment variable); the token goes only into the API's Authorization header. `api_url`
(GitHub Enterprise, the overlay network's API, a test server: https only, plain http only to a loopback address),
`token_file` and `token_env` are read by the Go implementation (`sp identity collect`); the Python one uses `gh_user`
and the vendors' fixed hosts. Go also follows pagination, reports unreadable or rate-limited listings as gaps and reads
organisation members without 2FA where the token may (IDENTITY-D1..D5).

## remediation

```yaml
remediation:
  tracker: {type: files}             # private markdown in the data dir; or {type: github-issues, repo: org/PRIVATE-repo, enabled: true}
  default_owner: security-oncall
  owners:                            # first match wins
    - {layer_in: [workload, supply-chain], owner: platform-team}
    - {asset_prefix: "repo:", owner: dev-team}
    - {check_prefix: "patch.", owner: it}
    - {severity_in: [critical], owner: security-oncall}
  slo: {kev_exposed: 1d, critical: 7d, high: 30d, medium: 90d, low: 180d}   # these are the defaults
```

Without `default_owner`, unmatched items are `unassigned` (reported). A finding closes only when a scan confirms it.

## notify

The daily summary (`sp digest`): counts, plain-language headlines, finding ids. Never asset names or addresses.

```yaml
notify:
  - {type: telegram, token_file: ~/.config/security-platform/telegram.token, chat_id: "123456789"}   # or chat_id_file
  - {type: webhook, url_file: ~/.config/security-platform/slack.url, format: slack}   # slack | json | text
  - {type: exec, argv: [mail, -s, "security summary", ops@example.com]}               # text on stdin; exec: {...} for a remote host
  - {type: file, path: /var/www/status/security.txt}
  - {type: stdout}
runner:
  jobs:
    notify: {type: notify, schedule: "0 8 * * *", days: 1}
```

`webhook` `format`: `slack` (`{"text"}`: Slack, Mattermost, Rocket.Chat), `json` (`{"title","text"}`: Teams
workflows, generic), `text` (plain body: ntfy, Gotify-like). Default `slack`. Adding a notifier: [adapters.md](adapters.md).

## cloud

Collector `cloud` ([cloud.md](cloud.md)). Without this section the cloud scorecard dimension is *not applicable*.

```yaml
cloud:
  refuse_over_privileged: true        # default: an identity that can write is reported AND not used (per account too)
  accounts:                           # one entry per AWS account / GCP project / Azure subscription
    - provider: aws                   # aws | gcp | azure
      account_id: "123456789012"
      mode: web_identity              # default; or `profile` (an SSO/role profile: aws configure export-credentials)
      role_arn: arn:aws:iam::123456789012:role/security-platform-audit
      audience: sts.amazonaws.com     # optional pre-check of the token's aud (all providers)
      identity_token: {type: file, path: /var/run/secrets/tokens/aws}   # | {type: command, argv: [..]} | {type: env, name: X}
      chain_role_arn: ...             # optional: then AssumeRole into this role (cross-account), `external_id` optional
      session_seconds: 3600           # default 3600; refreshed 300 s before expiry
      regions: [eu-west-1]            # first = home region
      endpoint_url: http://127.0.0.1:4566   # optional: an emulator (the e2e) or a private endpoint
      engines: [prowler, steampipe]   # default: every key of cloud.engines (prowler if none); [] = login + self-check only
    - provider: gcp
      project_id: my-project
      workload_identity_provider: projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>
      service_account: audit@my-project.iam.gserviceaccount.com
      identity_token: {type: file, path: ...}
      project_ids: [my-project, other-project]       # optional: what the engines scan (default project_id)
      # sts_url, iamcredentials_url, resourcemanager_url: optional endpoint overrides (default: Google's)
    - provider: gcp                   # a HUMAN-RUN scan (trial, investigation) with the operator's gcloud login
      project_id: my-project
      source: adc                     # default workload_identity (unattended); adc = Application Default Credentials
      service_account: audit@my-project.iam.gserviceaccount.com    # impersonated (operator: serviceAccountTokenCreator)
      adc_file: ~/.config/gcloud/application_default_credentials.json   # optional; default GOOGLE_APPLICATION_CREDENTIALS,
                                      #   then $CLOUDSDK_CONFIG or ~/.config/gcloud; authorized_user only, mode 0600
      engine_auth: access_token       # default: Prowler gets the SA's 1 h token only (scan must fit in session_seconds);
                                      #   impersonate: Prowler --impersonate-service-account (refreshes; reads the ADC)
      # oauth_token_url: optional endpoint override (default https://oauth2.googleapis.com/token)
    - provider: azure
      subscription_id: ...
      tenant_id: ...
      client_id: ...                  # app registration / user-assigned identity with a federated credential
      identity_token: {type: file, path: ...}
      subscription_ids: [...]         # optional
      # authority_host, arm_url, scope: optional endpoint overrides (default: Microsoft Entra / ARM public cloud);
      #   with the Go implementation the authority must be https and the root of a host (https://<host>[:port])
      # ca_file: optional, every provider (Go implementation only): PEM CA certificates trusted in addition to the
      #   system's for this account's endpoints (an emulator, a sovereign cloud, a TLS-inspecting proxy)
  engines:                            # external processes; install with `render.py tool-env --tool <name>`
    prowler:    {path: <install>/tools/prowler/current/bin/prowler, checks: [..], services: [..], excluded_checks: [..],
                 scan_unused_services: true, timeout: 3h, extra_args: []}
    steampipe:  {path: <install>/tools/steampipe/current/bin/steampipe, install_dir: <install>/tools/steampipe/current/home,
                 plugin: aws@1.34.1, queries: [ids], timeout: 10m}
    scoutsuite: {path: <install>/tools/scoutsuite/current/bin/scout, services: [..], timeout: 3h}
  imports:                            # exports of the provider's own posture service, merged with engine results
    - {type: securityhub, file: <ASFF json>, max_age: 2d, accounts: ["123456789012"]}
    - {type: scc, file: <gcloud scc findings list --format=json>, accounts: [my-project]}
    - {type: defender, file: <Resource Graph securityresources assessments json>, accounts: [<subscription id>]}
runner:
  jobs:
    cloud: {schedule: "30 4 * * *", timeout: 4h}
```

Refused: any long-lived key in an account entry (`access_key_id`, `secret_access_key`, `client_secret`,
`private_key`, ...). An import older than `max_age` (default 2d) is a coverage gap, not a pass.

## export

Into the team's own tools ([integrations.md](integrations.md)); run by a job of type `export`. Every sink runs even if
another fails; a failing sink is retried on the next run (`SecurityExportFailing` after 3 in a row).

```yaml
export:
  tickets:
    - {type: github, repo: example-org/security-findings, token_file: ~/.config/security-platform/issues.token}
  siem:
    - {type: http, url: https://logs.example.internal/ingest, token_file: ~/.config/security-platform/siem.token}
    - {type: file, path: /var/log/security-platform/findings.jsonl}
runner:
  jobs:
    export: {type: export, schedule: "55 * * * *"}     # dry_run: true = log the plan, write nothing
```

Tickets (`export.tickets[]`):

| key | default | meaning |
|---|---|---|
| `type` | — | `github` (`jira`: interface only, not implemented) |
| `repo` | — | `owner/name`; must be private (internal counts) or the sink refuses to run |
| `token_file` | — | 0600 file; fine-grained token with Issues read/write and Metadata read on that repository |
| `api_url` | `https://api.github.com` | GitHub Enterprise Server: `https://<host>/api/v3` |
| `min_severity` | `high` | new tickets only at or above; an existing ticket stays managed whatever the severity |
| `fields` | `[control, asset, severity, first_seen, evidence]` | body rows; also `title`, `layer`, `status`, `last_seen`, `owner`, `due`, `remediation`, `exception` |
| `title` | `check` | `check`: "[sev] check on asset"; `finding`: "[sev] <finding title>" |
| `evidence_url` | none | template with `{evidence}` (the private evidence pointer) on a private host; else the pointer as text |
| `labels` | `{base: security-platform, accepted: accepted-risk, severity_prefix: "severity:"}` | managed labels (other labels are left alone); `severity_prefix: ""` = none |
| `create_accepted` | `false` | also open (and immediately close as accepted) tickets for findings that never had one |
| `dry_run` | `false` | log what would change; read-only API calls only |
| `max_writes` | `100` | writes per run; the rest follows on the next run |
| `write_interval`, `max_wait`, `timeout` | `1s`, `60s`, `30` | pause between writes; longest wait for a rate-limit reset (longer = stop, continue next run); HTTP timeout |
| `name` | `tickets-<type>-<index>` | the `sink` label in `security_export_*` |

SIEM (`export.siem[]`):

| key | default | meaning |
|---|---|---|
| `type` | — | `http`, `file`, `stdout` |
| `mode` | `changes` | `changes`: new / status, severity or title changed (Create / Update / Close); `all`: every entry every run |
| `min_severity` | `info` | send only at or above |
| `url`, `token_file`, `auth_scheme` | —, none, `Bearer` | http: endpoint; `Authorization: <auth_scheme> <token>` |
| `format`, `wrap`, `headers` | `ndjson`, none, `{}` | http: `ndjson` or `json` (array); `wrap: event` = `{"event": {...}}`; extra non-secret headers |
| `batch_size`, `retries`, `timeout` | `500`, `3`, `30` | http: events per POST; retries on 429 / 5xx / connection errors (Retry-After honoured) |
| `path`, `max_bytes` | —, 100 MB | file: JSON lines, mode 0600, rotated to `<path>.1` |
| `name` | `siem-<type>-<index>` | the `sink` label and the state file `<data>/state/export/<name>.json` |

## scorecard

See [scorecard.md](scorecard.md). Defaults: `enabled: true`, `threshold: 75`, the product catalog only.

| key | default | meaning |
|---|---|---|
| `threshold` | `75` | a dimension below it fails the scorecard |
| `catalog_dirs`, `replace_catalog` | `[]`, `false` | your own catalog files, added to (or replacing) the product's |
| `overrides` | `{}` | per control: `weight`, `source`, `check`, ... ; `disabled: <reason>` = not applicable |
| `not_applicable` | `{}` | map of control id, glob or `tag:<tag>` to a reason: out of scope for this instance, excluded from every score; a reason is required. Product tags: `ai-agent`, `overlay-network` |
| `unconfigured_collectors` | `unknown` | `not_applicable`: a control that needs a collector this instance neither runs nor receives documents from is excluded (unless a human can attest it); default `unknown` counts it as failing |
| `vars`, `pillars`, `enabled` | | see [scorecard.md](scorecard.md) |

A dimension whose every control is not applicable is itself not applicable.

## runner

```yaml
runner:
  site: hub                          # this runner's label in metrics (a role, not a device name)
  role: hub                          # hub: keeps the ledger, publishes metrics; site: only fills an outbox
  tick_stale_after: 1h               # heartbeat threshold for SecurityRunnerStale (a laptop hub: 12h)
  retention: 30d                     # delete runs/<date>/ older than this (default: keep)
  implementations:                   # which implementation runs a component (default python for all)
    ledger: shadow                   # python | go | shadow
    remediation: python
  go_binary: /usr/local/bin/sp       # optional; default /usr/local/bin/sp, then `sp` on PATH
  sinks:
    - {type: textfile, path: /var/lib/node_exporter/textfile/security-platform.prom}
    - {type: kubernetes-configmap, kubeconfig: ~/.kube/config, namespace: security-platform, name: security-platform-metrics}
    - {type: remote_write, url: https://metrics.example.com/api/v1/write, bearer_token_file: ~/.config/security-platform/rw.token}
  jobs:
    host: {schedule: "15 2 * * *", jitter: 30m, timeout: 30m, retries: 2, retry_delay: 30m}
```

| job key | default | meaning |
|---|---|---|
| `type` | `collector` | `collector`, `command`, `ingest`, `remediation`, `export`, `digest`, `notify`, `snapshot`, `push`, `pull-snapshot` |
| `collector` | the job name | which collector (e.g. job `intel` with `collector: vuln-intel`) |
| `schedule` | — (required) | cron, local time |
| `jitter` | `0` | deterministic offset per job and slot, spreads load |
| `timeout` | `1h` (collectors), `10m` (remediation, digest), `5m` (notify) | the whole process group is killed after it |
| `retries`, `retry_delay` | `0`, `15m` | extra attempts per slot |
| `max_delay` | none (catch up once) | skip a slot older than this (keep heavy scans off-peak) |
| `env` | `{}` | non-secret environment variables |
| `as` | — | report under another collector name (the same collector deployed twice) |

Sinks: `textfile` (`path`, `exec?`), `kubernetes-configmap` (`kubeconfig?`, `context?`, `namespace`, `name`,
`key` default `security-platform.prom`), `remote_write` (`url`, `bearer_token_file?`, `labels?`, `timeout` default 30).
Multi-host topologies (sites, inbox, forward, ingest, snapshots): [runner.md](runner.md).

**Implementation switch** (`implementations`, `go_binary`; runner contract §7). Components: `ledger` (the merge after
every collector run and ingest) and `remediation` (the `remediation` job). Values:

| value | runs | outputs used |
|---|---|---|
| `python` (default) | the Python reference (`core/ledger.py`, `core/remediation.py`) | Python's |
| `go` | the Go `sp` binary (`sp ledger merge`, `sp ledger track`); if no Go binary is found, Python runs (logged once) | Go's |
| `shadow` | Python as usual, then Go on a temporary copy of the inputs; the outputs are diffed | Python's only |

The Go binary is `go_binary`, else `/usr/local/bin/sp` (the runner image), else `sp` on `PATH`; it is used only when
`sp version --json` lists the component's subcommand, so the Python `bin/sp` is never mistaken for it. A shadow run
writes `<run>/shadow-<component>.json` (every difference, those explained by a known deviation's target marked
`explained`, e.g. LEDGER-D2 due dates) and `<run>/shadow-<component>.log`, and exports
`security_impl_shadow_diffs{component}` (unexplained, alert-worthy when > 0), `security_impl_shadow_explained_diffs`
and `security_impl_shadow_last_run_timestamp_seconds`. A shadow `remediation` never calls an external tracker (the Go
side runs with `--no-external-sync`) and both sides get the same `--now`. How to move a component step by step:
[contracts.md](contracts.md).
