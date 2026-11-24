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
| `intel` | — | advisories (CISA KEV, EPSS, OSV, Trivy DB) matched against your software inventory |
| `remediation` | owners `unassigned`, SLOs below | who fixes what, by when |
| `advisor` | `{type: none}` | optional AI that drafts text; never changes a status |
| `notify` | `[]` | where the daily summary goes |
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
| `discovery[].type` | — | `static`, `tailscale`, `file` ([adapters.md](adapters.md)) |
| `static.targets` | `[]` | `{name, address, os?}` |
| `static.cidrs` | `[]` | ranges expanded to host addresses; an address where nothing answers is "no host", not a gap |
| `static.exclude` | `[]` | addresses to skip (e.g. the scanner itself) |
| `static.max_hosts` | `1024` | refuse larger ranges (a typo must not start a /8 scan) |
| `file.path`, `file.max_age` | —, none | a JSON list of `{name, address, os, online}`; older than `max_age` seconds = error |
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

## scorecard

See [scorecard.md](scorecard.md). Defaults: `enabled: true`, `threshold: 75`, the product catalog only.

## runner

```yaml
runner:
  site: hub                          # this runner's label in metrics (a role, not a device name)
  role: hub                          # hub: keeps the ledger, publishes metrics; site: only fills an outbox
  tick_stale_after: 1h               # heartbeat threshold for SecurityRunnerStale (a laptop hub: 12h)
  retention: 30d                     # delete runs/<date>/ older than this (default: keep)
  sinks:
    - {type: textfile, path: /var/lib/node_exporter/textfile/security-platform.prom}
    - {type: kubernetes-configmap, kubeconfig: ~/.kube/config, namespace: security-platform, name: security-platform-metrics}
    - {type: remote_write, url: https://metrics.example.com/api/v1/write, bearer_token_file: ~/.config/security-platform/rw.token}
  jobs:
    host: {schedule: "15 2 * * *", jitter: 30m, timeout: 30m, retries: 2, retry_delay: 30m}
```

| job key | default | meaning |
|---|---|---|
| `type` | `collector` | `collector`, `command`, `ingest`, `remediation`, `digest`, `notify`, `snapshot`, `push`, `pull-snapshot` |
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
