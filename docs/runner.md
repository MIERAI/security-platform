# Continuous operation: runner, sites, metrics, intel

Phase 0 ran collectors by hand (`bin/run`). From `runner` 0.1.0 the platform runs itself. This page is the operator's
reference; docs/design.md explains why.

## Topology

```
  site (role: site)                         hub (role: hub)                                monitoring
  e.g. an external vantage host             keeps the private ledger                       (any Prometheus)
 ┌──────────────────────────┐   spool    ┌───────────────────────────────────┐  sink   ┌────────────────────┐
 │ trigger → runner tick    │──────────▶ │ trigger → runner tick             │───────▶ │ textfile / ConfigMap│
 │  exposure (nmap) ...     │  (exec:    │  collectors, ingest (pull sites), │         │ + exporter, or      │
 │  findings → outbox       │   ssh)     │  ledger, digest, metrics          │         │ remote_write        │
 └──────────────────────────┘ ◀──────────│  publishes the asset list to sites│         └────────────────────┘
                                 assets  └───────────────────────────────────┘
```

- **One code base, one config format.** A site is the same runner with `role: site`: it runs its jobs and puts each
  finished findings document into an **outbox** (spool adapter). The hub's `ingest` job pulls outboxes, validates every
  document against the contract and merges it into the ledger in order, then acknowledges it (moved to `sent/`).
- **Sites that cannot discover assets** (no overlay-network CLI on the device, for example) receive the hub's asset
  list (`publish_assets`) and use the `file` discovery adapter with `max_age`: a list that is too old becomes a
  coverage gap, never a silent scan of the wrong hosts.
- **Collectors never talk to each other.** Inventories (`inventory/v1`) and findings documents are promoted into
  `<data>/latest/`; `vuln-intel` reads the newest inventory from there (`SP_INPUT_DIR`).

## Jobs and the schedule

The schedule is configuration, not the trigger (`runner/runner.py` docstring has every field):

```yaml
runner:
  site: hub
  role: hub
  sinks: [{type: textfile, path: /var/lib/node_exporter/textfile/security-platform.prom}]
  jobs:
    host:      {schedule: "15 2 * * *", jitter: 30m, timeout: 30m, retries: 2, retry_delay: 30m}
    intel:     {collector: vuln-intel, schedule: "30 6 * * *", timeout: 2h, retries: 2}
    ingest-vantage:
      type: ingest
      schedule: "*/30 * * * *"
      site: vantage
      source: {type: exec, exec: {type: ssh, host: vantage-host}, dir: "~/.local/share/security-platform/outbox"}
      site_state: "~/.local/share/security-platform/site-state"
      site_collectors: {exposure: "30 3 * * *"}        # the site's schedule, for staleness thresholds
      publish_assets: {dir: "~/.local/share/security-platform/assets", discovery: [{type: static, targets: [...]}]}
    digest:    {type: digest, schedule: "0 9 * * 1"}
```

Semantics, all deterministic and unit-tested (`tests/test_runner.py`):

| | |
|---|---|
| slot | the latest cron fire time ≤ now (host local time; set `TZ` in the trigger) |
| catch-up | a missed slot runs once when the host is back (sleeping laptops); `max_delay` skips slots older than that (keeps a heavy scan off-peak) |
| jitter | a deterministic offset in `[0, jitter)` per job and slot |
| retries | `retries` extra attempts per slot, `retry_delay` apart; then the slot is given up, the next one tries again |
| timeout | the job's whole process group gets SIGTERM, then SIGKILL after 30 s; exit code 124 |
| locking | one lock per job (no overlap), one ledger lock (merges serialized), one tick lock (a trigger that fires while a long job runs exits at once) |
| success | exit 0 **and** a findings document that passes the schema; anything else is a failure |
| ledger | every successful job merges into the ledger at once: `fixed` (only for covered assets), `reopened`, exception expiry |

`runner.py status --instance F --data D` (or `sp runner status ...`) prints each job's state and whether it is due.

## Triggers (deployment adapters)

`deploy/render.py <target>` renders them; every target calls the same `tick.sh` wrapper (`render.py wrapper`), which
sets PATH/TZ, `nice`, rotates its log, and runs `runner.py tick`. Install the product with `bin/sp-install` (a
release directory per product tag, `releases/vX.Y.Z`, `current` symlink; rollback = point `current` back;
docs/upgrade.md).

**Offline by design (deploy 0.2.0).** A security monitor must not stop because the network blips, so a tick never
resolves or downloads anything:

```sh
bin/sp-install ~/.local/opt/security-platform                                    # the code (a release)
~/.local/opt/security-platform/current/deploy/render.py env --install ~/.local/opt/security-platform
#   -> envs/<hash>/ from deploy/requirements.lock (exact versions + sha256), `env` -> it; network only here
#      (--find-links DIR for air-gapped hosts; uv when available, else python -m venv + pip)
render.py wrapper --install … --instance … --data …   # default python: <install>/env/bin/python3; exports
                                                       # PIP_NO_INDEX/UV_OFFLINE; refuses `uv run --with …`
```

Hosts with a JSON instance config need no third-party package at all (`--python python3`). Collectors that need the
network (feeds, a remote host, a cluster API) fail on their own and become coverage gaps; the tick goes on.
Every error goes to the runner log (`<data>/state/runner/tick.log`): the wrapper's own (`tick.sh: runner exited
rc=N`, `cannot enter …`), the runner's (`cannot start: …`), and the trigger's stdout/stderr (launchd, systemd, cron
all append to the same file; nothing goes to /dev/null). `tests/test_offline.py` ticks with every socket blocked.

**A broken tick is visible.** The heartbeat `security_runner_tick_timestamp_seconds` and its threshold
`security_runner_tick_max_gap_seconds` (instance `runner.tick_stale_after`, default 1h; a hub that sleeps at night
sets more) drive `SecurityRunnerStale`; it fires whether the trigger, the environment, the host or the only sink to
that cluster is broken. Each sink's result is kept in `state/runner/sinks.json` and exported
(`security_runner_sink_last_success_timestamp_seconds`, `…_failures_total`, `…_consecutive_failures`, label
`sink="<index>-<type>"`); a failing sink (e.g. its namespace does not exist yet) is retried every tick and never
fails the tick; `SecurityMetricsSinkFailing` after 4 in a row.

| target | where | notes |
|---|---|---|
| `launchd` | macOS | LaunchAgent with `StartInterval`; a sleeping Mac catches up once on wake |
| `cron` | any Unix | one crontab line |
| `systemd` | Linux | `.service` + `.timer`, `Persistent=true` |
| `termux-job` | Android (Termux) | JobScheduler, 15 min minimum, survives reboots (`--persisted`); no cron daemon needed |
| Kubernetes | a cluster | `deploy/kubernetes/`: the metrics exporter; `deploy/kubernetes/hub/`: the hub itself (below); `deploy/kubernetes/cronjob/`: an in-cluster site (CronJob → Secret outbox → hub `ingest` with `source: {type: kubernetes-secret, namespace, kubeconfig}`) |

## The Go runner (`sp runner`, runner 0.10.0)

`sp runner tick|run|status|metrics|serve-metrics|version` is a Go implementation of the same runner
(`internal/runner`, contract [runner 1.1](../contracts/runner/SPEC.md)). It passes every runner conformance case with
no expected failure and writes the same files: `state/runner/<job>.json`, `sinks.json`, the tick log lines, the
published metrics, `runs/<date>/<time>-<job>/`. One data directory works with either runner, in both directions
(`tests/test_runner_go.py` switches back and forth on the same directory). It still runs every job exactly as the
Python runner does: collectors, ledger merge, remediation, digest, notify, export and events are started as the same
programs; ingest, push, snapshot, pull-snapshot, spools, non-file sinks and findings validation run the Python
runner's own code through `runner/bridge.py`. So the Go runner can replace the Python one first, while jobs are
still Python. It needs a Unix-like system (process groups, `flock`), as the Python runner does; on Windows use WSL.

What changes when the Go runner ticks (the targets of the contract's known deviations; the Python runner keeps its
behaviour):

| | Python runner | Go runner |
|---|---|---|
| clock (`--now`) | due decisions only | every recorded or compared time (RUNNER-D1) |
| missed slots | not visible | `security_runner_job_missed_slots_total`, `…_pending_slot_timestamp_seconds`; log line `slot … missed` (RUNNER-D2) |
| daylight saving time | gap slot skipped, repeated hour runs twice | one slot per wall-clock time (§3.1; RUNNER-D4…D6) |
| job environment | the runner's whole environment | an allow-list plus `runner.env_passthrough` (RUNNER-D7) |
| a tick that cannot read its instance or has a malformed schedule/duration | crashes later (exit 1) or 78 | exit 78 at start, the reason in the log |
| orphaned job (its runner was killed) | may start a second copy | not started again while the orphan is within its timeout; killed after it |
| runner stopped (SIGTERM/SIGINT) | its job keeps running | the job's process group gets SIGTERM, then SIGKILL; recorded as 124 |

**Before switching**, list the variables your jobs read from the runner's environment that are not on the allow-list
(contract §4: paths, locale, time zone, proxies, CA bundles, the in-cluster API address, `SSH_AUTH_SOCK`, `SP_*`).
Typical: a token a collector reads from the environment (`GH_TOKEN`, an events source's `token_env`):

```yaml
runner:
  env_passthrough: [GH_TOKEN]     # names only; values stay in the trigger's environment, never in the instance
```

Each tick the Go runner logs the *names* of credential-like variables it withholds (`environment: not passed to jobs
…`): an empty line there means nothing is missing; values are never logged.

**Switch** (any trigger: the one line the wrapper or the CronJob runs):

```sh
# tick.sh (deploy/render.py wrapper): replace the runner line
nice -n 10 <install>/env/bin/python3 runner/runner.py tick --instance … --data … >> "$LOG" 2>&1   # Python
nice -n 10 <install>/current/bin/sp runner tick --instance … --data … >> "$LOG" 2>&1             # Go
```

`sp` finds the Python tree it sits in (`<tree>/bin/sp`, else `$SP_PY_HOME`) and its interpreter (`$SP_PYTHON`, else
`python3` on `PATH`): set `SP_PYTHON=<install>/env/bin/python3` in the wrapper so jobs use the pinned environment, as
before. In Kubernetes (`deploy/kubernetes/hub/cronjob.yaml`) the image already carries `/usr/local/bin/sp` and
`SP_PY_HOME`; add `command: ["/usr/local/bin/sp", "runner"]` (the `args` stay) and `SP_PYTHON: python3` to `env`.

**Switch back**: restore the previous line (or remove `command:`). The Go runner's extra state fields
(`missed_slots_total`, `missed_slot`) are ignored by the Python runner, `locks/<job>.owner.json` too; nothing needs
cleaning. Check after either switch: `sp runner status --instance … --data …` (or `runner.py status`) shows the same
`done_slot`/`runs_total` as before, and `tail $SP_DATA/state/runner/tick.log`.

**Shadow first** (docs/contracts.md): run the Go runner as a second trigger on a copy of the data directory, or replay
days with `bench/runner_soak.py`, which ticks both runners at the same fake instants (three days, a two-hour
downtime, a non-UTC zone) and classifies every difference in state, status, metrics, logs, ledger and `latest/`.

**Choosing the programs** (`runner.implementations`, both runners from the release that ships the switch; the Go
runner already): `<component>: python | go | [argv …]` for `ledger`, `remediation`, `scorecard`, `export`, `digest`,
`notify`, `events`, `collectors/<name>`. `python` (the default) is the program in this tree; `go` is a subcommand of
the `sp` binary that runs the runner (`ledger` → `sp ledger merge`, `remediation` → `sp ledger track`, `scorecard` →
`sp scorecard`); a list is an argument vector, `~` expanded, no shell. Unknown names or kinds are refused (64 for the
job, logged for the scorecard).

## In-cluster hub (deploy 0.3.0)

A hub on a workstation stops when the workstation sleeps or goes offline. `deploy/kubernetes/hub/` runs the hub in a
cluster instead; workstations and external hosts become **sites** that push to it.

```
 site: external vantage host        site: operator workstation            cluster (hub namespace)
 exposure → local outbox            host, secrets, agent, intel …         ┌─────────────────────────────────────────┐
     │ forward (every tick,          → local outbox                       │ CronJob security-platform-hub (*/15)    │
     │ retried; ack on delivery)     exceptions/catalog review (push)      │  tick: k8s (read-only), ingest-<site>,  │
     └──────────────┐               │ forward                              │  digest, snapshot, metrics              │
                    ▼               ▼                                      │ PVC: ledger, reports, state, tracker    │
           Kubernetes API (TLS, ServiceAccount tokens)  ── create only ──▶ │ inbox: Secrets sp-* (site label bound   │
                                                                           │  to the writer by admission policy)     │
           operator workstation ◀── get security-platform-snapshot ─────── │ snapshot Secret → pulled off-cluster    │
                                                                           │ ConfigMap security-platform-metrics ──▶ exporter → Prometheus
                                                                           └─────────────────────────────────────────┘
```

| piece | how | least privilege |
|---|---|---|
| trigger | CronJob `*/15`, `concurrencyPolicy: Forbid`; schedule per job in the instance ConfigMap `security-platform-hub` | — |
| state | PVC `security-platform-hub-data` (RWO): ledger, reports, runner state, tracker; `runner.retention` prunes `runs/` | only pods of the namespace mount it |
| identity | ServiceAccount `security-platform-hub` | cluster: get/list namespaces, pods, services, NetworkPolicies, RBAC, PolicyReports — **no Secrets**; namespace: list/get/delete the inbox Secrets, create + patch its own snapshot Secret and metrics ConfigMap (by name) |
| inbox | spool `kubernetes-secret` (adapters/kubeapi.py: HTTPS + bearer token, stdlib only — a phone needs no kubectl) | each site: ServiceAccount `security-platform-site-<site>`, Role `security-platform-inbox-writer` = **create** Secrets only (cannot read, list or delete anything) |
| site identity | ValidatingAdmissionPolicy `security-platform-inbox-identity`: a site SA may only create Opaque `sp-*` Secrets labelled `security-platform/site=<its own name>` | a site cannot speak for another site, mint tokens or plant other Secrets |
| control files | the workstation's `push` job sends `exceptions` / `catalog-review` when they change; the hub accepts them only on ingest jobs with `accept_control` | human approval stays in the operator's private repository |
| network | NetworkPolicy: no ingress; egress only DNS and the API server | — |
| metrics | sink `kubernetes-configmap` over the API (namespace defaults to the pod's) | patch one ConfigMap by name |
| off-cluster copy | `snapshot` job with `to: {type: kubernetes-secret, name: security-platform-snapshot}` (contract `security-platform/snapshot/v1`: tar.gz + manifest with sha256); the workstation's `pull-snapshot` job verifies and extracts it into its private git repository and commits | the workstation's SA: `get` that one Secret by name |

Sites keep working offline: they write to a **local** spool first and `forward` drains it to the inbox on every tick,
acknowledging only what was delivered (`state forward-<i>`, exported like a job: a stuck queue shows up as a failing,
stale job). Tokens: `kubectl create token security-platform-site-<site> --duration=…` from an admin session, stored as
a 0600 file on the site; rotate before expiry (an expired token = a stale site, which alerts).

Example configs: `deploy/kubernetes/hub/hub.example.json` (the hub), `site-identity.example.yaml` (per site). A site's
outbox for the inbox: `{type: kubernetes-secret, namespace: <hub ns>, site: <site>, server: https://<api>:6443,
ca_file: <cluster CA>, token_file: <0600 token>}` (`box: state` for its job states).

### Several hubs in one cluster (deploy 0.5.0)

Most objects of a hub live in its namespace, but four are cluster-scoped: ClusterRole and ClusterRoleBinding
`security-platform-hub-read`, ValidatingAdmissionPolicy and its Binding `security-platform-inbox-identity` (an in-cluster
site, `deploy/kubernetes/cronjob/`, has ClusterRole/ClusterRoleBinding `security-platform-site-read`). Two installations
in one cluster (one hub per environment, each in its own namespace) would otherwise write the same objects: a GitOps
tool shows one of them out of sync forever, and a combined render of several environments has duplicate objects.

Add the component `deploy/kubernetes/unique-names` and name the installation (a lowercase DNS label):

```yaml
namespace: security-staging
resources:  [https://github.com/MIERAI/security-platform//deploy/kubernetes/hub?ref=<tag>]
components: [https://github.com/MIERAI/security-platform//deploy/kubernetes/unique-names?ref=<tag>]
configMapGenerator:
  - { name: security-platform-installation, literals: [name=staging], options: { disableNameSuffixHash: true } }
```

The cluster-scoped names get the suffix (`security-platform-hub-read-staging`, `security-platform-inbox-identity-staging`,
`security-platform-site-read-staging`) and `roleRef` / `policyName` follow. Namespaced names do not change (the
runner, the site ServiceAccounts `security-platform-site-<site>` and the inbox policy rely on them). The ConfigMap
`security-platform-installation` stays in the namespace as a marker. The component fails the build when the ConfigMap
is missing, so it never falls back to the shared names silently. Without the component nothing changes: one
installation per cluster, as before. `tests/test_manifests.py` renders two environments side by side and fails on
any colliding cluster-scoped name, or on a cluster-scoped object that the component does not rename.

Both copies of the admission policy check every Secret creation by a `security-platform-site-*` ServiceAccount in
any namespace, against that namespace's own site name, so two copies give the same verdict.

**Migration of an existing install** (optional; only needed for a second installation in the same cluster): add the
component and the ConfigMap to each overlay. The new objects are created next to the old ones; the old unsuffixed ones
are no longer rendered and are pruned by a GitOps tool with pruning on (or `kubectl apply --prune`). Otherwise delete
them once, after every installation has switched:
`kubectl delete clusterrolebinding,clusterrole security-platform-hub-read; kubectl delete validatingadmissionpolicybinding,validatingadmissionpolicy security-platform-inbox-identity`
(and `security-platform-site-read` for sites). If two installations already shared the old objects, both GitOps
applications may claim them: switch both before deleting. During the switch the old and the new objects grant and
enforce the same rules, so nothing is briefly open or denied.

**Migration (parallel run).** A hub can also be a site of another hub (`outbox` on a hub = a copy): run the old hub
and the in-cluster hub side by side, compare the ledgers, then reduce the old host to its local collectors.

## Metrics delivery (choose per instance)

The hub always writes `<data>/metrics/security-platform.prom` in the Prometheus **text format** (the node_exporter
textfile convention), then hands the same text to every configured sink:

| sink | use when | notes |
|---|---|---|
| `textfile` (local or `exec:` to a host) | a node_exporter / Grafana Alloy / Telegraf / OTel collector already reads a directory | the most portable hand-off; values are scraped with fresh timestamps, staleness is carried by the `*_timestamp_seconds` heartbeats |
| `kubernetes-configmap` + `deploy/kubernetes` exporter | the alerting Prometheus runs in a cluster (Prometheus Operator) | the exporter serves the ConfigMap, a ServiceMonitor scrapes it; alerts get the namespace label that cluster routing expects |
| `remote_write` | a central TSDB that accepts remote-write 1.0 (Mimir, Thanos Receive, VictoriaMetrics, Prometheus with the receiver on) | stdlib encoder (protobuf + snappy literals); `bearer_token_file` must be mode 0600; each publish writes one sample per series, so query with `last_over_time(...[1d])` or publish at least every few minutes |

Recommendation: **text format first** (generic), delivered to wherever the alerting Prometheus scrapes. Push only
when no scrape path exists. Never a Pushgateway (stale values never expire).

Metric contract: names start with `security_`; labels are aggregates or scopes only (`tests/test_outputs.py` lists
the allowed ones) — never an asset, address, port, CVE or finding id.

## Security events (job type `events`, events 0.1.0)

Findings answer "what is misconfigured"; events answer "what is happening". An `events` job reads security events
from hosts and SaaS control planes and pushes them to a Loki push endpoint, where the detection rules
(detections/catalog.yaml, Loki ruler) evaluate them. It is for sources that have no resident log agent: a phone, a
router, a workstation's unified log, a code host account, an overlay network's audit log. Cluster nodes use the
`node-logs` DaemonSet instead (real time).

```yaml
jobs:
  auth-events:
    type: events
    schedule: "*/15 * * * *"          # detection latency for these sources = the schedule (+ the trigger's)
    timeout: 5m
    loki: {url: "http://<log store>/loki/api/v1/push", token_file: "~/.config/security-platform/loki.token"}   # 0600
    sources:
      - {name: self-sshd, type: command, host: <asset>, parser: openssh, exec: {type: local},
         argv: [logcat, -d, -v, epoch, -s, sshd, sshd-session]}
      - {name: router-sshd, type: command, host: <asset>, parser: dropbear, utc_offset: "+08:00",
         exec: {type: ssh, host: <ssh alias>}, argv: [sh, -c, "grep -h dropbear /tmp/messages || true"]}
      - {name: self-sudo, type: command, host: <asset>, parser: macos-unified, exec: {type: local},
         argv: [log, show, --style, ndjson, --info, --start, "{since_local}", --predicate,
                'process == "sudo" OR process == "sshd" OR process == "sshd-session"']}
      - {name: keys, type: file-integrity, host: <asset>, exec: {type: ssh, host: <alias>},
         paths: [{path: "~/.ssh/authorized_keys", user: <account>}]}
      - {name: codehost, type: github-account, host: <account>, token_env: GH_TOKEN, max_repos: 50}
      - {name: overlay, type: tailscale-audit, host: <tailnet>, token_file: "~/.config/security-platform/ts.token"}
```

| | |
|---|---|
| sources | `command` (argv run by the exec adapter, local or ssh; parsers `openssh`, `dropbear`, `sudo`/`syslog` for logcat `-v epoch`, ISO-8601 and BSD syslog lines, `macos-unified` for `log show --style ndjson`; argv placeholders `{since_epoch}`, `{since_local}`), `file-integrity` (sha256 of authorized_keys files → `authorized_keys_changed`), `github-account` (snapshot diff: keys, repository visibility, deploy keys, hooks, app installations + PublicEvent), `tailscale-audit` (configuration audit log API) |
| contract | labels `source` (auth / codehost / overlay-network) and `host`; the raw line (or a compact JSON of the API record, never a token or key material); structured metadata `event`, `user`, `src_ip`, `novel` / `actor`, `repo` |
| delivery | at-least-once: the cursor moves only after Loki accepted the batch; a failing source keeps its cursor, the others go on; exit 1 if any failed (the job's staleness metrics and `SecurityRunnerStale` show it) |
| baseline | a source's first run records a baseline (seen login sources, key hashes, the account snapshot) and reports nothing as new or novel |
| secrets | token files must be 0600 (refused otherwise); state files are written 0600 (`<data>/state/events/<job>/`) |
| API budget | GitHub: conditional requests (ETag; a 304 does not count against the rate limit), `max_repos` caps the per-repository calls; endpoints the token cannot read are recorded as `unsupported`, not failures |

Run once by hand: `runner.py run --instance F --data D auth-events`; dry run without pushing:
`events/ship.py --config <run dir>/events.config.json --state /tmp/x --dry-run`. Source capabilities and required
scopes: docs/detection-sources.md.

## Alerts, SLOs, dashboard

`generators/gen.py [--instance F] [--runbook-url URL]` writes:

- `prometheus-rules.yaml` — **regression-only** alerts: findings entering an SLI's set (`security_sli_new_total`
  increased: a new unauthenticated service, a new KEV match or critical vulnerability on an exposed asset, a new
  critical configuration finding), reopened findings, collector stale (no good run for 2 intervals), ledger stale,
  contract violation, intel feed stale, exception expired. Labels `severity: page|ticket`. A standing backlog never
  alerts; it is reviewed in the weekly digest.
- `slo-platform-slos.yaml` — values for slo-platform's SLO chart: one `age` SLO per collector (freshness) and the
  ledger, one `bool` SLO per SLI (`security_sli_ok`). Burn alerts are silent (`info`): the SLOs are for the error
  budget and the review.
- `grafana-dashboard.json` / `.configmap.yaml` — aggregates only.

## Threat intelligence

The `intel` job is the `vuln-intel` collector on a daily schedule:

1. Feeds with **conditional GET** (ETag / Last-Modified; an unchanged feed is one 304): CISA KEV, EPSS, OSV.dev
   per-ecosystem exports; `update_db: true` also refreshes Trivy's DB.
2. **Re-match** the latest SBOMs (cached by image digest; regenerated after `sbom_max_age_days`, new digests from the
   newest k8s inventory) with Trivy and, independently, with the OSV matcher (semver ranges, Go modules and stdlib).
3. New matches become findings; the ledger computes `time_to_know_hours` from the advisory's publication (or its KEV
   addition, whichever is later).
4. **Retired images**: when every container-image inventory is complete (k8s: the pods of every configured cluster
   were listed), an image that is no longer running closes its findings (fixed, `fixed_reason: asset_retired`), e.g.
   after a workload moved from `app:1.0` to `app:1.1`. If any cluster failed, nothing is retired in that run; the
   findings stay as they were until a complete run. A retired image that comes back reopens them (regression).
5. Only `alertable` matches page: affects our assets AND (KEV OR critical on an exposed asset). The rest is in the
   weekly digest (`digest` job → `<data>/reports/digest/<year>-W<week>.md`).

### Private registries

Trivy needs read access to pull private images for their SBOMs. Give it a **read-only** credential in a file:

```yaml
intel:
  registry_auth: [{host: ghcr.io, username: <user>, token_file: ~/.config/security-platform/registry-ghcr.token}]
```

The file must be mode 0600 (the collector refuses others). For GHCR: a classic personal access token with only
`read:packages` (fine-grained tokens cannot read packages yet). Without it the private images are coverage gaps;
SBOMs already cached for a digest keep being matched.
