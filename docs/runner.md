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

`runner.py status --instance F --data D` prints each job's state and whether it is due.

## Triggers (deployment adapters)

`deploy/render.py <target>` renders them; every target calls the same `tick.sh` wrapper (`render.py wrapper`), which
sets PATH/TZ, `nice`, rotates its log, and runs `runner.py tick`. Install the product with `bin/sp-install` (a
versioned release directory per commit, `current` symlink; rollback = point `current` back).

| target | where | notes |
|---|---|---|
| `launchd` | macOS | LaunchAgent with `StartInterval`; a sleeping Mac catches up once on wake |
| `cron` | any Unix | one crontab line |
| `systemd` | Linux | `.service` + `.timer`, `Persistent=true` |
| `termux-job` | Android (Termux) | JobScheduler, 15 min minimum, survives reboots (`--persisted`); no cron daemon needed |
| Kubernetes | a cluster | `deploy/kubernetes/`: the metrics exporter; `cronjob/` for an in-cluster site |

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
4. Only `alertable` matches page: affects our assets AND (KEV OR critical on an exposed asset). The rest is in the
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
