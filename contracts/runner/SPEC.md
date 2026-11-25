# Contract: runner — version 1.0

| | |
|---|---|
| contract | `runner`, version **1.0** (files: `security-platform/runner-state/v1`, `control/v1`, `snapshot/v1`) |
| schemas | [`runner-config-v1.schema.json`](runner-config-v1.schema.json) (the `runner:` block), [`runner-state-v1.schema.json`](runner-state-v1.schema.json), [`runner-status-v1.schema.json`](runner-status-v1.schema.json) |
| executable | reference `runner/runner.py`, impl `SP_IMPL_RUNNER` |
| conformance | `conformance/cases/runner/*` (a fake clock: `--now`) |
| background | `docs/runner.md` (operations, topologies), `docs/instance-reference.md` |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

The runner keeps everything going: any trigger (cron, launchd, systemd timer, Termux job, Kubernetes CronJob) calls
`tick` every 5–15 minutes; the schedule itself lives in the instance config, so the trigger stays dumb.

## 1. Commands

```
<runner> tick    --instance F --data D [--now EPOCH] [JOB ...]   run whatever is due, then publish; exit 0
<runner> run     --instance F --data D JOB ...                   run these jobs now, ignoring the schedule; exit = max job rc
<runner> status  --instance F --data D [--now EPOCH]             one JSON object on stdout (schema runner-status-v1)
<runner> metrics --instance F --data D                           (re)publish the metrics
<runner> serve-metrics --dir DIR [--port 9851]                   HTTP GET /metrics = every DIR/*.prom; /healthz, /ready
<runner> version                                                 the runner's version
```

- `tick` with `JOB ...` considers only those jobs and skips store-and-forward and pruning.
- `tick` MUST exit 0 whatever its jobs did (a failing job is reported in its state and metrics, not to the trigger);
  only a runner that cannot start (unreadable instance) exits 78. `run` exits with the highest job exit code.
- `--now`: the scheduling clock (epoch seconds). It decides which slot is due (and, TARGET RUNNER-D1, every timestamp
  the runner records). Without it: the wall clock.
- Every log line goes to stderr as `<local ISO 8601 time with offset> runner: <message>`; the trigger appends stdout
  and stderr to `<data>/state/runner/tick.log` (the rendered `tick.sh` wrapper adds `tick.sh: runner exited rc=N`).

## 2. Configuration (the `runner:` block the runner owns)

`site` (metrics label, a role not a device name; default `hub`), `role` (`hub`: keeps the ledger and publishes;
`site`: only fills an outbox), `outbox`, `state_outbox`, `forward`, `sinks`, `retention`, `tick_stale_after` (default
1h), `jobs`. Per job: `type` (default `collector`), `collector` (default the job name), `as`, `argv` (command),
`schedule` (5-field cron, required), `jitter`, `timeout`, `retries` (default 0), `retry_delay` (default 15m),
`max_delay`, `env`, plus type-specific keys (`docs/runner.md`). Durations: `<n>s|m|h|d|w` or seconds.

| type | what it runs | success |
|---|---|---|
| `collector` | the product's collector `collector` ([collector-protocol](../collector-protocol/SPEC.md)) | exit 0 and a valid findings document |
| `command` | `argv`: any program honouring the collector protocol | same |
| `ingest` | pull a site's outbox (spool) into the ledger; `site_state`, `accept_control`, `publish_assets`, `site_collectors` | every valid document merged (invalid ones stay in the outbox: 65) |
| `remediation` | [ledger track](../ledger/SPEC.md) | exit 0 |
| `export` | issue tracker / SIEM export (`core/export.py`) | exit 0 |
| `digest`, `notify` | the summary ([cli](../cli/SPEC.md)) | exit 0 |
| `snapshot`, `pull-snapshot`, `push`, `events` | audit trail, control files, event shipping | exit 0 |

## 3. Schedule semantics

Times are cron expressions in the **local time zone of the runner process** (`TZ`). For each job, at time `now`:

1. `slot` = the latest cron fire time ≤ `now` (minute resolution). If `now < slot + offset(job, slot)` the slot's
   jittered start is still ahead: use the previous fire time instead. `offset` = `int(sha1("<job>|<slot>")[:8], 16) mod
   jitter` (deterministic per job and slot, so every implementation spreads load the same way); 0 without `jitter`.
2. `done_slot ≥ slot` → nothing (**done**). Every slot runs at most once successfully.
3. `max_delay` set and `now − slot > max_delay` → skip (**missed (older than max_delay)**).
4. the slot was already attempted and failed: `attempts > retries` → nothing (**retries exhausted**);
   `now < last_attempt + retry_delay` → nothing (**waiting to retry**); else run again (**retry n**).
5. else run (**due**).

Consequences the suite checks: after downtime only the **newest** missed slot runs (once), not every missed slot
(catch-up once); a slot that failed is retried at most `retries` times, then given up (`done_slot = slot`) until the
next slot.

## 4. Execution

- **No overlap**: one lock per job (a job never runs twice at once: the second attempt is skipped and logged), one
  tick lock (a `tick` that finds another tick running exits 0 at once), one ledger lock (merges are serialized,
  blocking). Locks are advisory file locks under `<data>/state/runner/locks/`, released when the process dies.
- **Run directory**: `<data>/runs/<YYYY-MM-DD>/<HHMMSS>-<job>/`, fresh per run.
- **Environment** of a collector/command job: the runner's environment plus `SP_INSTANCE`, `SP_DATA`, `SP_RUN_DIR`,
  `SP_INPUT_DIR` (= `<data>/latest`), `SP_INSTANCE_NAME`, the job's `env`, and `SP_COLLECTOR_NAME` when `as:` is set.
- **Timeout** (default 1h for collectors): SIGTERM to the job's process group, SIGKILL 30 s later; recorded as 124.
- **Result codes recorded** (`last_rc`): the job's own exit code; 124 timeout; 65 document violates the findings
  contract; 1 exit 0 without a document; 70 internal error of the runner while running the job; 64 bad job config
  (`push`: unknown control kind); 75 forward failure (`forward-<i>` state).
- **Success of a collector/command job**: the document is promoted to `<data>/latest/` (with its `.prom`, derived from
  the document when the job wrote none, and `inventory.*.json`); then `site` → queued in the outbox; `hub` → merged into
  the ledger (and copied to the outbox if one is configured). A failure promotes nothing.
- **State** (`<data>/state/runner/<job>.json`, schema `runner-state-v1`, written atomically) after every run:
  `runs_total`, `failures_total`, `last_rc`, `last_duration`, `last_note`, `last_run_dir`, `runner_version`,
  `last_attempt` (start), `last_success` (end of the last success), `slot`, `attempts`, `done_slot`. Sites send the
  public subset (`last_success`, `last_attempt`, `last_rc`, `last_duration`, `runs_total`, `failures_total`,
  `runner_version`) to `state_outbox`; a hub's ingest keeps them in `<data>/state/sites/<site>.json`.
- **After the jobs** (`tick` without job arguments): store-and-forward (`forward`, every tick, ack only what was
  delivered; state `forward-<i>`), pruning of `runs/<date>` older than `retention`.
- **Publish** (role hub, every `tick`/`run`/`metrics`): recompute the scorecard (`scorecard compute --now`, unless
  `scorecard.enabled: false`; a failure is logged, the previous file stays), then build the metrics text =
  `latest/*.prom` + `metrics/{ledger,remediation,export,scorecard}.prom` + the runner's own series, merged by family
  (one HELP/TYPE per family), write it to `<data>/metrics/security-platform.prom` and hand it to every sink. A failing
  sink is counted (`state/runner/sinks.json`, `security_runner_sink_*`), retried next tick, and never fails the tick
  or blocks the other sinks.

## 5. `status`

One JSON object: job name → its state (§4) plus `due` (the reason string of §3: `due`, `retry <n>`, `done`,
`waiting to retry`, `retries exhausted`, `missed (older than max_delay)`, `no slot`) and `schedule`. A job that never
ran has `runs_total: 0`. This is the machine-readable job status; `sp status` is for humans.

## 6. Metrics

The runner's series (all with label `site`; job series also `job`; sink series also `sink="<index>-<type>"`) are listed
in the [metrics registry](../metrics/registry.json) with producer `runner`. Heartbeats: `security_runner_tick_timestamp_seconds`
with its threshold `security_runner_tick_max_gap_seconds` (`tick_stale_after`) drive the stale-runner alert.

## Known deviations

| id | current behaviour (reference) | target | case |
|---|---|---|---|
| RUNNER-D1 | with `--now`, `due` uses the fake clock but `last_attempt`, `last_success`, the tick heartbeat and the scorecard `--now` use the wall clock; a retry therefore ignores `retry_delay` under a fake clock | every time the runner records or compares comes from one clock (`--now` when given) | `runner/retry-waits-for-retry-delay` |
| RUNNER-D2 | a slot that will never run (skipped by `max_delay`, or given up after `retries`) leaves no trace in the metrics; after downtime nothing shows that scheduled work was missed until the catch-up tick | count it: `security_runner_job_missed_slots_total{site,job}`; and expose the due-but-not-done slot as `security_runner_job_pending_slot_timestamp_seconds{site,job}` (see CLI-D1 for `sp status`) | `runner/missed-slot-is-visible` |
| RUNNER-D3 | the reference's usage text mentions `--only JOB ...`; the actual interface is positional `JOB ...` (`--only` is rejected) | positional `JOB ...` as in §1 (documentation fix) | — |

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents runner 0.9.0) |
