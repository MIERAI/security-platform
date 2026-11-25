# Contracts, conformance, and replacing a component

security-platform is built from components that only talk through files and processes: collectors write findings
documents, the ledger merges them, the runner schedules everything and publishes metrics, the scorecard scores, `sp`
shows it. Each of these boundaries is a **language-neutral contract** in [`contracts/`](../contracts/README.md):
a prose spec (MUST / SHOULD), JSON Schemas where data is involved, examples, and a list of known deviations.
Interchangeability comes from these contracts, not from any language: a component may be rewritten in Go, Rust, shell
or anything else, and it may replace the current one when it passes the same black-box
[conformance suite](../conformance/README.md).

## Implementing a component in another language

1. **Pick the contract** of the component (`contracts/<name>/SPEC.md`) and read it whole, including "Known
   deviations": the target behaviour there is what your implementation must do (the reference is allowed to lag).
2. **Match the interface exactly**: the arguments, environment, input files and output files the spec lists. Your
   program may have a different name and extra subcommands; the suite appends its arguments to whatever command line
   you give it (`SP_IMPL_LEDGER="/opt/sp-go/bin/sp ledger merge"`).
3. **Data you write is validated against the schemas**; unknown fields you add are allowed, missing required ones are
   not. Finding ids, schedule jitter and similar derived values are defined bit for bit (sha1 based) so that two
   implementations produce the same ids and the same slots.
4. **Run the suite**:

   ```sh
   SP_IMPL_LEDGER="/path/to/your/ledger" python3 conformance/run.py --component ledger -v
   ```

   Run it with **no** expected-failures list: every case must pass, the target-behaviour cases included.
5. **Metrics**: emit the series your component's producer rows list in
   [`contracts/metrics/registry.json`](../contracts/metrics/registry.json) with the same names, types and label keys.
   Dashboards, alerts and SLOs depend on them.
6. **Versions**: your component has its own version (its `VERSION` file in this repository, or your release's), and it
   declares which contract versions it implements (e.g. "ledger 1.0, findings 1.0–1.2"). A component MUST accept every
   minor of the major it implements.

What the Go rewrite needs first is listed at the end.

## Replacing a component without stopping the platform

The platform keeps running throughout; every step is reversible until the last one.

| step | what | how | leave the step when |
|---|---|---|---|
| 0. conform | the new implementation passes the suite | `conformance/run.py` in its CI, no expected failures | green |
| 1. shadow | run old and new on the **same inputs**; only the old one's outputs are used | see below | the diff is empty (or every difference is an explained known deviation) for at least one full schedule cycle of every job involved — a week for daily jobs |
| 2. switch | the new one becomes the one that writes | change the one place that names the program (below); keep the old one installed | first runs after the switch are green: `sp status`, the heartbeats (`*_timestamp_seconds`), no new `security_contract_invalid_documents` |
| 3. soak | the new one runs alone | normal operation; SLO and alert dashboards unchanged | one release cycle |
| 4. remove | delete the old implementation | a release whose notes say so | — |

**Rollback** at any step after 2: point the same place back to the old program. The data directory format is the
contract's, so the old implementation reads what the new one wrote (same major; unknown fields are ignored). Commit the
data directory first if it is a git repository (the `snapshot` job does this).

### Shadow runs per component

- **Collector**: deploy the new one as a second job with `as: <name>-shadow` (or as a `command` job with its own
  `collector:` name) on the same schedule. Its findings land in the ledger under the shadow name and never resolve the
  real collector's findings. Compare the two documents in `latest/` (`<name>.findings.json` vs
  `<name>-shadow.findings.json`): same ids, coverage, severities. Then remove the shadow job and point the real job's
  `argv` (type `command`) at the new program; ids are identical by contract, so the ledger continues seamlessly.
- **Ledger / track** (built in): set `runner.implementations.ledger: shadow` (and/or `remediation: shadow`) in the
  instance config. The runner keeps running the Python implementation as the source of truth and, after each run, runs
  the Go `sp` binary on a temporary copy of the same inputs (same relative layout and `--now`; the shadow track never
  syncs an external tracker), compares the normalized outputs (`ledger.json`, `ledger.prom`, `sli.prom`, `ocsf.jsonl`;
  `tracker/items.json`, `remediation.prom`, `tracker/*.md`) and writes `<run>/shadow-<component>.json`. Watch
  `security_impl_shadow_diffs{component}` (unexplained differences; must stay 0) and
  `security_impl_shadow_last_run_timestamp_seconds` (the comparison is happening); differences that are the target
  of a known deviation are counted separately in `security_impl_shadow_explained_diffs` and marked `explained` (with
  the deviation id) in the report. The runner attributes them itself: LEDGER-D2 due dates by rule, a reference
  failure on a finding without `kind` as LEDGER-D1, and the rest by re-running Go with
  `--reference-behaviour LEDGER-D5` / `LEDGER-D3` (a difference that disappears there is that deviation's target).
  Nothing the Go side writes reaches the real data directory. `bench/shadow.py` runs the whole procedure on a
  realistic synthetic estate (10k findings, churn, gaps, exceptions, the conformance fixtures).
- **Scorecard, or any component without a registered spec** (pure functions of files): copy the data directory (or
  use the `snapshot` job's tarball), run the new program on the copy after every real run — e.g. a `command`-style
  wrapper or a cron line that runs `new-ledger --run <the same run dir> --data <copy>` — and diff the outputs:
  `jq -S 'del(.updated_at, .runs[].at)' ledger.json` from both sides, `tracker/items.json`, `reports/scorecard.json`,
  and the `.prom` files sorted (`sort | grep -v _timestamp_seconds`). Adding the component to the runner's
  `COMPONENTS` table (argv of each implementation, inputs, outputs, normalization, explained differences) gives it
  the built-in switch.
- **Runner**: run the new runner as a **site** with a private outbox and its own data directory, on the same instance
  (jobs that are read-only only; leave `push`, `export`, `snapshot`, `notify` out of the shadow), with its trigger
  next to the old one. Compare `state/runner/*.json` (slots, `done_slot`, `runs_total`) and `runner status` of both
  after each tick. Switch by changing the trigger's command (`tick.sh` renders one line).
- **CLI**: side by side; compare `sp findings --json`, `--ids`, exit codes. Switch by changing the `sp` symlink.

### Where the program is named (the switch)

| component | switch |
|---|---|
| a collector | the job's `argv` (`type: command`) in the instance config |
| ledger, track | `runner.implementations.{ledger,remediation}: python \| go \| shadow` in the instance config (runner contract §7; default `python`); `go` falls back to Python, logged once, when no Go `sp` binary is found. Rollback = set it back to `python`. |
| scorecard | the runner calls it by path inside the release (`scorecard/scorecard.py`); a release that ships the new implementation changes that path, and the old release stays installed for rollback (`bin/sp-install`, `current` symlink) — or it gets a `COMPONENTS` entry in the runner and the same switch as ledger/track. |
| runner | the trigger: `tick.sh` (`deploy/render.py wrapper`), the CronJob command in Kubernetes |
| cli | the `sp` symlink in `PATH` |

## Running the suite in CI

CI runs `conformance/impl/python/run.sh` against the reference implementation on every pull request, as part of the
unit tests (`tests/test_conformance_reference.py`, step "Unit and output-contract tests"). A rewrite runs
`conformance/run.py` with its own `SP_IMPL_*` the same way; it does not need the Python implementation, only Python 3
for the harness.

## What the Go rewrite needs first

1. `contracts/findings` + `contracts/collector-protocol`: the data everything else consumes; the id rule; the
   validation rules (`conformance/run.py validate findings`).
2. `contracts/ledger` §3–§5 (coverage matching, lifecycle, exceptions): the heart; 22 ledger cases including five
   known deviations to implement as targets (LEDGER-D1…D5).
3. `contracts/runner` §3 (schedule semantics; cron in local time, jitter `sha1("<job>|<slot>")`) with `--now` used for
   **every** timestamp (RUNNER-D1), and the missed-slot metrics (RUNNER-D2).
4. `contracts/metrics/registry.json`: exact names, types, labels.
5. YAML 1.2 input (instance config, `exceptions.yaml`, `attestations.yaml`, catalogs) — JSON is valid YAML, but
   operators write block-style YAML; the suite feeds both.
