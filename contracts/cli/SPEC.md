# Contract: cli — version 1.0

| | |
|---|---|
| contract | `cli` (the `sp` command), version **1.0** |
| schema | [`findings-json-v1.schema.json`](findings-json-v1.schema.json) (stdout of `sp findings --json`) |
| executable | reference `cli/sp.py` (`bin/sp`), impl `SP_IMPL_CLI` |
| conformance | `conformance/cases/cli/*` |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

`sp` is what people type and what the documentation tells them to type. **Machine-readable** outputs (a script may
parse them) are marked; everything else is for humans and may change wording in any release.

## 1. Locating the data

`--data DIR`, else `$SP_DATA`. The instance config: `--instance FILE`, else `$SP_INSTANCE`, else
`DIR/instance.yaml`, `instance.yml`, `instance.json` (first that exists). No data directory, or a missing one:
exit 2 with one line `sp: <what to do>` on stderr. Nothing in `sp` changes a finding's status.

## 2. Commands

| command | output | exit |
|---|---|---|
| `sp init DIR [--name N] [--force]` | creates DIR (mode 0700), `instance.yaml` (0600, a starter config; never overwritten without `--force`), `exceptions.yaml`, `.gitignore`; prints `wrote <path>` or `<path> exists: left as it is` | 0 |
| `sp doctor` | checks config, tools per configured collector, file permissions; one line per check | 0 ready, 1 something to fix |
| `sp run [JOB ...]` | runs the jobs now through the runner (`runner run`), collectors and ingests first; one result line per job | the runner's |
| `sp status` | one screen: open findings by severity, overdue fixes, jobs (`ok` / `FAILING` / `never`, last good run), coverage gaps, scorecard, SLIs, top risks. `no scan yet` before the first scan | 0 |
| `sp findings [--open] [--severity S] [--layer L] [--check PREFIX] [--overdue] [--json \| --ids]` | filters combine (AND); `--severity S` = S or worse; sorted worst first (severity, then layer, then asset) | 0 (also when nothing matches) |
| `sp explain ID` | what / why / how to fix / how to verify, and a ready-to-edit `exceptions.yaml` snippet; `ID` may be a unique prefix | 0; 2 unknown id |
| `sp digest [--daily \| --days N]` | the short summary notifiers send | 0 |
| `sp notify [--dry-run] [--days N]` | sends the digest through the instance's `notify:` adapters | 0; 1 none configured or one failed |
| `sp --version` | `sp <cli version> (security-platform <release>)` — **machine-readable** | 0 |

Machine-readable outputs:

- `sp findings --json`: a JSON array of ledger entries ([ledger](../ledger/SPEC.md) entry fields), schema
  `findings-json-v1`, in the order above.
- `sp findings --ids`: one finding id per line, same order.
- `sp --version`: the line format above.
- `runner status` (not `sp status`) is the machine-readable job status ([runner §5](../runner/SPEC.md)).

Table output of `sp findings` (human): columns `ID SEVERITY STATUS DUE LAYER ASSET WHAT`; DUE is the remediation due
date (`YYYY-MM-DD`), `OVERDUE`, or `-` when none is known.

## 3. What `sp` must never print

`sp digest` / `sp notify` leave the private boundary (chat services, phones): **aggregates only** — counts, check
families, plain words, finding ids for `sp explain`. Never an asset name, address, port, repository, evidence or
secret. `sp status`, `sp findings`, `sp explain` are local and may show assets.

## Known deviations

| id | current behaviour (reference) | target | case |
|---|---|---|---|
| CLI-D1 | after downtime, before the catch-up tick, `sp status` shows a job whose scheduled slot passed without a run as `ok … last good run 47m ago` (seen: remediation due 07:50, machine off 07:46–08:06) | the job line says that a scheduled run is late or missed (e.g. `LATE remediation  slot 07:50 not run yet (20m late)`), using the same schedule semantics as the runner ([runner §3](../runner/SPEC.md)); the runner exports the same fact as a metric (RUNNER-D2) | `cli/status-shows-missed-slot` |

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents cli 0.3.0) |
