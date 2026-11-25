# Contract: cli — version 1.1

| | |
|---|---|
| contract | `cli` (the `sp` command), version **1.1** |
| schema | [`findings-json-v1.schema.json`](findings-json-v1.schema.json) (stdout of `sp findings --json`) |
| executable | reference `cli/sp.py` (`bin/sp`); Go `sp` (`internal/cli`, `conformance/impl/go/cli`); impl `SP_IMPL_CLI` |
| conformance | `conformance/cases/cli/*` |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

`sp` is what people type and what the documentation tells them to type. **Machine-readable** outputs (a script may
parse them) are marked; everything else is for humans and may change wording in any release.

## 1. Locating the data

`--data DIR`, else `$SP_DATA`. The instance config: `--instance FILE`, else `$SP_INSTANCE`, else
`DIR/instance.yaml`, `instance.yml`, `instance.json` (first that exists). No data directory, or a missing one:
exit 2 with one line `sp: <what to do>` on stderr. `~` at the start of `--data`/`--instance` is the home directory. No
instance config where one is needed: exit 2, `sp: no instance config at <path> ...`. Unreadable input (a config that is
not YAML/JSON or not a mapping, a corrupt `ledger.json` or `tracker/items.json`, `sp init` onto a file): exit 2 with
one line `sp: <path>: <why>`, never a stack trace (CLI-D2). Nothing in `sp` changes a finding's status.

## 2. Commands

| command | output | exit |
|---|---|---|
| `sp init DIR [--name N] [--force]` | creates DIR (mode 0700; an existing one is made 0700), `instance.yaml` (a starter config; never overwritten without `--force`; a symbolic link in its place is replaced, never followed), `exceptions.yaml`, `.gitignore` (kept when present); every file 0600 whatever the umask (CLI-D5); prints `wrote <path>` or `<path> exists: left as it is (--force overwrites)` | 0; 2 DIR is a file |
| `sp doctor` | checks config, data directory mode, tools per configured collector (on `PATH`), ssh client for ssh hosts, every `*_file` secret of `codehost`/`notify`/`runner.sinks` (exists, not readable by others; `ca_file` is not a secret; never read or printed), PyYAML in the jobs' interpreter for a YAML config; one line per check, `  ok    <check>` or `  FIX   <problem>` + `        -> <fix>`; last line `ready: sp run` or `<n> thing(s) to fix` | 0 ready, 1 something to fix |
| `sp run [JOB ...]` | runs the jobs now through the runner (`runner run`), collectors and ingests first; without JOB every job except digest/notify/snapshot/push/pull-snapshot; first line `running <n> job(s): <names>  ...`, then one line per job `  ok  <job> ...` or `  FAILED  <job> ... <note>` | the runner's; 2 unknown job (`sp: not in runner.jobs: ...`) |
| `sp status` | one screen: open findings by severity, overdue fixes, jobs (`  <state>  <job>` with state `ok` / `FAILING` / `LATE` / `never`, last good run), `Could not check <n> thing(s)` (coverage gaps of `latest/*.findings.json`, at most 8 lines `  <collector>: <reason>`), scorecard, SLIs, top 5 risks. `no scan yet` before the first scan | 0 |
| `sp findings [--open] [--severity S] [--layer L] [--check PREFIX] [--overdue] [--json \| --ids]` | filters combine (AND); `--severity S` = S or worse; sorted worst first (severity, then layer, then asset) | 0 (also when nothing matches) |
| `sp explain ID` | what / why / how to fix / how to verify (texts: `internal/cli/explain/explanations.json`, one file for both implementations), and a ready-to-edit `exceptions.yaml` snippet expiring in 90 days; `ID` may be a unique prefix | 0; 2 unknown id or a prefix of several (CLI-D4) |
| `sp digest [--daily \| --days N]` | the short summary notifiers send | 0 |
| `sp notify [--dry-run] [--days N]` | sends the digest through the instance's `notify:` adapters (stdout, file, webhook, telegram, exec); `sent via <i>-<type>` per success, `notifier <i>-<type> failed: <why>` on stderr per failure (the reason's wording may differ between implementations and never holds a secret or a URL); one failing does not stop the others | 0; 1 none configured or one failed |
| `sp --version` | `sp <cli version> (security-platform <release>)` — **machine-readable** | 0 |

Machine-readable outputs:

- `sp findings --json`: a JSON array of ledger entries ([ledger](../ledger/SPEC.md) entry fields), schema
  `findings-json-v1`, in the order above.
- `sp findings --ids`: one finding id per line, same order.
- `sp --version`: the line format above.
- `runner status` (not `sp status`) is the machine-readable job status ([runner §5](../runner/SPEC.md)).

Parse-stable human output (scripts may rely on it; it changes only with a contract version):

- the `sp findings` table: columns `ID SEVERITY STATUS DUE LAYER ASSET WHAT` at fixed widths (13, 10, 9, 12, 13, 38;
  ASSET is cut to 37 characters, WHAT to 70), then an empty line and `<n> finding(s). ...`; DUE is the local date of the
  remediation due instant (`YYYY-MM-DD`, CLI-D3), `OVERDUE`, or `-` when none is known; `no matching findings`;
- the line prefixes of `sp doctor`, `sp run`, `sp status` (job states, `Could not check`), `sp init` and `sp notify`
  named in §2, and their exit statuses;
- errors: one line `sp: <message>` (exit 2, or 1 for `notify`); command-line mistakes: a synopsis and
  `<prog>: error: <message>` on stderr, nothing on stdout, exit 2.

Everything else (wording of `status`, `explain`, `digest`, help texts) is for humans and may change in any release.
The Go implementation prints it byte for byte as the reference does today (tests/test_cli_go.py compares every command,
plain and on a terminal); the reference's own wording depends on its Python version for argparse messages.

## 3. What `sp` must never print

`sp digest` / `sp notify` leave the private boundary (chat services, phones): **aggregates only** — counts, check
families, plain words, finding ids for `sp explain`. Never an asset name, address, port, repository, evidence or
secret. `sp status`, `sp findings`, `sp explain` are local and may show assets.

## Known deviations

| id | current behaviour (reference) | target | case |
|---|---|---|---|
| CLI-D2 | unreadable input (bad YAML, a non-mapping config, corrupt ledger/tracker JSON, `sp init` onto a file) escapes as a Python traceback, exit 1 | one line `sp: <path>: <why>`, exit 2 | `cli/bad-input-is-one-line` |
| CLI-D3 | timestamps parsed as local time minus the standard offset: under daylight saving time an instant is an hour off (a due date near midnight shows the previous day) | UTC instants, shown as the local date | `cli/due-date-in-local-time` |
| CLI-D4 | `sp explain PREFIX` with a prefix of several ids explains whichever comes first in the ledger | exit 2 naming the matching ids | `cli/explain-ambiguous-prefix` |
| CLI-D5 | `exceptions.yaml` and `.gitignore` are created with the process umask (0644 under 022) | every file `sp init` creates is 0600 | `cli/init-files-are-private` |

The Go implementation (`internal/cli`) follows every target. The reference keeps its behaviour (it still serves
`SP_CLI=python` and the runner's `notify` job).

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents cli 0.3.0) |
| 1.0 | CLI-D1 fixed in cli 0.3.1: `sp status` marks a job `LATE` when a scheduled slot passed without a run (more than 15 minutes after its jittered start) |
| 1.1 | parse-stable human lines listed (§2); errors and input mistakes specified; CLI-D2…D5 recorded; 16 more conformance cases (25): the quickstart flow, doctor, run, notify adapters, status overview, digest content, init modes, locating data, argument errors |
