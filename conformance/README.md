# Conformance suite

A black-box test suite for the [contracts](../contracts/README.md). It imports nothing from any implementation: each
component under test is a **process**, started from a command line you give it, fed fixture files in a fresh sandbox
directory, and judged only by its exit code, stdout/stderr and the files it writes — against golden subsets and the
JSON Schemas in `contracts/`. Python ≥ 3.10, standard library only (it is a test tool, not product code).

```sh
# the reference (Python) implementation, with its known deviations allowed to fail:
SP_PYTHON=~/.venvs/security-platform/bin/python3 conformance/impl/python/run.sh
# the Go implementation (sp ledger merge / track), with NO expected failures:
SP_PYTHON=~/.venvs/security-platform/bin/python3 conformance/impl/go/run.sh
# your implementation of one component:
SP_IMPL_LEDGER="/opt/sp-go/bin/sp-ledger merge" python3 conformance/run.py --component ledger
python3 conformance/run.py --impl runner="/opt/sp-go/bin/sp-runner" --component runner -v
# the Go implementation of a component (impl/go/<component>; builds ./cmd/sp unless SP_GO_SP names a binary):
python3 conformance/run.py --impl scorecard=conformance/impl/go/scorecard --component scorecard
python3 conformance/run.py --list                                 # every case, its contract and deviation id
python3 conformance/run.py validate findings out/x.findings.json # schema check of one file (also: ledger, tracker, ...)
```

## Components and how they are invoked

The command line is split like a shell would (no shell runs); the case's arguments are appended.

| component | env var (or `--impl C=CMD`) | arguments the suite appends | contract |
|---|---|---|---|
| `ledger` | `SP_IMPL_LEDGER` | `--run RUN --data DATA [--latest DIR]` | [ledger §1](../contracts/ledger/SPEC.md) |
| `remediation` | `SP_IMPL_REMEDIATION` | `--data DATA --now EPOCH [--instance F]` | [ledger §7](../contracts/ledger/SPEC.md) |
| `scorecard` | `SP_IMPL_SCORECARD` | `compute --data D --instance F --now EPOCH` | [scorecard](../contracts/scorecard/SPEC.md) |
| `runner` | `SP_IMPL_RUNNER` | `tick\|status --instance F --data D --now EPOCH [JOB ...]` | [runner](../contracts/runner/SPEC.md) |
| `cli` | `SP_IMPL_CLI` | `findings\|explain\|status\|digest\|init\|--version ...` | [cli](../contracts/cli/SPEC.md) |
| `collector-<name>` | `SP_IMPL_COLLECTOR_<NAME>` (`-` → `_`) | none; `SP_RUN_DIR`, `SP_INSTANCE`, `SP_DATA`, ... in the environment | [collector-protocol](../contracts/collector-protocol/SPEC.md) |

Every process runs with `TZ=UTC` (unless the case sets another), `LC_ALL=C`, `NO_COLOR=1`, `HOME=<sandbox>/home`,
stdin closed, and without the caller's `SP_DATA`/`SP_INSTANCE`/`SP_RUN_DIR`/... (other variables, e.g. `SP_PYTHON`,
pass through). A component without an implementation is skipped (`SKIP`), or a failure with `--require-all`.

## Results

`PASS`, `FAIL`, `SKIP`, `XFAIL` (listed in `--expected-failures FILE` and failed: allowed), `XPASS` (listed but
passed: the deviation is fixed — remove the line; this is a failure so the list stays honest). Exit 0 when nothing
failed. The reference implementation's list is `impl/python/expected-failures.txt`; a new implementation SHOULD run
with no list at all: the cases marked with a deviation id specify the target behaviour.

## Case format

`cases/<component>/<case>/case.json` plus fixture files next to it. The cases are generated from shared fixture
builders by `tools/gen_cases.py` (edit there, re-run, commit both); the generated files are the suite.

```json
{"component": "ledger", "title": "...", "contract": "ledger/1.0", "origin": "test or incident it comes from",
 "deviation": "LEDGER-D2 (only for target-behaviour cases)",
 "files":    {"data/exceptions.yaml": "fixture-in-case-dir.yaml", "x": {"text": "..."}, "y": {"json": {}}, "z": {"text": "", "mode": "0666"}},
 "services": [{"name": "gcp", "argv": ["{python}", "{case}/mock_gcp.py"]}],
 "steps": [
   {"name": "merge run1", "files": {"run1/host.findings.json": "run1.json"}, "remove": ["data/tracker"],
    "exec": {"impl": "ledger", "args": ["--run", "{sandbox}/run1", "--data", "{sandbox}/data"], "env": {"TZ": "Europe/Berlin"},
             "timeout": 120, "background": false, "writes_only_under": ["run"]},
    "exit": 0,
    "expect": [{"json": "data/ledger.json", "schema": "ledger", "subset": {"entries": {"<id>": {"status": "open"}}}}]},
   {"name": "wait", "sleep": 1.5}, {"name": "join", "wait": "<name of a background step>", "exit": 0}]}
```

- Templates in arguments, env values and text fixtures: `{sandbox}`, `{case}`, `{python}` (the suite's interpreter, for
  mocks only), `{path}` (the suite's own `PATH`, to put fake tools in front of it: `{sandbox}/bin:{path}`), `{now_epoch}`, `{fake_jwt}` (an unsigned JWT built at run time: fixtures never contain token-shaped strings), `{fake_key}` (a
  random stand-in for private key material, built at run time for the same reason), `{epoch:-2820}` / `{utc:+3600}` (real clock + offset), `{svc_<name>}` (a service URL).
- `exit`: a number, `{"in": [..]}` or `{"not": n}`.
- Assertions (`expect`):
  - `{"json": path, "schema": name, "subset": {...} | "file", "findings_ids": true}`; `{"jsonl": path, ...}`.
    **Subset** semantics: keys not mentioned are ignored (unknown fields are allowed by contract); lists compare
    element by element unless an operator says otherwise. Operators: `$absent`, `$null_or_absent`, `$any`, `$type`,
    `$regex`, `$approx [v, tol]`, `$ge`, `$le`, `$len`, `$contains [..]`, `$not_contains [..]`, `$unordered [..]`.
  - `{"prom": path, "families": [..], "has": [{"name", "labels", "value", "exact_labels"}], "absent": [..],
    "types": {name: type}, "forbidden_labels": [..]}` — parses the text format.
  - `{"stdout"|"stderr": {"regex": [..], "not_regex": [..], "not_contains": [..], "json": subset, "schema": name, "lines": [..]}}`.
  - `{"file": path, "regex": [..], "not_regex": [..], "lines": n}`, `{"exists": path}`, `{"absent": path}`, `{"glob": pattern, "count": n}`,
    `{"writes_only_under": true}` (with `exec.writes_only_under`: nothing outside those sandbox paths changed),
    `{"no_secret": [canaries], "in": path}` (no canary in any file under path, nor in stdout/stderr),
    `{"duration_max": seconds}`.
- Normalization: there is none to configure — volatile values (wall-clock timestamps, run directory names) are simply
  not in the golden subsets, or matched with `$regex`/`$type`; everything a contract fixes is compared exactly.
- Schemas: a draft 2020-12 subset is implemented in `run.py` (`$ref`, `type`, `enum`, `const`, `pattern`, lengths,
  `format` date/date-time, bounds, `required`, `properties`, `patternProperties`, `additionalProperties`, `items`,
  `minItems`, `anyOf`/`oneOf`/`allOf`); a full validator gives the same verdicts on `contracts/`.

## Adding a case

1. Add it to `tools/gen_cases.py` (reuse `finding()`, `doc()`, `merge()`, `tick()`, ...), run
   `python3 conformance/tools/gen_cases.py`.
2. Run it against the reference: `conformance/impl/python/run.sh --case '<component>/<name>' -v`.
3. If it documents a defect of the reference: give it a `deviation` id, describe current vs target behaviour in the
   contract's "Known deviations" table, list it in `impl/python/expected-failures.txt`.
