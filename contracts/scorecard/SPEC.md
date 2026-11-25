# Contract: scorecard — version 1.0

| | |
|---|---|
| contract | `scorecard`, version **1.1** (files: `security-platform/scorecard/v1`, `scorecard-catalog/v1`, `attestations/v1`) |
| schemas | [`scorecard-v1.schema.json`](scorecard-v1.schema.json) (output), [`catalog-v1.schema.json`](catalog-v1.schema.json), [`attestations-v1.schema.json`](attestations-v1.schema.json) |
| executable | reference `scorecard/scorecard.py`; Go `sp scorecard` (`internal/scorecard`); conformance impl `SP_IMPL_SCORECARD` |
| conformance | `conformance/cases/scorecard/*` |
| background | `docs/scorecard.md` (the model and the product catalog) |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## 1. Commands

```
<scorecard> compute --data D [--instance F] [--now EPOCH] [--catalog DIR ...]   exit 0; non-zero on a config error
<scorecard> attest  --data D CONTROL --by WHO [--note T] [--days N | --expires YYYY-MM-DD] [--false] [--not-applicable REASON]
<scorecard> lint    [--catalog DIR ...] [--instance F]                         exit 1 when the catalog has errors
<scorecard> list    [--catalog DIR ...] [--instance F] [--dimension ID]
<scorecard> version
```

`attest` is for humans only (an agent may draft the command, never run it as the human). `now` = `--now` or the wall
clock; every expiry is judged against it. The runner calls `compute --data D --instance F --now <tick time>` on every
publish.

## 2. Inputs of `compute`

| input | |
|---|---|
| catalog | every `*.yaml` / `*.json` file (schema `scorecard-catalog/v1`, one dimension per file) of the product catalog, then the instance's `scorecard.catalog_dirs`, then `--catalog` dirs; `scorecard.replace_catalog: true` drops the product catalog. A later control with the same id replaces the earlier one; `scorecard.overrides.<id>` patches a control. |
| instance `scorecard:` | `threshold` (default 75), `pillars`, `vars` (for `${var}` in sources), `not_applicable: {<id glob> or tag:<tag>: <reason>}` (a reason is REQUIRED), `unconfigured_collectors: unknown` (default) `| not_applicable`, `overrides`, `enabled` |
| `D/ledger.json` | [ledger](../ledger/SPEC.md) (entries, SLIs, collector heartbeats) |
| `D/latest/*.findings.json` | coverage of the newest document of every collector (`applies_when: coverage_prefix`, `require_coverage`) |
| `D/metrics/security-platform.prom` | the last published metrics (the `metric` evaluator; `security_score*` series are ignored) |
| `D/state/runner/*.json`, `D/state/sites/*.json` | job states (the `job` evaluator) |
| `D/attestations.yaml` | human attestations (schema `attestations/v1`) |

## 3. Status of a control

In this order:

1. the dimension's `applies_when` does not hold, or the control's, or the instance declares it out of scope
   (`overrides.<id>.disabled`, `not_applicable` by id glob or `tag:`, `unconfigured_collectors: not_applicable` for a
   control that needs a collector this instance never ran and that no human can attest) → `na`;
   `applies_when`: `{instance: <dotted key>}` (non-empty value), `{coverage_prefix: <p>}` (a newest document covered
   — ok or gap — an asset starting with `<p>`), `{any: [...]}`;
2. a human attestation with `not_applicable`, `attested_by` and an unexpired `expires` → `na`;
3. `check: attested` → from its attestation: none / no `attested_by` / no date → `unattested`; expired (expires ≤ now;
   `expires` absent = `at + validity`) → `expired`; `value: false` → `fail`; else `pass`;
4. `automated` / `evidence` → its `source` evaluator: `pass`, `fail`, `unknown` (no data, stale data, missing
   configuration) or `not_implemented` (`type: none`). Evaluator types and their parameters: `docs/scorecard.md`
   (`findings`, `sli`, `metric`, `collector_fresh`, `job`, `file`, `all`, `any`, `first_known`, `attestation`,
   `builtin`, `none`). `builtin` sources are evaluated after all others.

Only `pass` passes. `unknown`, `unattested`, `expired`, `not_implemented`, `fail` all count as failing (**no data ≠
secure**). `na` is excluded from every score, never a penalty.

## 4. Scores

- control weight `w ≥ 0` (default 1);
- score of a set = `100 × Σw(pass) / Σw(not na)`, rounded to 1 decimal; 0 when the denominator is 0 — computed
  exactly as §6.2 says, so that every implementation prints the same digits;
- **dimension**: its controls; `PASS` when it has controls and `score ≥ threshold` (dimension `threshold`, else the
  instance's, else 75). A dimension whose `applies_when` does not hold, or all of whose controls are `na`, is listed
  under `not_applicable` and in no score;
- **pillars** (network, device, people, software) and **NIST CSF functions** (GV ID PR DE RS RC, from `csf`): the
  controls tagged with them; `dimension_pillar` crosses both;
- **overall = the minimum dimension score** (weakest link); `status: PASS` only when every applicable dimension
  passes; `mean` (the rounded mean of the dimension scores, §6.2) is informative only; `weakest` = the first
  dimension, in report order, with the minimum score (null when no dimension applies);
- `attestations`: counts of attestable controls `valid` / `expiring` (within 14 days) / `expired` / `missing`.

## 5. Outputs

| output | |
|---|---|
| `D/reports/scorecard.json` | schema `scorecard-v1`, mode 0600 (failing controls are attacker intelligence) |
| `D/reports/scorecard.md` | human report (format not part of the contract) |
| `D/metrics/scorecard.prom` | `security_score{dimension|pillar|function|dimension,pillar}`, `security_score_overall`, `_threshold`, `_pass`, `_controls{dimension,status}`, `_regressions_total{dimension}`, `security_attestations{state}`, `security_scorecard_last_compute_timestamp_seconds` ([registry](../metrics/registry.json)) |
| `D/state/scorecard.json` | regression state: `below{dimension: bool}`, `regressions_total{dimension: n}` |

**Regressions**: a dimension that was passing on the previous compute and fails now adds 1 to
`regressions_total[dimension]`; the first compute is a baseline; a dimension that keeps failing does not count again.
Alerts fire on the counter's increase, never on a standing low score.

## 6. Values, arithmetic and printing

Implementations MUST agree byte for byte on `scorecard.json`, `scorecard.prom` and `state/scorecard.json` for the
same inputs (the conformance suite compares printed digits; `scorecard.md` is not part of the contract). This section
fixes what the reference implementation does implicitly.

### 6.1 Reading inputs

- **YAML** (catalog, instance, attestations; a `.json` catalog file is read as YAML too) is typed by the YAML 1.1
  rules of a safe loader: plain `yes/no/on/off/true/false` (any of their three spellings) are booleans, `~`/`null`/empty
  is null, `0o17` is text but `017` is octal, `0x1F`, `0b101`, `1_000` and `1:30` (sexagesimal) are integers, a float
  needs a dot (`1.0e+5`, not `1e5`, which is text), `2030-01-31` is a date and `2030-01-31T10:00:00Z` a date-time;
  quoted scalars are text; `<<` merges; a mapping keeps its key order and the last duplicate key wins. More than one
  document, an unknown tag or an invalid date is an error.
- **JSON** (ledger, documents, states): objects keep member order, numbers without fraction or exponent are integers.
- **Dates** (`at`, `expires`, `last_good_run`): the value's text (a YAML date as `YYYY-MM-DD`, a YAML date-time as
  `YYYY-MM-DD HH:MM:SS[.ffffff][±HH:MM]`) is read as its first 19 characters `%Y-%m-%dT%H:%M:%S` when it contains `T`,
  else its first 10 characters `%Y-%m-%d`; one-digit fields allowed, seconds up to 61, a zone suffix ignored, always
  **UTC** (SCORECARD-D1). A malformed date in an attestation is a configuration error; in an evaluator it is an
  evaluator error (§6.4).
- **Durations**: a number of seconds, or `<number><s|m|h|d|w>` with optional spaces.
- **Patterns**: `not_applicable` ids are shell globs on the whole id (`*` any text, `?` one character, `[a-z]`,
  `[!a-z]`; no escape character; a `[` without `]` is literal; a reversed range is empty). Regular expressions
  (`metric.match`, matched against the whole label value; `file.contains`, searched multi-line) MUST use the common
  subset of RE2 and Python `re`; a pattern outside it is an evaluator error whose message is implementation-specific.
- `not_applicable` entries are tried in the instance's order: the first match gives the reason. Site job states
  (`state/sites/*.json`) are read in file-name order; the runner's own state wins (SCORECARD-D2).

### 6.2 Arithmetic

- **Sums** (`weight_total`, `weight_passed`, the numerator and denominator of a score, `agg: sum`, the mean) add the
  values in report order: integers exactly while every value is an integer — the sum is then an integer and printed
  as one; from the first float on, in IEEE-754 double precision where every further float is added with Neumaier
  compensation (`t = s + x; c += (s - t) + x` if `|s| ≥ |x|` else `(x - t) + s; s = t`), every further integer
  without; at the end `s + c` when `c` is finite and non-zero (Python ≥ 3.12 `sum()`).
- **Score** = `round1(100.0 × P / W)`: `P` and `W` converted to doubles, the product first, then the quotient.
  **mean** = `round1(Σ scores / n)`.
- **round1(x)** = the double nearest to the decimal obtained by rounding the *exact binary value* of `x` to one
  decimal, ties to even (6.25 → 6.2, 18.75 → 18.8; 0.15, stored as 0.1499…, → 0.1). It is Python's `round(x, 1)`
  and Go's `strconv.FormatFloat(x, 'f', 1, 64)` read back.
- Comparisons (`score ≥ threshold`, `exp ≤ now`, `exp − now < 14 days`) are on doubles; `now` is `--now` (a decimal
  number of seconds) or the wall clock when it is absent or 0.

### 6.3 Printing

- `scorecard.json` and `state/scorecard.json`: keys sorted, indented by one space, `": "` after keys, `","` at line
  ends, no trailing newline; text as UTF-8 in the report and as `\uXXXX` escapes beyond ASCII in the state file;
  integers in decimal; a float as the **shortest** decimal that reads back as the same double, with `.0` when it is
  integral, in exponent form `d.ddde±XX` when its decimal exponent is < −4 or ≥ 16 (`100.0`, `66.7`, `1e+16`),
  `NaN` / `Infinity` for non-finite values. `computed_at` and `expires` are the UTC time / date of the second.
- `scorecard.prom`: floats as `%g` with six significant digits (`66.7`, `100`, `1.23457e+06`), integers in
  decimal, the timestamp truncated to an integer; label values with `\` → `/`, `"` → `'`, newline → space.
- Values quoted in a `detail` print as the reference prints them: null `None`, booleans `True`/`False`, floats as
  above (`3.5`, `0.0`), `metric` aggregates as `%g`, ages as `<days, 1 decimal>d` from one day on, else
  `<hours, 1 decimal>h`.

### 6.4 Errors

- A configuration error (a malformed catalog, instance or attestation file, an unknown `scorecard.unconfigured_collectors`,
  a `not_applicable` entry without a reason, a source that is not a mapping or whose `type` is a list or mapping,
  `scorecard.vars` redefining `data` or `product`, a catalog value of the wrong type where the score needs it: a
  non-numeric weight, a non-text id, title, pillar or check) makes `compute` exit non-zero and write nothing.
- An evaluator that cannot decide (a missing parameter, a value of the wrong type, a malformed date or duration) gives
  `unknown` with the detail `evaluator error: <Kind>: <message>` (at most 160 characters of message), where `<Kind>`
  is `KeyError` (`'<key>'`), `TypeError`, `ValueError`, `AttributeError` or `error` (a regular expression).

## 7. Examples


[`examples/`](examples/): `scorecard.json` (from `conformance/cases/scorecard/weakest-link`),
`catalog-01-example.yaml`, `attestations.yaml`.

## Known deviations

| id | current behaviour (reference) | target | case |
|---|---|---|---|
| SCORECARD-D1 | dates are parsed as local time and corrected by the standard offset: where daylight saving time is in effect, an attestation expires (and an age is measured) one hour early | dates are UTC (§6.1) | `scorecard/attestation-expiry-is-utc` |
| SCORECARD-D2 | site job states (`state/sites/*.json`) are read in directory order, so with the same job in two site files the winner depends on the file system | file-name order (§6.1) | — (not reproducible in a portable case) |

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents scorecard 0.4.0) |
| 1.1 | §6: reading, arithmetic (sums, rounding), printing and errors specified exactly, so that implementations agree bit for bit; SCORECARD-D1, -D2; 9 more conformance cases (scorecard 0.5.0, the Go implementation) |
