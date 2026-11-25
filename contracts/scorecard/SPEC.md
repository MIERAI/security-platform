# Contract: scorecard — version 1.0

| | |
|---|---|
| contract | `scorecard`, version **1.0** (files: `security-platform/scorecard/v1`, `scorecard-catalog/v1`, `attestations/v1`) |
| schemas | [`scorecard-v1.schema.json`](scorecard-v1.schema.json) (output), [`catalog-v1.schema.json`](catalog-v1.schema.json), [`attestations-v1.schema.json`](attestations-v1.schema.json) |
| executable | reference `scorecard/scorecard.py`, impl `SP_IMPL_SCORECARD` |
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
- score of a set = `100 × Σw(pass) / Σw(not na)`, rounded to 1 decimal; 0 when the denominator is 0;
- **dimension**: its controls; `PASS` when it has controls and `score ≥ threshold` (dimension `threshold`, else the
  instance's, else 75). A dimension whose `applies_when` does not hold, or all of whose controls are `na`, is listed
  under `not_applicable` and in no score;
- **pillars** (network, device, people, software) and **NIST CSF functions** (GV ID PR DE RS RC, from `csf`): the
  controls tagged with them; `dimension_pillar` crosses both;
- **overall = the minimum dimension score** (weakest link); `status: PASS` only when every applicable dimension
  passes; `mean` is informative only; `weakest` = the dimension with the minimum score;
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

## 6. Examples

[`examples/`](examples/): `scorecard.json` (from `conformance/cases/scorecard/weakest-link`),
`catalog-01-example.yaml`, `attestations.yaml`.

## Known deviations

None found while writing this version.

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents scorecard 0.4.0) |
