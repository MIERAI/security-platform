# Contract: ledger — version 1.0

| | |
|---|---|
| contract | `ledger`, version **1.0** (files: `security-platform/ledger/v1`, `security-platform/tracker/v1`, exceptions) |
| schemas | [`ledger-v1.schema.json`](ledger-v1.schema.json), [`tracker-v1.schema.json`](tracker-v1.schema.json), [`exceptions-v1.schema.json`](exceptions-v1.schema.json) |
| executables | **merge** (reference `core/ledger.py`, impl `SP_IMPL_LEDGER`) and **track** (reference `core/remediation.py`, impl `SP_IMPL_REMEDIATION`) |
| conformance | `conformance/cases/ledger/*`, `conformance/cases/remediation/*` |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

The ledger is the memory of the platform: every finding ever seen and where it is in its life. It is the only
component that decides `open → fixed`, and nothing but a human (an exception) decides `accepted`.

## 1. merge

```
<merge> --run RUN --data DATA [--latest LATEST]
```

Inputs:

| input | |
|---|---|
| `RUN/*.findings.json` | the documents of one run (usually one; an ingest may stage several), processed in file-name order |
| `DATA/ledger.json` | the previous ledger (absent: an empty one) |
| `DATA/exceptions.yaml` | human-approved exceptions (§5); YAML 1.2 (JSON is valid YAML) |
| `DATA/catalog-review.yaml` | `last_reviewed: <date>` of the check catalog (an SLI input) |
| `LATEST/*.findings.json` | optional: the newest document of every collector; coverage-gap and collector-metric SLIs are computed from these so a run of one collector does not hide the others' numbers |
| SLI catalog | bundled with the implementation (`generators/sli-catalog.yaml` format); not an operator input |
| clock | the wall clock (exception expiry, `updated_at`, `runs[].at`, 30-day windows). Implementations MAY accept `--now EPOCH`; the suite does not depend on it. |

Outputs (all written even when some documents were invalid):

| output | |
|---|---|
| `DATA/ledger.json` | the new ledger (schema `ledger-v1`), written atomically (temporary file + rename), mode 0600 |
| `DATA/metrics/ledger.prom` | metrics ([metrics](../metrics/SPEC.md), producer `ledger`), atomically |
| `RUN/sli.prom` | the same series, for this run |
| `RUN/all.prom` | every `RUN/*.prom` concatenated (textfile delivery) |
| `RUN/ocsf.jsonl` | one OCSF event per ledger entry ([findings §4](../findings/SPEC.md)) |
| `DATA/reports/latest-auto.md` | human-readable summary (private; format not part of the contract) |

Exit 0 when the ledger was written (invalid documents included: they are recorded, not fatal). Non-zero only when it
could not do its job (unreadable previous ledger, unwritable data directory); then `ledger.json` MUST be unchanged.
Callers serialize merges (the runner holds a ledger lock); a merge assumes exclusive access to `DATA`.

## 2. Validation

Each document is validated against the findings contract (major 1, schema). An invalid document MUST NOT change any
entry; it MUST be recorded in `runs[-1].invalid` (`<file name>: [errors]`) and counted in
`security_contract_invalid_documents`. The valid documents of the same run are merged.

## 3. Coverage matching

A run "covers" an asset when one of its `ok` coverage entries matches it:

1. exactly, or
2. the entry is a prefix of the asset ending right before one of `:` `/` `@` (`net-endpoint:h@192.0.2.10` covers
   `net-endpoint:h@192.0.2.10:443`; `host:h1` covers `host:h1/os-updates`), or
3. umbrella types: `host:<s>` covers `secret-file:<s>...`; `k8s-cluster:<s>` covers `k8s-workload:<s>...`,
   `k8s-namespace:<s>...`, `k8s-identity:<s>...`, `cis:<s>...` (scope `<s>` = the part after `<type>:` up to the
   first `/`, `:` or `@`).

A run "reports a gap" on an asset when one of its `gap` entries concerns it (see LEDGER-D3 for how the reference
matches today).

## 4. Lifecycle (per document of collector `C`, finished at `T`)

For every finding `f` in the document:

- **new id** → entry `open`, `first_seen = f.observed_at`, `fixed_at = null`, `reopened_count = 0`,
  `ttk_counted = (C had covered assets before) and (f.asset is covered by C's earlier ok entries)`.
- **existing, status fixed** → **regression**: `open`, `fixed_at = null`, `fixed_reason = null`,
  `time_to_fix_days = null`, `reopened_count += 1`. `first_seen` never changes.
- always: copy the finding's fields, `collector = C`, `collector_version`, `last_seen = f.observed_at`.
- advisories (`kind` vulnerability with `attributes.cve` or `attributes.advisory`): `disclosed_at` = the latest of
  `published_at`, `kev_added`; `time_to_know_hours = max(0, first_seen − disclosed_at)` in hours, 1 decimal.

Then for every entry `e` of collector `C` (same name) with status `open` or `accepted` that the document did NOT report:

1. a **narrow gap** of the run (`<a>/<part>` with `checks`) has `<a> == e.asset` and a pattern matching `e.check`
   (fnmatch, case-sensitive) → unchanged (unknown);
2. else, the run **covers** `e.asset` (§3) and reports no gap concerning it → `fixed`, `fixed_reason: not_observed`;
3. else, the run declared `complete_scope` prefixes (ok entries), `e.asset` starts with one of them, no gap concerns
   it, and the run listed it nowhere (neither ok nor gap, matched as in §3) → `fixed`, `fixed_reason: asset_retired`;
4. else → unchanged (gap, offline, or simply outside this run's scope).

On fixed: `fixed_at = T`, `time_to_fix_days = (T − first_seen)` in days, 2 decimals.

Entries of other collectors are never touched by this document. After every document: `coverage_seen[C]` = sorted
union of all assets C ever covered; `collectors[C].last_run = T`; `collectors[C].last_good_run = T` if the document
has at least one `ok` entry.

## 5. Exceptions (`exceptions.yaml`)

```yaml
exceptions:                     # finding id -> exception
  <id>: {approved_by: <human>, reason: <text>, expires: 'YYYY-MM-DD'}
coverage_exceptions:            # coverage asset, or "<collector>|<asset>" -> exception (the gap is not counted)
  host|host:phone: {approved_by: <human>, reason: <text>, expires: 'YYYY-MM-DD'}
```

- An exception without `approved_by` AND `expires` MUST be ignored. `expires` is a date (UTC midnight) or an RFC 3339
  time; valid while `expires > now`.
- Applied after the lifecycle step, to entries that are not `fixed`: valid → `accepted`, `exception` = its fields as
  strings; expired → `open`, `exception` = its fields + `expired: true`, counted in `security_exceptions_expired`.
- A fixed entry stays fixed whatever its exception. An accepted entry can be fixed by a covering run (§4).
- Only humans edit this file; no component writes it (the runner may copy a site's copy to a hub, `push`/`ingest`).

## 6. SLIs and metrics

The merge computes the bundled SLIs (`sli`, `sli_members`, `sli_new_total` — first sight of an SLI is a baseline, not
"new") and writes the `ledger` metrics of the [metrics registry](../metrics/registry.json). Coverage gaps
(`security_coverage_gaps_open{collector}`) are counted from `LATEST` when given (else from this run), minus gaps under
a valid coverage exception (`security_coverage_gaps_excepted`). `time_to_know` counts only entries with
`ttk_counted` first seen in the last 30 days.

## 7. track (remediation items, `tracker/v1`)

```
<track> --data DATA [--instance F] [--now EPOCH]
```

Reads `DATA/ledger.json` and the previous `DATA/tracker/items.json`; writes `DATA/tracker/items.json` (schema
`tracker-v1`, atomically), `DATA/metrics/remediation.prom`, and syncs the configured tracker adapter (default `files`:
inside `DATA/tracker/`). `now` = `--now` or the wall clock. Pure function of (previous items, ledger, instance
`remediation:` config, now):

- one item per entry that is or was open (an entry that is fixed when first seen gets none);
- `status` mirrors the ledger; an item is closed only when the ledger says `fixed` (`closed_at = fixed_at`,
  `time_to_remediate_days = closed_at − (reopened_at or opened_at)`);
- reopen: closed → not closed = `reopened_at = now`, `reopen_reason: regression`; accepted → open with an expired
  exception = `reopen_reason: exception expired`; the SLO clock restarts at `reopened_at`;
- `due_at = (reopened_at or opened_at) + SLO[slo_class]`; `slo_class = kev_exposed` when `attributes.kev` and
  `attributes.exposed`, else the severity; default SLO `kev_exposed 1d, critical 7d, high 30d, medium 90d, low 180d`
  (instance `remediation.slo` overrides; `info` has none unless configured → `due_at: null`);
- `overdue = status open and now > due_at` (accepted items are never overdue);
- owner: first matching `remediation.owners` rule (`layer_in`, `severity_in`, `asset_prefix`, `check_prefix`), else
  the finding's `owner` unless it is a role hint (`unknown`, `unassigned`, `platform`, `human`), else
  `remediation.default_owner`, else `unassigned` (`owner_source`: rule | finding | default | none);
- `history`: `{at, status}` on every status change, last 20 kept.
- An advisor (instance `remediation.advisor`) MAY draft text into `tracker/drafts/<id>.md`; it never changes a status.

## 8. Examples

[`examples/`](examples/): `ledger.json` (after a regression), `tracker-items.json`, `exceptions.yaml`.

## Known deviations

Each has a conformance case that specifies the TARGET; the reference implementation is listed in
`conformance/impl/python/expected-failures.txt` and a new implementation MUST pass it.

| id | current behaviour (reference) | target | case |
|---|---|---|---|
| LEDGER-D1 | a schema-valid finding without `kind` (optional in findings 1.x) makes the merge exit 1 (`KeyError`), so the whole run is lost | merge it as `kind: compliance` (the SDK's default) | `ledger/finding-without-kind` |
| LEDGER-D2 | a new finding has no due date until the next `remediation` job (hourly in the starter config): `sp findings` shows DUE `-` for up to an hour | the merge sets `due_at` on the entry when it first records (or reopens) it, with the same SLO rule as §7 (default table when the merge has no instance config); `track` keeps the same value | `ledger/due-date-on-first-record` |
| LEDGER-D3 | a gap entry protects every entry whose asset **contains** the gap's name after `<type>:` (`host:web` blocks fixing `image:registry.example/web:1`) — conservative, but a permanent gap can keep unrelated findings open forever | a gap concerns the assets it would cover under §3 | `ledger/gap-matches-asset-not-substring` |
| LEDGER-D4 | timestamps are parsed as local time and corrected by the standard offset: across a DST change, durations are off by one hour (`time_to_fix_days` 13.96 instead of 14.0 in Europe/Berlin) | all arithmetic on UTC instants | `ledger/time-arithmetic-is-utc` |
| LEDGER-D5 | an exception that a human deletes from `exceptions.yaml` leaves the entry `accepted` until a covering run fixes it | acceptance holds only while a valid exception exists: without one an accepted entry is `open` again | `ledger/removed-exception-reopens` |

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents core 0.9.0) |
