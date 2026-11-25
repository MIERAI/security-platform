# Contract: findings — version 1.2

| | |
|---|---|
| contract | `findings`, version **1.2** (documents carry `schema_version: "1.2"`; any `1.x` is the same major) |
| schema | [`findings-v1.schema.json`](findings-v1.schema.json) (JSON Schema 2020-12). `schema/findings-v1.schema.json` is the copy the core loads; their constraints are identical (`tests/test_contracts.py`) |
| producers | every collector ([collector-protocol](../collector-protocol/SPEC.md)), any program run as a `command` job |
| consumers | the ledger ([ledger](../ledger/SPEC.md)), the runner (validation, `latest/`), the scorecard (coverage), sites → hub |
| conformance | through its consumers and producers: `conformance/cases/ledger/*`, `conformance/cases/collector-*/*`; `python3 conformance/run.py validate findings FILE` validates one document |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## 1. What a document is

One findings document is the complete output of **one collector run**: what the run looked at (`coverage`), what it
found (`findings`) and optional numbers (`metrics`). It is JSON (UTF-8). A producer MUST write exactly one document per
run, named `<collector name>.findings.json`, into the run directory.

## 2. Fields

See the schema for types and patterns. Normative meaning:

- `schema_version` (required): `"1.<minor>"`. A producer MUST write the minor of the newest feature it uses
  (1.0 base, 1.1 `complete_scope`, 1.2 gap `checks`). A consumer MUST accept every `1.x` and MUST reject any other major
  (the whole document; see §6).
- `collector.name` (required, `^[a-z0-9-]+$`): the reporting name. The ledger resolves (marks fixed) only findings of
  the same name (`SP_COLLECTOR_NAME` overrides it: the same program deployed twice with different scopes).
- `collector.version` (required, `X.Y.Z`), `collector.tools` (optional map tool → version).
- `run.started_at`, `run.finished_at` (required, RFC 3339 UTC `YYYY-MM-DDTHH:MM:SSZ`); `run.instance` (optional).
  `finished_at` dates every fix this run causes.
- `coverage` (required, may be empty): entries `{asset, status: ok|gap, reason?, complete_scope?, checks?}`.
  - `ok`: the run evaluated the asset; a finding of this collector on it that the run did not report is **fixed**.
  - `gap`: the run could not evaluate it; its findings keep their state (**unknown ≠ fixed**). `reason` SHOULD say why.
  - no entry: out of this run's scope: unknown, state kept.
  - `complete_scope` (1.1, on an `ok` entry): an asset prefix (e.g. `image:`) the run inventoried **completely and
    authoritatively**. A producer MUST declare it only when every source of the inventory was read successfully.
    Consequence in the ledger: findings of this collector under the prefix on assets the run listed neither as ok nor
    as gap are closed as `asset_retired`.
  - `checks` (1.2, on a `gap` entry named `<asset>/<part>`): fnmatch patterns of the only checks that could not be
    evaluated on `<asset>` (a **narrow gap**, e.g. one probe timed out). The asset itself stays covered for every other
    check. A producer MUST NOT put `checks` on an entry without `/`.
- `findings` (required, may be empty): one entry per `(layer, asset, check)`; a producer MUST NOT repeat one.
  - `id` MUST be the first 12 hex characters of `sha1("<layer>|<asset>|<check>")`: implementations in other languages
    produce the same ids, so a rewritten collector continues the same ledger entries.
  - `check`: a stable name `^[a-z0-9_.-]+$`; a published check name MUST NOT be reused for another meaning.
  - `layer`: identity | network | host | workload | supply-chain | data-secrets | ai-agents | detection.
  - `asset`: `<type>:<rest>`. Coverage matching (ledger §3) relies on the separators `:`, `/`, `@` inside `<rest>`.
  - `title` (≤ 300 chars), `evidence` (a pointer into the run directory, `raw/<collector>/<file>[#key]`), `remediation`,
    `needs_human`, `owner` (a team name, or the role hints `platform` / `human`), `observed_at` (RFC 3339 UTC).
  - `kind` (optional): detection | vulnerability | compliance. Producers SHOULD always set it (see LEDGER-D1).
  - `refs` (optional list), `attributes` (optional object). Known attribute keys: `cve`, `cvss`, `epss`, `kev`,
    `exposed`, `published_at`, `kev_added`, `package`, `installed`, `fixed`, `base_severity`, `pillar`.
- `metrics` (optional): `{name: ^security_[a-z0-9_]+$, value, labels?, help?}`; re-exported by the runner with the
  label `collector=<name>` ([metrics](../metrics/SPEC.md)). Labels MUST NOT carry asset details.

**Never in a document**: secret values (tokens, passwords, private keys, cookie values), anywhere — not in `title`,
`evidence`, `remediation`, `attributes`, `reason`. Evidence files hold metadata, not contents.

## 3. Compatibility

- Unknown fields anywhere MUST be ignored by consumers (never fatal); producers MAY add fields only under a new minor
  documented here.
- A new minor is additive. Order of upgrade: consumers (hubs) first, then producers (sites), because an old consumer
  ignores a new field and may draw a wrong conclusion (e.g. an old core ignores `checks` and fixes what timed out).
- A new major follows the two-step rule of `docs/upgrade.md`: the core accepts v1 and v2, collectors move one by one,
  a later release stops reading v1.

## 4. OCSF mapping (export)

The ledger writes `<run>/ocsf.jsonl`: one OCSF 1.x Finding event per ledger entry (every status):

| finding / entry | OCSF |
|---|---|
| `kind` detection / vulnerability / compliance (absent: detection) | `class_uid` 2004 / 2002 / 2003, `class_name` Detection / Vulnerability / Compliance Finding, `category_uid` 2, `activity_id` 1 |
| `severity` info / low / medium / high / critical | `severity_id` 1 / 2 / 3 / 4 / 5 |
| status open / accepted / fixed | `status_id` 1 / 3 / 4, `status` = the ledger status |
| `last_seen` | `time` |
| `collector`, `collector_version` | `metadata.product.name` = `security-platform/<collector>`, `.version`; `metadata.version` = OCSF version |
| `id`, `title`, `first_seen`, `last_seen`, `check` | `finding_info.uid`, `.title`, `.first_seen_time`, `.last_seen_time`, `.types[0]` |
| `asset` `<type>:<rest>` | `resources[0]` = `{type, name: <rest>}` |
| `remediation` | `remediation.desc` |
| compliance: `check`, `refs` starting `cis:` / `cis-` | `compliance.control`, `compliance.standards` |
| vulnerability: attributes `cve`, `cvss`, `epss`, `kev`, `package`, `installed`, `fixed` | `vulnerabilities[0].cve.uid`, `.cve.cvss[0].base_score`, `.cve.epss.score`, `.is_exploit_available`, `.affected_packages[0]` |

Timestamps are copied as the ledger stores them (RFC 3339 strings), not converted to epoch milliseconds (OCSF's
`timestamp_t`); a SIEM sink converts if it needs to.

## 5. Examples

[`examples/`](examples/): `minimal.json`, `host-with-narrow-gap.json` (1.2), `inventory-complete-scope.json` (1.1);
negative: `invalid-unknown-major.json`, `invalid-fields.json`.

## 6. Validation rules a consumer applies

A consumer MUST reject (not merge, record as invalid) a document whose `schema_version` major is not 1, or that fails
the schema. It MUST NOT reject a document for unknown fields. Rejection of one document MUST NOT stop the processing of
other valid documents of the same run.

## Known deviations

None in the contract itself. Consumers' deviations are listed in their contracts (LEDGER-D1: a finding without `kind`).

## History

| version | change |
|---|---|
| 1.2 | gap entries may carry `checks` (narrow gaps) |
| 1.1 | ok entries may carry `complete_scope` (asset retirement) |
| 1.0 | base |
