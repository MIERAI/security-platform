# Scorecard: the weakest link decides

The ledger answers "what is wrong right now". The scorecard answers "how good is the security programme, and where is
it weakest". It is computed by the platform on every publish, from evidence only, and it is generic: the catalog of
controls is data, and an organisation brings its own.

## Model

```
 control  ──(evaluator / human attestation)──▶ pass | fail | unknown | not_implemented | unattested | expired | na
 dimension score = 100 × Σ weight(pass) / Σ weight(not na)            (weighted pass ratio, 0-100)
 overall score   = min(dimension scores)                              (the weakest link)
 status          = FAIL as soon as one dimension < its threshold      (default 75)
```

- Only `pass` counts. `unknown` (no data, stale data, a missing adapter: *no findings != secure*), `not_implemented`
  (a planned control) and an attestation that is missing or `expired` all count as failing. `na` is excluded from the
  denominator, and only with a human's approval and an expiry (like a risk exception).
- The same controls are also scored per **pillar** (network, device, people, software; a control may serve several)
  and per **NIST CSF 2.0 function** (Govern, Identify, Protect, Detect, Respond, Recover; from the control's `csf`
  category, e.g. `PR.AA` = Protect / Identity management, authentication and access control). The pillars are the
  user-facing view ("which of the four is weak"), CSF the governance view; CIS Controls v8 **IG1** is the baseline
  every control cites (`cis:`), so gaps against IG1 are visible.

## Default dimensions (product catalog)

| # | dimension (id) | question it answers | main pillars | main CSF functions | CIS v8 (IG1 focus) |
|---|---|---|---|---|---|
| 1 | design | Is the programme designed (threat model, contracts, AI guard rails)? | all | GV, ID | 1.1, 3.1, 4.1, 16.1 |
| 2 | coverage | Is everything we own in scope, and was it actually looked at? | network, device, software | ID | 1.1, 1.2, 2.1, 12.1 |
| 3 | intel | Do KEV/EPSS/advisories reach us quickly and match our assets? | software, device | ID | 7.1, 7.2, 7.4, 7.7 |
| 4 | operation | Does the platform run itself reliably, and is its data recoverable? | software | DE, PR, RC | 8.2, 11.1-11.5 |
| 5 | alerting | Do regressions reach a human; are SLOs defined and met? | all | DE, RS, GV | 8.11, 17.2, 17.4 |
| 6 | remediation | Are findings owned, fixed within SLO and confirmed? | all | RS, GV | 7.2-7.4, 17.8 |
| 7 | detection | If someone gets in, do we see it and know what to do? | all | DE, RS | 8.2, 8.5, 10.1, 17.1-17.7 |
| 8 | self | Is the platform (which knows every weakness) itself protected? | software, device | GV, PR, ID | 3.3, 3.6, 3.11, 16.x |
| 9 | generality | Can another organisation adopt it without forking? | software | GV | - |
| 10 | usability | Does an operator get value quickly and keep getting it? | software | GV | - |
| 11 | people | Who can act as us (humans, tokens, keys, AI agents): known, strongly authenticated, reviewed? | people | PR, GV, RC, DE | 5.1-5.4, 6.1-6.5, 14.1-14.3 |

`scorecard.py list` prints every control with its pillars and CSF category; `reports/scorecard.md` has the CIS column.

## Control catalog

One YAML file per dimension: `scorecard/catalog/<NN>-<dimension>.yaml` (schema `security-platform/scorecard-catalog/v1`).
Each work stream edits **only its own dimension's file**, so parallel work does not conflict; control ids are
prefixed with the dimension (`people.codehost-mfa`), and `scorecard.py lint` (a CI test) rejects ids that do not
match their file, duplicate ids, unknown pillars or CSF functions, attested controls without a validity or question.

```yaml
schema: security-platform/scorecard-catalog/v1
dimension: {id: people, order: 11, title: People and identity security, pillars: [people], threshold: 75}
controls:
  - id: people.codehost-mfa                  # <dimension>.<name>, stable once published
    title: Every code-host account has two-factor authentication on
    csf: PR.AA                               # NIST CSF 2.0 category (the function is the prefix)
    cis: ["6.3", "6.5"]                      # CIS Controls v8 safeguards
    pillars: [people]                        # default: the dimension's pillars
    check: automated                         # automated | evidence | attested
    weight: 3                                # relative importance inside the dimension (0 = informational)
    source: {type: findings, check_in: [identity.mfa_disabled], require_collector: identity}
    remediation: optional one-liner
  - id: people.password-manager
    title: A password manager holds unique passwords for every account
    csf: PR.AA
    cis: ["5.2"]
    check: attested
    validity: 90d                            # attestations expire and the control fails again
    question: "Is every account's password unique and stored in a password manager?"
    weight: 2
```

### Check types

| check | decided by | typical source |
|---|---|---|
| `automated` | a collector / runner metric, every run | `findings`, `sli`, `metric`, `collector_fresh`, `job`, `builtin` |
| `evidence` | a document or artefact exists, is current, says the right thing | `file` (`max_age` by git commit date, `contains`, `mode_max`) |
| `attested` | a human, with an expiry; reopens automatically | `<data>/attestations.yaml` (written by `scorecard.py attest`) |

Evaluators (`scorecard/evaluators.py`, documented in its docstring): `findings` (ledger selector, `max`,
`require_collector` + `max_age`, `require_coverage: <asset prefix>`), `sli`, `metric` (label regex match,
`agg`, `op`, `value`, `age: true` for timestamps, `absent`), `collector_fresh`, `job`, `file`, `all`/`any`,
`builtin` (`pillars_covered`, `functions_covered`, `attestations_current`), `none` (declared, not implemented).
A new KIND of evidence is one function in `EVALUATORS`; a new control is only YAML.

`require_collector` and `require_coverage` make "0 findings" mean something: a control over a check that nobody ran,
or over an adapter that is not configured (e.g. an identity provider API without a key), is `unknown`, not `pass`.

### Instance variables

Catalog strings may use `${var}`: `${data}` (the private data directory) and `${product}` are built in; others come
from the instance's `scorecard.vars` (for example `hub_host`, `self_repo`, `self_image` in the `self` dimension).
A control whose variable is not set is `unknown` with "configure scorecard.vars: ...".

## Attestations (humans only)

What no API can tell - phishing-resistant MFA on an identity provider, a password manager, recovery codes stored
offline, a quarterly access review, an IR exercise - is answered by a person:

```sh
scorecard/scorecard.py attest --data <data> people.password-manager --by alice --note "vault reviewed, 0 reused"
scorecard/scorecard.py attest --data <data> people.recovery-offline --by alice --false --note "Google codes missing"
scorecard/scorecard.py attest --data <data> people.org-mfa-required --by alice --not-applicable "no organisations" --days 180
```

- The file (`<data>/attestations.yaml`, mode 0600, schema `security-platform/attestations/v1`) records who, when,
  until when (default `at + validity`), and an optional note. **Never a secret.**
- Expired attestations make the control fail again (`SecurityAttestationExpired`, ticket); the weekly digest lists
  what is missing or expires within 14 days. Entries without `attested_by` are ignored.
- AI agents never attest on a human's behalf; they may draft the command.
- An in-cluster hub receives the file from a site: `push` job `files: {attestations: attestations.yaml}` and the
  hub's ingest `accept_control: [attestations]`.

## Outputs

| output | where | content |
|---|---|---|
| `reports/scorecard.json` | private data dir | schema `security-platform/scorecard/v1`: dimensions, pillars, functions, dimension×pillar, every control's status and detail |
| `reports/scorecard.md` | private data dir | the same for humans; failing controls first |
| `metrics/scorecard.prom` | private data dir → every sink | aggregates only, see below |
| weekly digest | `reports/digest/<week>.md` | "Scorecard" section: dimensions sorted weakest first, failing controls, attestations due |
| Grafana | generated dashboard, first row | overall, by dimension, pillar, CSF function, history, failing controls, attestations |

Metrics (labels are aggregates: never a control id, asset or finding):

| metric | labels | meaning |
|---|---|---|
| `security_score` | `dimension` / `pillar` / `function` / `dimension`+`pillar` | 0-100 |
| `security_score_overall` | - | min over dimensions |
| `security_score_threshold`, `security_score_pass` | - | threshold; 1 while every dimension meets it |
| `security_score_controls` | `dimension`, `status` (pass/fail/na) | control counts |
| `security_score_regressions_total` | `dimension` | counter: times the dimension dropped below its threshold (first sight = baseline) |
| `security_attestations` | `state` (valid/expiring/expired/missing) | human controls |
| `security_scorecard_last_compute_timestamp_seconds` | - | heartbeat |

Alerts (generated): `SecurityScoreRegression` (ticket; `increase(security_score_regressions_total)` - regression
only, a standing low score is for the weekly review), `SecurityAttestationExpired`, `SecurityScorecardStale`.
Runbooks: `docs/runbooks.md#score-regression`, `#attestation-expired`.

## Another organisation's scorecard

Everything is configuration in the instance:

```yaml
scorecard:
  threshold: 80                       # default 75; a dimension may set its own `threshold`
  catalog_dirs: [~/sec/catalog]       # added after the product catalog (same id = replaces the product's control)
  replace_catalog: false              # true: ONLY your catalog_dirs (your own dimensions, ids, weights)
  overrides:                          # tune product controls without copying them
    people.org-mfa-required: {weight: 3}
    usability.time-to-first-run: {disabled: "measured elsewhere"}
  vars: {hub_host: "host:sec-hub-1", self_repo: "repo:github/acme/security-platform", self_image: "ghcr.io/acme/sp"}
  pillars: [network, device, people, software]   # the pillar vocabulary
  enabled: true                       # false: the runner does not compute it
```

Lowering a weight, disabling a control or changing a threshold is a Re-plan decision: do it in a reviewed change
with the reason in the file, never to silence an alert.

## Adding controls (work streams)

1. Pick your dimension's file; add the control at the end of its section; id `<dimension>.<name>`.
2. Prefer `automated`; use `require_collector`/`require_coverage` so missing data is `unknown`, never a silent pass.
   Use `attested` only for what no API can tell, with an honest `validity`.
3. A control for something not built yet is `source: {type: none, reason: ...}`: it counts as failing, which is the
   honest score, and it is the roadmap.
4. `scorecard.py lint` and `python -m unittest tests.test_scorecard` must pass; run
   `scorecard.py compute --data <a copy of the data>` to see the effect before merging.
