# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 60.0 / threshold 75; mean 60.0; weakest: scope.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Scope (`scope`) | 60.0 | FAIL | device | DE, PR | scope.col-fallback, scope.col-job |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 60.0 | 14 |
| people | 0.0 | 0 |
| software | 0.0 | 0 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 0.0 | 0 |
| ID Identify | 0.0 | 0 |
| PR Protect | 100.0 | 8 |
| DE Detect | 50.0 | 6 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 1 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `scope.col-fallback` Needs k8s, or a human | scope | automated | 1 | unattested | not attested: a human answers "Does it hold?" (scorecard.py attest) |  |
| `scope.col-job` Collector of a runner job | scope | automated | 1 | unknown | no recent coverage (vuln: never covered anything) |  |
| `scope.col-ledger` Collector in the ledger | scope | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `scope.plain` Plain | scope | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `scope.star` Any collector | scope | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `scope.bracket1` Character class | scope | automated | 1 | na | not applicable: out of scope for the instance (scope.bracket[0-9]): a character class |  |
| `scope.disabled` Disabled with a reason | scope | automated | 1 | na | not applicable: disabled by the instance: replaced by a manual check |  |
| `scope.disabled-flag` Disabled | scope | automated | 1 | na | not applicable: disabled by the instance |  |
| `scope.exact` Exact id | scope | automated | 1 | na | not applicable: out of scope for the instance (scope.exact): an exact id |  |
| `scope.glob-a` Glob a | scope | automated | 1 | na | not applicable: out of scope for the instance (scope.glob-?): one character |  |
| `scope.glob-b` Glob b | scope | automated | 1 | na | not applicable: out of scope for the instance (scope.glob-?): one character |  |
| `scope.needs-col` Needs k8s | scope | automated | 1 | na | not applicable: collector not configured: k8s |  |
| `scope.nested-col` Needs identity or cloud, nested | scope | automated | 1 | na | not applicable: collector not configured: cloud, identity |  |
| `scope.tagged` Tagged | scope | automated | 1 | na | not applicable: out of scope for the instance (tag:ai-agent): no AI coding agents in use |  |
