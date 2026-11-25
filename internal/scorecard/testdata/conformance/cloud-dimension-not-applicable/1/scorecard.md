# Security scorecard 2030-01-10T00:00:00Z

**PASS** - overall (weakest dimension) 100.0 / threshold 75; mean 100.0; weakest: base.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Base (`base`) | 100.0 | PASS | device | PR | - |
| 12 | Cloud (`cloud`) | 100.0 | PASS | software | DE | - |
| 13 | Agents (`agents`) | n/a | NOT APPLICABLE | - | - | every control is not applicable |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 100.0 | 1 |
| people | 0.0 | 0 |
| software | 100.0 | 2 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 0.0 | 0 |
| ID Identify | 0.0 | 0 |
| PR Protect | 100.0 | 2 |
| DE Detect | 100.0 | 1 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `base.ok` Ok | base | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `cloud.logging` Audit logging | cloud | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `agents.deny` Deny rules | agents | automated | 1 | na | not applicable: out of scope for the instance (tag:ai-agent): no AI coding agents |  |
