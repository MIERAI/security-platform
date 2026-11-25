# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 0.0 / threshold 75; mean 0.0; weakest: alpha.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Alpha (`alpha`) | 0.0 | FAIL | device | PR | alpha.ok |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 0.0 | 1 |
| people | 0.0 | 0 |
| software | 0.0 | 0 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 0.0 | 0 |
| ID Identify | 0.0 | 0 |
| PR Protect | 0.0 | 1 |
| DE Detect | 0.0 | 0 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `alpha.ok` Ok | alpha | automated | 1 | fail | 1 matching finding(s) (max 0): host.crit |  |
