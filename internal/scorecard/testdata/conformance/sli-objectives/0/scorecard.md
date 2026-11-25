# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 25.0 / threshold 75; mean 25.0; weakest: sli.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | SLIs (`sli`) | 25.0 | FAIL | software | DE, RS | sli.broken, sli.gone, sli.ttr |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 0.0 | 0 |
| people | 0.0 | 0 |
| software | 25.0 | 4 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 0.0 | 0 |
| ID Identify | 0.0 | 0 |
| PR Protect | 0.0 | 0 |
| DE Detect | 100.0 | 1 |
| RS Respond | 0.0 | 3 |
| RC Recover | 0.0 | 0 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `sli.ttr` Time to remediate | sli | automated | 1 | fail | SLI ttr = 3.5 (objective <= 1) |  |
| `sli.broken` No SLI named | sli | automated | 1 | unknown | evaluator error: KeyError: 'sli' |  |
| `sli.gone` Not computed yet | sli | automated | 1 | unknown | SLI gone not computed yet |  |
| `sli.crit` No open critical | sli | automated | 1 | pass | SLI crit = 0 (objective <= 0) |  |
