# Security scorecard 2030-01-10T00:00:00Z

**PASS** - overall (weakest dimension) 100.0 / threshold 75; mean 100.0; weakest: alpha.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Alpha (`alpha`) | 100.0 | PASS | device, network | GV, ID | - |
| 2 | Beta (`beta`) | 100.0 | PASS | people | PR | - |
| 3 | Gamma (cloud only) (`gamma`) | n/a | NOT APPLICABLE | - | - | instance has no cloud.accounts |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 100.0 | 1 |
| device | 100.0 | 1 |
| people | 100.0 | 4 |
| software | 0.0 | 1 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 100.0 | 1 |
| ID Identify | 100.0 | 1 |
| PR Protect | 100.0 | 5 |
| DE Detect | 0.0 | 0 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 4 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `alpha.no-critical` No open critical finding | alpha | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `alpha.reviewed` Reviewed | alpha | attested | 2 | pass | attested by alice until 2030-03-01 |  |
| `beta.expired` Expired attestation | beta | attested | 1 | pass | attested by bob until 2031-01-01 |  |
| `beta.missing` Never attested | beta | attested | 1 | pass | attested by bob until 2031-01-01 |  |
| `beta.trained` Trained | beta | attested | 2 | pass | attested by bob until 2031-01-01 |  |
| `beta.waived` Waived by a human | beta | attested | 5 | na | not applicable (approved by carol): not used here |  |
| `gamma.thing` Thing | gamma | attested | 1 | na | not applicable: instance has no cloud.accounts |  |
