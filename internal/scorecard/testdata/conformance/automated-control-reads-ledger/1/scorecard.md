# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 50.0 / threshold 75; mean 58.4; weakest: beta.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Alpha (`alpha`) | 66.7 | FAIL | device, network | GV, ID | alpha.no-critical |
| 2 | Beta (`beta`) | 50.0 | FAIL | people | PR | beta.expired, beta.missing |
| 3 | Gamma (cloud only) (`gamma`) | n/a | NOT APPLICABLE | - | - | instance has no cloud.accounts |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 100.0 | 1 |
| device | 0.0 | 1 |
| people | 50.0 | 4 |
| software | 0.0 | 1 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 100.0 | 1 |
| ID Identify | 0.0 | 1 |
| PR Protect | 50.0 | 5 |
| DE Detect | 0.0 | 0 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 2 valid, 0 expiring within 14 days, 1 expired, 1 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `alpha.no-critical` No open critical finding | alpha | automated | 1 | fail | 1 matching finding(s) (max 0): host.crit |  |
| `beta.expired` Expired attestation | beta | attested | 1 | expired | attestation by bob expired 2029-11-01: re-attest |  |
| `beta.missing` Never attested | beta | attested | 1 | unattested | not attested: a human answers "Holds?" (scorecard.py attest) |  |
| `alpha.reviewed` Reviewed | alpha | attested | 2 | pass | attested by alice until 2030-03-01 |  |
| `beta.trained` Trained | beta | attested | 2 | pass | attested by bob until 2031-01-01 |  |
| `beta.waived` Waived by a human | beta | attested | 5 | na | not applicable (approved by carol): not used here |  |
| `gamma.thing` Thing | gamma | attested | 1 | na | not applicable: instance has no cloud.accounts |  |
