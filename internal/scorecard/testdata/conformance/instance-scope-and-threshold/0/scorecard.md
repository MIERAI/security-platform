# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 0.0 / threshold 50; mean 50.0; weakest: beta.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Alpha (`alpha`) | 100.0 | PASS | device, network | GV, ID | - |
| 2 | Beta (`beta`) | 0.0 | FAIL | people | PR | beta.expired |
| 3 | Gamma (cloud only) (`gamma`) | n/a | NOT APPLICABLE | - | - | instance has no cloud.accounts |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 100.0 | 1 |
| device | 100.0 | 1 |
| people | 0.0 | 4 |
| software | 0.0 | 1 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 100.0 | 1 |
| ID Identify | 100.0 | 1 |
| PR Protect | 0.0 | 5 |
| DE Detect | 0.0 | 0 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 1 valid, 0 expiring within 14 days, 1 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `beta.expired` Expired attestation | beta | attested | 1 | expired | attestation by bob expired 2029-11-01: re-attest |  |
| `alpha.no-critical` No open critical finding | alpha | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `alpha.reviewed` Reviewed | alpha | attested | 2 | pass | attested by alice until 2030-03-01 |  |
| `beta.missing` Never attested | beta | attested | 1 | na | not applicable: out of scope for the instance (beta.miss*): not ours |  |
| `beta.trained` Trained | beta | attested | 2 | na | not applicable: out of scope for the instance (tag:people): no staff |  |
| `beta.waived` Waived by a human | beta | attested | 5 | na | not applicable (approved by carol): not used here |  |
| `gamma.thing` Thing | gamma | attested | 1 | na | not applicable: instance has no cloud.accounts |  |
