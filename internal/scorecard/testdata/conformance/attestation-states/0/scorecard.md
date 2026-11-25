# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 45.5 / threshold 75; mean 45.5; weakest: att.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Attestations (`att`) | 45.5 | FAIL | people | GV | att.expired, att.false, att.missing, att.na-expired, att.no-by, att.no-date |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 0.0 | 0 |
| people | 45.5 | 12 |
| software | 0.0 | 0 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 45.5 | 12 |
| ID Identify | 0.0 | 0 |
| PR Protect | 0.0 | 0 |
| DE Detect | 0.0 | 0 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 0 |

## Attestations: 4 valid, 1 expiring within 14 days, 2 expired, 3 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `att.expired` Attestation expired | att | attested | 1 | expired | attestation by alice expired 2030-01-10: re-attest |  |
| `att.false` Attestation false | att | attested | 1 | fail | attested as NOT holding by bob: it does not hold |  |
| `att.na-expired` Attestation na-expired | att | attested | 1 | expired | attestation by carol expired 2029-06-01: re-attest |  |
| `att.missing` Attestation missing | att | attested | 1 | unattested | not attested: a human answers "Does missing hold?" (scorecard.py attest) |  |
| `att.no-by` Attestation no-by | att | attested | 1 | unattested | attestation without attested_by is ignored |  |
| `att.no-date` Attestation no-date | att | attested | 1 | unattested | attestation without a date (at/expires) is ignored |  |
| `att.at-validity` Attestation at-validity | att | attested | 1 | pass | attested by alice until 2030-02-04 |  |
| `att.expiring` Attestation expiring | att | attested | 1 | pass | attested by alice until 2030-01-20 (expires within 14 days) |  |
| `att.fallback-api` The API decides | att | automated | 1 | pass | SLI crit = 0 (objective <= 0) |  |
| `att.fallback-human` API cannot tell, a human can | att | automated | 1 | pass | attested by dave until 2030-03-01 |  |
| `att.valid` Attestation valid | att | attested | 1 | pass | attested by alice until 2031-01-01 |  |
| `att.na-valid` Attestation na-valid | att | attested | 1 | na | not applicable (approved by carol): not used here |  |
