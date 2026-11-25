# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 6.2 / threshold 75.5; mean 28.6; weakest: one.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | One (`one`) | 6.2 | FAIL | device, network | GV, ID | one.b |
| 2 | Two (`two`) | 18.8 | FAIL | device | PR | two.b |
| 3 | Three (`three`) | 83.3 | PASS | software | DE, RS | three.b, three.c |
| 5 | Five (`five`) | 6.2 | FAIL | people | GV, ID | five.b |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 6.2 | 2 |
| device | 9.7 | 3 |
| people | 6.2 | 2 |
| software | 83.3 | 3 |
| physical | 0.0 | 0 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 100.0 | 2 |
| ID Identify | 0.0 | 2 |
| PR Protect | 18.8 | 2 |
| DE Detect | 100.0 | 2 |
| RS Respond | 0.0 | 1 |
| RC Recover | 0.0 | 0 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `five.b` B | five | automated | 15 | fail | 0 matching finding(s) (max -1) |  |
| `one.b` B | one | automated | 15 | fail | 0 matching finding(s) (max -1) |  |
| `three.b` B | three | automated | 0.5 | fail | 0 matching finding(s) (max -1) |  |
| `two.b` B | two | automated | 13 | fail | 0 matching finding(s) (max -1) |  |
| `three.c` Declared only | three | evidence | 0 | not_implemented | later |  |
| `five.a` A | five | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `one.a` A | one | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `three.a` A | three | automated | 2.5 | pass | 0 matching finding(s) (max 0) |  |
| `two.a` A | two | automated | 3 | pass | 0 matching finding(s) (max 0) |  |
