# Security scorecard 2030-01-10T00:00:00Z

**FAIL** - overall (weakest dimension) 35.7 / threshold 75; mean 35.7; weakest: ev.

PRIVATE: failing controls are attacker intelligence.

## Dimensions

| # | dimension | score | status | pillars | CSF | failing controls |
|---|---|---|---|---|---|---|
| 1 | Evaluators (`ev`) | 35.7 | FAIL | software | DE, GV, ID, PR, RC | ev.all-fail, ev.all-unknown, ev.any-unknown, ev.bad-builtin, ev.bogus, ev.file-missing, ev.file-mode, ev.file-text, ev.find-asset, ev.find-cov, ev.find-kind, ev.find-nocov, ev.find-prefix, ev.find-status, ev.first-known, ev.fresh-all, ev.functions, ev.job-all, ev.job-ghost, ev.job-rc, ev.job-site, ev.metric-absent, ev.metric-old, ev.metric-own, ev.none, ev.pillars, ev.var-missing |

## Pillars

| pillar | score | controls |
|---|---|---|
| network | 0.0 | 0 |
| device | 0.0 | 0 |
| people | 0.0 | 0 |
| software | 35.7 | 39 |

## NIST CSF 2.0 functions

| function | score | controls |
|---|---|---|
| GV Govern | 58.3 | 9 |
| ID Identify | 20.0 | 5 |
| PR Protect | 12.5 | 8 |
| DE Detect | 42.9 | 14 |
| RS Respond | 0.0 | 0 |
| RC Recover | 0.0 | 3 |

## Attestations: 0 valid, 0 expiring within 14 days, 0 expired, 0 missing

## Controls

| control | dim | check | w | status | detail | CIS |
|---|---|---|---|---|---|---|
| `ev.all-fail` all with none | ev | automated | 1 | fail | not implemented yet |  |
| `ev.file-missing` missing | ev | evidence | 1 | fail | {sandbox}/data/nothing.md missing |  |
| `ev.file-mode` secret mode | ev | evidence | 1 | fail | {sandbox}/data/policy.md mode 0o644 exceeds 0600 |  |
| `ev.file-text` lacks text | ev | evidence | 1 | fail | {sandbox}/data/policy.md lacks /^## Owner/ |  |
| `ev.find-asset` on h2 | ev | automated | 1 | fail | 1 matching finding(s) (max 0): ssh.password_auth_enabled |  |
| `ev.find-cov` needs host coverage | ev | automated | 1 | fail | 3 matching finding(s) (max 0): CVE-1, ssh.password_auth_enabled, ssh.root_login |  |
| `ev.find-kind` vulnerabilities | ev | automated | 1 | fail | 1 matching finding(s) (max 0): CVE-1 |  |
| `ev.find-prefix` ssh findings | ev | automated | 1 | fail | 2 matching finding(s) (max 1): ssh.password_auth_enabled, ssh.root_login |  |
| `ev.find-status` accepted too | ev | automated | 1 | fail | 1 matching finding(s) (max 0): tls.weak |  |
| `ev.first-known` first known | ev | automated | 1 | fail | 0 matching finding(s) (max -1) |  |
| `ev.fresh-all` Every collector fresh | ev | automated | 1 | fail | k8s: last good run 40.0d ago |  |
| `ev.functions` functions covered | ev | automated | 1 | fail | no passing automated control for: RS, RC |  |
| `ev.job-all` Every job | ev | automated | 1 | fail | broken: last run failed (rc=2); remote: no success within 2d |  |
| `ev.job-ghost` Never ran | ev | automated | 1 | fail | ghost: never ran |  |
| `ev.job-rc` Job failed | ev | automated | 1 | fail | broken: last run failed (rc=2) |  |
| `ev.job-site` Site job old | ev | automated | 1 | fail | remote: no success within 2d |  |
| `ev.metric-old` Metric too old | ev | automated | 1 | fail | security_collector_last_run_timestamp_seconds age 2.3d (<= 1d) |  |
| `ev.metric-own` Own scores are ignored | ev | automated | 1 | fail | metric security_score_overall absent |  |
| `ev.pillars` pillars covered | ev | automated | 1 | fail | no passing automated control for: network, device, people |  |
| `ev.all-unknown` all with unknown | ev | automated | 1 | unknown | SLI gone not computed yet |  |
| `ev.any-unknown` any unknown | ev | automated | 1 | unknown | SLI a not computed yet; SLI b not computed yet |  |
| `ev.bad-builtin` bad builtin | ev | automated | 1 | unknown | evaluator error: ValueError: unknown builtin 'nothing' |  |
| `ev.bogus` bogus type | ev | automated | 1 | unknown | unknown source type 'bogus' |  |
| `ev.find-nocov` needs k8s coverage | ev | automated | 1 | unknown | nothing covered k8s:* (adapter not configured or failing) |  |
| `ev.metric-absent` Metric absent | ev | automated | 1 | unknown | metric nope absent |  |
| `ev.var-missing` unset variable | ev | automated | 1 | unknown | configure scorecard.vars: nope |  |
| `ev.none` declared | ev | automated | 1 | not_implemented | needs a restore drill |  |
| `ev.any-pass` any | ev | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `ev.current` attestations current | ev | automated | 1 | pass | 0 attested controls, none expired |  |
| `ev.file-ok` policy | ev | evidence | 1 | pass | {sandbox}/data/policy.md present (mode 0o644) |  |
| `ev.find-sev` critical findings | ev | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `ev.fresh` Host fresh | ev | automated | 1 | pass | 1 collector(s) fresh |  |
| `ev.job-ok` Job ok | ev | automated | 1 | pass | 1 job(s) healthy |  |
| `ev.metric-absent-ok` Absent is fine | ev | automated | 1 | pass | metric nope absent |  |
| `ev.metric-age` Metric age | ev | automated | 1 | pass | security_collector_last_run_timestamp_seconds age 1.0h (<= 2h) |  |
| `ev.metric-count` Metric count | ev | automated | 1 | pass | count(security_collector_last_run_timestamp_seconds) = 2 (>= 2) |  |
| `ev.metric-sum` Metric sum | ev | automated | 1 | pass | sum(security_sli) = 3.5 (< 4) |  |
| `ev.replaced` organisation version | ev | automated | 1 | pass | 0 matching finding(s) (max 0) |  |
| `ev.weighty` weight from the instance | ev | automated | 4 | pass | 0 matching finding(s) (max 0) |  |
