# Runbooks

Rule for all of them: the platform and AI only **propose**; changes go through the instance's normal change
process (PR, review, soak, rollback plan). Production is never used for drills.

## slo-breach

1. Open the private ledger report (`<data>/reports/latest-auto.md`), filter by the SLI's checks.
2. Decide per finding: fix (PR) / exception (human-approved, `approved_by`, `reason`, `expires`) / false positive.
3. After the fix, re-run the collector; the ledger marks it `fixed` only if the asset was covered.

## regression

Two kinds of alert land here, both regression-only (a standing backlog never pages; it is in the weekly digest):

- `SecurityRegression_<sli>`: findings ENTERED an SLI's set (`security_sli_new_total` increased): a new
  unauthenticated service, a new KEV match / critical vulnerability on an exposed asset (`vuln_alertable`, pages),
  a new critical configuration finding. Look the SLI up in `<data>/reports/latest-auto.md` / the digest; decide fix /
  exception / false positive as for an SLO breach. For `vuln_alertable` follow [emergency-disclosure](#emergency-disclosure).
- `SecurityFindingRegression`: a `fixed` finding came back (`security_findings_reopened_total` increased).
1. Treat as an incident: who/what reintroduced it (GitOps history, image rebuild, host rebuild)?
2. Fix, then add a **preventive control** (CI policy, admission rule, ansible task) so it cannot return silently.
3. Postmortem (template below) — mandatory for regressions.

## collector-stale

No findings ≠ secure. `SecurityCollectorStale`: the collector has not covered a single asset for two scheduled
intervals; `SecurityLedgerStale`: the hub has not merged anything for two days.
1. `runner.py status --instance … --data …` on the host that runs it: `last_rc`, `last_note`, `last_run_dir`.
2. The collector log in that run dir; the exec adapter reachability (offline host = gap); credentials (expired or
   missing read-only token); tool versions; the trigger itself (`security_runner_tick_timestamp_seconds`).
3. Sites (e.g. an external vantage host) reach the ledger through the hub's `ingest` job: check both ends.
Fix the collector before trusting any SLI that depends on it.

## runner-stale

`SecurityRunnerStale`: the hub's tick heartbeat (`security_runner_tick_timestamp_seconds`) is older than
`security_runner_tick_max_gap_seconds` (instance `runner.tick_stale_after`). Nothing reached this cluster: the trigger
did not fire, the runner could not start, the host is down, or the only sink to this cluster fails.
`SecurityMetricsSinkFailing`: a sink failed 4 ticks in a row (seen through another sink or the local metrics file).
1. The runner log (`<data>/state/runner/tick.log`, or the CronJob's pod logs): `tick.sh: runner exited rc=…`,
   `cannot start: …`, `sink …: … (failed Nx in a row; retried next tick)`.
2. `runner.py status`; `<data>/state/runner/sinks.json` (last error per sink).
3. Environment: ticks never install anything (`deploy/render.py env` built it at deploy time). If the interpreter is
   missing, rebuild the environment (`render.py env --install DIR`) and re-render the wrapper.
4. Sink: credentials, namespace existence, reachability; it recovers by itself on the next tick once fixed.

## contract-violation

A findings document failed the schema and was ignored (`security_contract_invalid_documents` > 0). The runner keeps
the document in the run dir (or the site's outbox). Usually a collector and the core disagree on a major version:
upgrade the core first (it accepts both majors during a two-step change), then the collector.

## intel-feed-stale

A threat-intelligence feed (KEV, EPSS, OSV, the Trivy DB) is older than 3 days: time-to-know degrades silently.
Check the `intel` job's run dir: network, the feed URL (moved?), the cache directory permissions. A 304 (unchanged)
still refreshes the age.

## exception-expired

A human-approved risk acceptance passed its `expires` date; the finding is `open` again. The owner renews it
(new `expires`, `approved_by`, reason) in the private `exceptions.yaml`, or fixes the finding.

## emergency-disclosure

For a major disclosure (xz-backdoor-like, KEV addition affecting a common package). Target: hours.

| Step | Within | Action |
|---|---|---|
| 1 Confirm | 1h | Refresh feeds; query the SBOM cache for the package/version range (`grep -l <purl> <data>/sbom/*.json` or trivy sbom); list affected assets with exposure flags from the latest run. If the advisory is unstructured, the advisor may extract the range; a human confirms it. Nobody concludes "not affected" without a deterministic query. |
| 2 Mitigate | 4h | Reduce exposure first: close the port / NetworkPolicy / scale to zero non-critical / block at the edge. Through the change process, expedited. |
| 3 Patch | 24h (KEV + exposed) / 7d (critical) | Rebuild/upgrade, promote through the normal environments (shortened soak allowed with explicit approval). |
| 4 Verify | after patch | Re-run vuln-intel + exposure; the ledger must show `fixed`. |
| 5 Postmortem | 5 days | time-to-know and time-to-remediate from the ledger; what would have made it faster; new checks. |

## postmortem template

```
# Postmortem: <title>            date / author / status (draft|reviewed)
Finding ids: …        Layer: …       Severity: …
Timeline (UTC): disclosed → first_seen (time-to-know) → mitigated → fixed (time-to-remediate)
Impact: what was exposed, to whom, for how long (evidence pointers into the private ledger)
Root cause (technical + process):
What went well / badly:
Actions (each with owner + due date): fix, preventive control, detection, check catalog change
Re-plan inputs: threat model changes, SLO target changes, checks to add/retire
AI involvement: advisor proposals used (decision-log ids); human decisions
```
