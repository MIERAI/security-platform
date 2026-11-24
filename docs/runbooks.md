# Runbooks

Rule for all of them: the platform and AI only **propose**; changes go through the instance's normal change
process (PR, review, soak, rollback plan). Production is never used for drills.

## slo-breach

1. Open the private ledger report (`<data>/reports/latest-auto.md`), filter by the SLI's checks.
2. Decide per finding: fix (PR) / exception (human-approved, `approved_by`, `reason`, `expires`) / false positive.
3. After the fix, re-run the collector; the ledger marks it `fixed` only if the asset was covered.

## regression

A `fixed` finding came back (`security_findings_reopened_total` increased).
1. Treat as an incident: who/what reintroduced it (GitOps history, image rebuild, host rebuild)?
2. Fix, then add a **preventive control** (CI policy, admission rule, ansible task) so it cannot return silently.
3. Postmortem (template below) — mandatory for regressions.

## collector-stale

No findings ≠ secure. Check the collector log in the run dir, the exec adapter reachability (offline host = gap),
credentials (expired token), tool versions. Fix the collector before trusting any SLI that depends on it.

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
