# Using it in a team: push into the tools you already have

The platform has no UI and no user accounts of its own, on purpose. A team keeps working where it already works:
findings become **tickets** in its issue tracker and **events** in its SIEM; numbers go to its monitoring (metric
sinks, [runner.md](runner.md)); the short summary goes to its chat ([instance-reference.md](instance-reference.md#notify)).
Access control is the access control of those tools.

## Division of responsibility

| concern | who owns it | here |
|---|---|---|
| real-time detection, correlation, alert triage, investigation, retention of raw events | your **SIEM** / log platform | send it the ledger as OCSF events (`export.siem`); ship raw security events with the `events` job |
| cloud configuration checks | the cloud provider's **posture service** (Security Hub, Security Command Center, Defender for Cloud) or an engine | **import** their results (`cloud.imports`, [cloud.md](cloud.md)); do not rewrite their checks |
| identity and device state (MFA enforcement, managed devices) | your **IdP** / **MDM** | import their exports as a findings document (a `command` job) and point the people controls at it ([scorecard.md](scorecard.md#not-applicable-environments-without-the-thing)) |
| work tracking, assignment, discussion | your **issue tracker** | one ticket per finding (`export.tickets`), opened, closed and reopened by the ledger |
| **aggregation** of every source into one contract | this platform | collectors, imports, `command` jobs → findings/v1 |
| **de-duplication** and finding identity | this platform | one id per (layer, asset, check), one finding listing every source |
| **lifecycle**: first seen, fixed only when a run covered the asset, regression, human-approved exceptions with expiry | this platform | the ledger |
| **scoring** of the programme (weakest link) | this platform | the scorecard |
| **remediation SLOs**: owner, due date, overdue, time to remediate | this platform | core/remediation.py, `security_remediation_*` |

Rule: if another tool already detects something well, import its result instead of adding a check here. This
platform adds what those tools do not keep: one ledger across all of them, its history, and the SLOs on it.

## Tickets

```yaml
export:
  tickets:
    - type: github                     # GitHub or GitHub Enterprise Server (api_url); jira: interface only, later
      repo: example-org/security-findings
      token_file: ~/.config/security-platform/issues.token     # 0600; fine-grained: Issues read/write, Metadata read
      min_severity: high               # new tickets only at or above this
runner:
  jobs:
    export: {type: export, schedule: "55 * * * *"}    # after remediation, so owner / due date are current
```

- **Idempotent.** Each issue carries a hidden marker with the finding id and the label `security-platform`; every
  run lists those issues and changes only what differs. No local mapping file: a lost data directory does not create
  duplicates (a duplicate found anyway is closed). Do not remove the base label from an issue.
- **The ledger decides.** fixed (a run covered the asset) → closed as completed; accepted (exceptions.yaml) → closed
  as not planned with `accepted-risk`; back to open → reopened with one comment (regression or expired exception).
  Closing an issue by hand fixes nothing: the next run reopens it. Labels you add yourself are kept.
- **Minimal by default.** The body has the control, asset, severity, first seen and the evidence *pointer* (a path in
  the private data directory; `evidence_url` turns it into a link on a private host). The finding title, remediation
  text, owner and due date only with `fields:`. Never evidence content, never a secret.
- **Private only.** A repository that is not private is refused before anything is written.
- **Rate limits.** One second between writes (`write_interval`), waits for the reset / `Retry-After` up to `max_wait`,
  at most `max_writes` per run; the rest follows on the next run. `dry_run: true` (or the job's `dry_run`) only logs.

The older `remediation.tracker: {type: github-issues}` (gh CLI, full body) keeps working; prefer `export.tickets` for
a team repository.

## SIEM

```yaml
export:
  siem:
    - {type: http, url: https://logs.example.internal/ingest, token_file: ~/.config/security-platform/siem.token}
    - {type: file, path: /var/log/security-platform/findings.jsonl}     # for a log shipper that tails it
    - {type: stdout}                                                    # a container's log stream
```

Events are OCSF 1.x Finding classes (`core/ocsf.py`: Detection 2004, Vulnerability 2002, Compliance 2003) with
activity Create / Update / Close. Default `mode: changes`: a finding is sent when it is new or its status, severity
or title changed (per sink state in `<data>/state/export/`, advanced only after the receiver accepted the batch);
`mode: all` re-sends the whole ledger every run. HTTP: ndjson or a JSON array, `batch_size`, retries on 429 / 5xx
with backoff, bearer token from a file (`auth_scheme` for receivers that want another word, `wrap: event` for an
envelope). Events carry asset names and titles: the SIEM must be as private as the ledger.

Health: `security_export_*` metrics per sink and the `SecurityExportFailing` alert ([runbooks.md](runbooks.md#export-failing)).
Keys: [instance-reference.md](instance-reference.md#export).
