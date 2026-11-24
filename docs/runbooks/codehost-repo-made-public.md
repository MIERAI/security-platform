# Repository made public

**What fired:** `SecurityDetectionCodehostRepoMadePublic` (detection `codehost-repo-made-public`, severity `page`, ATT&CK T1567, T1213.003, pillar network).

## Why it matters

Making a repository public publishes its whole history: secrets once committed, internal names, configuration.

## Triage

1. The matching events (structured metadata: event, actor, repo; the line keeps the API object):

   ```
   {source="codehost"} | event="repo_made_public"
   ```

2. Everything on the account in the last day:

   ```
   {source="codehost", host="<account>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A planned open-sourcing (should have a decision record).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Unplanned: make it private again immediately, then assume everything in its history is exposed: rotate secrets ever committed (scan the history).
2. Check forks and clones made while public (cannot be undone: rotate).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the time window it was public, the repository's history scan result.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune.
