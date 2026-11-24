# Deploy key, webhook or application access added

**What fired:** `SecurityDetectionCodehostIntegrationAdded` (detection `codehost-integration-added`, severity `ticket`, ATT&CK T1098, T1199, pillar network).

## Why it matters

Deploy keys, webhooks and app authorizations are durable access paths into repositories (read, write, or every push sent to a third party).

## Triage

1. The matching events (structured metadata: event, actor, repo; the line keeps the API object):

   ```
   {source="codehost"} | event=~"deploy_key_added|hook_added|app_installation_added|oauth_authorization_added"
   ```

2. Everything on the account in the last day:

   ```
   {source="codehost", host="<account>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A new CI/CD integration or deploy key added on purpose.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Not planned: remove the deploy key / webhook / authorization; check the webhook's target URL and the key's write flag.
2. Review what was accessed or pushed since.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the integration's details (target URL, permissions, read-only flag), creation time.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune; acknowledge planned additions with the change reference.
