# New SSH, GPG or signing key on the code host account

**What fired:** `SecurityDetectionCodehostCredentialAdded` (detection `codehost-credential-added`, severity `page`, ATT&CK T1098.004, T1098.001, pillar network).

## Why it matters

A new key on the code host account can push code and sign commits as you: the account's most powerful persistence.

## Triage

1. The matching events (structured metadata: event, actor, repo; the line keeps the API object):

   ```
   {source="codehost"} | event=~"ssh_key_added|gpg_key_added|signing_key_added"
   ```

2. Everything on the account in the last day:

   ```
   {source="codehost", host="<account>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- You added a key for a new device (confirm the fingerprint and the time).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Not you: delete the key in the account settings, change the password, review active sessions and personal access tokens, enable/verify 2FA.
2. Review pushes and repository settings changes since the key was added.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the key's fingerprint and title, creation time, the account's security log export (web UI).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune; acknowledge your own keys as `benign`.
