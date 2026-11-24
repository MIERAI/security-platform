# SSH authorized keys changed on a host

**What fired:** `SecurityDetectionAuthAuthorizedKeysChanged` (detection `auth-authorized-keys-changed`, severity `page`, ATT&CK T1098.004, pillar device).

## Why it matters

A host's authorized_keys changed (file-integrity event from the collector that watches hosts without a runtime sensor). New keys are persistence.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="authorized_keys_changed"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- Configuration management deploying keys; the operator adding a key.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Compare the current file with the expected one (configuration management); remove unknown keys after copying the file.
2. Review logins since the change (`| event="ssh_login_success"`).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the file before/after (the collector keeps the previous hash; copy the current file), logins since.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Acknowledge each legitimate change against its change record.
