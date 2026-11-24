# Failed or refused sudo

**What fired:** `SecurityDetectionAuthSudoFailure` (detection `auth-sudo-failure`, severity `ticket`, ATT&CK T1548.003, T1110, pillar device).

## Why it matters

Refused sudo (wrong password, not in sudoers) is an account probing for privilege, or a person who forgot a password.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="sudo_failure"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- The operator mistyping a password.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Confirm with the account owner. Not them: lock the account, review the session that ran sudo.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the sudo lines, the session (login line for the same user before it).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: No tuning; acknowledge confirmed mistakes as `benign`.
