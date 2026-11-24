# sudo by an unexpected user

**What fired:** `SecurityDetectionAuthSudoUnexpectedUser` (detection `auth-sudo-unexpected-user`, severity `ticket`, ATT&CK T1548.003, pillar device).

## Why it matters

Privilege use by an account that should not have it: a new account, a compromised service account, or a sudoers change.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="sudo" | user="<user>"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A newly onboarded administrator not yet in `sudo_users`.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Check why the user can sudo (`sudo -l -U <user>`, sudoers drop-ins) and whether that was a reviewed change.
2. Not reviewed: remove the sudo right, lock the account, review its sessions.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the sudo lines (COMMAND=…), sudoers files with hashes, the user's sessions.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add the account to `sudo_users` through a reviewed change.
