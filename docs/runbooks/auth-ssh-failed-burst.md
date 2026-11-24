# Burst of failed SSH logins

**What fired:** `SecurityDetectionAuthSshFailedBurst` (detection `auth-ssh-failed-burst`, severity `ticket`, ATT&CK T1110, pillar device).

## Why it matters

A burst of failed logins is password guessing or a scan; harmless with key-only login, but it shows the SSH port is reachable from where the attempts come.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="ssh_login_failure"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A misconfigured client or automation retrying with the wrong key.
- The operator's own mistyped user name.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Check the source addresses: from outside the trusted networks = the port is exposed; close it at the firewall / bind sshd to the overlay network.
2. Confirm password authentication is off (the platform's ssh.password_auth_enabled check).
3. Look for any success from the same source (auth-ssh-login-* alerts).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: source addresses, user names tried, time distribution.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Raise `ssh_failure_burst` only with evidence; fix noisy automation instead.
