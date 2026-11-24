# Successful SSH login from outside the trusted networks

**What fired:** `SecurityDetectionAuthSshLoginUntrustedNetwork` (detection `auth-ssh-login-untrusted-network`, severity `page`, ATT&CK T1078, T1133, pillar network).

## Why it matters

A successful login from outside the private, overlay and loopback networks means the SSH service is reachable from somewhere unexpected and someone holds a working credential.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="ssh_login_success"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A new trusted network (e.g. a second overlay range) not yet in `trusted_networks`.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Page-level incident unless the person is confirmed out of band within minutes.
2. Kill the session (`pkill -KILL -t <tty>` or the sshd-session pid) after capturing `ss -tpn` and `ps auxwwf`.
3. Remove/rotate the key used (fingerprint in the raw line), close the exposure (firewall, sshd ListenAddress).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the raw line (key fingerprint), the session's commands (shell history is not trustworthy: use Falco events on the node and the journal), network connections.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add a genuinely trusted network to `trusted_networks` through a reviewed change.
