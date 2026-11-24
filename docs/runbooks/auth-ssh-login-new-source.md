# Successful SSH login from a source never seen before

**What fired:** `SecurityDetectionAuthSshLoginNewSource` (detection `auth-ssh-login-new-source`, severity `ticket`, ATT&CK T1078, pillar device).

## Why it matters

The first login of a user from an address never seen before for that host: new device, new network, or a stolen key used from elsewhere.

## Triage

1. The matching events (raw line = evidence; `event`, `user`, `src_ip` are structured metadata):

   ```
   {source="auth", host="<host>"} | event="ssh_login_success" | novel="true"
   ```

2. All authentication activity on the host in the window:

   ```
   {source="auth", host="<host>"}
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- The operator on a new network or device (confirm and acknowledge as `benign`).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Ask the user out of band. Not confirmed: proceed as auth-ssh-login-untrusted-network.
2. Check what the session did (Falco host events, sudo events of the same user).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the raw line with key fingerprint, the session's activity.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune: the baseline learns the source after the first sighting.
