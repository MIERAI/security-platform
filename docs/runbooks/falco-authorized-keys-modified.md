# SSH authorized keys or sshd configuration written (cluster node or container)

**What fired:** `SecurityDetectionFalcoAuthorizedKeysModified` (detection `falco-authorized-keys-modified`, severity `page`, ATT&CK T1098.004, pillar device).

## Why it matters

A new SSH key (or a changed sshd configuration) is the cheapest persistence: it survives password changes and reboots.

## Triage

1. The matching Falco events (host-level: `hostname` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname | rule="SP Authorized keys modified" | hostname="<host>"
   ```

2. Everything else Falco saw in the same pod in the window (other rules often tell the story):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | ns="<ns>" | pod="<pod>"
   ```

3. Who touched the pod through the API (exec, attach, patch) around the same time:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | ns="<ns>" | name="<pod>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- Configuration management (e.g. an Ansible run) deploying keys or sshd drop-ins: correlate with the change record and the run's timestamp.
- The operator adding a key by hand (should be rare; prefer configuration management).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Compare the file with the expected content from configuration management; list keys added (fingerprints).
2. Remove unknown keys and reload sshd only after copying the file for evidence.
3. Review successful logins since the change (auth-* runbooks, `{source="auth", host="<host>"} | event="ssh_login_success"`).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the file before and after (copy, hash), the writing process and its parent, the login sessions open at the time (`who`, `ss -tpn`).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Do not exclude configuration management by process name; acknowledge each change against its change record instead.
