# Sensitive file read or credential search

**What fired:** `SecurityDetectionFalcoSensitiveFileRead` (detection `falco-sensitive-file-read`, severity `ticket`, ATT&CK T1003.008, T1552.001, pillar device).

## Why it matters

Reading /etc/shadow, sudoers, PAM configuration, or searching the filesystem for private keys and passwords is credential access: it precedes privilege escalation and lateral movement.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule=~"Read sensitive file untrusted|Search Private Keys or Passwords" | ns="<ns>" | pod="<pod>"
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

- A package manager, user-management tool or configuration agent not covered by the upstream exceptions.
- A backup or scanning tool reading the whole filesystem.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Find the process and its parent chain (`proc.cmdline`, `proc.pname` in the event).
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. Assume every credential readable by that process is exposed: list them and rotate (Secrets mounted in the pod, keys on the node).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the file names read, the process tree, the mounted Secrets list of the pod (names only).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add the legitimate program to the upstream exception lists through the instance's rules file.
