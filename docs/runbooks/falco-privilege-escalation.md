# Privilege escalation or container escape attempt

**What fired:** `SecurityDetectionFalcoPrivilegeEscalation` (detection `falco-privilege-escalation`, severity `page`, ATT&CK T1548, T1611, T1055.008, T1547.006, pillar device).

## Why it matters

These rules mark the step from 'code runs in a container' to 'code runs as root / on the host': sudo or su inside a container, new setuid binaries, ptrace injection, kernel modules, cgroup release_agent escapes.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule=~"SP Privilege escalation tool in container|SP Setuid or setgid bit set|PTRACE attached to process|Linux Kernel Module Injection Detected|Detect release_agent File Container Escapes" | ns="<ns>" | pod="<pod>"
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

- A package upgrade on the host setting setuid bits (dpkg and friends are excluded; other installers may not be).
- A debugger used on purpose by an operator (ptrace).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Page-level: start the incident (../incident-response.md) and appoint yourself incident commander.
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. For kernel-module or release_agent events assume host compromise: cordon the node, capture node evidence, then plan a rebuild of the node from configuration management (do not trust in-place cleaning).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the exact rule, binary path and hash (`/proc/<pid>/exe`), loaded modules (`lsmod`) on the node, the cgroup paths touched.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Exclude a specific legitimate installer by process name in the instance's rules file; never disable the rule.
