# New or fileless binary executed in a container

**What fired:** `SecurityDetectionFalcoDropAndExecute` (detection `falco-drop-and-execute`, severity `page`, ATT&CK T1105, T1620, pillar device).

## Why it matters

Executing a binary that was not in the image (written at run time, from memory or from /dev/shm) is the classic second stage after initial access.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule=~"Drop and execute new binary in container|Fileless execution via memfd_create|Execution from /dev/shm" | ns="<ns>" | pod="<pod>"
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

- Applications that compile or unpack code at run time (JIT caches are not binaries; self-extracting tools are).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Page-level incident.
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. Copy the binary out (`/proc/<pid>/exe` while the process lives) before the pod is gone.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the binary itself and its hash, `proc.exepath`, parent chain, network connections of the process (`ss -tpn` on the node, filtered by the pid).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Known self-extracting images go in the upstream list `known_drop_and_execute_containers` via the instance's rules file.
