# Crypto miner activity

**What fired:** `SecurityDetectionFalcoCryptoMiner` (detection `falco-crypto-miner`, severity `page`, ATT&CK T1496, pillar device).

## Why it matters

Resource hijacking is the most common payload after a workload is taken over; a miner also proves remote code execution happened.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule="SP Crypto miner activity" | ns="<ns>" | pod="<pod>"
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

- Practically none in a production cluster; a security test that uses miner ports on purpose.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Page-level incident.
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. Find the entry point: the workload's exposure (public ports, vulnerable image in the ledger), recent deployments, credentials it holds. Rotate those credentials.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the miner binary (copy and hash it before anything is deleted), its configuration (pool, wallet), the parent process chain, the container's writable layer.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: If a miner port is legitimately used by an application, narrow the rule by destination network in the instance's rules file.
