# Reverse shell pattern

**What fired:** `SecurityDetectionFalcoReverseShell` (detection `falco-reverse-shell`, severity `page`, ATT&CK T1059.004, T1095, pillar network).

## Why it matters

A shell whose input and output are a network socket is a reverse shell: somebody outside is typing commands in your workload.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule=~"Redirect STDOUT/STDIN to Network Connection in Container|Netcat Remote Code Execution in Container" | ns="<ns>" | pod="<pod>"
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

- Almost none; some debugging sessions with netcat.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Page-level incident.
2. Cut the network first: deny-all egress NetworkPolicy on the pod (the remote side loses the shell), then capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the remote address and port, the process tree, the commands run in the session (Falco events of the same pod after the alert).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Do not tune without a postmortem: a legitimate netcat in production is itself a finding.
