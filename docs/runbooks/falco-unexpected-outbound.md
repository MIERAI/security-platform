# Unexpected outbound connection from a container

**What fired:** `SecurityDetectionFalcoUnexpectedOutbound` (detection `falco-unexpected-outbound`, severity `ticket`, ATT&CK T1041, T1071, pillar network).

## Why it matters

Workloads that never talk to the internet suddenly connecting out is the first visible step of a downloader, a reverse shell, command and control or data exfiltration.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule="SP Unexpected outbound connection from container" | ns="<ns>" | pod="<pod>"
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

- A new feature or dependency that legitimately calls an external API (check the latest deployment and its PR).
- An image pull or update check done by the application itself (telemetry, update checks).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Look up the destination (`dest=` in the output): reputation, owner, whether it is in the application's documented dependencies.
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. Block the destination at the egress layer you have (NetworkPolicy egress, firewall) before anything else if data is leaving.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the destination address and port, the process and command line, connection counts over time (rerun the query as a metric with `count_over_time`).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Expected egress is declared per namespace in the instance's rules file: append the namespace to `sp_outbound_namespaces` (or the network to `sp_allowed_outbound_nets`) through a reviewed change.
