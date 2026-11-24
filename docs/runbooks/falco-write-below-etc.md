# Write below /etc in a running container

**What fired:** `SecurityDetectionFalcoWriteBelowEtc` (detection `falco-write-below-etc`, severity `ticket`, ATT&CK T1543, T1222, pillar device).

## Why it matters

Images are immutable; writing below /etc at run time changes users, cron, resolvers or sudoers: persistence or tampering.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule="SP Write below etc in container" | ns="<ns>" | pod="<pod>"
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

- An image whose entrypoint renders configuration into /etc (templated nginx/haproxy configuration).
- Certificate bundle updates done at start-up.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Diff the file against the image (`kubectl exec` is itself alerted: prefer copying the file out with `kubectl cp` and comparing it with the image layer).
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the written file's content and hash, the process, the image digest.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Append the image repository to `sp_etc_writer_images` in the instance's rules file (reviewed change).
