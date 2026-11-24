# Interactive shell in a container

**What fired:** `SecurityDetectionFalcoShellInContainer` (detection `falco-shell-in-container`, severity `ticket`, ATT&CK T1059, T1609, pillar device).

## Why it matters

An interactive shell in a running container is how humans (and attackers with a stolen kubeconfig or an RCE) explore a workload. Containers are not meant to be logged into; every interactive session should map to a known person and reason.

## Triage

1. The matching Falco events (full `output` and `output_fields`):

   ```
   {container="falco"} | json rule, hostname, ns="output_fields[\"k8s.ns.name\"]", pod="output_fields[\"k8s.pod.name\"]" | rule="Terminal shell in container" | ns="<ns>" | pod="<pod>"
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

- An operator debugging (`kubectl exec -it`): the k8s-pod-exec alert fires at the same time with the operator's identity.
- A drill (recorded in `<data>/detections/drills/`).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Identify the API subject from the audit log query above. Unknown subject or no matching audit line (shell started by something inside the container): treat as an intrusion.
2. Isolate the pod without killing it: apply a deny-all NetworkPolicy selecting the pod's labels (ingress and egress); the process stays alive for capture.
3. Stop new copies from scheduling the same image: scale the owner to 0 only after the evidence below is captured; keep the pod object if possible (remove it from the Service by relabelling instead of deleting).
4. If the node itself may be affected, `kubectl cordon <node>`; do not drain or reboot before the node evidence is captured.
5. Revoke the credential used for the exec (ServiceAccount token, client certificate, kubeconfig) if it is not the operator's own.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the command lines of the shell's children (Falco `proc.cmdline` in later events), the audit lines of the exec, `kubectl get pod -o yaml`.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: If a specific image legitimately runs a terminal shell (rare), exclude it upstream-style through the macro `user_expected_terminal_shell_in_container_conditions` in the instance's own rules file.
