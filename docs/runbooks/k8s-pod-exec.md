# Exec, attach or port-forward into a pod

**What fired:** `SecurityDetectionK8sPodExec` (detection `k8s-pod-exec`, severity `ticket`, ATT&CK T1609, pillar network).

## Why it matters

Exec, attach and port-forward give a subject a shell or a tunnel into a workload, bypassing the application's own authentication; with a stolen credential this is the first thing an attacker does.

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | resource="pods" | sub=~"exec|attach|portforward" | ns="<ns>"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- An operator's debugging session (the subject is the operator's identity, from the operator's usual address).
- A drill (recorded in `<data>/detections/drills/`).
- Tooling that uses exec by design (backup or database operators): allowlist through the subject regex, not by silencing.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Unknown subject or unusual source address: revoke the credential (delete the ServiceAccount token Secret / rotate the client certificate / remove the kubeconfig), then follow falco-shell-in-container for the pod.
2. Known subject but unexpected: ask the person (out of band) before acting further.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the request URI (it contains the command), source IPs, user agent, the Falco events of the same pod.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Operators' sessions are expected and acknowledged as `benign`; recurring automation goes into an allowlist param through a reviewed change.
