# Secret read by an unexpected subject

**What fired:** `SecurityDetectionK8sSecretReadUnexpected` (detection `k8s-secret-read-unexpected`, severity `ticket`, ATT&CK T1552.007, pillar network).

## Why it matters

Secrets hold the credentials of everything else. A subject outside the known controllers reading them is credential access (stolen token, over-broad RBAC, a compromised workload).

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | resource="secrets" | verb=~"get|list|watch" | user="<user>"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A new controller or operator added through GitOps whose ServiceAccount is not yet in `secret_readers`.
- An operator inspecting a Secret by hand.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Find which RoleBinding/ClusterRoleBinding grants the read (`kubectl auth can-i --list --as=<user>`).
2. If unexpected: remove the binding through GitOps (or immediately by hand, then reconcile Git), revoke the subject's token.
3. Rotate every Secret the subject read (names are in the audit lines; values never are).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the list of Secret names read, the RBAC path that allowed it, the subject's other actions.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add the controller's ServiceAccount to the `secret_readers` param (instance params file) through a reviewed change.
