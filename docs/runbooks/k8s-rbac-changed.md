# RBAC changed outside GitOps

**What fired:** `SecurityDetectionK8sRbacChanged` (detection `k8s-rbac-changed`, severity `ticket`, ATT&CK T1098, T1078.004, pillar network).

## Why it matters

RBAC changes outside the GitOps controller are privilege changes nobody reviewed: escalation or persistence (T1098).

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | resource=~"roles|rolebindings|clusterroles|clusterrolebindings" | verb=~"create|update|patch|delete|deletecollection"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- An operator applying an emergency fix by hand (should be followed by the same change in Git).
- A controller that manages RBAC itself (operators) and is not yet in `rbac_writers`.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Compare with Git: is the object in the repository? If not, revert by deleting/restoring it via GitOps sync.
2. Revoke the subject's credential if the change was not made by a known person.
3. Check what the new permissions were used for (subject's actions after the change).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the request body (audit level Request records the object), the before/after objects, the subject's session.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add the controller to `rbac_writers` through a reviewed change.
