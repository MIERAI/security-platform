# New ClusterRoleBinding

**What fired:** `SecurityDetectionK8sClusterrolebindingCreated` (detection `k8s-clusterrolebinding-created`, severity `ticket`, ATT&CK T1098, pillar network).

## Why it matters

A ClusterRoleBinding grants cluster-wide power. Even when the GitOps controller creates it, the binding must trace back to a reviewed change.

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | resource="clusterrolebindings" | verb="create"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A new platform component synced by the GitOps controller (check the commit that introduced it).
- Cluster bootstrap / upgrade.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Find the commit/PR that introduced the binding; none = treat as unauthorised: delete the binding (after copying it), revoke the subject's credentials.
2. Check the bound role: cluster-admin or wildcard verbs to a workload ServiceAccount is a finding even if reviewed.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the binding object (`kubectl get clusterrolebinding <name> -o yaml`), the creating request, the commit.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Acknowledge GitOps-created bindings as `benign` with the commit in the note; nothing to tune.
