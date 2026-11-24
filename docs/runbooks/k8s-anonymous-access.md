# Anonymous request allowed beyond public discovery

**What fired:** `SecurityDetectionK8sAnonymousAccess` (detection `k8s-anonymous-access`, severity `ticket`, ATT&CK T1190, T1078.001, pillar network).

## Why it matters

Anonymous requests should only reach public discovery endpoints. Anything else answering 2xx to anonymous means RBAC grants to `system:anonymous` or `system:unauthenticated`: an unauthenticated door into the cluster.

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="system:anonymous" | code=~"2.."
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- Very few: a monitoring probe hitting a health endpoint not in the excluded list.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Find the binding granting the access (`kubectl get clusterrolebindings -o wide | grep -E 'system:(anonymous|unauthenticated)'`) and remove it via GitOps.
2. Check from where the requests came (source IPs) and whether the API server is reachable from untrusted networks.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the URIs requested, source addresses, the offending binding.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Extend the excluded URI list only for genuinely public endpoints.
