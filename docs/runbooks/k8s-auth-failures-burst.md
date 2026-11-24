# Burst of rejected API requests

**What fired:** `SecurityDetectionK8sAuthFailuresBurst` (detection `k8s-auth-failures-burst`, severity `ticket`, ATT&CK T1110, T1580, pillar network).

## Why it matters

Many rejected requests from one subject is brute force, credential stuffing or an attacker enumerating what a stolen token can do (discovery).

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | code=~"401|403" | user="<user>"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A controller with missing RBAC after an upgrade (403 loop): the subject is a ServiceAccount and the URIs are the same few.
- An expired token in a client (401 loop).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Look at the URIs: enumeration (many different resources) is hostile; a single repeated URI is usually a broken client.
2. Hostile: revoke the subject's credential, block the source address at the network layer.
3. Broken client: fix it (a ticket); it is noise that hides real signal.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: source addresses, user agents, the list of resources tried.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Raise `auth_failure_burst` only with evidence of recurring benign bursts.
