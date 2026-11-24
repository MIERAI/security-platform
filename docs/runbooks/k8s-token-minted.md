# ServiceAccount token minted by a person or unexpected subject

**What fired:** `SecurityDetectionK8sTokenMinted` (detection `k8s-token-minted`, severity `ticket`, ATT&CK T1528, pillar network).

## Why it matters

Minting a token for a ServiceAccount hands out that account's permissions; an attacker with token-create permission can impersonate any account in reach (T1528).

## Triage

1. The matching audit lines (who, what, from where: add `| json src="sourceIPs[0]", ua="userAgent"` for the client):

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | resource="serviceaccounts" | sub="token" | verb="create"
   ```

2. Everything the same subject did in the window:

   ```
   {source="k8s-audit", cluster="<cluster>"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | user="<user>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- An operator creating a token for a site or tool on purpose (should be in the change record).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Identify the ServiceAccount and its permissions; if unexpected, delete/recreate the ServiceAccount (invalidates bound tokens) or rotate its signing material.
2. Remove the permission that allowed the minting from the subject.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the token request (audience, expiration: audit level Request), the subject, the ServiceAccount's RBAC.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Add automation that mints tokens by design to `token_minters`.
