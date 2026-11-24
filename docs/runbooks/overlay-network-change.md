# Overlay network control-plane change

**What fired:** `SecurityDetectionOverlayNetworkChange` (detection `overlay-network-change`, severity `ticket`, ATT&CK T1098, T1133, pillar network).

## Why it matters

The overlay network's control plane decides which devices can reach everything: a new node, a disabled key expiry, a policy change or a new auth key can open the private network to an attacker.

## Triage

1. The matching events (structured metadata: event, actor):

   ```
   {source="overlay-network"} | event=~"node_added|node_key_expiry_disabled|policy_changed|auth_key_created|user_added|user_role_changed|exit_node_enabled|subnet_routes_changed"
   ```

2. All control-plane events of the same actor:

   ```
   {source="overlay-network"} | actor="<actor>"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- The administrator adding a device or editing the access policy.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Unknown node: remove/expire it in the admin console, revoke the auth key used.
2. Unknown policy change: restore the previous policy (keep it in version control), review connections allowed meanwhile.
3. Unknown actor: revoke their access, rotate API keys.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the audit log entries (old/new values), node details, the policy diff.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune; acknowledge planned changes.
