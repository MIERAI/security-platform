# Kubernetes audit log went quiet

**What fired:** `SecurityDetectionK8sAuditSilent` (detection `k8s-audit-silent`, severity `ticket`, ATT&CK T1562.008, pillar network).

## Why it matters

No API audit line from a cluster for 15 minutes: either the API server stopped writing (flags removed, disk full, policy broken) or shipping broke. The control plane is unobserved; stopping audit logging is a defence-evasion technique (T1562.008).

## Triage

Treat blindness as an incident: assume an attacker may have caused it until the cause is proven benign.

1. What still arrives from that cluster:

   ```
   sum by (source, host) (count_over_time({cluster="<cluster>"}[15m]))
   ```

2. On the control-plane node:

   ```
   ls -l <audit log directory>; tail -1 <audit log>; ps -ef | grep -o 'audit-[a-z-]*=[^ ]*'
   ```

3. The shipper:

   ```
   see node-logs-down
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A control-plane restart (a few minutes)
- Planned maintenance of the log store.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Check whether the API server still has its audit flags and the policy file is intact (configuration management diff). Removed without a change record: incident.
2. Restore the configuration through configuration management; restart the API server only after copying the existing audit files.
3. Review the gap with whatever else is available (Falco, auth logs, GitOps history).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the audit files on disk (hash them), the API server's command line, the configuration management diff.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Exclude planned maintenance with a silence, not by changing the rule.
