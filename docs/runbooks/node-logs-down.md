# Node security log shipping broken

**What fired:** `SecurityDetectionNodeLogsDown` (detection `node-logs-down`, severity `ticket`, ATT&CK T1562.002, pillar device).

## Why it matters

A node's audit and authentication logs are not reaching the log store: API audit and login detections are blind for that node (T1562.002).

## Triage

Treat blindness as an incident: assume an attacker may have caused it until the cause is proven benign.

1. Prometheus (readiness and drops):

   ```
   kube_daemonset_status_number_ready{daemonset="node-logs"}; increase(loki_write_dropped_entries_total{pod=~"node-logs-.*"}[30m])
   ```

2. Last lines that did arrive per source:

   ```
   sum by (source, host) (count_over_time({source=~"k8s-audit|auth"}[15m]))
   ```

3. Pod logs:

   ```
   kubectl -n <namespace> logs <node-logs pod>
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- The log store unreachable (network, restart): the shipper retries, then drops.
- A rejected token after a rotation (401 in the pod logs).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Check the audit log for changes to the DaemonSet, its ConfigMap or the token Secret by anyone but the GitOps controller.
2. Fix the shipper; the files on the node are still there: once fixed, check that the gap is covered (positions are kept on the node), otherwise copy the node's audit log and journal for the gap.
3. Until fixed, review the node's auth journal by hand (`journalctl SYSLOG_FACILITY=10 --since …`).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the pod logs, the local audit log files for the gap window (copy with hashes).

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune.
