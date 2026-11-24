# Runtime sensor not running on every node

**What fired:** `SecurityDetectionFalcoSensorDown` (detection `falco-sensor-down`, severity `ticket`, ATT&CK T1562.001, pillar device).

## Why it matters

Falco not ready on a node means runtime detection is blind there. Blindness is an incident: disabling the sensor is a standard defence-evasion step (T1562.001).

## Triage

Treat blindness as an incident: assume an attacker may have caused it until the cause is proven benign.

1. Prometheus:

   ```
   kube_daemonset_status_desired_number_scheduled{daemonset="falco"} - kube_daemonset_status_number_ready{daemonset="falco"}
   ```

2. Pod status and the last logs:

   ```
   kubectl -n <falco namespace> get pods -o wide; kubectl -n <falco namespace> logs <pod> --previous
   ```

3. Who changed it through the API:

   ```
   {source="k8s-audit"} | json verb, user="user.username", resource="objectRef.resource", sub="objectRef.subresource", ns="objectRef.namespace", name="objectRef.name", code="responseStatus.code", uri="requestURI" | ns="<falco namespace>" | verb=~"create|update|patch|delete"
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- A rollout of a new Falco version or configuration (rules file error: Falco refuses to start on an unknown rule name).
- Node pressure (OOM-killed, evicted).
- A kernel update the probe does not support yet.

## Contain

Least destructive first; never delete evidence before it is captured.

1. Until proven otherwise assume the sensor was stopped on purpose: check the audit log for deletes/patches of the DaemonSet or its ConfigMaps by anyone but the GitOps controller.
2. Restore the sensor from Git (sync); if a rules change broke it, revert the change.
3. Review what happened on the blind node meanwhile (node-logs, auth events).

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the DaemonSet and pod objects, the last logs, the audit lines of changes.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: If evictions caused it, raise the sensor's priority/requests rather than the alert threshold.
