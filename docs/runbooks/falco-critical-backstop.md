# Falco critical event (in-cluster backstop)

**What fired:** `SecurityDetectionFalcoCriticalBackstop` (detection `falco-critical-backstop`, severity `page`, ATT&CK none, pillar device).

## Why it matters

An in-cluster copy of the critical runtime detections, evaluated by the cluster's own Prometheus on Falco's metrics. It fires even when the log store or its ruler is down, so a critical event is never lost to a broken pipeline.

## Triage

Treat blindness as an incident: assume an attacker may have caused it until the cause is proven benign.

1. Prometheus (which rule, how often):

   ```
   sum by (rule_name) (increase(falcosecurity_falco_rules_matches_total{priority=~"0|1|2|(?i:emergency|alert|critical)"}[1h]))
   ```

2. The Falco events themselves, if the log store is reachable:

   ```
   {container="falco"} | json rule | rule="<rule_name>"
   ```

3. Without the log store: the Falco pod logs on the node

   ```
   kubectl logs -n <falco namespace> <falco pod> --since=1h | grep '<rule_name>'
   ```

Replace `<…>` with the alert's labels; widen the time range to at least 1 hour before the alert.

## Benign explanations

- The same event already handled through its log-based alert (the log-based runbook is the main one).

## Contain

Least destructive first; never delete evidence before it is captured.

1. Follow the runbook of the log-based detection for that rule (falco-*).
2. If the log-based alert did NOT fire: also treat the detection pipeline as broken (see falco-sensor-down / node-logs-down / the log store's ruler) and fix it.

## Evidence

Follow [evidence preservation](../incident-response.md#evidence-preservation). Specific to this alert: the Falco pod logs (they rotate on the node: copy them now), the metric values.

## Close

Record the verdict (`true_positive`, `false_positive`, `benign` or `drill`) as described in [recording a verdict](../incident-response.md#recording-a-verdict). A true positive opens an incident ([playbook](../incident-response.md)) and ends with a postmortem.
False positive: Nothing to tune here; tune the underlying Falco rule.
