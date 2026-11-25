# Detection and response (component `detections`, phase 2)

Until phase 1 the platform found **conditions** (misconfigurations, vulnerabilities). This component detects
**activity**: an attack in progress, on the network and device pillars, and hands it to a response process
(NIST CSF Detect / Respond / Recover). Everything here is generic; an instance supplies only parameters
(allowlists, cluster names, where the log store is).

## Architecture

```
 cluster node                                    log store (Loki)                 Alertmanager (reachable by the ruler)
 ┌────────────────────────────────────┐          ┌───────────────────────┐        ┌──────────────────────┐
 │ Falco (DaemonSet, modern eBPF)     │ stdout → │                       │        │ severity page|ticket │
 │   curated rules (tag selection)    │ pod-log  │  ruler: loki/rules.yaml│──────▶│ → the instance's     │
 │   metrics → Prometheus ────────────┼─ shipper │  (catalog.yaml)       │ alerts │   receivers          │
 │ node-logs (DaemonSet, Alloy)       │────────▶ │                       │        └──────────▲───────────┘
 │   API audit log, auth journal      │          │  raw lines = evidence │                   │
 └────────────────────────────────────┘          └──────────▲────────────┘                   │
 off-cluster hosts / SaaS                                    │                                 │
   runner job `events` (sshd, sudo, key changes,  ──────────┘     Prometheus (in-cluster): falco/prometheus-rules.yaml
   code host account, overlay network audit)                     backstop + pipeline health ───┘
```

- **One catalog** (`detections/catalog.yaml`) is the source of truth: id, source, pillar, severity, ATT&CK, query,
  runbook (`docs/runbooks/<id>.md`, enforced by tests). `render.py` produces the Loki ruler rules and the in-cluster
  PrometheusRule; `--params` applies an instance's allowlists without forking the catalog.
- **Detection runs where the logs are** (the log store's ruler), not in each shipper: one rule language (LogQL), one
  place to test, rules change without redeploying sensors. Shippers only normalise (structured metadata) and never
  decide what is an incident.
- **Backstop that does not need the log store**: Falco's own metrics (`falcosecurity_falco_rules_matches_total`)
  alert in-cluster on critical rules, and the sensors' readiness / dropped entries alert there too. A log store outage
  therefore degrades detection, it does not blind it; the log store's own liveness is watched by the instance's
  monitoring (separate from this component).
- **Evidence first**: raw lines are kept (the store's retention); normalised fields ride as structured metadata.

## Decisions (2026-11-24)

| question | decision | why |
|---|---|---|
| runtime sensor | **Falco** (modern eBPF, CO-RE) rather than Tetragon | detection-oriented with a maintained, ATT&CK-tagged rule library (content freshness without writing kernel policies), built-in Prometheus metrics, no kernel headers or driver build (needs BTF), CRI metadata without extra components. Tetragon is stronger at in-kernel enforcement (kill on match) and process-level observability; revisit when enforcement is wanted. |
| low noise | upstream rules all disabled; enable by tag `security-platform` only; our file tags the kept upstream rules and adds `SP ...` rules | an upstream rename fails loudly at start; new upstream rules never appear unreviewed |
| Falco footprint | no falcosidekick, no k8s-metacollector (CRI labels give namespace/pod), no falcoctl follow sidecar (rules pinned by version; updates are reviewed changes) | memory: the sensor must fit small nodes |
| where rules run | log store ruler + in-cluster backstop | above |
| audit levels | Request for exec/attach/port-forward, RBAC, admission, token requests; **Metadata only** for Secrets and ConfigMaps | Request level for Secrets would copy secret values into the log store |
| host auth logs | cluster nodes: node-logs reads the journal (auth/authpriv facilities); other hosts and SaaS: runner job `events` (pull, cursor, at-least-once) | no resident agent on hosts that cannot run one (appliances, phones, workstations) |
| "new source" logins | baseline kept by the shipper that has state (`novel` metadata); everywhere else: logins from outside trusted networks (`ip()` filters) | the ruler is stateless |
| alert routing | severity labels only (`page`/`ticket`/`info`); receivers are the instance's | same contract as every other alert |

## Log contract (shippers → store)

| source | stream labels | structured metadata | shipped by |
|---|---|---|---|
| `falco` | the pod-log shipper's (`namespace`, `pod`, `container=falco`, `cluster`) | — (JSON line: `rule`, `priority`, `output_fields`) | the cluster's pod-log pipeline |
| `k8s-audit` | `source`, `cluster`, `host` | — (JSON audit event) | node-logs |
| `auth` | `source`, `host`, (`cluster`, `ident` from the journal) | `event` (ssh_login_success, ssh_login_failure, sudo, sudo_failure, authorized_keys_changed), `user`, `src_ip`, `novel` | node-logs, `events` |
| `codehost` | `source`, `host` | `event`, `actor`, `repo` | `events` |
| `overlay-network` | `source`, `host` | `event`, `actor` | `events` |

## Deploying (an instance)

1. **Falco**: the official chart, pinned. Values that matter: `driver.kind: modern_ebpf`, CRI socket of the
   distribution, `falco.rules: [{disable: {rule: "*"}}, {enable: {tag: security-platform}}]`, JSON output to stdout,
   `metrics.enabled` + `webserver.prometheus_metrics_enabled`, `falcoctl.artifact.install.refs: [falco-rules:<pinned>]`,
   `falcoctl.artifact.follow.enabled: false`, mount the ConfigMap `falco-rules-security-platform`
   (`detections/falco`, kustomize) into `/etc/falco/rules.d`.
2. **node-logs + backstop rules**: kustomize bases `detections/node-logs` and `detections/falco` at a pinned commit;
   the overlay sets CLUSTER, LOKI_URL, LOKI_TOKEN (Secret) and the namespace.
3. **API audit log**: `detections/k8s-audit/policy.yaml` + the API server flags (`audit-policy-file`, `audit-log-path`
   under the directory node-logs mounts, rotation). Requires an API server restart. The policy file is a copy on
   each control-plane node: when a release changes `policy.yaml`, copy it again and restart the API server (the
   CHANGELOG says when). Service accounts' access reviews (`selfsubjectaccessreviews`, `subjectaccessreviews`,
   `localsubjectaccessreviews`, `selfsubjectrulesreviews`: controllers checking their own permissions, up to a third
   of all lines on a cluster with a policy engine) are not logged; a person's are (possible reconnaissance).
4. **Ruler**: render with the instance's params, put the file into the ruler's rule directory, point the ruler at
   the Alertmanager(s). Alerts carry `cluster` where the source has one; route per cluster as needed.
5. **Off-cluster sources**: runner job `events` (docs/runner.md).

### Instance additions to the curated Falco rules

Lists in `detections/falco/security-platform.rules.yaml` are empty or generic on purpose (`sp_outbound_namespaces`,
`sp_etc_writer_images`, `sp_allowed_outbound_nets`). An instance appends in its own rules file, loaded after the
product's (file-name order in `rules.d`, e.g. `zz-instance.rules.yaml` through a projected volume):

```yaml
- list: sp_outbound_namespaces
  items: [argocd]                 # add a namespace only with the event that showed it
  override: { items: append }
```

### Where the alerts go

The ruler sends to whichever Alertmanager it can reach. When the clusters' Alertmanagers are not exposed outside the
clusters (recommended), run a small Alertmanager next to the log store and route there by `severity` and `cluster`
(e.g. a lab cluster recorded only, `page` to a notifying receiver). The in-cluster Falco rules still reach each
cluster's own Alertmanager, so the most urgent runtime detections do not depend on the log store host.

### Resource cost (first instance, single small node)

| piece | CPU | memory |
|---|---|---|
| Falco (modern eBPF, 2 MB ring buffers, ~25 rules) | ~30m steady (~250m for a minute at start) | ~100 Mi working set; the start-up peak charges ~350 MB of kernel memory to the container: limit 768Mi, request 128Mi |
| node-logs (Alloy) | ~5m | ~50 Mi |
| API audit log with this policy | — | ~50 KB/min written on a busy single-node control plane (~75 MB/day before log-store compression) |
| ruler + Alertmanager next to the log store | negligible | Alertmanager ~25 MB |

## Checking detection from outside (collector `detection`)

`collectors/detection` runs on the hub like any collector and turns "is detection working" into findings and metrics:
scope (every cluster of the instance's `kubernetes:` list has a sensor and an audit source), sensors ready on every
node, in-cluster rules present, every expected source delivered logs in its window, the ruler loaded every catalog
rule, page alerts reach a notifying receiver; quality: alert minutes per severity (ALERTS history), false-positive
ratio from human verdicts, the last drill and its time to detect, rule-content age. The scorecard's detection
dimension is computed from these. Configuration: the collector's docstring.

**Go implementation** (`sp detection collect`, `internal/collectors/detection`): the same checks, findings, evidence
and metrics, byte for byte on the conformance fixtures (`conformance/tools/compare_impls.py`). Selected with a
`command` job (`argv: [sp, detection, collect]`); the catalog comes from the product tree `sp` belongs to (or
`SP_PY_HOME`). Differences an operator can notice: a `token_file` readable by group or others is refused and the
checks that need it become gaps (DETECTION-D1; the Python collector sends it); recorded times (`fired_at`,
`action_at`, the catalog's `released`) are read as UTC whatever the host's time zone (DETECTION-D2; the Python
collector is an hour off under daylight saving time); only GET requests are ever sent, and a redirect to another
origin is not followed; a `kubeconfig` that could be read as an option is refused.

## Measuring detection (dimension "detection & response")

| metric | how |
|---|---|
| alerts per day, per detection | the ruler's/Alertmanager's alert history; `count_over_time` of the source selectors |
| false-positive rate | verdicts recorded per alert in the private data directory (`detections/verdicts.yaml`, see incident-response.md) |
| time to detect | drills (`detections/drills/*.yaml`): alert received at Alertmanager minus the action time |
| rule-content freshness | `released` in catalog.yaml and the pinned upstream rules version; reviewed at every Re-plan (≤ 90 days) |

## Response

`docs/incident-response.md` (playbook, evidence preservation, verdicts, drills) and one runbook per alert in
`docs/runbooks/`. Drills are benign simulations in a lab cluster only.
