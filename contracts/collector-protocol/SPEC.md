# Contract: collector-protocol — version 1.0

| | |
|---|---|
| contract | `collector-protocol`, version **1.0** |
| data | the findings document: [findings](../findings/SPEC.md) |
| caller | the runner ([runner](../runner/SPEC.md)) — `collector` jobs (`collectors/<name>/collector.py`) and `command` jobs (any `argv`) |
| example | [`examples/collector.sh`](examples/collector.sh): a complete collector in POSIX sh, no SDK |
| conformance | `conformance/cases/collector-*/*` (impl: `SP_IMPL_COLLECTOR_<NAME>`), plus `runner/job-environment`, `runner/timeout-kills-job`, `runner/contract-violation-not-promoted`, `runner/missing-document-is-failure` |

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

A collector is **an executable**. Nothing about its language, libraries or internal structure is part of the contract;
`sdk/spsdk` is a convenience for Python collectors, not a requirement.

## 1. Invocation

The runner starts the collector as a child process:

- **argv**: a `collector` job runs the product's collector program for `collector:` (default: the job name) with no
  arguments; a `command` job runs its `argv` exactly (`~` expanded, no shell). A collector MUST NOT require arguments
  beyond what its `argv` declares.
- **working directory**: inherited from the runner (unspecified). A collector MUST NOT depend on it; every path it
  needs comes from the environment or the instance config.
- **stdin**: not connected to anything meaningful; a collector MUST NOT read it or prompt (no password prompts: key
  or token based access only).
- **process group**: its own session/process group (the runner kills the whole group on timeout).

## 2. Inputs

Environment (set by the runner; the runner's own environment is inherited underneath):

| variable | meaning | required |
|---|---|---|
| `SP_RUN_DIR` | absolute path of a fresh, empty, per-run directory (`<data>/runs/<date>/<time>-<job>`). Every output goes here. | MUST be honoured |
| `SP_INSTANCE` | path of the private instance config (YAML 1.2 or JSON). The collector reads its own section(s). | |
| `SP_DATA` | the private data directory (read-only for collectors, except §4) | |
| `SP_INPUT_DIR` | `<data>/latest`: the newest valid document of every collector and every `inventory.*.json`; read-only | |
| `SP_INSTANCE_NAME` | the instance's `name` (goes into `run.instance`) | |
| `SP_COLLECTOR_NAME` | set when the job has `as:`: the collector MUST report under this name (document name and `collector.name`) | MUST when set |
| job `env:` | non-secret settings of this job (e.g. `EXAMPLE_FILES`) | |

Secrets (tokens, keys) MUST come from files named in the instance config (`*_file` keys, e.g. `token_file`) or from
the inherited environment of the trigger; they MUST NOT be passed on a command line (visible in process listings)
and MUST NOT appear in any output (§5).

Per-asset scope (instance `scope:`): an asset limited to other collectors MUST be skipped silently (not a gap); with
`offline: expected` an unreachable asset is not a gap either.

## 3. Outputs

In `SP_RUN_DIR`:

| file | |
|---|---|
| `<name>.findings.json` | **required on success**: exactly one findings document ([findings](../findings/SPEC.md)), `<name>` = `SP_COLLECTOR_NAME` or the collector's own name |
| `raw/<name>/...` | optional evidence that findings point to (`evidence: raw/<name>/<file>[#key]`); metadata only |
| `<name>.prom` | optional Prometheus text; if absent the runner derives the generic per-collector metrics from the document |
| `inventory.<kind>.json` | optional inventories other collectors consume (promoted to `latest/`) |
| stdout / stderr | free text, appended by the runner to `<run>/<name>.log` (private); one summary line on stderr is customary |

The document SHOULD be written in one step (write a temporary file, then rename) so that it is complete or absent.

## 4. What a collector must never do

- Write outside `SP_RUN_DIR`, with one exception: a cache it can rebuild, under `$SP_DATA/cache/<name>/`. In
  particular it MUST NOT touch `ledger.json`, `exceptions.yaml`, `attestations.yaml`, `tracker/`, `state/runner/`,
  `latest/` or another run's directory. Temporary files go to a private temporary directory that it removes.
- Change the systems it looks at. Collectors are **read-only**; a write-capable credential is itself a finding
  (`cloud.platform_credential_over_privileged`).
- Log, print or store a secret value: not in the document, the evidence, `<name>.log`, metric labels or exit messages.
- Report "no findings" for something it could not look at: an asset it could not evaluate is a `gap` with a reason.

## 5. Exit codes and partial results

| exit | meaning | runner |
|---|---|---|
| 0 | the run completed and wrote its document. Unreachable assets, failed sub-checks, missing tools for one target are **gaps inside the document**, not a non-zero exit. | validates the document; valid → promoted, merged (hub) or queued (site); invalid → failure 65 |
| non-zero | the run as a whole failed (configuration error, no credentials at all, crash). Any document in the run directory is **ignored**. | failure; retried per the job's `retries` |
| (killed) | the job exceeded `timeout` (default 1h): SIGTERM to the process group, SIGKILL 30 s later | failure, recorded as 124 |

Exit 0 without a document is a failure (no document ≠ secure). A collector SHOULD use 1 for failures and 2 for usage
or configuration errors. A collector SHOULD bound its own per-target work (time limits per host, per probe) so that one
slow target becomes a gap — a narrow gap with `checks` when only some checks are affected — instead of the whole run
hitting the job timeout and losing every result.

## 6. Determinism

- Finding ids MUST be `sha1("<layer>|<asset>|<check>")[:12]` (hex), so the same finding keeps its ledger entry when a
  collector is rewritten in another language.
- Asset names and check names are part of the collector's public behaviour: renaming one makes old findings look
  fixed (on a covering run) and new ones appear; that is a breaking change under the two-step rule (`docs/upgrade.md`:
  emit the new name, keep the old one in the ledger until closed, never reuse a published check name).

## Known deviations

| id | what | target |
|---|---|---|
| COLLECTOR-D1 | `vuln-intel` and `host-sbom` write SBOMs to `$SP_DATA/sbom/` and caches to `$SP_DATA/cache/{repos,trivy}`; `vuln-intel` keeps `$SP_DATA/state/vendor-advisories.json` and appends to the advisor decision log; `identity` caches under `$SP_DATA/cache/identity/`. | Only `$SP_DATA/cache/<name>/` (rebuildable). SBOMs that other components read become `inventory.*`/run-directory outputs or an explicit, versioned data-directory path in a later minor of this contract. No conformance case (these collectors need external tools/network). |

### Collector `k8s`

Target behaviour of `collectors/k8s` (the Go implementation, `sp k8s collect`, has it; the Python one does not).

| id | what | target |
|---|---|---|
| K8S-D1 | One part of a cluster that cannot be read (e.g. `list clusterrolebindings` forbidden for an in-cluster reader) raises out of the cluster: the cluster becomes a gap and every later part (Secrets, PolicyReports, the operator credential, CIS) is skipped. A Secret listing that fails is read as zero Secrets. | Each part is read on its own: a failed part is a gap of that part — `k8s-workload:<c>` + `k8s-namespace:<c>` (workloads), `k8s-identity:<c>` (rbac), `k8s-cluster:<c>/secrets`, `k8s-cluster:<c>/policy` with `checks: [k8s.policy.*]`, `k8s-identity:<c>/operator-kubeconfig` — and the cluster itself stays covered. Case `collector-k8s/failing-part-is-a-gap-of-that-part`. |
| K8S-D2 | Any error listing PolicyReports (forbidden, timeout) is reported as `k8s.policy.engine_missing`. | Only a missing resource type means no policy engine; any other error is the narrow gap `k8s-cluster:<c>/policy` (`checks: [k8s.policy.*]`). Case `collector-k8s/unreadable-policy-reports-are-a-gap`. |
| K8S-D3 | A failed kube-bench run is a gap on `cis:<c>`, but the CIS findings live on `k8s-cluster:<c>`, which the same run covers: the ledger marks them fixed. | Also the narrow gap `k8s-cluster:<c>/cis` with `checks: [cis.*]`. Case `collector-k8s/kube-bench-failure-keeps-cis-findings`. |
| K8S-D4 | A RoleBinding to a namespaced Role is never evaluated (only ClusterRole references are looked up). | Roles are listed (`get roles -A`) and judged by the same rules (wildcard, secrets read, pods/exec, RBAC write). Case `collector-k8s/namespaced-role-is-evaluated`. |

### Collector `vuln-intel`

Target behaviour of `collectors/vuln-intel` (Go: `sp vuln-intel collect`).

None recorded yet.

### Collector `identity`

Target behaviour of `collectors/identity` (Go: `sp identity collect`).

None recorded yet.

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents existing behaviour of runner 0.9.0 / sdk 0.5.0) |
