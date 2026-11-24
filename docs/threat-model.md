# Threat model of the platform itself

The platform knows every weakness of the environment it watches and holds read credentials to most of it. It is
therefore one of the most valuable targets in that environment, and it must be protected at least as well as what it
watches. This document is the **product's** threat model (generic). An instance keeps its own filled-in copy of
`docs/threat-model-template.md` for its environment, privately (`<data>/threat-model.md`; scorecard control
`design.instance-threat-model`). Reviewed in every Re-plan step; scorecard control `self.threat-model` fails when
this file is older than 180 days.

## Assets

| Asset | Where | Why it is valuable |
|---|---|---|
| Findings, ledger, raw evidence, scorecard report, digest, tracker | private data directory (hub), hub PVC / snapshot Secret (in-cluster hub), site outboxes | a ranked list of how to break in (attacker intelligence) |
| Read credentials the collectors use | operator workstation / hub: code-host token, kubeconfigs, SSH keys, registry token file, identity-provider API keys, metrics-sink token | read access to code, clusters, hosts, identity data |
| The metrics stream | sinks (textfile, ConfigMap, remote write) | forged "all green" metrics hide an attack; real ones reveal aggregate posture |
| The control files | `exceptions.yaml`, `attestations.yaml`, `catalog-review.yaml` | whoever writes them can accept risk or mark controls as passing |
| The product (code, image, catalog) | public repository, container registry | a malicious change runs with all of the above |
| The AI advisor's inputs and outputs | `decisions/`, tracker drafts | a prompt-injected advisor could steer humans |

## Trust boundaries

```
 targets (hosts, clusters, repos, IdPs) ◀─read-only─ collectors ── findings ──▶ hub (ledger, scorecard) ──aggregates──▶ sinks
        ▲ untrusted data flows back: banners, repo content, log lines, issue text            ▲
        └── an attacker controls some of it                                                │ humans: exceptions, attestations
 sites (external vantage, in-cluster) ── outbox / inbox (authenticated) ─────────────────────┘
```

Everything a collector reads from a target is **data, never instructions** (design §9), including what an AI advisor
reads. Only humans change state that lowers risk scores (exceptions, attestations, false positives).

## Threats

STRIDE per element; "control" names the mechanism and, where it exists, the scorecard control that checks it.

| # | Threat | Element | Control in the product | Residual / gap |
|---|---|---|---|---|
| T1 | **Information disclosure**: findings leak (public repo, artifact, metrics labels, logs, chat) | data dir, metrics, reports | product/instance split + `bin/check-residue --history` (`design.product-instance-separation`, `generality.no-residue`); metrics carry aggregates only, contract-tested (`self.metrics-aggregate-only`); data dir 0700, ledger 0600 (`self.data-dir-private`, `self.ledger-private`); never pushed | residue patterns are not available to CI yet (`self.ci-residue-enforced`) |
| T2 | **Disclosure at rest**: stolen or disposed disk of the hub / node holding the PVC | data dir, PVC | full-disk encryption on every host that holds the data (`self.data-encrypted-at-rest`); see *Data at rest* | an in-cluster hub's PVC is only as encrypted as its node's disk |
| T3 | **Spoofing a site**: a compromised workload writes forged findings into the hub's inbox ("all fixed") | inbox | inbox writer Role is create-only; a ValidatingAdmissionPolicy binds the document's site label to the writer's ServiceAccount; contract validation; only covered assets can be marked fixed | a compromised *legitimate* site can still lie about its own assets: cross-check with another vantage |
| T4 | **Tampering with control files**: someone accepts risk or marks a control attested | exceptions, attestations | entries need `approved_by`/`attested_by` and an expiry, else ignored; expired ones reopen; accepted only from sites listed in `accept_control`; snapshots keep the history (git) | the data dir's own access control is the boundary: a local attacker with the operator's account can write them |
| T5 | **Forged metrics** (all green) or a silent platform | sinks | regression-only alerts include staleness of every heartbeat (collector, ledger, runner, scorecard); remote-write sink requires a bearer token file 0600; the receiving end must authenticate writers | a writer to the metrics backend can forge values: restrict who can write there |
| T6 | **Credential theft from the hub** (code-host token, kubeconfigs, SSH keys) | workstation / hub | collectors read-only; credentials read from files with mode checks (kubeapi, sinks, registry, identity API keys) or the OS keychain; token values only in child process environments, never logged or stored | the code-host token in use is the operator's broad interactive token (`people.token-scope`); a dedicated fine-grained read-only token per collector is the target |
| T7 | **Prompt injection** through collected data (repo text, log lines, banners) into an AI advisor or a coding agent that operates the platform | advisor, agents | AI only proposes; decisions logged; findings and repo content are data; the agent itself is monitored as personnel (`people.agent-*`) | an agent with broad local permissions can still act on injected text: keep agent permissions narrow |
| T8 | **Supply chain of the platform**: malicious dependency, base image, action or pull request | product, image | dependencies pinned by hash (`self.dependencies-pinned`); base image by digest; Dependabot; image built once in CI, Trivy-scanned (fails on fixable CRITICAL), SBOM, signed keyless (`self.image-signed`, `self.image-ci-scan-sbom`); default branch protected (`self.repo-protected`); gitleaks over the full history (`self.ci-secret-scan`); fork PRs need approval (`people.fork-pr-approval`) | the shared build workflow is referenced by branch, not by SHA |
| T9 | **Denial of service / blindness**: a collector hangs, a host sleeps, the API quota is exhausted | runner | timeouts per job, locks, retries, catch-up, stale alerts; conditional requests (ETags) for code-host APIs | a quota shared with other automation can still starve the platform |
| T10 | **Elevation through the in-cluster hub**: its ServiceAccount is used to read Secrets or change workloads | hub SA | read-only cluster role without Secrets; namespaced writes only to its inbox / snapshot / metrics; NetworkPolicy (DNS + API only) (`self.least-privilege-identity`) | verify the deployed bindings, not only the manifests |
| T11 | **Repudiation**: who accepted a risk, who changed a control, what an agent did | control files, agents | `approved_by`/`attested_by` + dates; snapshots (git); agent transcripts as audit trail with known retention (`people.agent-audit-trail`) | the data repository is local: its history is as trustworthy as the host |

## Secret handling

Review of every credential the platform touches (2026-11; repeat with this file):

| Credential | Read by | How it is held | Rule |
|---|---|---|---|
| code-host token | `codehost-github`, `identity` | `gh auth token --user <u>` into the child's environment only | never logged; responses reduced server-side (`--jq`) when they could contain secret material; ETag cache stores response bodies of non-secret endpoints only |
| kubeconfigs | `k8s`, sinks, spools | files referenced by path; in-cluster: the pod's projected ServiceAccount token | kubeapi refuses token files readable by others |
| SSH keys | exec adapter | the operator's agent / key files; `BatchMode=yes` | a password prompt is a coverage gap, never a prompt |
| registry token | `vuln-intel` | `registry_auth[].token_file` (0600 enforced); `SP_REGISTRY_TOKEN` env as a fallback | prefer the file: the environment is inherited by children |
| identity-provider API keys | `identity` | `api_key_file` (0600 enforced, else refused); read-only keys only | never written to evidence or cache |
| metrics bearer token | `remote_write` sink | `bearer_token_file` (0600 enforced) | - |
| advisor API key | advisor adapters | the adapter's own configuration (off by default) | prompts contain findings: an external advisor is a disclosure decision |

Outputs never contain values: collectors record location, type, scopes, age and mode (`secrets-files`, `identity`
local credentials: metadata only; Kubernetes Secrets: key names only); tests assert this for the identity adapter, the
agent memory scan and the metrics contract. Findings about credentials name the file or store, never the content.

Open items found by the review: (1) the code-host token is the operator's broad interactive OAuth token - replace it
with a fine-grained read-only token for automation (T6); (2) `SP_REGISTRY_TOKEN` in the environment should be retired
in favour of `token_file`; (3) the CI residue check skips while its patterns are not a repository secret (T1).

## Data at rest

Decision: the private data directory is protected by **full-disk encryption of every host that holds it** (FileVault,
BitLocker, LUKS) plus owner-only permissions; it is **not** additionally encrypted file by file.

- Why not per-file encryption (age, SOPS, git-crypt) on the hub: the runner must read and write the ledger every few
  minutes, so the key would live on the same host, unlocked; it would add no protection against a stolen disk that
  FDE does not already give, and none against an attacker running as the operator.
- What must be encrypted separately: every copy that **leaves** the host (off-host backups, sync, snapshot exports):
  encrypt before it leaves (e.g. `age` to a recipient whose private key is offline), scorecard control
  `self.offsite-backup-encrypted`.
- In-cluster hub: the PVC is on a node's disk (encrypt the node's disk) and the snapshot is a Kubernetes Secret
  (enable encryption of Secrets at rest in the API server).
- Checked continuously: `self.data-encrypted-at-rest` reads the host collector's disk-encryption result for the hub
  host (`scorecard.vars.hub_host`).

## Review

Re-read at every Re-plan review and after any incident that involved the platform. Record the date in the instance's
`catalog-review.yaml`; changes to this file reset `self.threat-model`'s age.
