# Adapters (plugins)

Collectors never talk to an environment directly; they go through these interfaces. Adding an environment =
adding an adapter, never changing core. All adapters are **read-only** and **non-interactive** (a password
prompt is a failure that the collector records as a coverage gap).

| Interface | Function | Implemented | Future (documented only) |
|---|---|---|---|
| discovery (`discovery.py`) | `discover(cfg) -> [{name, address, os, online, attrs}]` | `tailscale`, `static` (addresses + CIDR ranges), `file`, `gcp` (VM instances via Cloud Asset / Compute, read-only; login as a cloud GCP account) | `aws-vpc`, `azure`, CMDB |
| exec (`exec.py`) | `executor(cfg).run(argv, stdin, timeout) -> (rc, out, err)`; `powershell(executor, script)` (any length, via stdin) | `local`, `ssh` (BatchMode, keys only; `shell: windows` for cmd.exe quoting) | `ssm`, `osquery`, EDR APIs |
| vantage (role) | an exec target declared to be OUTSIDE the scanned trust zone | any ssh-able host | cloud VM, CI runner |
| feeds (`feeds.py`) | `load(cfg, cache_dir) -> {fetched_at, version, index}` | `cisa-kev`, `epss`, `osv`, `android-bulletins`, `apple-security-releases`, `msrc-cvrf`, `vendor-advisories` (headline candidates only) (+ Trivy DB for GHSA/OSV/NVD/distros) | `nvd`, other vendors |
| codehost | one collector per API: `collectors/codehost-github`, `collectors/codehost-gitea` | GitHub, Gitea / Forgejo | GitLab, Bitbucket |
| identity (`identity.py`) | `provider(cfg).collect() -> {accounts, orgs, grants, credentials, policies, gaps, covered}`; `local_credentials(cfg)` | `github` (2FA where the API tells, orgs' 2FA requirement, collaborators, deploy keys, fork-PR approval, token scopes/age; ETag cache), `tailscale` (read-only API key: users, devices, ACL; else CLI: devices, key expiry), local stores (gh keyring, kubeconfig, SSH, Docker, token files: metadata only) | `google-workspace`, `okta`, `entra`, `gitlab` (interfaces documented in the module) |
| secrets store | `collectors/secrets-files` (metadata only) | files | Vault, AWS/GCP Secret Manager, 1Password |
| cloud (`cloud.py`) | `provider(cfg)`: `credentials()` (short-lived, in memory, refreshed), `identity()`, `permissions()` (self-verification), `engine_env(tmp)`; `collectors/cloud` runs engines (`ENGINES`) and imports (`IMPORTERS`) | `aws` (OIDC web identity [+ AssumeRole chain], SSO/role profile), `gcp` (workload identity federation + impersonation; or the operator's gcloud ADC + impersonation for human-run scans), `azure` (federated credential); engines `prowler`, `steampipe`, `scoutsuite`; imports `securityhub`, `scc`, `defender` | `oci`, `alibaba`; more engines (docs/cloud.md) |
| tickets (`tickets.py`) | `backend(cfg)`: `check()`, `list() -> {finding id: ticket}`, `create(desired)`, `update(ticket, desired)`, `comment(ticket, text)`; engine `sync(backend, entries, cfg)` | `github` (REST, private repositories only, rate-limit aware) | `jira` |
| SIEM (`siem.py`) | `deliver(cfg, [(id, OCSF event)], done)` | `http` (ndjson/json, batching, retry), `file`, `stdout` | vendor-specific envelopes |
| agent | `collectors/agent-claude-code` | Claude Code | other coding agents |
| advisor (`core/advisor.py`) | `advise(task, context) -> proposal` | `none` | `claude`, `local` model |
