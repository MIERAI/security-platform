# Adapters (plugins)

Collectors never talk to an environment directly; they go through these interfaces. Adding an environment =
adding an adapter, never changing core. All adapters are **read-only** and **non-interactive** (a password
prompt is a failure that the collector records as a coverage gap).

| Interface | Function | Implemented | Future (documented only) |
|---|---|---|---|
| discovery (`discovery.py`) | `discover(cfg) -> [{name, address, os, online, attrs}]` | `tailscale`, `static` | `aws-vpc`, `gcp`, `azure`, CMDB |
| exec (`exec.py`) | `executor(cfg).run(argv, stdin, timeout) -> (rc, out, err)` | `local`, `ssh` (BatchMode, keys only) | `ssm`, `osquery`, EDR APIs |
| vantage (role) | an exec target declared to be OUTSIDE the scanned trust zone | any ssh-able host | cloud VM, CI runner |
| feeds (`feeds.py`) | `load(cfg, cache_dir) -> {fetched_at, version, index}` | `cisa-kev`, `epss` (+ Trivy DB for GHSA/OSV/NVD/distros) | `osv`, `nvd`, vendor advisories (AI extraction + human validation) |
| codehost | inside `collectors/codehost-github` | GitHub | GitLab, Bitbucket |
| identity (`identity.py`) | `provider(cfg).collect() -> {accounts, orgs, grants, credentials, policies, gaps, covered}`; `local_credentials(cfg)` | `github` (2FA where the API tells, orgs' 2FA requirement, collaborators, deploy keys, fork-PR approval, token scopes/age; ETag cache), `tailscale` (read-only API key: users, devices, ACL; else CLI: devices, key expiry), local stores (gh keyring, kubeconfig, SSH, Docker, token files: metadata only) | `google-workspace`, `okta`, `entra`, `gitlab` (interfaces documented in the module) |
| secrets store | `collectors/secrets-files` (metadata only) | files | Vault, AWS/GCP Secret Manager, 1Password |
| cloud | — | — | Prowler wrapped as a collector |
| agent | `collectors/agent-claude-code` | Claude Code | other coding agents |
| advisor (`core/advisor.py`) | `advise(task, context) -> proposal` | `none` | `claude`, `local` model |
