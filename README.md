# security-platform — Security, the SRE way (collect → urgent fix → monitor/alert → continuous improvement)

A small, environment-agnostic security platform run like an SRE service: read-only **collectors** (wrapping
mature OSS: nmap, Trivy, kube-bench, gh) emit **findings** in one versioned contract; a **ledger** tracks each
finding's lifecycle (first seen → fixed / accepted with expiry → regression); **security SLIs/SLOs**, regression
alerts and a dashboard are **generated** from a catalog. AI is an optional, read-only advisor.

This repository is the **product**. It contains nothing about any concrete environment. Your instance config
and every finding live in a **private** data directory (see docs/design.md §6). Findings are attacker intelligence.

```
schema/        findings contract (v1, OCSF mapping)          core/        ledger, validation, OCSF export, advisor iface
sdk/           collector helper (spsdk)                      generators/  SLI catalog -> rules / dashboard / SLO drafts
adapters/      discovery, exec, feeds (plugins)              collectors/  exposure, host, k8s, vuln-intel,
docs/          design, runbooks, templates                                codehost-github, secrets-files, agent-claude-code
tests/         contract + ledger tests (synthetic fixtures)  dist/        generated drafts (not deployed)
```

Quick start (any environment):

```sh
cp examples/instance.example.yaml /secure/place/instance.yaml     # pick adapters + targets
bin/run --instance /secure/place/instance.yaml --data /secure/place/data     # read-only run + ledger
uv run -q --with pyyaml python3 generators/gen.py                 # rules / dashboard / SLO drafts
uv run -q --with pyyaml python3 -m unittest discover -s tests     # contract tests
```

Requirements: python3 ≥ 3.10, `uv` (for PyYAML), and per collector: `nmap` on the vantage host, `trivy`, `kubectl`,
`gh`, `ssh`. Every component is versioned on its own (`*/VERSION`); see docs/design.md §5.

Status: phase 0 (skeleton + first read-only inventory). See docs/design.md §12 for the roadmap.
