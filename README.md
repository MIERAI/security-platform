Security, the SRE way: collect → urgent fix → monitor/alert → continuous improvement.

# security-platform

A small, environment-agnostic security platform run like an SRE service: read-only **collectors** (wrapping
mature OSS: nmap, Trivy, kube-bench, gh) emit **findings** in one versioned contract; a **ledger** tracks each
finding's lifecycle (first seen → fixed / accepted with expiry → regression); a **runner** keeps it all going on a
schedule on any host or cluster; **security SLIs/SLOs**, regression-only alerts and a dashboard are **generated** from
a catalog; threat intelligence (CISA KEV, EPSS, OSV) is re-matched against your SBOMs every day. AI is an optional,
read-only advisor.

This repository is the **product**. It contains nothing about any concrete environment. Your instance config
and every finding live in a **private** data directory (docs/design.md §6). Findings are attacker intelligence.

```
schema/      findings contract (v1, OCSF mapping)           core/        ledger, digest, validation, OCSF export, advisor
sdk/         collector helper (spsdk)                       runner/      scheduler: jobs, sites, locking, retries, metrics
adapters/    discovery, exec, feeds, sinks, spool (plugins) collectors/  exposure, host, k8s, vuln-intel, codehost-github,
generators/  SLI catalog -> rules / dashboard / SLOs                     secrets-files, agent-claude-code
deploy/      triggers (launchd, cron, systemd, termux,      docs/        design, runner (operations), runbooks
             Kubernetes manifests)                          tests/       contract, ledger, runner, outputs, intel tests
dist/        generated rules / dashboard / SLO values (generic; instances regenerate with --instance)
```

Quick start (any environment):

```sh
cp examples/instance.example.yaml /secure/place/instance.yaml       # pick adapters, targets and the job schedule
python3 runner/runner.py run host --instance /secure/place/instance.yaml --data /secure/place/data   # one job now
python3 runner/runner.py tick --instance /secure/place/instance.yaml --data /secure/place/data       # whatever is due
deploy/render.py launchd|cron|systemd|termux-job --install ... --instance ... --data ...           # keep ticking
uv run -q --with pyyaml python3 generators/gen.py --instance /secure/place/instance.yaml --out <gitops dir>
uv run -q --with pyyaml python3 -m unittest discover -s tests       # tests
```

Requirements: python3 ≥ 3.10 (PyYAML for YAML configs; JSON configs need nothing else), and per collector: `nmap` on
the vantage host, `trivy`, `kubectl`, `gh`, `ssh`. Every component is versioned on its own (`*/VERSION`, adapter
modules' `VERSION`); see docs/design.md §5 and CHANGELOG.md. Operations: docs/runner.md.

License: Apache-2.0 (LICENSE, NOTICE).
