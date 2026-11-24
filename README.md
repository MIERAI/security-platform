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
adapters/    discovery, exec, feeds, sinks, spool, cloud    collectors/  exposure, host, k8s, vuln-intel, codehost-github/-gitea,
generators/  SLI catalog -> rules / dashboard / SLOs                     secrets-files, agent-claude-code, identity, cloud
deploy/      triggers (launchd, cron, systemd, termux,      docs/        design, runner (operations), runbooks
             Kubernetes manifests)                          tests/       contract, ledger, runner, outputs, intel tests
dist/        generated rules / dashboard / SLO values (generic; instances regenerate with --instance)
scorecard/   control catalog (one file per dimension) -> score per dimension / pillar / NIST CSF function
cli/         `sp`: init, doctor, run, status, findings, explain, digest, notify; plain-language check texts
notifier/    daily summary adapters (telegram, webhook, exec, file)   e2e/   kind (second environment), cloud-localstack
```

**Scorecard** (docs/scorecard.md): every dimension of the programme (design, coverage, intel, operation, alerting,
remediation, detection, platform self-security, generality, usability, people/identity, cloud - not applicable without cloud) gets a 0-100 score from its
controls (automated, evidence, or human attestations that expire); the overall status FAILS when any dimension is
below 75 - security is decided by the weakest link. Bring your own catalog and weights.

## Quick start

First findings in about 15 minutes, starting with the machine you are on ([docs/quickstart.md](docs/quickstart.md)):

```sh
git clone https://github.com/MIERAI/security-platform.git ~/security-platform && cd ~/security-platform
python3 -m venv ~/.venvs/security-platform && ~/.venvs/security-platform/bin/pip install --require-hashes -r deploy/requirements.lock
ln -sf ~/security-platform/bin/sp ~/bin/sp && export PATH=~/.venvs/security-platform/bin:~/bin:$PATH
sp init ~/security-data && export SP_DATA=~/security-data    # private data directory + starter instance.yaml
sp doctor && sp run && sp status                              # check, scan, one-screen overview
sp findings --open --severity high && sp explain <id>         # what, why, how to fix, how to verify
```

| guide | for |
|---|---|
| [quickstart.md](docs/quickstart.md) | install, first scan, add your environment, keep it running, see it daily |
| [instance-reference.md](docs/instance-reference.md) | every config key and its default |
| [adapters.md](docs/adapters.md) | supporting something new: discovery, exec, sink, notifier, collector |
| [upgrade.md](docs/upgrade.md) | versions, upgrade and rollback, two-step breaking changes |
| [faq.md](docs/faq.md) | common questions and problems |
| [runner.md](docs/runner.md) | operations: schedules, multi-host topologies, in-cluster hub, metrics delivery |
| [scorecard.md](docs/scorecard.md) | the programme scorecard: dimensions, pillars, controls, attestations |
| [cloud.md](docs/cloud.md) | cloud posture (AWS, GCP, Azure): short-lived read-only access, engines, imports, what is validated where |
| [design.md](docs/design.md) | why it works this way (Chinese); summaries in [日本語](docs/summary.ja.md) and [中文](docs/summary.zh.md) |

Proof of generality: `e2e/kind/run.sh` installs a tagged release from this repository into a fictional company's
environment (static CIDR discovery, plain ssh servers, Gitea, kind + kube-prometheus-stack) and checks collectors →
ledger → remediation → scorecard → metrics → Prometheus → Grafana, then tears everything down. Cloud:
`e2e/cloud-localstack/run.sh` scans a deliberately misconfigured LocalStack account with two engines through OIDC
federation, with local GCP/Azure token mocks, and tears it down ([cloud.md](docs/cloud.md#what-is-validated-where)).

Lower-level commands (what `sp` and the scheduled runner call):

```sh
python3 runner/runner.py run host --instance F --data D       # one job now;   `tick`: whatever is due
deploy/render.py env --install DIR                            # once, at deploy time: pinned environment (offline ticks)
deploy/render.py launchd|cron|systemd|termux-job --install DIR --instance F --data D       # keep ticking
python3 generators/gen.py --instance F --out <gitops dir>     # rules, dashboards, SLOs for your instance
python3 scorecard/scorecard.py compute --data D               # (the runner does this too)
python3 -m unittest discover -s tests                         # tests
```

Requirements: python3 ≥ 3.10 (PyYAML for YAML configs; JSON configs need nothing else), and per collector: `nmap` on
the vantage host, `trivy`, `kubectl`, `gh`, `ssh`. Every component is versioned on its own (`*/VERSION`, adapter
modules' `VERSION`); see docs/design.md §5 and CHANGELOG.md. Operations: docs/runner.md.

License: Apache-2.0 (LICENSE, NOTICE).
