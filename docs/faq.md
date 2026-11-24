# FAQ

## Getting started

**Do I need Kubernetes, Prometheus or Grafana?**
No. `sp init` + `sp run` on one laptop gives findings, a ledger and `sp status`. Metrics, dashboards and alerts are
for when you want them on a screen or a pager; any Prometheus-compatible stack works.

**Does it change anything on my systems?**
No. Every collector is read-only (GET requests, `get/list` in Kubernetes, `sshd -T`-style reads on hosts, a gentle
TCP connect scan). Fixes are made by people, through your normal change process; the next scan confirms them.

**What does it need on the hosts it checks?**
An account with key-based ssh and `sudo -n` for a few read-only commands. Nothing is installed; the check script is
streamed over ssh and leaves no files.

**How long until the first findings?**
About 15 minutes from `git clone` ([quickstart.md](quickstart.md)); the first scan of the local machine takes
under a minute. The end-to-end test measures the time from clone to the first ledger on every run.

**Can it run without internet access?**
Yes. Install the pinned environment once (`deploy/render.py env`, `--find-links` for an offline wheel directory);
ticks never download anything. Only the threat-intel feeds need the internet; without it they become "stale"
(reported), and everything else continues.

## Findings

**A finding is wrong (a false positive). What do I do?**
Check `sp explain <id>`; if it is wrong, record it in `exceptions.yaml` with your name, the reason and an expiry
(the platform never hides findings on its own). Please also open an issue with the check name (never the details):
noisy checks get fixed or retired.

**I fixed it, but it is still open.**
Findings close only when a scan **covers** the asset again and the problem is gone (`sp run <job>` scans now). If the
asset could not be checked (offline, permission denied), the finding stays open on purpose: "could not look" is not
"fixed". `sp status` lists what could not be checked.

**Why is "no findings" not good news on its own?**
Because a broken collector also produces no findings. The platform tracks coverage gaps, collector freshness and
its own heartbeat, and the scorecard counts missing data as failing.

**What do the severities mean?**
critical: fix today; high: this week; medium: this month; low: when convenient (defaults of `remediation.slo`, which
you can change). Exploited-in-the-wild vulnerabilities (CISA KEV) on exposed assets get one day.

**How do I accept a risk?**
`sp explain <id>` prints a ready entry for `exceptions.yaml`: who approved it, why, until when. When it expires the
finding reopens automatically. Only a person edits that file; no automation or AI can accept a risk.

## Notifications and dashboards

**What exactly goes to my phone/chat?**
Counts by severity, new/fixed/overdue numbers, plain-language headlines, and finding ids. Never host names,
addresses, ports, repository names or evidence: the summary passes through third-party services. Details stay in
your private data directory (`sp explain <id>`).

**I get nothing.**
`sp notify --dry-run` shows the text; `sp notify` sends it and prints the error per notifier (a status code, never the
token). Check the token file is mode 0600 and, for Telegram, that you started a chat with your bot first.

**Why do alerts fire so rarely?**
By design: alerts fire on **regressions** (something new and serious, a fix that came back, a collector that stopped).
The standing backlog is reviewed in the weekly digest and the dashboard, not paged.

**Prometheus does not show `security_*` metrics.**
Check `runner.sinks` and `sp status` (the sink result is reported); with the Kubernetes exporter: the ServiceMonitor
is picked up by your Prometheus (kube-prometheus-stack needs `serviceMonitorSelectorNilUsesHelmValues: false` or a
matching label), and the exporter's NetworkPolicy admits the namespace your Prometheus runs in (default `monitoring`;
patch it in your overlay otherwise). On **kind** (kindnet), the exporter's deny-all-egress policy also drops its replies
to Prometheus (scrapes time out): keep only the ingress rule in your overlay, as `e2e/kind/run.sh` does
(`policyTypes: [Ingress]`). Calico, Cilium and kube-router handle the reply traffic as expected.

## Environments

**We do not use Tailscale / GitHub / Kubernetes.**
Everything environment-specific is an adapter. Static address lists and CIDR ranges, plain ssh, Gitea/Forgejo and
any Kubernetes are supported; the end-to-end test runs such an environment. Missing ones: [adapters.md](adapters.md).

**Our CPUs are ARM (Apple silicon, Graviton). Is there an image?**
The published runner image is `linux/amd64` today. On ARM, build the same `Dockerfile` (`docker build -t
security-platform .`; the end-to-end test does this automatically) or run the runner directly with python3 (it is
stdlib + PyYAML). A multi-architecture image is on the roadmap.

**Several sites (an external scanner, an office, a cluster)?**
One hub keeps the ledger; sites run their collectors and push documents to the hub's inbox (store-and-forward,
offline-safe). [runner.md](runner.md) "In-cluster hub".

**Can we use our own controls in the scorecard?**
Yes: `scorecard.catalog_dirs` adds your catalog, `overrides` changes weights or disables a product control with a
reason, `replace_catalog: true` uses only yours. [scorecard.md](scorecard.md).

## Security of the platform itself

**Where are the findings stored?**
Only in your private data directory (mode 0700) and, if you run a hub in Kubernetes, on its volume and in a snapshot
Secret of its namespace. Never in this repository, never in metrics labels, never in notifications.

**Does it use AI?**
Only if you configure an advisor (default: none). An advisor may draft text (a remediation note); it never changes a
finding's status, never accepts a risk, and its inputs are treated as data, not instructions.
