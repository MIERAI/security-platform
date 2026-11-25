# Quick start: first findings in 15 minutes

You need a Linux or macOS machine with `python3` (3.10 or newer) and `git`. Nothing is installed system-wide, nothing
is deployed anywhere, and every check is **read-only**: the platform looks, it never changes your systems.

The first run checks **this machine** only, so you see real findings before you configure anything else. Then you add
your servers, clusters and code hosts one section at a time.

## 1. Install (2 minutes)

```sh
git clone https://github.com/MIERAI/security-platform.git ~/security-platform
cd ~/security-platform && git checkout v0.3.0            # a release tag; `git tag` lists them
python3 -m venv ~/.venvs/security-platform                # its own Python environment (PyYAML only)
~/.venvs/security-platform/bin/pip install --require-hashes -r deploy/requirements.lock
mkdir -p ~/bin && ln -sf ~/security-platform/bin/sp ~/bin/sp
export PATH=~/.venvs/security-platform/bin:~/bin:$PATH    # add this line to your shell profile
sp --version
```

Releases also ship a single `sp` binary per platform, signed and with build provenance: how to verify and
install it is in [install.md](install.md). It uses the Python tree installed above.

## 2. Create your private data directory (1 minute)

```sh
sp init ~/security-data
export SP_DATA=~/security-data                            # so you can leave out --data; add it to your profile too
```

`sp init` writes `~/security-data/instance.yaml` (what to look at, and when) and `exceptions.yaml` (risks you decide
to accept). The directory is mode 0700: **findings are a map for attackers, keep them private** — never commit this
directory to a shared or public repository.

## 3. First scan (3 minutes)

```sh
sp doctor          # checks the config, the tools each check needs, file permissions
sp run             # runs every configured job once, now
sp status          # one screen: what is open, what is overdue, what could not be checked
```

On macOS the first `sp run` can take a few minutes: the software-update check asks Apple's servers and may need
over a minute. If it (or any other single check) does not finish in time, the other checks still report, and that
one shows under "Could not check" (e.g. `os-updates: could not check`) — that means *unknown*, not safe. The next run
tries again; `slow_probe_timeout` in `instance.yaml` ([instance-reference.md](instance-reference.md#hosts)) gives it
more time.

Example:

```
Open findings: high 1, medium 2, low 2
Top risks (sp explain <id>):
  c3c78abf7215  high     The disk is not encrypted (FileVault is off).
```

```sh
sp findings --open --severity high     # the list (this severity or worse)
sp explain c3c78abf7215                # what it means, why it matters, how to fix, how to verify
```

You fix the problem yourself (the platform never changes anything). The next scan confirms the fix and marks the
finding `fixed` on its own. If you decide to live with a risk, `sp explain` prints the entry to paste into
`exceptions.yaml`: who approved it, why, and until when (it reopens automatically when it expires).

## 4. Add your environment (5-10 minutes per section)

Edit `~/security-data/instance.yaml`. Each section is independent; add one, run `sp doctor`, then `sp run <job>`.
Every field and its default: [instance-reference.md](instance-reference.md).

| you have | section | needs |
|---|---|---|
| servers you reach with ssh | `hosts:` with `exec: {type: ssh, host: <ssh alias>}` | key login (never a password prompt), `sudo -n` for a few read-only commands |
| addresses or ranges to look at from outside | `exposure:` with `{type: static, targets: [...], cidrs: [...]}` | `nmap` on the scanning host (`vantage`) |
| Kubernetes | `kubernetes:` with a read-only kubeconfig | `kubectl` |
| GitHub | `codehost: [{type: github, owner, gh_user}]` | `gh` logged in |
| Gitea / Forgejo | `codehost: [{type: gitea, url, owner, token_file}]` | a read-only token in a 0600 file |
| container images and libraries to match against advisories | `intel:` | `trivy` |

Every section also needs a job under `runner.jobs` (the starter config has them, commented out).

Secrets (tokens, webhook URLs) always live in **separate files with mode 0600**, never in `instance.yaml`.

## 5. Keep it running (3 minutes)

Install a versioned copy that the scheduler runs (your git clone stays free for upgrades), build its pinned
environment once, and let a trigger call the runner every 15 minutes:

```sh
I=~/.local/opt/security-platform
~/security-platform/bin/sp-install $I                  # releases/<version>/ + current -> it (rollback = repoint)
$I/current/deploy/render.py env --install $I           # pinned environment, built now; ticks never download
$I/current/deploy/render.py wrapper --install $I --instance $SP_DATA/instance.yaml --data $SP_DATA > $I/tick.sh
sh $I/tick.sh && tail -3 $SP_DATA/state/runner/tick.log # one tick by hand: runs whatever is due
{ crontab -l 2>/dev/null | grep -v 'security-platform runner tick' || true   # keep your other lines (none yet: ok)
  $I/current/deploy/render.py cron --install $I --instance $SP_DATA/instance.yaml --data $SP_DATA; } | crontab -
crontab -l | grep 'security-platform runner tick'      # check: exactly one tick line is installed
#   macOS: render.py launchd ... > ~/Library/LaunchAgents/<label>.plist; Linux: systemd; Android: termux-job
```

The runner runs each job on its own schedule (`runner.jobs`), retries failures, never overlaps a job with itself, and
catches up once after the machine slept. The crontab line is written so that it also works under `set -e` when you
have no crontab yet (`crontab -l` then exits 1; a plain `( crontab -l; ... ) | crontab -` would install an EMPTY
crontab without a word) and so that running it twice does not add a second tick line.
Errors go to `$SP_DATA/state/runner/tick.log`. Details: [runner.md](runner.md).

## 6. See it every day

- **On your phone or chat**: add a notifier and a `notify` job; you get a short summary every morning (counts and
  plain-language headlines only, never addresses or host names):

  ```yaml
  notify:
    - {type: telegram, token_file: ~/.config/security-platform/telegram.token, chat_id: "123456789"}
    # - {type: webhook, url_file: ~/.config/security-platform/slack.url}     # Slack / Mattermost / Teams / ntfy
  runner:
    jobs:
      notify: {type: notify, schedule: "0 8 * * *"}
  ```

  `sp notify --dry-run` shows the text without sending it.
- **On a dashboard**: send the metrics to your Prometheus (`runner.sinks`: a node_exporter textfile, a Kubernetes
  ConfigMap with the bundled exporter, or remote-write) and import `dist/grafana-dashboard.json` (or apply
  `dist/grafana-dashboard.configmap.yaml` where Grafana's dashboard sidecar runs). Alert rules: `dist/prometheus-rules.yaml`
  (they fire on regressions only, never on the standing backlog). [runner.md](runner.md) "Metrics delivery".

## Where next

- [faq.md](faq.md) — common questions and problems
- [adapters.md](adapters.md) — your environment has something we do not support yet (another code host, cloud,
  identity provider): write an adapter
- [upgrade.md](upgrade.md) — versions and how to upgrade safely
- [design.md](design.md) — why it works this way (Chinese); summaries: [日本語](summary.ja.md), [中文](summary.zh.md)

This guide is tested: `e2e/kind/run.sh` installs the platform from this repository on a clean machine of a fictional
company (static address ranges, plain ssh servers, Gitea, kind + kube-prometheus-stack) and checks every step through
to the Grafana dashboard.
