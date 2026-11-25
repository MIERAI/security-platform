package cli

// starterTemplate is the starter instance config sp init writes ({name}, {host} and {profile} are filled in): the
// reference's text (cli/sp.py STARTER), byte for byte (tests compare them).
const starterTemplate = `# security-platform instance config: what to look at, and when. PRIVATE (it describes your environment).
# Every section is optional: delete what you do not have. Reference with all defaults: docs/instance-reference.md
name: {name}

# 1. Machines (read-only checks; key login only, never a password prompt). The first entry is THIS machine, so the
#    first ` + "`" + `sp run` + "`" + ` already has something to show.
hosts:
  - {name: {host}, exec: {type: local}, profile: {profile}}
#  - {name: web-1, exec: {type: ssh, host: web-1}, profile: linux}       # profile: linux | macos | windows | busybox | termux

# 2. What can an outsider reach? (needs nmap where ` + "`" + `vantage` + "`" + ` runs; then add the ` + "`" + `exposure` + "`" + ` job below)
# exposure:
#   discovery:
#     - {type: static, targets: [{name: web-1, address: 192.0.2.10}], cidrs: ["192.0.2.0/28"]}
#   vantage: {type: local}         # better: a host OUTSIDE the network, {type: ssh, host: <ssh alias>}

# 3. Kubernetes clusters (get/list only)
kubernetes: []
#  - {name: prod, kubeconfig: ~/.kube/prod-readonly.yaml, role: prod}

# 4. Code hosts
codehost: []
#  - {type: github, owner: your-org, gh_user: your-bot}
#  - {type: gitea, url: https://git.example.com, owner: your-org, token_file: ~/.config/security-platform/gitea.token}

# Who fixes what, and how fast (defaults: critical 7d, high 30d, medium 90d, low 180d)
remediation:
  default_owner: security-oncall

# Notifications: a short daily summary (counts only, never asset details). Default: none.
notify: []
#  - {type: telegram, token_file: ~/.config/security-platform/telegram.token, chat_id_file: ~/.config/security-platform/telegram.chat}
#  - {type: webhook, url_file: ~/.config/security-platform/webhook.url}     # Slack / Mattermost / Teams / ntfy

# When things run (cron syntax, local time). ` + "`" + `sp run` + "`" + ` runs them all now.
runner:
  site: hub
  role: hub
  sinks: []                          # where metrics go; see docs/runner.md "Metrics delivery"
  jobs:
    host:        {schedule: "15 2 * * *", timeout: 30m}
    remediation: {type: remediation, schedule: "50 * * * *"}
    digest:      {type: digest, schedule: "0 9 * * 1"}
#   exposure:        {schedule: "30 3 * * *", timeout: 2h}
#   k8s:             {schedule: "45 2 * * *", timeout: 45m}
#   codehost-github: {schedule: "0 7 * * *"}
#   codehost-gitea:  {schedule: "0 7 * * *"}
#   notify:          {type: notify, schedule: "0 8 * * *"}
`
