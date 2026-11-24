# security-platform 概要（中文）

按 SRE 方式运营安全的小平台：**采集 → 紧急修复 → 监控/告警 → 持续改进**。完整文档为英文（设计书 [design.md](design.md)
为中文），本页是摘要。

## 做什么

- **collector**（只读）检查外部暴露面（nmap）、服务器（ssh）、Kubernetes、代码托管（GitHub / Gitea / Forgejo）、
  密钥存放位置、AI 助手的权限、漏洞情报（CISA KEV、EPSS、OSV），统一输出 findings/v1 契约（有 OCSF 映射）。
  **从不修改**被检查的系统。
- **台账（ledger）** 管理每条发现的生命周期（首次发现 → 确认修复 / 有期限的风险接受 → 回归）。只有下一次采集确实覆盖到
  该资产且问题消失，才判定为已修复。
- **负责人与期限**（按严重度的 SLO）、**只在回归时告警**、**Grafana 看板**、**记分卡**（最弱的维度决定总分）、
  **每日简报**（只有数量和通俗说明，不含主机名和地址）。

## 15 分钟上手

```sh
git clone https://github.com/MIERAI/security-platform.git ~/security-platform && cd ~/security-platform
python3 -m venv ~/.venvs/security-platform && ~/.venvs/security-platform/bin/pip install --require-hashes -r deploy/requirements.lock
ln -sf ~/security-platform/bin/sp ~/bin/sp && export PATH=~/.venvs/security-platform/bin:~/bin:$PATH
sp init ~/security-data && export SP_DATA=~/security-data
sp doctor && sp run && sp status
sp findings --open --severity high
sp explain <ID>          # 是什么问题、为什么重要、怎么修、怎么确认
```

第一次运行只检查本机；之后在 `instance.yaml` 里逐个加入服务器、集群和代码托管。完整步骤见 [quickstart.md](quickstart.md)，
所有配置项与默认值见 [instance-reference.md](instance-reference.md)。

## 几条约定

- **发现物就是攻击者情报**：只留在私有数据目录（0700）；指标标签和通知里都不带资产细节。
- 密钥（令牌、Webhook URL）放在 0600 的文件里，从不写进日志。
- 环境相关的东西（Tailscale、GitHub、某家云）都是**适配器**；缺的按 [adapters.md](adapters.md) 加，不改核心。
- 破坏性变更**两步走**（[upgrade.md](upgrade.md)）。每个标签都通过单元测试、契约测试、`bin/check-residue --history`
  和基于 kind 的另一套环境的端到端测试。
- AI 只是可选的顾问，不能改变发现的状态，也不能接受风险。

常见问题：[faq.md](faq.md)
