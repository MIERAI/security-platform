# Threat model (template) — the instance's filled-in copy is PRIVATE (`<data>/threat-model.md`)

| Asset / zone | Valuable because | Adversary | Entry points (from exposure + identity findings) | Controls (checks) | Gaps |
|---|---|---|---|---|---|

Adversaries to consider: opportunistic internet scanner; compromised device on the same LAN/overlay; stolen
laptop/phone; malicious dependency/image (supply chain); compromised CI token; **prompt-injected AI agent**
(reads logs/repos/issues and has shell + credentials); insider mistake.

Reviewed in every Re-plan step (docs/design.md §10). Record the date in `<data>/catalog-review.yaml`.

The platform's own threat model (it is a high-value target too) is docs/threat-model.md.
