# security-platform 概要（日本語）

セキュリティを SRE のやり方で運用するための小さなプラットフォームです。**収集 → 緊急修正 → 監視・アラート → 継続改善**
のループを回します。詳細な文書は英語（一部中国語）です。この頁は要約です。

## 何をするか

- **コレクター**（読み取り専用）が外部からの露出（nmap）、サーバー（ssh）、Kubernetes、コードホスティング
  （GitHub / Gitea / Forgejo）、秘密情報の置き場所、AI アシスタントの権限、脆弱性情報（CISA KEV・EPSS・OSV）を調べ、
  共通の契約（findings/v1、OCSF 対応）で結果を出します。対象のシステムを**変更することはありません**。
- **台帳（ledger）** が各指摘のライフサイクル（初検出 → 修正確認 / 期限付きのリスク受容 → 再発）を管理します。
  修正済みと判定するのは、次の収集でその資産を実際に確認できたときだけです。
- **担当者と期限**（重大度ごとの SLO）、**回帰のみのアラート**、**Grafana ダッシュボード**、**スコアカード**
  （最も弱い分野が全体の点数）、**毎日の短い要約**（件数と平易な説明のみ。ホスト名やアドレスは含めない）。

## 15 分で始める

```sh
git clone https://github.com/MIERAI/security-platform.git ~/security-platform && cd ~/security-platform
python3 -m venv ~/.venvs/security-platform && ~/.venvs/security-platform/bin/pip install --require-hashes -r deploy/requirements.lock
ln -sf ~/security-platform/bin/sp ~/bin/sp && export PATH=~/.venvs/security-platform/bin:~/bin:$PATH
sp init ~/security-data && export SP_DATA=~/security-data
sp doctor && sp run && sp status
sp findings --open --severity high
sp explain <ID>          # 何が問題か・なぜ重要か・直し方・確認方法
```

最初の実行はこのマシン自身だけを調べます。その後 `instance.yaml` にサーバー・クラスタ・コードホストを一つずつ追加します。
手順の全体は [quickstart.md](quickstart.md)、設定項目と既定値は [instance-reference.md](instance-reference.md)。

## 大事な約束

- **発見事項は攻撃者にとっての地図**です。データディレクトリ（0700）から外に出しません。メトリクスのラベルにも
  通知にも資産の詳細は載りません。
- 秘密情報（トークン・Webhook URL）は 0600 のファイルに置き、ログに出しません。
- 環境固有のもの（Tailscale、GitHub、特定のクラウド）はすべて**アダプター**です。足りないものは
  [adapters.md](adapters.md) の手順で追加できます。コアは変更不要です。
- 破壊的変更は**二段階**で行います（[upgrade.md](upgrade.md)）。各タグは単体テスト、契約テスト、
  `bin/check-residue --history`、kind を使った別環境の E2E テストを通っています。
- AI は任意の助言役で、指摘の状態を変えたりリスクを受容したりすることはできません。

よくある質問: [faq.md](faq.md)
