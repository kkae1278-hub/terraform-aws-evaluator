# Terraform AWS Best-Practice Evaluator

![CI](https://github.com/kkae1278-hub/terraform-aws-evaluator/actions/workflows/ci.yml/badge.svg)

Terraform の `.tf` ファイルを静的解析し、AWS のベストプラクティスと照合して問題点をスコアリングするツールです。生成 AI は使用せず、ルールベースの評価エンジンと boto3 による実環境比較で動作します。

---

## 構成ファイル

```
terraform_evaluator/
├── main.py                        # エントリーポイント（CLI 引数解析・実行制御）
├── hcl_parser.py                  # HCL2 パーサー（.tf ファイルの読み込みと変数解決）
├── evaluator.py                   # 評価エンジン（静的チェック・レポート生成）
├── reference.py                   # 公開 API（TERRAFORM_RULES / SEVERITY_WEIGHTS を re-export）
├── rule_loader.py                 # YAML ルールファイルを読み込み TERRAFORM_RULES を構築
├── checks.py                      # 複雑なチェック関数（YAML DSL で表現できないロジック）
├── helpers.py                     # HCL2 ブロック操作ヘルパー（_block / _blocks / _int）
├── rules/
│   └── rules.yml                  # ベストプラクティス定義（72 リソース・188 ルール、カテゴリ別キー構成）
├── requirements.txt               # 実行依存ライブラリ
├── requirements-dev.txt           # 開発・テスト用依存ライブラリ
├── scripts/
│   └── count_rules.py             # ルール数・リソースタイプ数の集計ユーティリティ
├── tests/
│   ├── test_rules.py              # pytest テストスイート（42 件）
│   └── fixtures/
│       ├── sample_good/main.tf    # 正しく設定されたリソース群（テスト用）
│       └── sample_bad/main.tf     # 意図的に設定ミスしたリソース群（テスト用）
└── README.md                      # このファイル
```

---

## 必要要件

| 項目 | バージョン |
|---|---|
| Python | 3.8 以上 |
| python-hcl2 | 4.3.0 以上（**必須**） |
| pyyaml | 6.0 以上（**必須**） |

## セットアップ

```bash
cd terraform_evaluator

# 実行環境
pip install -r requirements.txt

# 開発・テスト環境（pytest / flake8 が必要な場合）
pip install -r requirements-dev.txt
```

| ライブラリ | 必須 | 用途 |
|---|---|---|
| `python-hcl2` | **必須** | HCL2 形式の `.tf` ファイルのパース |
| `pyyaml` | **必須** | `rules/` 配下の YAML ルールファイルの読み込み |
| `pytest` | テスト時のみ | ユニットテスト・フィクスチャ評価 |

> **注意:** `python-hcl2` および `pyyaml` はともに必須依存ライブラリです。
> `pip install -r requirements.txt` で両方インストールされます。

---

## 使い方

### 静的解析のみ（AWS 接続不要）

```bash
python main.py --dir path/to/terraform
```

### JSON レポートとして保存

```bash
python main.py --dir path/to/terraform --output report.json
```

### HTML レポートとして保存

```bash
python main.py --dir path/to/terraform --output-html report.html
```

### 表示する最低重大度を絞り込む

```bash
# HIGH 以上のみ表示
python main.py --dir path/to/terraform --min-severity HIGH
```

### 全オプション

| オプション | デフォルト | 説明 |
|---|---|---|
| `--dir` | `../terraform` | 評価対象の Terraform ディレクトリ |
| `--output` | なし | JSON レポートの出力先ファイルパス |
| `--output-html` | なし | HTML レポートの出力先ファイルパス |
| `--min-severity` | `LOW` | 表示する最低重大度 |

---

## 評価スコア

100 点満点からスタートし、発見された問題の重大度に応じて減点します。

| 重大度 | 減点 | 基準 |
|---|---|---|
| CRITICAL | 15 点 | 即時対応が必要なセキュリティリスク |
| HIGH | 10 点 | 可用性・機密性に直接影響する問題 |
| MEDIUM | 5 点 | ベストプラクティスからの逸脱 |
| LOW | 2 点 | 推奨設定の不足 |
| INFO | 0 点 | 参考情報（自動判定不可・要手動確認） |

| スコア | 評価 |
|---|---|
| 90 〜 100 | EXCELLENT |
| 75 〜 89 | GOOD |
| 60 〜 74 | FAIR |
| 40 〜 59 | POOR |
| 0 〜 39 | CRITICAL ISSUES |

---

## 重大度の判別基準

新しいルールを追加する際は、以下の基準を参考に重大度を選択してください。

### CRITICAL

**「現状の設定のまま攻撃・情報漏洩が成立する」** 状態。外部からの直接アクセスや機密データの公開が即座に起こりうる場合に適用します。

| 判断基準 | 具体例 |
|---|---|
| 機密データ・リソースがインターネットに直接公開されている | S3 バケットのパブリック公開、RDS の `publicly_accessible = true` |
| 管理ポートが全 IP に開放されている | SG の ingress で SSH（22）/ RDP（3389）が `0.0.0.0/0` に開放 |
| 認証・認可が完全に無効化されている | IAM ポリシーで `"Principal": "*"` かつ `"Action": "*"` |
| 保管データが一切暗号化されていない（機密性の高いリソース） | EBS ルートボリュームの暗号化なし、Secrets Manager の暗号化なし |

### HIGH

**「直接の攻撃経路はないが、障害・インシデント発生時の影響が甚大」** な状態。可用性の喪失・データ消失・権限昇格につながる設定不備に適用します。

| 判断基準 | 具体例 |
|---|---|
| 単一障害点になっており、AZ 障害でサービス全断する | RDS `multi_az = false`、NAT Gateway 単一 AZ |
| 削除保護がなく、誤操作でデータが永久消失する | `deletion_protection = false`、`skip_final_snapshot = true` |
| 通信が平文であり、盗聴・改ざんが可能 | ALB の HTTP-only（HTTPS なし）、DB 接続の SSL 未強制 |
| IAM 権限が過剰で、侵害時の横展開リスクが高い | ロールに `*` アクション、信頼ポリシーで `"AWS": "*"` |
| セキュリティ設定の中核機能が無効 | IMDSv1 許可（`http_tokens = optional`）、VPC Flow Logs なし |

### MEDIUM

**「直接のリスクは低いが、AWS ベストプラクティスや Well-Architected Framework から外れている」** 状態。攻撃難易度が高い・影響範囲が限定的・代替手段が存在するケースに適用します。

| 判断基準 | 具体例 |
|---|---|
| CMK ではなく AWS マネージドキーを使用している | CloudTrail / CloudWatch Logs / SNS の KMS 暗号化なし |
| 監査・可観測性の設定が不足している | CloudTrail の S3 未出力、RDS Enhanced Monitoring 無効 |
| セキュリティ強化オプションが未設定（デフォルトが安全側でない） | ALB `drop_invalid_header_fields = false`、`enable_deletion_protection = false` |
| バックアップ・復旧設定が不十分 | RDS バックアップ保持 7 日未満、`force_destroy = true` |
| 詳細モニタリング・パフォーマンス分析が無効 | RDS Performance Insights 無効、EC2 詳細モニタリング無効 |

### LOW

**「機能・セキュリティへの影響はほぼないが、運用品質・コンプライアンス上の推奨設定が欠けている」** 状態。

| 判断基準 | 具体例 |
|---|---|
| リソースの識別・監査に必要なメタデータが不足 | IAM Role に `description` なし、タグ未設定 |
| 障害時の通知・ロギングが不完全 | SNS の `redrive_policy` なし、アクセスログ未設定 |
| 冗長化・自動復旧のオプションが未設定（単体では機能する） | EIP のタグなし、EBS `delete_on_termination` の明示指定なし |
| セキュリティ設定の意図が不明確（機能的問題はない） | VPC Endpoint SG に egress ルールなし |

### INFO

**「自動判定が不可能、または文脈依存で正誤が決まる」** 設定。違反としてカウントせず、確認を促す情報として表示します。

| 判断基準 | 具体例 |
|---|---|
| 構成の意図によって正しい値が異なる | VPC-attached Lambda のセキュリティグループ適切性 |
| 静的解析では判定できない実行時の設定 | ASG のヘルスチェック猶予期間の妥当性 |
| EIP の割り当て先が別リソース参照で判定不可 | `aws_eip` が NAT Gateway に割り当て済みかどうか |

---

## チェックルール概要

現在 **72 リソースタイプ・188 ルール** を収録しています。
AWS Well-Architected Framework の 5 つの柱（SEC / REL / OPS / PERF / COST）を基準にしています。

主なカバー範囲：

| カテゴリ | リソース例 |
|---|---|
| コンピューティング | EC2, Lambda, ECS (Cluster/Service/TaskDef), EKS, Auto Scaling, Launch Template/Configuration |
| データベース | RDS, Aurora, DynamoDB, ElastiCache, Redshift |
| ネットワーク | VPC, ALB, Security Group (inline / standalone rule), VPC Flow Logs, CloudFront |
| ストレージ | S3, EBS, ECR |
| セキュリティ | IAM (Role/Policy/Attachment), KMS, Secrets Manager, GuardDuty, Security Hub, Macie |
| 監視・運用 | CloudTrail, CloudWatch, Config, Backup |
| メッセージング | SQS, SNS, SNS Subscription, Kinesis, MSK |
| CI/CD | CodeBuild, CodePipeline, CodeDeploy |
| サーバーレス | Lambda, Step Functions, API Gateway |
| その他 | OpenSearch, ACM, SSM, Route53, VPN |

---

## テスト実行

```bash
# ユニットテスト（42 件）
pytest tests/ -v

# ルール数・リソースタイプ数の確認
python scripts/count_rules.py
```

---

## CI/CD への組み込み例

```yaml
# GitHub Actions の例
- name: Terraform Best-Practice Check
  run: |
    pip install -r terraform_evaluator/requirements.txt
    python terraform_evaluator/main.py \
      --dir terraform \
      --min-severity HIGH
  # HIGH 以上の問題があると exit code 1 でジョブが失敗する
```

---

## このツールの位置づけ

| フェーズ | ツール |
|---|---|
| **デプロイ前**（Terraform コードレビュー） | **このツール** ← ここ |
| デプロイ後（設定コンプライアンス常時監視） | AWS Security Hub (FSBP) |
| デプロイ後（脅威検知・異常行動検出） | AWS GuardDuty |

Security Hub と内容が重複する部分はありますが、**デプロイ前に CI/CD でキャッチできる**点がこのツールの主な価値です。

---

## 制限事項

| 制限 | 内容 |
|---|---|
| サブディレクトリ非対応 | `parse_tf_directory` はトップレベルの `*.tf` のみ解析。`modules/` 配下は評価対象外 |
| モジュール呼び出し非対応 | `module "vpc" { ... }` 形式のモジュール参照は評価対象外。直接の `resource` ブロックのみ対象 |
| 変数未解決 | `default` のない変数（`.tfvars` で渡す場合）は `var.xxx` のまま残りルールが正しく評価されない場合がある |
