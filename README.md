# Terraform AWS Best-Practice Evaluator

![CI](https://github.com/kkae0/terraform-aws-evaluator/actions/workflows/ci.yml/badge.svg)

Terraform の `.tf` ファイルを静的解析し、AWS のベストプラクティスと照合して問題点をスコアリングするツールです。生成 AI は使用せず、ルールベースの評価エンジンと boto3 による実環境比較で動作します。

---

## 構成ファイル

```
terraform_evaluator/
├── main.py                        # エントリーポイント（CLI 引数解析・実行制御）
├── hcl_parser.py                  # HCL2 パーサー（.tf ファイルの読み込みと変数解決）
├── reference.py                   # ルール辞書（各リソースのベストプラクティスルール定義）
├── evaluator.py                   # 評価エンジン（静的チェック・AWS 実環境比較・レポート生成）
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
| boto3 | 1.34.0 以上（`--live` 使用時のみ必須） |

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
| `python-hcl2` | **必須** | HCL2 形式の `.tf` ファイルのパース。未インストールの場合はエラーで終了 |
| `boto3` | `--live` 時のみ | AWS API による実環境との照合 |
| `pytest` | テスト時のみ | ユニットテスト・フィクスチャ評価 |

> **注意:** `python-hcl2` は必須依存ライブラリです。以前あった正規表現フォールバックパーサーは削除されました。
> ネストブロック（`metadata_options`, `root_block_device` 等）の正確なパースに hcl2 が必要なためです。

---

## 使い方

### 静的解析のみ（AWS 接続不要）

```bash
python main.py --dir path/to/terraform
```

### AWS 実環境との照合あり

```bash
python main.py --dir path/to/terraform --live --region ap-northeast-1
```

### AWS プロファイルを指定する場合

```bash
python main.py --dir path/to/terraform --live --region ap-northeast-1 --profile myprofile
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
| `--live` | 無効 | boto3 で AWS 実環境と照合する |
| `--region` | `ap-northeast-1` | AWS リージョン（`--live` 時に使用） |
| `--profile` | なし（環境変数の認証情報を使用） | AWS CLI プロファイル名 |
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
| INFO | 0 点 | 参考情報 |

| スコア | 評価 |
|---|---|
| 90 〜 100 | EXCELLENT |
| 75 〜 89 | GOOD |
| 60 〜 74 | FAIR |
| 40 〜 59 | POOR |
| 0 〜 39 | CRITICAL ISSUES |

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

## AWS 実環境照合（`--live` モード）

boto3 を使用して実際に AWS API を呼び出し、Terraform 定義との差異（ドリフト）や実環境の設定不備を検出します。

| サービス | チェック内容 |
|---|---|
| EC2 | IMDSv2 の状態、詳細モニタリングの状態 |
| RDS | Multi-AZ、削除保護、Enhanced Monitoring、Performance Insights |
| ALB | 削除保護、HTTPS リスナーの有無 |
| Security Group | 0.0.0.0/0 による管理/DB ポートの公開 |
| CloudTrail | ログ検証の有効化、KMS 暗号化 |
| GuardDuty | ディテクターの存在確認 |
| S3 | パブリックアクセスブロックの完全設定 |

実環境で検出された問題には `[LIVE]` タグが付き、Terraform 定義上の問題（`[STATIC]`）と区別できます。

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
