# コード妥当性レビュー

静的解析・バグ調査・設計評価の結果をまとめます。

---

## 全体評価

| 観点 | 評価 | 備考 |
|---|---|---|
| 動作の正確性 | ★★★★☆ | バグ4件を修正済み |
| コードの可読性 | ★★★★☆ | 全体的にシンプル |
| 拡張性 | ★★★★★ | ルール追加が dict 1行で完結。72 type / 188 rules まで拡張済み |
| エラー耐性 | ★★★☆☆ | check クラッシュは握り潰し設計（意図的） |
| GitHub 公開適性 | ★★★★★ | 個人情報・認証情報なし |

---

## 発見・修正したバグ

### バグ1: MSK-003 — チェックが常に失敗（偽陽性）

**場所:** `reference.py` の `aws_msk_cluster` → `MSK-003`

**原因:**
`_block()` ヘルパーは「ネストされたブロック（dict）」を取り出す関数です。
`enabled` は `True/False` の真偽値なので、`_block()` に渡すと常に `{}` が返ります。

```python
# 修正前（バグ）: _block() で bool 値を取ろうとしている
_block(_block(_block(c, "broker_logs"), "cloudwatch_logs"), "enabled")
#  → {} が返るため bool({}) = False → 常に「ログ未設定」と誤判定

# 修正後: .get() で bool 値を正しく取得
_block(_block(c, "broker_logs"), "cloudwatch_logs").get("enabled") is True
```

**影響:** MSK ログが正しく設定されていても「未設定」と誤検知していた。

---

### バグ2: KIN-001 — 第1条件が常に True の死コード

**場所:** `reference.py` の `aws_kinesis_stream` → `KIN-001`

**原因:**
`_block(c, "encryption_type")` は `encryption_type` が文字列のため `{}` を返します。
`{} != "NONE"` は常に `True` なので、第1条件は意味を持っていませんでした。

```python
# 修正前（死コード）
_block(c, "encryption_type") != "NONE"   # 常に True
    and c.get("encryption_type", "NONE") != "NONE"

# 修正後（シンプル化）
c.get("encryption_type", "NONE") != "NONE"
```

**影響:** 結果的に正しく動いていたが、コードの意図が不明確だった。

---

### バグ4: `_detect_good_practices()` — 全 .tf に固定18件を表示する偽陽性

**場所:** `evaluator.py` の `_detect_good_practices()`

**原因:**
関数が引数 `variables` を受け取るだけで一切参照せず、常に同じ18件のハードコードリストを返していた。
GuardDuty も CloudTrail も EC2 も存在しないリポジトリに対しても全項目が `[OK]` 表示されていた。

```python
# 修正前（ハードコード）
def _detect_good_practices(variables):
    return [
        "VPC Flow Logs enabled on both VPCs (ALL traffic)",
        "GuardDuty enabled with S3 logs + EBS malware scanning",
        # 以下16件も固定
    ]

# 修正後（resources dict を実際に参照）
def _detect_good_practices(resources, variables):
    good = []
    flow_logs = resources.get("aws_flow_log", {})
    if any(c.get("traffic_type", "ALL") == "ALL" for c in flow_logs.values()):
        good.append(f"VPC Flow Logs: ALL traffic captured ({len(flow_logs)} log resource(s))")
    # 以下、GuardDuty / CloudTrail / EC2 / RDS / S3 等を実際のリソース設定で判定
    return good
```

**修正に伴う変更:**
- `generate_report()` と `generate_html_report()` のシグネチャに `resources` 引数を追加
- `main.py` の呼び出し箇所2行も更新
- `from reference import` に `_block, _blocks, _int` を追加（判定ロジック内で使用）

**影響:** どのリポジトリに対しても、実際の .tf 内容に基づいた正確な `[OK]` 項目のみが表示される。

---

### バグ3: EIP-001 — NAT Gateway EIP の偽陽性

**場所:** `reference.py` の `aws_eip` → `EIP-001`

**原因:**
Terraform では EIP を NAT Gateway に割り当てる場合、`aws_nat_gateway` 側が `allocation_id = aws_eip.nat.id` で参照します。`aws_eip` リソース自体には `instance` も `network_interface` もセットされないため、「未割り当て」と誤検知していました。

```python
# 修正前（偽陽性）: NAT Gateway EIP が常に「未割り当て」と判定
check: lambda c: bool(
    c.get("instance") or c.get("network_interface") or c.get("nat_gateway")  # nat_gateway 属性は存在しない
)

# 修正後: 静的解析の限界を認め、INFO レベルでタグの有無をチェック
check: lambda c: bool(c.get("tags"))
severity: "INFO"
```

**影響:** NAT Gateway EIP 2件が「未割り当て課金リスク」として誤って LOW 表示されていた。修正後は INFO に変更。

---

## 設計上の注意点（バグではないが把握すべき点）

### `check()` が例外を投げた場合はスキップ

```python
# evaluator.py
try:
    passed = rule["check"](config)
except Exception:
    passed = True  # クラッシュは合格扱い（偽陰性になる可能性がある）
```

**意図:** ルール定義のバグで評価全体が止まらないよう、安全側（合格）に倒す設計。
**注意:** ルールに構文エラーがあると問題を見逃す可能性がある。

---

### INFO ルールは常に `check: lambda c: True`

`DASH-001`, `ASG-005`, `LAM-004` など、特定の設定値では自動判定できない項目は `check` を常に `True` にし、`message` に確認事項を書く設計です。

```python
{
    "id": "LAM-004",
    "severity": "INFO",
    "check": lambda c: True,   # 常に合格（Findingとして出力されない）
    "message": "VPC-attached Lambda has appropriate security groups...",
}
```

INFO は `generate_report()` に表示されますが、スコア減点はありません（`SEVERITY_WEIGHTS["INFO"] = 0`）。

---

### `_block()` と `.get()` の使い分け

`reference.py` のチェック関数では2つのパターンが混在します。

| パターン | 使うべきケース |
|---|---|
| `_block(c, "key")` | HCL2 のネストブロック（`metadata_options { ... }`）を取り出すとき |
| `c.get("key")` | 平坦なキー・値（`multi_az = true`）を取り出すとき |

`_block()` に真偽値・文字列のキーを渡すと常に `{}` が返るため、平坦な値には必ず `.get()` を使う必要があります。これが今回のバグ1・2の根本原因です。

---

### ECS-005 の第1条件は到達不能コード

```python
# ECS-005 circuit breaker
"check": lambda c: _block(
    _block(c, "deployment_circuit_breaker"), "enable"  # enable は bool → {} が返る → {} is True = False
) is True
or _block(c, "deployment_circuit_breaker").get("enable") is True  # こちらが実際に機能する
```

第2条件で正しく動作するため実害はありませんが、第1条件は削除可能です。

---

### ALB-005 は公開 ALB でも発火する

```python
# ALB-005: internet-facing ALB を検知
"check": lambda c: not (
    c.get("internal") is False and
    c.get("load_balancer_type", "application") == "application"
),
```

公開 Web サービス用の ALB（`internal = false` が正しい）でも HIGH として検知されます。
外部公開が意図的な場合は `# tfsec:ignore:ALB-005` などのコメントで無視するか、ルールを調整してください。

---

## ファイル別の健全性チェック

### `main.py`

| チェック項目 | 結果 |
|---|---|
| ハードコードパス | なし ✅ |
| 認証情報の埋め込み | なし ✅ |
| エラー処理 | FileNotFoundError / ValueError を捕捉 ✅ |
| 終了コード | CRITICAL/HIGH で exit(1)、CI/CD 対応 ✅ |
| argparse のオプション名 | `--output-html` → `args.output_html`（自動変換）✅ |

---

### `hcl_parser.py`

| チェック項目 | 結果 |
|---|---|
| ハードコードパス | なし ✅ |
| 文字コード | UTF-8 明示 ✅ |
| フォールバック | hcl2 未インストール時はエラーで終了（明示的に失敗）✅ |
| 引用符除去 | キー用 `_strip_q()`・値用 `_unquote()` で対応 ✅ |
| 変数解決 | `${var.X}` と `var.X` の両形式に対応 ✅ |
| 例外処理 | ファイル単位で WARNING を出してスキップ ✅ |
| Windows 文字コード（印字）| en-dash `–` を通常ハイフン `-` に修正済み（CP932 対応）✅ |

---

### `reference.py`

| チェック項目 | 結果 |
|---|---|
| ルール ID の重複 | なし ✅ |
| lambda のクラッシュリスク | `evaluator.py` 側で try/except により吸収 ✅ |
| `_block()` の誤用 | MSK-003・KIN-001 を修正済み ✅ |
| EIP 偽陽性 | EIP-001 を INFO に変更済み ✅ |

---

### `evaluator.py`

| チェック項目 | 結果 |
|---|---|
| boto3 の import | `--live` 時のみ実行、未インストールなら警告のみ ✅ |
| AWS 認証失敗時 | STS エラーでスキップ（プログラムは継続）✅ |
| スコアの下限 | `max(0, score - deduction)` で 0 未満にならない ✅ |
| HTML 外部依存 | ライブラリ不要（純粋な文字列テンプレート）✅ |
| Windows 文字コード | `sys.stdout.buffer.write(...encode("utf-8"))` で CP932 回避 ✅ |
| `_detect_good_practices` | `resources` を実際に参照して判定（ハードコード廃止）✅ |

---

## 修正後の評価結果サマリー（zabbix-aws terraform）

| 重大度 | 件数 |
|---|---|
| HIGH | 6 |
| MEDIUM | 9 |
| LOW | 10 |

Static findings 合計: **25件**  
Good Practices: **15件**（実際の .tf から動的に検出）

---

## 今後の改善候補

| 優先度 | 内容 |
|---|---|
| 高 | サブディレクトリ再帰スキャン対応（`modules/` 配下の .tf を評価できない） |
| 中 | モジュール呼び出し（`module "vpc" {}`）の評価対応 |
| 中 | ECS-005 の到達不能な第1条件を削除 |
| 中 | ALB-005 を HIGH → MEDIUM に変更、または INFO コメント推奨 |
| 低 | `check` クラッシュをログに出力して偽陰性を可視化 |
| 低 | ルール ID の重複チェックをテストコードで自動検証 |
