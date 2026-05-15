# Python コード手順解説

各 `.py` ファイルが何を・どの順番で・どのように実行しているかを1ステップずつ説明します。

---

## 実行の全体フロー

```
python main.py --dir ./terraform
        │
        ▼ ステップ1
   CLI 引数を解析（argparse）
        │
        ▼ ステップ2
   parse_tf_directory()   ← hcl_parser.py
   ┌─────────────────────────────────┐
   │ 2-1: .tf ファイル一覧を取得      │
   │ 2-2: 変数のデフォルト値を収集    │
   │ 2-3: リソースブロックを収集      │
   │ 2-4: 引用符の除去               │
   │ 2-5: var.X 参照を解決           │
   └─────────────────────────────────┘
        │
        ▼ ステップ3
   evaluate_static()      ← evaluator.py
   ┌─────────────────────────────────┐
   │ 3-1: リソースタイプごとにルール取得│
   │ 3-2: check() を実行             │
   │ 3-3: 違反を Finding に記録       │
   │ 3-4: スコアを減点               │
   └─────────────────────────────────┘
        │
        ▼ ステップ4（--live 指定時のみ）
   compare_live()         ← evaluator.py
   ┌─────────────────────────────────┐
   │ 4-1: boto3 セッション作成        │
   │ 4-2: EC2/RDS/ALB/SG/CT/GD/S3   │
   │      を AWS API で取得           │
   │ 4-3: 設定不備・ドリフトを記録    │
   └─────────────────────────────────┘
        │
        ▼ ステップ5
   重大度フィルタリング（--min-severity）
        │
        ▼ ステップ6
   generate_report() でターミナル出力
        │
        ▼ ステップ7a（--output 指定時）
   JSON ファイルに保存
        │
        ▼ ステップ7b（--output-html 指定時）
   generate_html_report() で HTML ファイルに保存
        │
        ▼ ステップ8
   終了コード（CRITICAL/HIGH があれば exit 1）
```

---

## ステップ1 — CLI 引数の解析（`main.py`）

```python
parser = argparse.ArgumentParser(...)
parser.add_argument("--dir",          default="../terraform")
parser.add_argument("--live",         action="store_true")
parser.add_argument("--region",       default="ap-northeast-1")
parser.add_argument("--profile",      default=None)
parser.add_argument("--output",       default=None)   # JSON 出力先
parser.add_argument("--output-html",  default=None)   # HTML 出力先
parser.add_argument("--min-severity", default="LOW")
args = parser.parse_args()
```

**何をしているか**
`argparse` がコマンドライン引数を読み取り、`args` オブジェクトに格納します。
`--live` は `store_true` なのでフラグが付いたとき `True`、なければ `False` になります。

---

## ステップ2 — .tf ファイルの解析（`hcl_parser.py`）

> **前提:** `python-hcl2` が必須です（`pip install python-hcl2`）。
> 未インストールの場合はモジュール読み込み時点でエラーを出力して終了します。
> 正規表現フォールバックパーサーは削除されました。

### 2-1: ファイル一覧の取得

```python
tf_path = Path(terraform_dir)
tf_files = sorted(tf_path.glob("*.tf"))
```

`Path.glob("*.tf")` で対象ディレクトリ内の全 `.tf` ファイルを列挙し、ファイル名でソートします。

---

### 2-2: 変数デフォルト値の収集

```python
for f in tf_files:
    parsed = _load_hcl2(f)
    for block in parsed.get("variable", []):
        for raw_var_name, var_cfg in block.items():
            var_name = _strip_q(raw_var_name)   # 引用符を除去
            if "default" in var_cfg:
                variables[var_name] = var_cfg["default"]
```

全 `.tf` ファイルを走査し、`variables.tf` の `variable` ブロックから `default` 値を収集します。

例：`variables.tf` に `variable "vpc_cidr" { default = "10.0.0.0/16" }` があれば
→ `variables["vpc_cidr"] = "10.0.0.0/16"` として保存されます。

---

### 2-3: リソースブロックの収集

```python
for f in tf_files:
    parsed = _load_hcl2(f)
    _merge_resources(parsed, resources)
```

全ファイルをもう一度走査し、`resource` ブロックを `resources` 辞書に統合します。

**`_merge_resources`**
```python
for block in parsed.get("resource", []):
    for raw_rtype, instances in block.items():
        rtype = _strip_q(raw_rtype)         # 例: '"aws_db_instance"' → 'aws_db_instance'
        for raw_name, cfg in instances.items():
            name = _strip_q(raw_name)       # 例: '"zabbix"' → 'zabbix'
            resources[rtype][name] = _flatten_config(cfg)
```

python-hcl2 はリソースタイプ名・リソース名のキーに HCL の引用符 `"` を含めて返すため、`_strip_q()` で除去します。

**`_flatten_config`**
```python
def _flatten_config(cfg):
    if isinstance(cfg, list):
        return cfg[0] if cfg else {}   # リストで返ってきた場合は最初の要素を使う
    return cfg if isinstance(cfg, dict) else {}
```

python-hcl2 はブロックをリストとして返すことがあるため、最初の要素（辞書）を取り出して平坦化します。

この時点での `resources` の構造：
```python
{
  "aws_db_instance": {
    "zabbix": {
      "multi_az": False,
      "deletion_protection": False,
      "skip_final_snapshot": True,
      ...
    }
  },
  "aws_instance": {
    "zabbix_server": { ... },
    "monitored_target": { ... }
  },
  ...
}
```

---

### 2-4: 引用符の除去（`_strip_q` と `_unquote`）

**`_strip_q`** — キー用
```python
def _strip_q(s):
    return s.strip('"').strip("'")
# '"aws_db_instance"' → 'aws_db_instance'
```

**`_unquote`** — 値用
```python
def _unquote(s):
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        if '"' not in inner:    # 内側にさらに " がなければ単純な文字列リテラル
            return inner
    return s
# '"required"' → 'required'
# '"gp3"'      → 'gp3'
# '"ALL"'      → 'ALL'
```

python-hcl2 は文字列値にも HCL の引用符を残す場合があります。
両方の関数で除去することで、ルールの `check` 関数が期待する Python 文字列と一致するようにします。

---

### 2-5: var.X 参照の解決（`_resolve`）

```python
_VAR_RE = re.compile(r'\$\{var\.([^}]+)\}|(?<!["\w])var\.(\w+)(?!["\w])')

def _resolve(obj, variables):
    if isinstance(obj, str):
        obj = _unquote(obj)                  # まず引用符を除去
        def _replace(m):
            vname = m.group(1) or m.group(2)
            return str(variables.get(vname, m.group(0)))
        return _VAR_RE.sub(_replace, obj)    # var.X を実際の値に置換
    if isinstance(obj, dict):
        return {k: _resolve(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(item, variables) for item in obj]
    return obj
```

辞書・リスト・文字列を再帰的に走査し、`${var.vpc_cidr}` や `var.vpc_cidr` を変数デフォルト値で置換します。

例：
```
"${var.vpc_cidr}"  →  "10.0.0.0/16"
var.project_name   →  "zabbix"
```

---

## ステップ3 — 静的ルールチェック（`evaluator.py`）

### 3-1: ルールの取得

```python
for rtype, instances in resources.items():
    rules = TERRAFORM_RULES.get(rtype, [])
    if not rules:
        continue    # ルール定義がないリソースはスキップ
```

`TERRAFORM_RULES`（`reference.py`）から、リソースタイプに対応するルールリストを取得します。

---

### 3-2: check() の実行

```python
for rname, config in instances.items():
    for rule in rules:
        passed = rule["check"](config)
```

各ルールが持つ `check` は lambda 関数です。
パース済み設定辞書 `config` を受け取り、合格なら `True`、違反なら `False` を返します。

**ルール定義の例（`reference.py` RDS-001）**
```python
{
    "id": "RDS-001",
    "severity": "HIGH",
    "check": lambda c: c.get("multi_az") is True,
    # ↑ config["multi_az"] が True でないと False（＝違反）を返す
}
```

**ネストブロックへのアクセス（`_block` ヘルパー）**
```python
def _block(config, key):
    val = config.get(key, {})
    if isinstance(val, list):
        return val[0] if val else {}
    return val if isinstance(val, dict) else {}

# 使用例（EC2-001）:
# _block(c, "metadata_options").get("http_tokens") == "required"
# → metadata_options ブロック（リストの場合も安全）から http_tokens を取得
```

---

### 3-3 & 3-4: Finding の記録とスコア減点

```python
if not passed:
    result.add(Finding(
        rule_id       = rule["id"],
        severity      = rule["severity"],
        resource_type = rtype,
        resource_name = rname,
        message       = rule["message"],
        recommendation= rule["recommendation"],
        source        = "static",
    ))
```

`result.add()` 内でスコアを減点します：
```python
def add(self, finding):
    self.findings.append(finding)
    self.score = max(0, self.score - SEVERITY_WEIGHTS[finding.severity])
    # CRITICAL:-15  HIGH:-10  MEDIUM:-5  LOW:-2
```

`max(0, ...)` によりスコアは 0 未満にはなりません。

---

## ステップ4 — AWS 実環境照合（`evaluator.py`、`--live` 時のみ）

### 4-1: boto3 セッションの作成と認証確認

```python
session = boto3.Session(region_name=region, profile_name=profile)
sts = session.client("sts")
identity = sts.get_caller_identity()   # 認証情報のテスト
```

`sts:GetCallerIdentity` を呼び出して AWS 接続を確認します。失敗した場合は実環境チェック全体をスキップします。

---

### 4-2 & 4-3: サービスごとの実環境チェック

各チェック関数は同じパターンで動作します。

```
① AWS API で全リソースを取得
② Terraform 定義のリソースと名前で突合
③ 設定値を比較して不備があれば Finding を追加（source="live"）
```

| 関数名 | AWS API | 突合キー |
|---|---|---|
| `_check_ec2_live` | `describe_instances` | Name タグ |
| `_check_rds_live` | `describe_db_instances` | `identifier` 属性 |
| `_check_alb_live` | `describe_load_balancers` | `name` 属性 |
| `_check_sg_live` | `describe_security_groups` | `name` 属性 |
| `_check_cloudtrail_live` | `describe_trails` | — |
| `_check_guardduty_live` | `list_detectors` | — |
| `_check_s3_live` | `list_buckets` + `get_public_access_block` | `bucket` 属性 |

**例: RDS 実環境チェック**
```python
rds = session.client("rds")
resp = rds.describe_db_instances()
live_dbs = {db["DBInstanceIdentifier"]: db for db in resp["DBInstances"]}

for _name, _cfg in tf_dbs.items():
    identifier = _cfg.get("identifier", _name)
    live = live_dbs.get(identifier)      # 同名の実 RDS を探す
    if live is None:
        continue                         # まだデプロイされていない場合はスキップ

    if not live.get("MultiAZ"):          # 実 RDS の MultiAZ フラグを確認
        result.add(Finding(rule_id="RDS-001-LIVE", ...))
```

---

## ステップ5 — 重大度フィルタリング（`main.py`）

```python
severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
min_idx = severity_order.index(args.min_severity)   # 例: "HIGH" → index 1

result.findings = [
    f for f in result.findings
    if severity_order.index(f.severity) <= min_idx
]
```

`--min-severity HIGH` を指定すると、index が 1 以下（CRITICAL=0, HIGH=1）の Finding だけが残ります。

---

## ステップ6 — テキストレポート生成（`evaluator.py`）

```python
def generate_report(result, resources, variables):
    lines = []
    # ヘッダー（スコア・集計）
    lines.append(f"Score : {result.score}/100  {_score_label(result.score)}")

    # 重大度ごとに Finding を列挙
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for f in result.by_severity(sev):
            tag = "[LIVE]" if f.source == "live" else "[STATIC]"
            lines.append(f"{tag} {f.rule_id}  {f.resource_type}.{f.resource_name}")
            lines.append(f"  Problem : {f.message}")
            lines.append(f"  Fix     : {f.recommendation}")

    # 実際の .tf 内容を参照して合格項目を一覧表示
    for item in _detect_good_practices(resources, variables):
        lines.append(f"[OK] {item}")

    return "\n".join(lines)
```

**スコアラベルの判定**
```python
def _score_label(score):
    if score >= 90: return "(EXCELLENT)"
    if score >= 75: return "(GOOD)"
    if score >= 60: return "(FAIR)"
    if score >= 40: return "(POOR)"
    return "(CRITICAL ISSUES)"
```

出力はバイト列として書き出すことで、Windows の CP932 ターミナルでも UTF-8 テキストを正しく表示します：
```python
sys.stdout.buffer.write((report_text + "\n").encode("utf-8", errors="replace"))
```

---

## ステップ7a — JSON 出力（`main.py`、`--output` 指定時）

```python
if args.output:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
```

`result.to_dict()` が返す構造：
```python
{
  "score": 9,
  "resources_checked": 65,
  "rules_checked": 137,
  "live_check_enabled": False,
  "findings_count": {"CRITICAL": 0, "HIGH": 6, "MEDIUM": 9, "LOW": 11},
  "findings": [
    {
      "rule_id": "RDS-001",
      "severity": "HIGH",
      "resource_type": "aws_db_instance",
      "resource_name": "zabbix",
      "message": "multi_az = false ...",
      "recommendation": "Set multi_az = true",
      "source": "static"
    },
    ...
  ]
}
```

---

## ステップ7b — HTML レポート生成（`evaluator.py`、`--output-html` 指定時）

```python
def generate_html_report(result, resources, variables, tf_dir=""):
    ...
```

外部ライブラリを一切使わず、Python の文字列テンプレートだけで HTML を生成します。
`resources` を受け取ることで、HTML の Good Practices セクションも実際の .tf 内容から動的に生成されます。

**含まれるセクション**

| セクション | 実装方法 |
|---|---|
| スコアゲージ | SVG 円弧（`stroke-dasharray` で進捗を表現） |
| 重大度カード | インライン CSS + 重大度別の色定義 |
| Findings テーブル | `<table>` に全 Finding を出力、重大度バッジ付き |
| WAF Pillar バーチャート | `reference.TERRAFORM_RULES` を集計して SVG `<rect>` で描画 |
| Good Practices | グリッドレイアウトのリスト |

**STATIC / LIVE の区別**
```python
tag = "LIVE" if f.source == "live" else "STATIC"
tag_color = "#7c3aed" if f.source == "live" else "#374151"
```

`[LIVE]` は紫色、`[STATIC]` はグレーで表示されます。

---

## ステップ8 — 終了コード（`main.py`）

```python
critical_high = len(result.by_severity("CRITICAL")) + len(result.by_severity("HIGH"))
sys.exit(1 if critical_high > 0 else 0)
```

CRITICAL または HIGH の問題が 1 件以上あれば終了コード `1` で終了します。
CI/CD パイプライン（GitHub Actions 等）でこの終了コードを受けてジョブを失敗させることができます。

---

## データの変換まとめ

```
.tf ファイル（HCL テキスト）
    ↓ hcl2.load()
Python dict（ raw、引用符あり ）
    ↓ _strip_q() / _unquote()
Python dict（ クリーン、引用符なし ）
    ↓ _resolve()
Python dict（ 変数参照を実際の値に置換済み ）
    ↓ evaluate_static()
List[Finding]（ 違反一覧 ）
    ↓ generate_report()        → ターミナル出力
    ↓ to_dict() + json.dump()  → JSON ファイル
    ↓ generate_html_report()   → HTML ファイル
```

---

## ファイルと担当の対応表

| ファイル | 担当 | 主な関数・定義 |
|---|---|---|
| `main.py` | 実行制御・CLI | `main()` |
| `hcl_parser.py` | .tf 読み込み・変数解決 | `parse_tf_directory()`, `_resolve()`, `_strip_q()`, `_unquote()` |
| `reference.py` | ルール定義（188件 / 72 resource type） | `TERRAFORM_RULES`, `_block()`, `_blocks()`, `_int()` |
| `evaluator.py` | 評価・AWS 照合・レポート | `evaluate_static()`, `compare_live()`, `generate_report()`, `generate_html_report()`, `_detect_good_practices()` |
