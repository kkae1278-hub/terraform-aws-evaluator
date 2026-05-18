# Python コード手順解説

各ファイルが何を・どの順番で・どのように実行しているかを1ステップずつ説明します。

---

## 実行の全体フロー

```
python main.py --dir ./terraform
        │
        ▼ ステップ0（インポート時・1回のみ）
   rule_loader.load_rules()  ← rule_loader.py
   ┌─────────────────────────────────────────┐
   │ 0-1: rules/rules.yml を YAML で読み込み  │
   │ 0-2: DSL を解釈してチェック関数を生成    │
   │ 0-3: TERRAFORM_RULES 辞書を構築         │
   └─────────────────────────────────────────┘
        │
        ▼ ステップ1
   CLI 引数を解析（argparse）
   --dir / --output / --output-html / --min-severity
        │
        ▼ ステップ2
   parse_tf_directory()   ← hcl_parser.py
   ┌─────────────────────────────────┐
   │ 2-1: .tf ファイル一覧を取得      │
   │ 2-2: 変数デフォルト値を収集      │
   │ 2-3: リソースブロックを収集      │
   │ 2-4: var.X 参照を実際の値に解決 │
   └─────────────────────────────────┘
        │
        ▼ ステップ3
   evaluate_static()      ← evaluator.py
   ┌──────────────────────────────────────┐
   │ 3-1: リソースタイプごとにルール取得   │
   │ 3-2: check(config) を呼び出し        │
   │ 3-3: 違反を Finding に記録           │
   │ 3-4: スコアを減点                    │
   └──────────────────────────────────────┘
        │
        ▼ ステップ4
   重大度フィルタリング（--min-severity）
        │
        ▼ ステップ5
   generate_report() でターミナル出力
        │
        ├─ ▼ ステップ6a（--output 指定時）
        │  JSON ファイルに保存
        │
        └─ ▼ ステップ6b（--output-html 指定時）
           generate_html_report() で HTML ファイルに保存
                │
                ▼ ステップ7
           終了コード（CRITICAL/HIGH があれば exit 1）
```

---

## ステップ0 — ルール定義の読み込み（`rule_loader.py`）

`reference.py` を `import` した瞬間に `load_rules()` が呼ばれ、以後のすべての評価で使われる `TERRAFORM_RULES` が構築されます。

### 0-1: YAML ファイルの読み込み

```python
rules_file = Path(__file__).parent / "rules" / "rules.yml"
data = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
```

`rules/rules.yml` は1ファイルで、カテゴリをトップキーとした構造になっています:

```yaml
compute:
  aws_instance:
    - id: EC2-001
      pillar: SEC
      severity: HIGH
      description: "..."
      message: "..."
      recommendation: "..."
      check:
        op: block_eq
        block: metadata_options
        field: http_tokens
        value: required
```

### 0-2: DSL の解釈とチェック関数の生成

```python
for _category, resources in data.items():       # compute, database, ... をループ
    for resource_type, rules in resources.items():
        for raw in rules:
            rule = dict(raw)
            rule["check"] = _resolve_check(rule.pop("check"))
```

`_resolve_check` が YAML の `check:` ブロックを Python 関数に変換します。

**シンプルな変換例（DSL）:**
```yaml
check:
  op: is_true
  field: monitoring
```
→ `lambda c: c.get("monitoring") is True`

```yaml
check:
  op: block_eq
  block: metadata_options
  field: http_tokens
  value: required
```
→ `lambda c: _block(c, "metadata_options").get("http_tokens") == "required"`

**複雑なチェック（fn）:**
```yaml
check:
  op: fn
  name: sg_no_admin_ports_open
```
→ `checks.sg_no_admin_ports_open`（`checks.py` の関数を直接参照）

### 0-3: TERRAFORM_RULES の完成

```python
result = {
    "aws_instance":    [{"id": "EC2-001", "check": <func>, ...}, ...],
    "aws_db_instance": [{"id": "RDS-001", "check": <func>, ...}, ...],
    ...  # 72 リソースタイプ / 188 ルール
}
```

---

## ステップ1 — CLI 引数の解析（`main.py`）

```python
parser.add_argument("--dir",          default="../terraform")
parser.add_argument("--output",       default=None)
parser.add_argument("--output-html",  default=None)
parser.add_argument("--min-severity", default="LOW")
args = parser.parse_args()
```

| 引数 | デフォルト | 効果 |
|---|---|---|
| `--dir` | `../terraform` | 評価対象ディレクトリ |
| `--output` | なし | JSON レポートを保存 |
| `--output-html` | なし | HTML レポートを保存 |
| `--min-severity` | `LOW` | この重大度未満の Finding を非表示 |

```python
tf_dir = str(Path(args.dir).resolve())
```
- 相対パスを絶対パスに変換。`../terraform` のような指定でも確実に動作する。

---

## ステップ2 — `.tf` ファイルの解析（`hcl_parser.py`）

> **前提:** `python-hcl2` と `pyyaml` が必須です（`pip install -r requirements.txt`）。
> `hcl2` が未インストールの場合はインポート時点でエラーを出力して終了します。

### 2-1: ファイル一覧の取得

```python
tf_path = Path(terraform_dir)
tf_files = sorted(tf_path.glob("*.tf"))
```

ディレクトリ**直下**の `.tf` ファイルをアルファベット順で列挙します。サブディレクトリ（`modules/` 等）は対象外です。

### 2-2: 変数デフォルト値の収集（Pass 1）

```python
for f in tf_files:
    parsed = hcl2.load(open(f))
    for block in parsed.get("variable", []):
        for var_name, var_cfg in block.items():
            if "default" in var_cfg:
                variables[_strip_q(var_name)] = var_cfg["default"]
```

`variables.tf` の `variable` ブロックから `default` 値を先に収集します。

```
variable "instance_type" { default = "t3.micro" }
→ variables["instance_type"] = "t3.micro"
```

変数収集を先に行うことで、定義ファイルの順序に関係なく `var.xxx` を解決できます。

### 2-3: リソースブロックの収集（Pass 2）

```python
for f in tf_files:
    parsed = hcl2.load(open(f))
    _merge_resources(parsed, resources)
```

**`_merge_resources` の処理:**
```python
for block in parsed.get("resource", []):
    for raw_rtype, instances in block.items():
        rtype = _strip_q(raw_rtype)          # '"aws_instance"' → 'aws_instance'
        for raw_name, cfg in instances.items():
            name = _strip_q(raw_name)        # '"web"' → 'web'
            resources[rtype][name] = _flatten_config(cfg)
```

python-hcl2 はキー名に HCL の引用符 `"` を含めて返す場合があります。`_strip_q` で除去します。

**`_flatten_config` — リスト/辞書の正規化:**
```python
def _flatten_config(cfg):
    if isinstance(cfg, list):
        return cfg[0] if cfg and isinstance(cfg[0], dict) else {}
    return cfg if isinstance(cfg, dict) else {}
```
python-hcl2 はブロックをリストで返すことがあります。先頭要素（辞書）を取り出して平坦化します。

この時点での `resources` 構造:
```python
{
    "aws_instance": {
        "web": {
            "instance_type": "t3.micro",
            "monitoring": True,
            "metadata_options": {"http_tokens": "required"},
            ...
        }
    },
    "aws_db_instance": {
        "main": {"multi_az": False, "deletion_protection": False, ...}
    },
    ...
}
```

### 2-4: `var.X` 参照の解決

```python
_VAR_RE = re.compile(r'\$\{var\.([^}]+)\}|(?<!["\w])var\.(\w+)(?!["\w])')

resources = _resolve(resources, variables)
```

`_resolve` は辞書・リスト・文字列を**再帰的に**走査して `var.xxx` を置換します:

```
instance_type = var.instance_type  →  "t3.micro"
cidr_block    = "${var.vpc_cidr}"  →  "10.0.0.0/16"
```

変数が定義されていない場合は `var.xxx` のまま残ります（ルールが正しく評価されない場合があります）。

---

## ステップ3 — 静的ルールチェック（`evaluator.py`）

### 3-1: リソースタイプごとのルール取得

```python
for rtype, instances in resources.items():
    rules = TERRAFORM_RULES.get(rtype, [])
    if not rules:
        continue
```

`TERRAFORM_RULES` にないリソースタイプ（`random_string`, `aws_codestarconnections_connection` 等）はスキップします。

### 3-2: `check(config)` の実行

```python
for rname, config in instances.items():
    result.resources_checked += 1
    for rule in rules:
        result.rules_checked += 1
        try:
            passed = rule["check"](config)
        except Exception:
            passed = True   # クラッシュは偽陰性より偽陽性を防ぐ
```

`check` は `True`（合格）または `False`（違反）を返す関数です。

**DSL 由来のチェック（シンプル）:**
```python
# RDS-001: lambda c: c.get("multi_az") is True
config = {"multi_az": False, ...}
passed = rule["check"](config)  # → False（違反）
```

**`checks.py` 由来のチェック（複雑）:**
```python
# SG-001: sg_no_admin_ports_open
config = {
    "ingress": [{"from_port": 22, "to_port": 22,
                 "cidr_blocks": ["0.0.0.0/0"]}]
}
passed = rule["check"](config)  # → False（SSH が全開放）
```

**ネストブロックへのアクセス（`_block` ヘルパー）:**
```python
# EC2-001 のチェック内部
_block(config, "metadata_options").get("http_tokens") == "required"
# python-hcl2 が {"metadata_options": [{"http_tokens": "required"}]} と返しても
# _block が先頭要素を取り出して安全にアクセスできる
```

### 3-3 & 3-4: Finding の記録とスコア減点

```python
if not passed:
    result.add(Finding(
        rule_id=rule["id"],
        severity=rule["severity"],
        resource_type=rtype,
        resource_name=rname,
        description=rule["description"],
        message=rule["message"],
        recommendation=rule["recommendation"],
    ))
```

```python
def add(self, finding: Finding):
    self.findings.append(finding)
    self.score = max(0, self.score - SEVERITY_WEIGHTS.get(finding.severity, 0))
```

減点表:
```
CRITICAL: -15  HIGH: -10  MEDIUM: -5  LOW: -2  INFO: 0
```
`max(0, ...)` でスコアは 0 未満になりません。

---

## ステップ4 — 重大度フィルタリング（`main.py`）

```python
severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
min_idx = severity_order.index(args.min_severity)  # "HIGH" → 1

result.findings = [
    f for f in result.findings
    if severity_order.index(f.severity) <= min_idx
]
```

`--min-severity HIGH` を指定すると index が 1 以下（CRITICAL=0, HIGH=1）のみ残ります。
**スコアはフィルタリング前の全 Finding に基づいて計算済みなので変わりません。**

---

## ステップ5 — テキストレポート生成（`evaluator.py`）

```python
def generate_report(result, resources, variables):
    lines = []

    # ヘッダー: リソース数・ルール数・スコア
    lines.append(f"  Score       : {result.score}/100  {_score_label(result.score)}")

    # 重大度ごとのサマリー件数
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = len(result.by_severity(sev))
        if cnt:
            lines.append(f"  {sev:<10} {cnt}")

    # 重大度の高い順に全 Finding
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        for f in result.by_severity(sev):
            lines.append(f"  {f.rule_id}  {f.resource_type}.{f.resource_name}")
            lines.append(f"    Problem : {f.message}")
            lines.append(f"    Fix     : {f.recommendation}")

    # 合格している設定を [OK] で表示
    for item in _detect_good_practices(resources, variables):
        lines.append(f"  [OK] {item}")

    return "\n".join(lines)
```

```python
def _score_label(score: int) -> str:
    if score >= 90: return "(EXCELLENT)"
    if score >= 75: return "(GOOD)"
    if score >= 60: return "(FAIR)"
    if score >= 40: return "(POOR)"
    return "(CRITICAL ISSUES)"
```

出力は UTF-8 バイト列として書き出します（Windows の CP932 ターミナルでの文字化け防止）:
```python
sys.stdout.buffer.write((report_text + "\n").encode("utf-8", errors="replace"))
```

---

## ステップ6a — JSON 出力（`main.py`、`--output` 指定時）

```python
if args.output:
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
```

`to_dict()` の出力構造:
```json
{
  "score": 52,
  "resources_checked": 10,
  "rules_checked": 32,
  "findings_count": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 4, "LOW": 4, "INFO": 0},
  "findings": [
    {
      "rule_id": "LC-002",
      "severity": "HIGH",
      "resource_type": "aws_launch_configuration",
      "resource_name": "example",
      "description": "Root EBS volume must be encrypted at rest",
      "message": "Root EBS volume in launch configuration is not encrypted.",
      "recommendation": "Set root_block_device { encrypted = true }"
    }
  ]
}
```

---

## ステップ6b — HTML レポート生成（`evaluator.py`、`--output-html` 指定時）

外部ライブラリを使わず Python の文字列テンプレートだけで完全な HTML を生成します。

**SVG スコアゲージの計算:**
```python
pct = result.score / 100        # 0.52
r = 54                          # 円の半径
circumference = 2 * 3.14159 * r # ≈ 339.3
dash = pct * circumference      # 塗りつぶす弧の長さ
gap  = circumference - dash     # 空白の弧の長さ

# SVG の stroke-dasharray で表現
# stroke-dasharray="176.4 162.9" → 176.4px 塗りつぶし、残りは空白
```

**重大度カードの生成:**
```python
sev_colors = {
    "CRITICAL": ("#b91c1c", "#fee2e2"),  # (前景色, 背景色)
    "HIGH":     ("#c2410c", "#ffedd5"),
    ...
}
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
    fg, bg = sev_colors[sev]
    cnt = len(result.by_severity(sev))
    card_html += f'<div class="card" style="background:{bg}"><div class="card-count" style="color:{fg}">{cnt}</div>...'
```

**Findings テーブルの生成:**
```python
for f in result.findings:
    fg, bg = sev_colors.get(f.severity, ("#374151", "#f3f4f6"))
    rows_html += f"""
        <tr>
          <td><span class="badge" style="background:{bg};color:{fg}">{f.severity}</span></td>
          <td><code>{f.rule_id}</code></td>
          <td><code>{f.resource_type}.<strong>{f.resource_name}</strong></code></td>
          <td>{f.message}</td>
          <td>{f.recommendation}</td>
        </tr>"""
```

**WAF Pillar バーチャートの生成:**
```python
from reference import TERRAFORM_RULES
pillar_counts = {}
for rtype, rules in TERRAFORM_RULES.items():
    for rule in rules:
        p = rule.get("pillar", "OTHER")
        pillar_counts[p] = pillar_counts.get(p, 0) + 1

# 各柱のルール数を SVG <rect> で描画
for pillar, cnt in sorted(pillar_counts.items()):
    w = int(cnt / max_val * bar_width)
    bars += f'<rect x="45" y="{y}" width="{w}" height="16" .../>'
```

---

## ステップ7 — 終了コード（`main.py`）

```python
critical_high = len(result.by_severity("CRITICAL")) + len(result.by_severity("HIGH"))
sys.exit(1 if critical_high > 0 else 0)
```

CRITICAL または HIGH の問題が1件以上あれば終了コード `1`。CI/CD でこの値を受けてジョブを失敗させます。

```yaml
# GitHub Actions の例
- name: Terraform Best-Practice Check
  run: python terraform_evaluator/main.py --dir terraform --min-severity HIGH
  # HIGH 以上があると exit 1 → ジョブ失敗
```

---

## データ変換フロー

```
rules/rules.yml（YAML テキスト）
    ↓ yaml.safe_load()
Python dict（カテゴリ → リソースタイプ → ルールリスト）
    ↓ _resolve_check()
check: <callable>（DSL または checks.py 関数）
    ↓ TERRAFORM_RULES として保持

.tf ファイル（HCL テキスト）
    ↓ hcl2.load()
Python dict（raw、引用符あり）
    ↓ _strip_q() / _flatten_config()
Python dict（クリーン、型正規化済み）
    ↓ _resolve()
Python dict（var.X → 実際の値に置換済み）
    ↓ evaluate_static()
EvaluationResult（score, List[Finding]）
    ↓ generate_report()        → ターミナル出力
    ↓ to_dict() + json.dump()  → JSON ファイル
    ↓ generate_html_report()   → HTML ファイル
```

---

## ファイルと担当の対応表

| ファイル | 担当 | 主な関数・定義 |
|---|---|---|
| `main.py` | 実行制御・CLI | `main()` |
| `helpers.py` | ブロックアクセスヘルパー | `_block()`, `_blocks()`, `_int()` |
| `rule_loader.py` | YAML 読み込み・DSL 解釈 | `_resolve_check()`, `load_rules()` |
| `rules/rules.yml` | ルール定義（188件 / 72 リソースタイプ） | カテゴリ別 YAML |
| `checks.py` | 複雑なチェック関数（約 60 個） | `sg_no_admin_ports_open()` 等 |
| `reference.py` | 公開 API の re-export | `TERRAFORM_RULES`, `SEVERITY_WEIGHTS` |
| `evaluator.py` | 評価・レポート生成 | `evaluate_static()`, `generate_report()`, `generate_html_report()` |
| `hcl_parser.py` | `.tf` 読み込み・変数解決 | `parse_tf_directory()`, `_resolve()` |
