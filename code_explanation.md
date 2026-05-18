# Terraform Evaluator — コード解説

対象ファイル:
`main.py` / `helpers.py` / `rule_loader.py` / `rules/rules.yml` / `checks.py` / `reference.py` / `evaluator.py` / `hcl_parser.py`

---

## main.py（エントリポイント）

```python
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
```
- `argparse` — コマンドライン引数（`--dir` など）を解析する標準ライブラリ。
- `sys.path.insert(0, ...)` — このスクリプトと同じフォルダにある `hcl_parser.py` / `evaluator.py` を `import` できるようにパスを先頭に追加。

```python
from hcl_parser import parse_tf_directory
from evaluator import evaluate_static, generate_report, generate_html_report
```
- `.tf` ファイルの解析・評価・レポート生成の3関数をインポート。

```python
parser.add_argument("--dir",          default="../terraform")
parser.add_argument("--output",       default=None)
parser.add_argument("--output-html",  default=None, metavar="FILE")
parser.add_argument("--min-severity", choices=["CRITICAL","HIGH","MEDIUM","LOW","INFO"], default="LOW")
```
- `--dir` — 評価対象の Terraform ディレクトリ（省略時は `../terraform`）。
- `--output` — JSON レポートの保存先。省略時は保存しない。
- `--output-html` — HTML レポートの保存先。省略時は生成しない。
- `--min-severity` — 表示する最低重大度。デフォルト `LOW`（ほぼ全件表示）。

```python
tf_dir = str(Path(args.dir).resolve())
```
- 相対パスを絶対パスに変換。`../terraform` のような指定でも確実に動作する。

```python
resources, variables = parse_tf_directory(tf_dir)
```
- `.tf` ファイルを解析して `resources`（リソース設定辞書）と `variables`（変数デフォルト値）を取得。
- ディレクトリが存在しない・`.tf` ファイルがない場合は例外が発生し `sys.exit(1)` で終了。

```python
result = evaluate_static(resources)
```
- 全リソースに対してルールを適用し `EvaluationResult` を返す。

```python
severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
min_idx = severity_order.index(args.min_severity)
result.findings = [f for f in result.findings
                   if severity_order.index(f.severity) <= min_idx]
```
- `--min-severity HIGH` なら index が 1 以下（CRITICAL=0, HIGH=1）の Finding のみ残す。
- インデックスが小さいほど重大度が高い。

```python
sys.stdout.buffer.write((report_text + "\n").encode("utf-8", errors="replace"))
```
- `buffer.write` で UTF-8 バイト列として直接書き出す。Windows の CP932 ターミナルでも文字化けしない。

```python
critical_high = len(result.by_severity("CRITICAL")) + len(result.by_severity("HIGH"))
sys.exit(1 if critical_high > 0 else 0)
```
- CRITICAL / HIGH が1件でもあれば終了コード `1`。CI/CD でジョブを失敗させる用途に使う。

---

## helpers.py（共通ヘルパー）

python-hcl2 はブロックをリストや辞書で返す場合があり、扱いが不安定です。
この3関数で安全に値を取り出します。

```python
def _block(config, key):
    val = config.get(key, {})
    if isinstance(val, list):
        return val[0] if val else {}
    return val if isinstance(val, dict) else {}
```
- HCL の `metadata_options { ... }` のような単一ブロックを取得。
- python-hcl2 がリストで返した場合は先頭要素を使う。辞書でも dict でもない場合は空辞書を返す。
- 使用例: `_block(c, "metadata_options").get("http_tokens")`

```python
def _blocks(config, key):
    val = config.get(key, [])
    if isinstance(val, list):
        return val
    return [val] if isinstance(val, dict) else []
```
- `ingress { ... }` のような複数存在しうるブロック群をリストで取得。
- 使用例: `for rule in _blocks(c, "ingress"):`

```python
def _int(config, key, default=0):
    try:
        return int(config.get(key, default))
    except (TypeError, ValueError):
        return default
```
- フィールドを安全に整数で取得。未設定・文字列・None でもクラッシュしない。
- 使用例: `_int(c, "backup_retention_period") >= 7`

---

## rule_loader.py（YAML ローダー + DSL リゾルバー）

`rules/rules.yml` を読み込み、各ルールの `check` フィールドを呼び出し可能な関数に変換して `TERRAFORM_RULES` を構築します。

### DSL リゾルバー (`_resolve_check`)

YAML の `check:` ブロックを見て、対応するラムダ関数を生成します。

```python
def _resolve_check(spec: dict):
    op = spec.get("op")

    if op == "is_true":
        f = spec["field"]
        return lambda c, f=f: c.get(f) is True
```
- `f=f` のデフォルト引数でクロージャのスコープ問題（変数が後から書き換わる問題）を回避。
- ループ内でラムダを生成するときの Python の定番パターン。

**サポートする演算子一覧:**

| op | 生成するチェック | 代表的な用途 |
|---|---|---|
| `is_true` | `c.get(f) is True` | monitoring, multi_az, deletion_protection |
| `not_true` | `c.get(f) is not True` | publicly_accessible, associate_public_ip_address |
| `not_false` | `c.get(f, True) is not False` | auto_minor_version_upgrade（デフォルトTrue） |
| `truthy` | `bool(c.get(f))` | tags, encryption_key |
| `eq` | `c.get(f, d) == v` | http_tokens == "required", volume_type == "gp3" |
| `not_in` | `c.get(f, d) not in [...]` | ca_cert_identifier の非推奨値チェック |
| `gte` | `_int(c, f, d) >= v` | backup_retention_period >= 7 |
| `gt` | `_int(c, f, d) > v` | monitoring_interval > 0 |
| `lte` | `_int(c, f, d) <= v` | deregistration_delay <= 300 |
| `has_key` | `f in c` | health_check, tags の存在確認 |
| `block_is_true` | `_block(c, b).get(f) is True` | root_block_device.encrypted |
| `block_eq` | `_block(c, b).get(f, d) == v` | metadata_options.http_tokens |
| `block_truthy` | `bool(_block(c, b).get(f))` | ネストブロック内のフィールド存在確認 |
| `block_has_key` | `f in _block(c, b)` | delete_on_termination の明示的設定確認 |
| `has_blocks` | `bool(_blocks(c, f))` | rule リストの存在確認（Backup, WAF） |
| `not_startswith` | `not str(c.get(f, d)).startswith(tuple)` | 旧世代インスタンスタイプの検出 |
| `fn` | `checks.func_name(c)` | 複雑なロジック（イテレーション・深いネスト） |

`fn` の場合は `checks.py` から関数名でルックアップします:
```python
if op == "fn":
    import checks as _checks_mod
    return getattr(_checks_mod, spec["name"])
```

### YAML ローダー (`load_rules`)

```python
def load_rules() -> dict:
    rules_file = _RULES_DIR / "rules.yml"
    data = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
    result = {}
    for _category, resources in data.items():
        if not isinstance(resources, dict):
            continue
        for resource_type, rules in resources.items():
            rule_list = []
            for raw in rules:
                rule = dict(raw)                    # シャローコピーで元 YAML を汚染しない
                rule["check"] = _resolve_check(rule.pop("check"))
                rule_list.append(rule)
            result[resource_type] = rule_list
    return result
```
- YAML のトップキー（`compute:`, `database:` 等）はカテゴリ名としてスキップし、その下の `resource_type → rules` を処理。
- `dict(raw)` でルールをコピーしてから `check` キーを取り出し、関数に変換して差し替える。

---

## rules/rules.yml（ルール定義）

10カテゴリ・72リソースタイプ・188ルールを1ファイルで管理します。

```yaml
# カテゴリがトップキー
compute:
  aws_instance:
    - id: EC2-001
      pillar: SEC            # WAF の柱: SEC/REL/OPS/PERF/COST
      severity: HIGH         # CRITICAL/HIGH/MEDIUM/LOW/INFO
      description: "IMDSv2 (http_tokens=required) must be enforced"
      message: "IMDSv2 is not required..."
      recommendation: "Set metadata_options { http_tokens = \"required\" }"
      check:
        op: block_eq         # DSL 演算子
        block: metadata_options
        field: http_tokens
        value: required

    - id: EC2-003
      ...
      check:
        op: is_true
        field: monitoring

database:
  aws_db_instance:
    - id: RDS-001
      ...
```

**複雑なチェックの場合 (`op: fn`):**
```yaml
security:
  aws_security_group:
    - id: SG-001
      ...
      check:
        op: fn
        name: sg_no_admin_ports_open   # checks.py の関数名
```

**`default` パラメータ付きの例:**
```yaml
    - id: EBS-002
      check:
        op: eq
        field: type
        value: gp3
        default: gp2     # Terraform のデフォルト値。未指定時はこの値でチェック
```

---

## checks.py（複雑なチェック関数）

DSL で表現できない複雑なロジック（`any()`/`all()` イテレーション・深いネスト・文字列検索など）を named 関数として定義します。

```python
from helpers import _block, _blocks, _int
```
- `reference.py` ではなく `helpers.py` から直接インポート（循環インポート防止）。

**パターン例：イテレーション型（SG-001）**
```python
def sg_no_admin_ports_open(c):
    _ADMIN_PORTS = {22, 3306, 5432, 1433, 27017, 6379, 5439, 9200}
    for i in _blocks(c, "ingress"):
        if (("0.0.0.0/0" in (i.get("cidr_blocks") or [])
             or "::/0" in (i.get("ipv6_cidr_blocks") or []))
                and int(i.get("from_port", 0)) in _ADMIN_PORTS):
            return False   # 違反あり
    return True            # 全ルール問題なし
```

**パターン例：文字列検索型（IAM-001）**
```python
def iam_no_wildcard_principal(c):
    policy = str(c.get("assume_role_policy", ""))
    return ('"AWS": "*"' not in policy
            and "'AWS': '*'" not in policy)
```

**パターン例：深いネスト型（MSK-001）**
```python
def msk_tls_encryption(c):
    return (_block(_block(c, "encryption_info"), "encryption_in_transit")
            .get("client_broker", "TLS_PLAINTEXT") == "TLS")
```

ルールの追加手順:
1. `rules/rules.yml` に `op: fn, name: 関数名` でエントリを追加
2. `checks.py` に対応する関数を追加

---

## reference.py（公開 API の re-exporter）

```python
from helpers import _block, _blocks, _int
from rule_loader import load_rules

SEVERITY_WEIGHTS = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}

TERRAFORM_RULES = load_rules()
```
- 実体は `helpers.py` と `rule_loader.py` に移動済み。
- このファイルは既存の `from reference import ...` が壊れないようにするための薄いラッパー。
- `evaluator.py` と `tests/test_rules.py` は変更なしでそのまま動く。

---

## evaluator.py（評価エンジン）

### データモデル

```python
@dataclass
class Finding:
    rule_id: str        # "EC2-001"
    severity: str       # "HIGH"
    resource_type: str  # "aws_instance"
    resource_name: str  # Terraform 上のリソース名
    description: str    # ルールの説明
    message: str        # 具体的な問題内容
    recommendation: str # 推奨対処法
```
- 1件の違反を表すデータクラス。`source` フィールドは存在しない（ライブチェックを廃止したため）。

```python
@dataclass
class EvaluationResult:
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    resources_checked: int = 0
    rules_checked: int = 0
```

```python
def add(self, finding: Finding):
    self.findings.append(finding)
    self.score = max(0, self.score - SEVERITY_WEIGHTS.get(finding.severity, 0))
```
- `max(0, ...)` でスコアが0未満にならないよう保護。

### 静的評価 (`evaluate_static`)

```python
for rtype, instances in resources.items():
    rules = TERRAFORM_RULES.get(rtype, [])
    if not rules:
        continue
```
- ルール定義のないリソースタイプ（`random_string` 等）は無視。

```python
    for rname, config in instances.items():
        result.resources_checked += 1
        for rule in rules:
            result.rules_checked += 1
            try:
                passed = rule["check"](config)
            except Exception:
                passed = True  # クラッシュは偽陽性より偽陰性を選ぶ
            if not passed:
                result.add(Finding(...))
```
- `check(config)` は `True`（合格）または `False`（違反）を返す。
- 例外が発生してもクラッシュさせず `passed=True` として続行（偽陽性を避けるため）。

### レポート生成 (`generate_report`)

```python
lines.append(f"  Score       : {result.score}/100  {_score_label(result.score)}")
```

```python
def _score_label(score: int) -> str:
    if score >= 90: return "(EXCELLENT)"
    if score >= 75: return "(GOOD)"
    if score >= 60: return "(FAIR)"
    if score >= 40: return "(POOR)"
    return "(CRITICAL ISSUES)"
```
- スコアを5段階ラベルに変換。

```python
for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
    for f in result.by_severity(sev):
        lines.append(f"  {f.rule_id}  {f.resource_type}.{f.resource_name}")
        lines.append(f"    Problem : {f.message}")
        lines.append(f"    Fix     : {f.recommendation}")
```
- 重大度の高い順に全 Finding を列挙。

```python
good = _detect_good_practices(resources, variables)
for item in good:
    lines.append(f"  [OK] {item}")
```
- 合格している設定（IMDSv2 有効・KMS 暗号化済み等）を `[OK]` として表示。

### HTML レポート生成 (`generate_html_report`)

外部ライブラリを使わず Python の文字列テンプレートだけで HTML を生成します。

```python
pct = result.score / 100
circumference = 2 * 3.14159 * 54  # r=54 の円周
dash = pct * circumference
gap  = circumference - dash
```
- SVG の `stroke-dasharray` で円弧の長さを計算してスコアゲージを描画。

```python
sev_colors = {
    "CRITICAL": ("#b91c1c", "#fee2e2"),
    "HIGH":     ("#c2410c", "#ffedd5"),
    "MEDIUM":   ("#b45309", "#fef9c3"),
    "LOW":      ("#1d4ed8", "#dbeafe"),
    "INFO":     ("#374151", "#f3f4f6"),
}
```
- 重大度ごとに前景色（テキスト・ボーダー）と背景色のペアを定義。

| セクション | 実装方法 |
|---|---|
| スコアゲージ | SVG 円弧（`stroke-dasharray`） |
| 重大度カード | インライン CSS + 色定義辞書 |
| Findings テーブル | `<table>` タグで全 Finding を出力、重大度バッジ付き |
| WAF Pillar バーチャート | `TERRAFORM_RULES` を集計して SVG `<rect>` で描画 |
| Good Practices | グリッドレイアウトのリスト |

---

## hcl_parser.py（HCL2 パーサー）

```python
try:
    import hcl2
except ImportError:
    print("ERROR: python-hcl2 is required but not installed.")
    sys.exit(1)
```
- モジュール読み込み時点で `hcl2` の存在を確認。未インストールならインストール方法を案内して終了。

### メイン関数 (`parse_tf_directory`)

```python
tf_files = sorted(tf_path.glob("*.tf"))
```
- ディレクトリ**直下**の `.tf` ファイルのみ対象（サブディレクトリは非対応）。

**2パス処理:**

```python
# Pass 1: 変数のデフォルト値を収集
for f in tf_files:
    parsed = _load_hcl2(f)
    for block in parsed.get("variable", []):
        for raw_var_name, var_cfg in block.items():
            if isinstance(cfg, dict) and "default" in cfg:
                variables[var_name] = cfg["default"]
```
- 全ファイルから `variable` ブロックの `default` を先に収集する。
- Pass 2 で `var.xxx` を置換するための辞書を作る。

```python
# Pass 2: リソースブロックを収集
for f in tf_files:
    parsed = _load_hcl2(f)
    _merge_resources(parsed, resources)

resources = _resolve(resources, variables)
```
- 2回走査することで、変数定義が後ろのファイルにあっても正しく解決できる。

### `_flatten_config`

```python
def _flatten_config(cfg: Any) -> Dict:
    if isinstance(cfg, list):
        return cfg[0] if cfg and isinstance(cfg[0], dict) else {}
    return cfg if isinstance(cfg, dict) else {}
```
- python-hcl2 はリソース設定をリストで返すことがある。先頭要素（辞書）を取り出して平坦化。

### `_resolve`（変数参照の置換）

```python
_VAR_RE = re.compile(r'\$\{var\.([^}]+)\}|(?<!["\w])var\.(\w+)(?!["\w])')
```
- `${var.xxx}` 形式と `var.xxx` 形式の両方にマッチ。
- 前後の文字クラスで誤マッチを防ぐ。

```python
def _resolve(obj: Any, variables: Dict[str, Any]) -> Any:
    if isinstance(obj, str):
        obj = _unquote(obj)
        return _VAR_RE.sub(lambda m: str(variables.get(m.group(1) or m.group(2), m.group(0))), obj)
    if isinstance(obj, dict):
        return {k: _resolve(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(item, variables) for item in obj]
    return obj
```
- 辞書・リストを**再帰的に**走査して全ての `var.xxx` を実際の値で置換。
- 変数が未定義の場合は元の参照文字列（`var.xxx`）をそのまま残す。

---

## まとめ

| ファイル | 役割 |
|---|---|
| `main.py` | CLI 引数解析 → パース → 評価 → レポート出力の流れを制御 |
| `helpers.py` | HCL2 のネストブロックを安全に取得する3関数（`_block` / `_blocks` / `_int`） |
| `rule_loader.py` | `rules/rules.yml` を読み込み、DSL を解釈してチェック関数を生成 |
| `rules/rules.yml` | 188 ルールの定義（YAML、カテゴリ別キー構成）。ここを編集するだけでルールを追加・修正できる |
| `checks.py` | DSL で表現できない複雑なチェックロジック（約 60 関数） |
| `reference.py` | `TERRAFORM_RULES` / `SEVERITY_WEIGHTS` / ヘルパー3関数を re-export する薄いラッパー |
| `evaluator.py` | ルール適用・スコア計算・テキスト/HTML レポート生成 |
| `hcl_parser.py` | `.tf` ファイルを HCL2 でパースし、変数参照を解決して辞書で返す |
