# Terraform Evaluator — コード解説

対象ファイル: `main.py` / `evaluator.py` / `hcl_parser.py`

---

## main.py（エントリポイント）

```
1  """
2  Terraform AWS Best-Practice Evaluator
3  ...
8  """
```
- 1〜8行目: モジュールの docstring（説明文）。コマンドラインの使い方が記載されている。

```
10  import argparse
```
- コマンドライン引数 (`--dir`, `--live` など) を解析するための標準ライブラリをインポート。

```
11  import json
```
- JSON ファイルへの書き出しに使う標準ライブラリをインポート。

```
12  import sys
```
- `sys.exit()` や `sys.stdout.buffer` など OS レベルの操作に使う標準ライブラリをインポート。

```
13  from pathlib import Path
```
- ファイルパスをオブジェクトとして扱う標準ライブラリをインポート（文字列連結より安全）。

```
16  sys.path.insert(0, str(Path(__file__).parent))
```
- このスクリプトのあるディレクトリをモジュール検索パスの先頭に挿入。  
  同じフォルダにある `hcl_parser.py` / `evaluator.py` を `import` できるようにする。

```
18  from hcl_parser import parse_tf_directory
```
- `.tf` ファイルを解析する関数を `hcl_parser.py` からインポート。

```
19  from evaluator import evaluate_static, compare_live, generate_report, generate_html_report
```
- ルール評価・レポート生成の関数を `evaluator.py` からインポート。

```
22  def main():
```
- プログラムのメイン処理を定義する関数。

```
23      parser = argparse.ArgumentParser(
24          description="Evaluate Terraform configurations against AWS best practices."
25      )
```
- `ArgumentParser` オブジェクトを作成。`--help` 表示時の説明文を設定。

```
26      parser.add_argument(
27          "--dir",
28          default="../terraform",
29          help="Path to the Terraform directory (default: ../terraform)",
30      )
```
- `--dir` 引数を定義。省略時のデフォルトは `../terraform`。

```
31      parser.add_argument(
32          "--live",
33          action="store_true",
34          help="Also compare against live AWS state via boto3",
35      )
```
- `--live` フラグを定義。指定すると `True` になるブール型の引数。実際のAWSと比較する。

```
36      parser.add_argument(
37          "--region",
38          default="ap-northeast-1",
39          ...
40      )
```
- `--region` 引数。AWS リージョン指定。デフォルトは東京リージョン。

```
41      parser.add_argument(
42          "--profile",
43          default=None,
44          ...
45      )
```
- `--profile` 引数。AWS CLI プロファイル名。省略時は環境変数の認証情報を使用。

```
46      parser.add_argument(
47          "--output",
48          default=None,
49          ...
50      )
```
- `--output` 引数。結果を保存する JSON ファイルパス。省略時は保存しない。

```
51      parser.add_argument(
52          "--min-severity",
53          choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
54          default="LOW",
55          ...
56      )
```
- `--min-severity` 引数。表示する最低重要度を指定。デフォルトは LOW（ほぼ全件表示）。

```
57      parser.add_argument(
58          "--output-html",
59          default=None,
60          metavar="FILE",
61          ...
62      )
```
- `--output-html` 引数。HTMLレポートを保存するファイルパス。省略時は生成しない。

```
63      args = parser.parse_args()
```
- コマンドライン引数を解析し、`args` オブジェクトに格納。

```
65      tf_dir = str(Path(args.dir).resolve())
```
- 指定ディレクトリを絶対パスに変換（相対パスでも確実に動くようにする）。

```
66      print(f"\nEvaluating: {tf_dir}")
67      print("-" * 50)
```
- 処理開始のメッセージと区切り線を表示。

```
70      print("Parsing Terraform files...")
71      try:
72          resources, variables = parse_tf_directory(tf_dir)
73      except (FileNotFoundError, ValueError) as exc:
74          print(f"ERROR: {exc}")
75          sys.exit(1)
```
- `.tf` ファイルを解析。ディレクトリが存在しない or `.tf` ファイルが無い場合はエラーで終了（終了コード1）。

```
77      resource_summary = {rtype: len(inst) for rtype, inst in resources.items()}
```
- リソースの種類ごとに件数を集計した辞書を作成（例: `{"aws_instance": 2}`）。

```
78      print(f"  Resource types found: {len(resource_summary)}")
79      for rtype, count in sorted(resource_summary.items()):
80          print(f"    {rtype}: {count}")
81      print()
```
- 見つかったリソース種別と件数をアルファベット順に表示。

```
84      print("Running static rule checks...")
85      result = evaluate_static(resources)
86      print(f"  Static findings: {len(result.findings)}")
```
- 静的ルールチェックを実行。`EvaluationResult` オブジェクトが返る。

```
90      if args.live:
91          print(f"Connecting to AWS ({args.region})...")
92          compare_live(result, resources, region=args.region, profile=args.profile)
93          print()
```
- `--live` フラグが指定された場合のみ、boto3 経由で実際の AWS と比較。

```
96      severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
97      min_idx = severity_order.index(args.min_severity)
98      result.findings = [
99          f for f in result.findings
100         if severity_order.index(f.severity) <= min_idx
101     ]
```
- `--min-severity` 以上の重大度の findings のみに絞り込む。  
  インデックスが小さいほど重大度が高い（CRITICAL=0, INFO=4）。

```
104     report_text = generate_report(result, resources, variables)
105     sys.stdout.buffer.write((report_text + "\n").encode("utf-8", errors="replace"))
106     sys.stdout.buffer.flush()
```
- テキストレポートを生成し、UTF-8 バイト列として標準出力に書き出す。  
  `resources` を渡すことで `_detect_good_practices` が実際の .tf 内容を参照できる。  
  `buffer.write` を使うことで Windows での文字化けを防ぐ。

```
109     if args.output:
110         output_path = Path(args.output)
111         with open(output_path, "w", encoding="utf-8") as fh:
112             json.dump(result.to_dict(), fh, ensure_ascii=False, indent=2)
113         print(f"JSON report saved to: {output_path.resolve()}")
```
- `--output` が指定されていれば、結果を JSON ファイルに保存（日本語もそのまま出力）。

```
116     if args.output_html:
117         html_path = Path(args.output_html)
118         html_content = generate_html_report(result, resources, variables, tf_dir=tf_dir)
119         with open(html_path, "w", encoding="utf-8") as fh:
120             fh.write(html_content)
121         print(f"HTML report saved to: {html_path.resolve()}")
```
- `--output-html` が指定されていれば、HTML レポートを生成して保存。  
  `resources` を渡すことで Good Practices セクションも実際の設定に基づいて描画される。

```
124     critical_high = len(result.by_severity("CRITICAL")) + len(result.by_severity("HIGH"))
125     sys.exit(1 if critical_high > 0 else 0)
```
- CRITICAL か HIGH の findings があれば終了コード1（CI でのエラー検知に使える）。問題なければ0。

```
128  if __name__ == "__main__":
129      main()
```
- スクリプトとして直接実行された場合のみ `main()` を呼ぶ（import 時は呼ばない）。

---

## evaluator.py（評価ロジック）

```
1  """
2  Terraform best-practice evaluator.
3  ...
4  """
```
- モジュールの docstring。静的評価と boto3 によるライブ比較を行うと説明。

```
6  from __future__ import annotations
```
- 型ヒントで前方参照（まだ定義していないクラス名）を文字列なしで書けるようにする。Python 3.10 未満向け互換。

```
8  import json
```
- JSON 変換に使用（`to_dict` の結果をシリアライズするため）。

```
9  from dataclasses import dataclass, field
```
- `@dataclass` デコレータと `field()` をインポート。ボイラープレートを減らしてデータクラスを定義できる。

```
10  from typing import Any, Dict, List, Optional
```
- 型ヒント用の型をインポート。

```
12  from reference import SEVERITY_WEIGHTS, TERRAFORM_RULES, _block, _blocks, _int
```
- `reference.py` から重要度の重み辞書、ルール定義、および `_detect_good_practices` 内で使うヘルパー関数をインポート。

---

### データモデル

```
19  @dataclass
20  class Finding:
21      rule_id: str        # ルールID（例: "EC2-001"）
22      severity: str       # 重要度（"CRITICAL"/"HIGH"/"MEDIUM"/"LOW"/"INFO"）
23      resource_type: str  # リソース種別（例: "aws_instance"）
24      resource_name: str  # リソース名（Terraform 上の名前）
25      description: str    # 問題の説明
26      message: str        # 具体的なメッセージ
27      recommendation: str # 推奨対処法
28      source: str = "static"  # 発生源: "static"（静的解析）or "live"（AWS実機）
```
- 1件の評価結果（問題）を表すデータクラス。

```
32  @dataclass
33  class EvaluationResult:
34      findings: List[Finding] = field(default_factory=list)  # 全 Finding のリスト
35      score: int = 100           # 初期スコア 100 点（問題が見つかるたびに減点）
36      resources_checked: int = 0 # チェックしたリソース数
37      rules_checked: int = 0     # 実行したルール数
38      live_check_enabled: bool = False  # ライブチェックを行ったか
39      aws_region: str = "ap-northeast-1"  # 対象 AWS リージョン
```
- 評価全体の結果をまとめるデータクラス。

```
40      def add(self, finding: Finding):
41          self.findings.append(finding)
42          self.score = max(0, self.score - SEVERITY_WEIGHTS.get(finding.severity, 0))
```
- `Finding` を追加しつつ、重要度に応じたスコアを減点。スコアは0未満にならない。

```
44      def by_severity(self, severity: str) -> List[Finding]:
45          return [f for f in self.findings if f.severity == severity]
```
- 指定した重要度の Finding だけをリストで返すフィルタメソッド。

```
47      def to_dict(self) -> Dict:
48          return {
49              "score": self.score,
50              ...
69          }
```
- JSON 出力用に `EvaluationResult` を辞書形式に変換するメソッド。

---

### 静的評価

```
76  def evaluate_static(resources: Dict[str, Dict]) -> EvaluationResult:
77      result = EvaluationResult()
```
- 静的評価関数。空の `EvaluationResult` を作成して結果を蓄積していく。

```
79      for rtype, instances in resources.items():
80          rules = TERRAFORM_RULES.get(rtype, [])
81          if not rules:
82              continue
```
- リソース種別ごとにループ。そのリソース種別に対応するルールがなければスキップ。

```
83          for rname, config in instances.items():
84              result.resources_checked += 1
85              for rule in rules:
86                  result.rules_checked += 1
```
- リソース名とその設定ごとにループ。チェックカウンタをインクリメント。

```
87                  try:
88                      passed = rule["check"](config)
89                  except Exception:
90                      passed = True  # チェック自体がクラッシュした場合は false-positive を避ける
```
- ルールのチェック関数を呼び出す。例外が発生しても偽陽性を出さないよう `passed=True` で続行。

```
91                  if not passed:
92                      result.add(Finding(...))
```
- チェックが失敗（`passed=False`）した場合に `Finding` を作成して結果に追加。

---

### ライブ AWS 比較

```
110  def compare_live(result, resources, region, profile=None) -> None:
```
- boto3 でライブの AWS 状態を取得し、差分・コンプライアンス違反を result に追記する関数。

```
116      try:
117          import boto3
118      except ImportError:
119          print("  [WARNING] boto3 not installed — skipping live AWS check.")
120          return
```
- boto3 が未インストールの場合は警告を出してスキップ（オプション依存なので即終了しない）。

```
123      session_kwargs: Dict[str, Any] = {"region_name": region}
124      if profile:
125          session_kwargs["profile_name"] = profile
```
- boto3 セッションの引数を構築。プロファイルが指定された場合のみ追加。

```
127      try:
128          session = boto3.Session(**session_kwargs)
129          sts = session.client("sts")
130          identity = sts.get_caller_identity()
131          print(f"  AWS account: {identity['Account']}  region: {region}")
```
- STS で `GetCallerIdentity` を呼び認証情報の確認（接続テスト）。アカウントIDも表示。

```
133      except Exception as exc:
134          print(f"  [WARNING] AWS credentials error — skipping live check: {exc}")
135          return
```
- 認証エラーの場合は警告してスキップ（例外で終了しない）。

```
140      _check_ec2_live(session, result, resources)
141      _check_rds_live(session, result, resources)
142      _check_alb_live(session, result, resources)
143      _check_sg_live(session, result, resources)
144      _check_cloudtrail_live(session, result)
145      _check_guardduty_live(session, result)
146      _check_s3_live(session, result, resources)
```
- サービスごとのライブチェック関数を順番に呼び出す。

---

### EC2 ライブチェック (`_check_ec2_live`)

```
154          resp = ec2.describe_instances(
155              Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
156          )
```
- running / stopped 状態の EC2 インスタンス一覧を取得。

```
157          live_instances = {
158              i["InstanceId"]: i
159              for r in resp["Reservations"]
160              for i in r["Instances"]
161          }
```
- InstanceId をキーにした辞書に変換（二重ループをdict内包表記で記述）。

```
166          for _name, _cfg in tf_instances.items():
167              matched = next(
168                  (inst for inst in live_instances.values()
169                   if any(t["Key"] == "Name" and _name in t.get("Value", "")
170                          for t in inst.get("Tags", []))),
171                  None,
172              )
```
- Terraform のリソース名と AWS のNameタグを照合してインスタンスを特定する。

```
178              md_opts = matched.get("MetadataOptions", {})
179              if md_opts.get("HttpTokens") != "required":
180                  result.add(Finding(rule_id="EC2-001-LIVE", severity="HIGH", ...))
```
- IMDSv2（HttpTokens=required）が強制されていなければ HIGH 問題として記録。

```
192              if matched.get("Monitoring", {}).get("State") != "enabled":
193                  result.add(Finding(rule_id="EC2-003-LIVE", severity="MEDIUM", ...))
```
- 詳細モニタリングが無効なら MEDIUM 問題として記録。

---

### RDS ライブチェック (`_check_rds_live`)

```
211          resp = rds.describe_db_instances()
212          live_dbs = {db["DBInstanceIdentifier"]: db for db in resp["DBInstances"]}
```
- RDS インスタンス一覧を取得し、DB識別子をキーの辞書に変換。

```
223          checks = [
224              ("MultiAZ", "RDS-001-LIVE", "HIGH", "Multi-AZ"),
225              ("DeletionProtection", "RDS-002-LIVE", "HIGH", "Deletion protection"),
226          ]
227          for attr, rule_id, sev, label in checks:
228              if not live.get(attr):
229                  result.add(Finding(...))
```
- MultiAZ と削除保護を一括チェック。リスト化することでコード重複を避けている。

```
240          if live.get("MonitoringInterval", 0) == 0:
```
- Enhanced Monitoring が無効（interval=0）なら MEDIUM 問題として記録。

```
252          if not live.get("PerformanceInsightsEnabled"):
```
- Performance Insights が無効なら MEDIUM 問題として記録。

---

### ALB ライブチェック (`_check_alb_live`)

```
272          resp = elb.describe_load_balancers()
273          live_albs = {lb["LoadBalancerName"]: lb for lb in resp["LoadBalancers"]}
```
- ALB 一覧を取得し、名前をキーの辞書に変換。

```
285          lb_arn = live["LoadBalancerArn"]
286          attrs_resp = elb.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
287          attrs = {a["Key"]: a["Value"] for a in attrs_resp["Attributes"]}
```
- ARN を使って ALB の詳細属性を取得し、Key→Value の辞書に変換。

```
289          if attrs.get("deletion_protection.enabled") != "true":
290              result.add(Finding(rule_id="ALB-001-LIVE", severity="MEDIUM", ...))
```
- 削除保護が無効なら MEDIUM 問題として記録。

```
302          listeners_resp = elb.describe_listeners(LoadBalancerArn=lb_arn)
303          protocols = {ln["Protocol"] for ln in listeners_resp["Listeners"]}
304          if "HTTPS" not in protocols:
305              result.add(Finding(rule_id="ALB-004-LIVE", severity="HIGH", ...))
```
- リスナーのプロトコル一覧を set で取得。HTTPS がなければ HIGH 問題として記録。

---

### SG ライブチェック (`_check_sg_live`)

```
329          sensitive_ports = {22, 3306, 5432, 1433, 27017, 6379}
```
- 危険ポートの集合: SSH(22), MySQL(3306), PostgreSQL(5432), MSSQL(1433), MongoDB(27017), Redis(6379)。

```
336          for perm in live.get("IpPermissions", []):
337              cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
338              from_port = perm.get("FromPort", 0)
339              to_port = perm.get("ToPort", 65535)
340              if "0.0.0.0/0" in cidrs:
341                  for port in sensitive_ports:
342                      if from_port <= port <= to_port:
343                          result.add(Finding(rule_id="SG-001-LIVE", severity="CRITICAL", ...))
```
- インバウンドルールを検査。`0.0.0.0/0`（全開放）かつ危険ポートが範囲内ならCRITICAL問題。

---

### CloudTrail ライブチェック (`_check_cloudtrail_live`)

```
361          resp = ct.describe_trails(includeShadowTrails=False)
```
- このリージョンで管理しているトレールのみ取得（`includeShadowTrails=False`）。

```
366          if not trail.get("LogFileValidationEnabled"):
367              result.add(Finding(rule_id="CT-002-LIVE", severity="HIGH", ...))
```
- ログファイル検証（改ざん検知）が無効なら HIGH 問題として記録。

```
377          if not trail.get("KMSKeyId"):
378              result.add(Finding(rule_id="CT-003-LIVE", severity="MEDIUM", ...))
```
- KMS 暗号化が設定されていなければ MEDIUM 問題として記録。

---

### GuardDuty ライブチェック (`_check_guardduty_live`)

```
396          detector_ids = gd.list_detectors().get("DetectorIds", [])
397          print(f"  GuardDuty: {len(detector_ids)} detector(s)")
```
- このリージョンの GuardDuty 検出器一覧を取得。

```
399          if not detector_ids:
400              result.add(Finding(rule_id="GD-001-LIVE", severity="HIGH", ...))
```
- 検出器が1つも無ければ HIGH 問題（GuardDuty が有効化されていない）として記録。

---

### S3 ライブチェック (`_check_s3_live`)

```
418          resp = s3.list_buckets()
419          live_buckets = {b["Name"] for b in resp.get("Buckets", [])}
```
- S3 バケット一覧を取得し、バケット名の set に変換（高速検索用）。

```
431              pab = s3.get_public_access_block(Bucket=bucket_name)
432              cfg = pab["PublicAccessBlockConfiguration"]
433              if not all([
434                  cfg.get("BlockPublicAcls"),
435                  cfg.get("BlockPublicPolicy"),
436                  cfg.get("IgnorePublicAcls"),
437                  cfg.get("RestrictPublicBuckets"),
438              ]):
439                  result.add(Finding(rule_id="S3-PAB-LIVE", severity="CRITICAL", ...))
```
- パブリックアクセスブロックの4設定が全て有効でなければ CRITICAL 問題として記録。

```
449          except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
450              result.add(Finding(rule_id="S3-PAB-LIVE", severity="CRITICAL", ...))
```
- パブリックアクセスブロック設定自体が存在しない場合も CRITICAL 問題として記録。

---

### レポート生成 (`generate_report`)

```
472      lines = []
```
- 出力行を蓄積するリスト。最後に `"\n".join(lines)` で1つの文字列にする。

```
475      lines.append("=" * 70)
...
483      lines.append(f"  Score : {result.score}/100  {_score_label(result.score)}")
```
- ヘッダー情報（リージョン、ライブチェック有無、スコア）を追記。

```
488      for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
489          cnt = len(result.by_severity(sev))
490          if cnt:
491              lines.append(f"  {sev:<10} {cnt}")
```
- 重要度ごとの件数サマリー。件数が0の重要度は表示しない。

```
495      for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
496          findings = result.by_severity(sev)
```
- 重要度の高い順に全ての Finding を一覧表示。

```
502          tag = "[LIVE]" if f.source == "live" else "[STATIC]"
503          lines.append(f"  {tag} {f.rule_id}  {f.resource_type}.{f.resource_name}")
504          lines.append(f"    Problem : {f.message}")
505          lines.append(f"    Fix     : {f.recommendation}")
```
- 各 Finding をソース（LIVE/STATIC）、ルールID、リソース名、問題内容、推奨対処で表示。

```
511      good = _detect_good_practices(resources, variables)
```
- ベストプラクティスが適用済みの項目リストを取得。  
  `resources` 辞書を実際に参照し、GuardDuty / CloudTrail / EC2 IMDSv2 / RDS 暗号化など  
  各リソースの設定値を確認した結果のみ `[OK]` として表示する（ハードコードではない）。

---

### スコアラベル (`_score_label`)

```
520  def _score_label(score: int) -> str:
521      if score >= 90: return "(EXCELLENT)"
522      if score >= 75: return "(GOOD)"
523      if score >= 60: return "(FAIR)"
524      if score >= 40: return "(POOR)"
525      return "(CRITICAL ISSUES)"
```
- スコアを5段階のラベルに変換する関数。

---

### HTML レポート生成 (`generate_html_report`)

```
562      now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
```
- 現在時刻を文字列として取得（レポートの生成日時として使用）。

```
564      sev_colors = {
565          "CRITICAL": ("#b91c1c", "#fee2e2"),   # 前景色, 背景色
566          ...
570      }
```
- 重要度ごとの HTML カラーコード（前景・背景）の辞書。

```
571      score_color = (
572          "#16a34a" if result.score >= 90 else   # 緑
573          "#2563eb" if result.score >= 75 else   # 青
574          "#d97706" if result.score >= 60 else   # 黄
575          "#dc2626" if result.score >= 40 else   # 赤
576          "#7f1d1d"                              # 暗赤
577      )
```
- スコアに応じてゲージの色を変える（高いほど緑に近い）。

```
584      pct = result.score / 100
585      r = 54
586      cx, cy = 70, 70
587      circumference = 2 * 3.14159 * r
588      dash = pct * circumference
589      gap = circumference - dash
```
- SVG で円形ゲージを描くための計算。`dash` が塗りつぶし長さ、`gap` が空白長さ。

```
591      gauge_svg = f"""
592          <svg viewBox="0 0 140 140" ...>
```
- インライン SVG として円グラフ風スコアゲージを生成。

```
603      card_html = ""
604      for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
605          fg, bg = sev_colors[sev]
606          cnt = counts[sev]
607          card_html += f"""<div class="card" ...>{cnt}...{sev}</div>"""
```
- 重要度ごとの件数を表示するカードHTMLを生成。

```
615      for f in result.findings:
616          fg, bg = sev_colors.get(f.severity, ...)
617          tag = "LIVE" if f.source == "live" else "STATIC"
618          rows_html += f"""<tr><td>...</td>...</tr>"""
```
- Finding 1件ごとにテーブル行HTMLを生成。LIVE発見は紫色でハイライト。

```
637          pillar_counts: Dict[str, int] = {}
638      try:
639          from reference import TERRAFORM_RULES
640          for rtype, rules in TERRAFORM_RULES.items():
641              for rule in rules:
642                  p = rule.get("pillar", "OTHER")
643                  pillar_counts[p] = pillar_counts.get(p, 0) + 1
```
- AWS Well-Architected Framework の柱（Security, Reliability 等）ごとのルール数を集計。

```
657          for i, (pillar, cnt) in enumerate(sorted(pillar_counts.items())):
658              w = int(cnt / max_val * bar_w)
659              bars += f"""<rect x="45" y="{y}" width="{w}" .../>"""
```
- 柱ごとの棒グラフを SVG の `<rect>` タグで描画。最大値を基準に幅を正規化。

```
671      html = f"""<!DOCTYPE html>
672      <html lang="ja">
```
- HTML 全体を f-string で構築してまとめて返す。

---

## hcl_parser.py（HCL パーサー）

```
1  """
2  HCL2 parser for Terraform .tf files.
3  ...
5  Requires: python-hcl2>=4.3.0
6  """
```
- モジュールの docstring。`python-hcl2` ライブラリが必要だと記載。

```
7  import re
```
- 正規表現モジュール。`var.xxx` の参照を解決するために使用。

```
8  import sys
```
- `sys.exit(1)` で hcl2 未インストール時に終了するために使用。

```
9  from pathlib import Path
```
- `*.tf` ファイルを glob で列挙するためのパスオブジェクト。

```
10  from typing import Any, Dict, Tuple
```
- 型ヒント用。`Tuple[Dict, Dict]` で2つの辞書を返す型を表現。

```
12  try:
13      import hcl2
14  except ImportError:
15      print("ERROR: python-hcl2 is required but not installed.")
16      print("       Run: pip install python-hcl2")
17      sys.exit(1)
```
- `hcl2` が未インストールの場合はインストール方法を案内して即終了（モジュールレベルで実行）。

---

### メイン関数 (`parse_tf_directory`)

```
20  def parse_tf_directory(terraform_dir: str) -> Tuple[Dict[str, Dict], Dict[str, Any]]:
```
- Terraformディレクトリを受け取り、`(resources, variables)` のタプルを返す関数。

```
28      tf_path = Path(terraform_dir)
29      if not tf_path.exists():
30          raise FileNotFoundError(f"Directory not found: {terraform_dir}")
```
- 指定ディレクトリが存在しなければ `FileNotFoundError` を raise。

```
32      tf_files = sorted(tf_path.glob("*.tf"))
33      if not tf_files:
34          raise ValueError(f"No .tf files found in {terraform_dir}")
```
- ディレクトリ直下の `.tf` ファイルを名前順で列挙。1ファイルもなければ `ValueError`。

```
36      variables: Dict[str, Any] = {}
37      resources: Dict[str, Dict] = {}
```
- 変数定義と リソース定義を格納する辞書を初期化。

```
39      # Pass 1 – collect variable defaults from all files
40      for f in tf_files:
41          try:
42              parsed = _load_hcl2(f)
43              for block in parsed.get("variable", []):
44                  for raw_var_name, var_cfg in block.items():
45                      var_name = _strip_q(raw_var_name)
46                      cfg = var_cfg[0] if isinstance(var_cfg, list) and var_cfg else var_cfg
47                      if isinstance(cfg, dict) and "default" in cfg:
48                          variables[var_name] = cfg["default"]
```
- **1パス目**: 全 `.tf` ファイルから `variable` ブロックを収集し、`default` 値を辞書に格納。  
  `var_cfg` がリストの場合は先頭要素を取る（python-hcl2 の仕様）。

```
49      except Exception as exc:
50          print(f"  [WARNING] variables pass – skipping {f.name}: {exc}")
```
- パースに失敗したファイルは警告を出してスキップ（1ファイル壊れていても処理継続）。

```
52      # Pass 2 – collect resource blocks from all files
53      for f in tf_files:
54          try:
55              parsed = _load_hcl2(f)
56              _merge_resources(parsed, resources)
```
- **2パス目**: 全ファイルから `resource` ブロックを収集して `resources` に統合。

```
61      resources = _resolve(resources, variables)
62      return resources, variables
```
- 収集した変数定義を使って `var.xxx` 参照を実際の値に置換してから返す。

---

### ローダー (`_load_hcl2`)

```
69  def _load_hcl2(path: Path) -> Dict:
70      with open(path, "r", encoding="utf-8") as fh:
71          return hcl2.load(fh)
```
- ファイルを UTF-8 で開き、`hcl2.load()` に渡してパース。Python 辞書を返す。

---

### リソースマージ関連

```
78  def _strip_q(s: str) -> str:
79      """Remove surrounding HCL label quotes that python-hcl2 may preserve."""
80      return s.strip('"').strip("'")
```
- python-hcl2 がキー名に引用符を残す場合があるため、前後の `"` や `'` を除去する。

```
83  def _merge_resources(parsed: Dict, resources: Dict) -> None:
84      for block in parsed.get("resource", []):
85          for raw_rtype, instances in block.items():
86              rtype = _strip_q(raw_rtype)
87              if rtype not in resources:
88                  resources[rtype] = {}
```
- `resource` ブロックを取り出し、リソース種別ごとに辞書を初期化。

```
89              if isinstance(instances, dict):
90                  for raw_name, cfg in instances.items():
91                      name = _strip_q(raw_name)
92                      resources[rtype][name] = _flatten_config(cfg)
```
- インスタンスが辞書形式の場合（hcl2 の出力パターン1）: 名前→設定に変換して格納。

```
93              elif isinstance(instances, list):
94                  for item in instances:
95                      if isinstance(item, dict):
96                          for raw_name, cfg in item.items():
97                              name = _strip_q(raw_name)
98                              resources[rtype][name] = _flatten_config(cfg)
```
- インスタンスがリスト形式の場合（hcl2 の出力パターン2）: ループで同様に処理。  
  python-hcl2 のバージョンによって辞書とリストで挙動が変わるため両方に対応。

```
101  def _flatten_config(cfg: Any) -> Dict:
102      if isinstance(cfg, list):
103          return cfg[0] if cfg and isinstance(cfg[0], dict) else {}
104      return cfg if isinstance(cfg, dict) else {}
```
- 設定値がリスト（`[{...}]` 形式）の場合は先頭辞書を返す。辞書以外は空辞書を返す。

---

### 変数参照の解決

```
111  _VAR_RE = re.compile(r'\$\{var\.([^}]+)\}|(?<!["\w])var\.(\w+)(?!["\w])')
```
- `var.xxx` 参照にマッチする正規表現。  
  - `${var.xxx}` 形式（HCL 補間構文）  
  - `var.xxx` 形式（単純参照）  
  の両方にマッチ。前後の文字で誤マッチを防ぐ後読み/先読みアサション付き。

```
114  def _unquote(s: str) -> str:
115      """
116      python-hcl2 がたまに文字列に外側の HCL引用符を残す場合がある
117      例: '"required"' -> 'required'
118      """
119      if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
120          inner = s[1:-1]
121          if '"' not in inner:
122              return inner
123      return s
```
- 外側に `"` が付いた単純なリテラル文字列だけを剥がす。内部に `"` がある場合は剥がさない（JSON 文字列等を破壊しないため）。

```
127  def _resolve(obj: Any, variables: Dict[str, Any]) -> Any:
128      if isinstance(obj, str):
129          obj = _unquote(obj)
130          def _replace(m):
131              vname = m.group(1) or m.group(2)
132              return str(variables.get(vname, m.group(0)))
133          return _VAR_RE.sub(_replace, obj)
```
- 文字列の場合: まず `_unquote` して、次に `var.xxx` を変数デフォルト値で置換。  
  変数が定義されていない場合は元の参照文字列のまま残す。

```
134      if isinstance(obj, dict):
135          return {k: _resolve(v, variables) for k, v in obj.items()}
136      if isinstance(obj, list):
137          return [_resolve(item, variables) for item in obj]
138      return obj
```
- 辞書・リストに対してはすべての値に再帰的に `_resolve` を適用。  
  それ以外の型（int, bool, None 等）はそのまま返す。

---

## まとめ

| ファイル | 役割 |
|---|---|
| `main.py` | CLI エントリポイント。引数解析 → パース → 評価 → レポート出力の流れを制御 |
| `evaluator.py` | ルール評価エンジン。静的チェックと boto3 を使ったライブチェック、レポート生成を担当 |
| `hcl_parser.py` | Terraform `.tf` ファイルの HCL 構文を解析し、リソース設定と変数定義を辞書で返す |
| `reference.py` | ルール辞書（72 リソースタイプ・188 ルール）。各ルールの check / message / recommendation を定義 |
