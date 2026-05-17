"""
Terraform best-practice evaluator.
Applies rules from reference.py against parsed HCL configs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from reference import SEVERITY_WEIGHTS, TERRAFORM_RULES, _block, _int


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────

@dataclass
class Finding:
    rule_id: str
    severity: str
    resource_type: str
    resource_name: str
    description: str
    message: str
    recommendation: str


@dataclass
class EvaluationResult:
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    resources_checked: int = 0
    rules_checked: int = 0

    def add(self, finding: Finding):
        self.findings.append(finding)
        self.score = max(0, self.score - SEVERITY_WEIGHTS.get(finding.severity, 0))

    def by_severity(self, severity: str) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> Dict:
        return {
            "score": self.score,
            "resources_checked": self.resources_checked,
            "rules_checked": self.rules_checked,
            "findings_count": {
                sev: len(self.by_severity(sev)) for sev in SEVERITY_WEIGHTS
            },
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "resource_type": f.resource_type,
                    "resource_name": f.resource_name,
                    "description": f.description,
                    "message": f.message,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
        }


# ──────────────────────────────────────────────
# Static evaluator
# ──────────────────────────────────────────────

def evaluate_static(resources: Dict[str, Dict]) -> EvaluationResult:
    result = EvaluationResult()

    for rtype, instances in resources.items():
        rules = TERRAFORM_RULES.get(rtype, [])
        if not rules:
            continue
        for rname, config in instances.items():
            result.resources_checked += 1
            for rule in rules:
                result.rules_checked += 1
                try:
                    passed = rule["check"](config)
                except Exception:
                    passed = True  # if check crashes, skip rather than false-positive
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

    return result


# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def generate_report(result: EvaluationResult, resources: Dict[str, Dict], variables: Dict[str, Any]) -> str:
    lines = []

    lines.append("=" * 70)
    lines.append("  TERRAFORM BEST-PRACTICE EVALUATION REPORT")
    lines.append("=" * 70)
    lines.append(f"  Resources   : {result.resources_checked}")
    lines.append(f"  Rules run   : {result.rules_checked}")
    lines.append(f"  Score       : {result.score}/100  {_score_label(result.score)}")
    lines.append("")

    lines.append("  FINDINGS SUMMARY")
    lines.append("  " + "-" * 40)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = len(result.by_severity(sev))
        if cnt:
            lines.append(f"  {sev:<10} {cnt}")
    lines.append("")

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        findings = result.by_severity(sev)
        if not findings:
            continue
        lines.append(f"  [{sev}]")
        lines.append("  " + "-" * 40)
        for f in findings:
            lines.append(f"  {f.rule_id}  {f.resource_type}.{f.resource_name}")
            lines.append(f"    Problem : {f.message}")
            lines.append(f"    Fix     : {f.recommendation}")
            lines.append("")

    lines.append("  GOOD PRACTICES DETECTED")
    lines.append("  " + "-" * 40)
    good = _detect_good_practices(resources, variables)
    for item in good:
        lines.append(f"  [OK] {item}")
    lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def _score_label(score: int) -> str:
    if score >= 90:
        return "(EXCELLENT)"
    if score >= 75:
        return "(GOOD)"
    if score >= 60:
        return "(FAIR)"
    if score >= 40:
        return "(POOR)"
    return "(CRITICAL ISSUES)"


def _detect_good_practices(resources: Dict[str, Dict], variables: Dict) -> List[str]:
    """Detect good practices actually present in the parsed resource configs."""
    good = []

    flow_logs = resources.get("aws_flow_log", {})
    all_flow = [n for n, c in flow_logs.items() if c.get("traffic_type", "ALL") == "ALL"]
    if all_flow:
        good.append(f"VPC Flow Logs: ALL traffic captured ({len(all_flow)} log resource(s))")

    gd = resources.get("aws_guardduty_detector", {})
    gd_on = [c for c in gd.values() if c.get("enable", True) is not False]
    if gd_on:
        s3_on = any(_block(_block(c, "datasources"), "s3_logs").get("enable") is True for c in gd_on)
        suffix = " with S3 logs" if s3_on else ""
        good.append(f"GuardDuty detector enabled{suffix}")

    if resources.get("aws_securityhub_account"):
        good.append("Security Hub enabled")

    for name, cfg in resources.get("aws_cloudtrail", {}).items():
        parts = []
        if cfg.get("is_multi_region_trail") is True:
            parts.append("multi-region")
        if cfg.get("include_global_service_events", True) is not False:
            parts.append("global events")
        if cfg.get("enable_log_file_validation") is True:
            parts.append("log file validation")
        if cfg.get("cloud_watch_logs_group_arn"):
            parts.append("CloudWatch Logs delivery")
        if parts:
            good.append(f"CloudTrail ({name}): {', '.join(parts)}")

    instances = resources.get("aws_instance", {})
    if instances:
        if all(_block(c, "metadata_options").get("http_tokens") == "required"
               for c in instances.values()):
            good.append(
                f"EC2 IMDSv2 enforced on all {len(instances)} instance(s) (http_tokens = required)")

    if instances:
        if all(_block(c, "root_block_device").get("encrypted") is True
               for c in instances.values()):
            good.append(f"EBS root volumes encrypted on all {len(instances)} instance(s)")

    if instances:
        if all(not c.get("key_name") for c in instances.values()):
            good.append("EC2 instances: no key_name set (SSM Session Manager access implied)")

    dbs = resources.get("aws_db_instance", {})
    if dbs:
        if all(c.get("storage_encrypted") is True for c in dbs.values()):
            good.append(f"RDS storage encrypted on all {len(dbs)} DB instance(s)")

    if dbs:
        if all(c.get("deletion_protection") is True for c in dbs.values()):
            good.append(f"RDS deletion protection enabled on all {len(dbs)} DB instance(s)")

    if dbs:
        if all(_int(c, "backup_retention_period") >= 7 for c in dbs.values()):
            good.append(f"RDS backup retention >= 7 days on all {len(dbs)} DB instance(s)")

    if dbs:
        if all(not c.get("password") for c in dbs.values()):
            good.append("RDS: no plaintext password in config (Secrets Manager or managed password)")

    secrets = resources.get("aws_secretsmanager_secret", {})
    if secrets:
        good.append(f"Secrets Manager: {len(secrets)} secret(s) defined")

    pab = resources.get("aws_s3_bucket_public_access_block", {})
    if pab:
        if all(
            c.get("block_public_acls") is True and
            c.get("block_public_policy") is True and
            c.get("ignore_public_acls") is True and
            c.get("restrict_public_buckets") is True
            for c in pab.values()
        ):
            good.append(f"S3 public access block fully enabled on all {len(pab)} bucket(s)")

    endpoints = resources.get("aws_vpc_endpoint", {})
    if endpoints:
        svc_names = sorted({
            c.get("service_name", "").split(".")[-1]
            for c in endpoints.values()
            if c.get("service_name")
        })
        label = ", ".join(svc_names[:5]) if svc_names else f"{len(endpoints)}"
        good.append(f"VPC Endpoints defined: {label}")

    albs = resources.get("aws_lb", {})
    if albs:
        if all(_block(c, "access_logs").get("enabled") is True for c in albs.values()):
            good.append(f"ALB access logs enabled on all {len(albs)} load balancer(s)")

    if albs:
        if all(c.get("enable_deletion_protection") is True for c in albs.values()):
            good.append(f"ALB deletion protection enabled on all {len(albs)} load balancer(s)")

    dashboards = resources.get("aws_cloudwatch_dashboard", {})
    if dashboards:
        good.append(f"CloudWatch Dashboard configured: {', '.join(dashboards.keys())}")

    alarms = resources.get("aws_cloudwatch_metric_alarm", {})
    if alarms:
        with_actions = sum(1 for c in alarms.values()
                           if c.get("alarm_actions") or c.get("ok_actions"))
        good.append(f"CloudWatch Metric Alarms: {len(alarms)} defined ({with_actions} with actions)")

    kms_keys = resources.get("aws_kms_key", {})
    if kms_keys:
        if all(c.get("enable_key_rotation") is True for c in kms_keys.values()):
            good.append(f"KMS key rotation enabled on all {len(kms_keys)} key(s)")

    ecr = resources.get("aws_ecr_repository", {})
    if ecr:
        if all(_block(c, "image_scanning_configuration").get("scan_on_push") is True
               for c in ecr.values()):
            good.append(f"ECR scan on push enabled on all {len(ecr)} repository/ies")

    if resources.get("aws_launch_template") and not resources.get("aws_launch_configuration"):
        count = len(resources["aws_launch_template"])
        good.append(f"Launch templates used ({count}) — no deprecated aws_launch_configuration")

    eks = resources.get("aws_eks_cluster", {})
    if eks:
        if all(bool(c.get("enabled_cluster_log_types")) for c in eks.values()):
            good.append(f"EKS control plane logging enabled on all {len(eks)} cluster(s)")

    return good


# ──────────────────────────────────────────────
# HTML report generation
# ──────────────────────────────────────────────

def generate_html_report(result: EvaluationResult, resources: Dict[str, Dict],
                         variables: Dict[str, Any], tf_dir: str = "") -> str:
    import datetime
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

    sev_colors = {
        "CRITICAL": ("#b91c1c", "#fee2e2"),
        "HIGH":     ("#c2410c", "#ffedd5"),
        "MEDIUM":   ("#b45309", "#fef9c3"),
        "LOW":      ("#1d4ed8", "#dbeafe"),
        "INFO":     ("#374151", "#f3f4f6"),
    }
    score_color = (
        "#16a34a" if result.score >= 90 else
        "#2563eb" if result.score >= 75 else
        "#d97706" if result.score >= 60 else
        "#dc2626" if result.score >= 40 else
        "#7f1d1d"
    )
    score_label = _score_label(result.score).strip("()")

    counts = {sev: len(result.by_severity(sev)) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    total_findings = sum(counts.values())

    pct = result.score / 100
    r = 54
    cx, cy = 70, 70
    circumference = 2 * 3.14159 * r
    dash = pct * circumference
    gap = circumference - dash

    gauge_svg = f"""
    <svg viewBox="0 0 140 140" width="140" height="140">
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e5e7eb" stroke-width="12"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{score_color}" stroke-width="12"
        stroke-dasharray="{dash:.1f} {gap:.1f}"
        stroke-dashoffset="{circumference/4:.1f}"
        stroke-linecap="round" transform="rotate(-90 {cx} {cy})"/>
      <text x="{cx}" y="{cy+6}" text-anchor="middle" font-size="26" font-weight="bold" fill="{score_color}">{result.score}</text>
      <text x="{cx}" y="{cy+22}" text-anchor="middle" font-size="9" fill="#6b7280">{score_label}</text>
    </svg>"""

    card_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        fg, bg = sev_colors[sev]
        cnt = counts[sev]
        card_html += f"""
        <div class="card" style="background:{bg};border-left:4px solid {fg}">
          <div class="card-count" style="color:{fg}">{cnt}</div>
          <div class="card-label" style="color:{fg}">{sev}</div>
        </div>"""

    rows_html = ""
    if result.findings:
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
    else:
        rows_html = '<tr><td colspan="5" style="text-align:center;color:#6b7280;padding:2rem">No findings</td></tr>'

    good = _detect_good_practices(resources, variables)
    good_html = "".join(f'<li>&#x2705; {item}</li>' for item in good)

    pillar_counts: Dict[str, int] = {}
    try:
        from reference import TERRAFORM_RULES
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                p = rule.get("pillar", "OTHER")
                pillar_counts[p] = pillar_counts.get(p, 0) + 1
    except Exception:
        pass

    pillar_colors = {"SEC": "#dc2626", "REL": "#2563eb", "OPS": "#16a34a",
                     "PERF": "#d97706", "COST": "#7c3aed", "OTHER": "#6b7280"}
    pillar_html = ""
    if pillar_counts:
        max_val = max(pillar_counts.values())
        bar_w = 340
        bar_h = 22
        gap_y = 34
        svg_h = len(pillar_counts) * gap_y + 10
        bars = ""
        for i, (pillar, cnt) in enumerate(sorted(pillar_counts.items())):
            y = i * gap_y + 4
            w = int(cnt / max_val * bar_w)
            col = pillar_colors.get(pillar, "#6b7280")
            bars += f"""
            <text x="40" y="{y + bar_h - 5}" font-size="11" fill="#374151" text-anchor="end">{pillar}</text>
            <rect x="45" y="{y}" width="{w}" height="{bar_h}" rx="3" fill="{col}" opacity="0.8"/>
            <text x="{45 + w + 5}" y="{y + bar_h - 5}" font-size="11" fill="#374151">{cnt}</text>"""
        pillar_html = f"""
        <div class="section">
          <h2>WAF Pillar Coverage (total rules)</h2>
          <svg viewBox="0 0 420 {svg_h}" width="420" height="{svg_h}">{bars}</svg>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Terraform Evaluation Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: #f8fafc; color: #1e293b; font-size: 14px; }}
  .header {{ background: #1e293b; color: #f8fafc; padding: 24px 32px; }}
  .header h1 {{ font-size: 20px; font-weight: 700; letter-spacing: 0.02em; }}
  .header .meta {{ color: #94a3b8; font-size: 12px; margin-top: 4px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px 32px; }}
  .summary {{ display: flex; gap: 20px; align-items: center; margin-bottom: 24px;
              flex-wrap: wrap; }}
  .gauge {{ flex-shrink: 0; }}
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; }}
  .card {{ padding: 12px 20px; border-radius: 8px; min-width: 90px; text-align: center; }}
  .card-count {{ font-size: 28px; font-weight: 800; line-height: 1; }}
  .card-label {{ font-size: 11px; font-weight: 600; margin-top: 4px; letter-spacing: 0.05em; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
                gap: 8px; margin-bottom: 24px; }}
  .meta-item {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 6px;
                padding: 10px 14px; }}
  .meta-item .label {{ font-size: 11px; color: #64748b; text-transform: uppercase;
                       letter-spacing: 0.05em; }}
  .meta-item .value {{ font-size: 15px; font-weight: 600; margin-top: 2px; }}
  .section {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
              padding: 20px 24px; margin-bottom: 20px; }}
  .section h2 {{ font-size: 15px; font-weight: 700; margin-bottom: 14px;
                 color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 10px; background: #f1f5f9;
        font-size: 11px; font-weight: 700; text-transform: uppercase;
        letter-spacing: 0.04em; color: #475569; border-bottom: 2px solid #e2e8f0; }}
  td {{ padding: 9px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
  tr:hover td {{ background: #f8fafc; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 9999px;
            font-size: 11px; font-weight: 700; letter-spacing: 0.04em; }}
  code {{ font-family: "SFMono-Regular", Consolas, monospace; font-size: 12px;
          background: #f1f5f9; padding: 1px 4px; border-radius: 3px; }}
  ul.good {{ list-style: none; display: grid;
             grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 6px; }}
  ul.good li {{ padding: 6px 10px; background: #f0fdf4; border-radius: 6px;
                border-left: 3px solid #16a34a; font-size: 13px; color: #166534; }}
  .footer {{ text-align: center; color: #94a3b8; font-size: 11px; padding: 16px 0; }}
  @media print {{
    body {{ background: #fff; }}
    .container {{ padding: 12px; }}
  }}
</style>
</head>
<body>
<div class="header">
  <h1>Terraform AWS Best-Practice Evaluation Report</h1>
  <div class="meta">Generated: {now} &nbsp;|&nbsp; Directory: {tf_dir}</div>
</div>
<div class="container">

  <div class="summary">
    <div class="gauge">{gauge_svg}</div>
    <div class="cards">{card_html}</div>
  </div>

  <div class="meta-grid">
    <div class="meta-item">
      <div class="label">Resources Checked</div>
      <div class="value">{result.resources_checked}</div>
    </div>
    <div class="meta-item">
      <div class="label">Rules Executed</div>
      <div class="value">{result.rules_checked}</div>
    </div>
    <div class="meta-item">
      <div class="label">Total Findings</div>
      <div class="value">{total_findings}</div>
    </div>
  </div>

  <div class="section">
    <h2>Findings ({total_findings})</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule ID</th>
          <th>Resource</th>
          <th>Problem</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  {pillar_html}

  <div class="section">
    <h2>Good Practices Detected ({len(good)})</h2>
    <ul class="good">{good_html}</ul>
  </div>

</div>
<div class="footer">Terraform Evaluator &mdash; rule-based static analysis, no AI</div>
</body>
</html>"""

    return html
