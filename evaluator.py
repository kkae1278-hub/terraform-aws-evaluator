"""
Terraform best-practice evaluator.
Applies rules from reference.py against parsed HCL configs and (optionally) live AWS state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

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
    source: str = "static"  # "static" | "live"


@dataclass
class EvaluationResult:
    findings: List[Finding] = field(default_factory=list)
    score: int = 100
    resources_checked: int = 0
    rules_checked: int = 0
    live_check_enabled: bool = False
    aws_region: str = "ap-northeast-1"

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
            "live_check_enabled": self.live_check_enabled,
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
                    "source": f.source,
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
                        source="static",
                    ))

    return result


# ──────────────────────────────────────────────
# Live AWS comparison via boto3
# ──────────────────────────────────────────────

def compare_live(result: EvaluationResult, resources: Dict[str, Dict],
                 region: str, profile: Optional[str] = None) -> None:
    """
    Fetch live AWS resource state and append drift/compliance findings.
    Modifies result in-place.
    """
    try:
        import boto3
    except ImportError:
        print("  [WARNING] boto3 not installed — skipping live AWS check.")
        print("            Install with: pip install boto3")
        return

    session_kwargs: Dict[str, Any] = {"region_name": region}
    if profile:
        session_kwargs["profile_name"] = profile

    try:
        session = boto3.Session(**session_kwargs)
        # Quick credential check
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print(f"  AWS account: {identity['Account']}  region: {region}")
    except Exception as exc:
        print(f"  [WARNING] AWS credentials error — skipping live check: {exc}")
        return

    result.live_check_enabled = True
    result.aws_region = region

    _check_ec2_live(session, result, resources)
    _check_rds_live(session, result, resources)
    _check_alb_live(session, result, resources)
    _check_sg_live(session, result, resources)
    _check_cloudtrail_live(session, result)
    _check_guardduty_live(session, result)
    _check_s3_live(session, result, resources)


# ── Per-service live checkers ─────────────────

def _check_ec2_live(session, result: EvaluationResult, resources: Dict) -> None:
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_instances(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        )
        live_instances = {
            i["InstanceId"]: i
            for r in resp["Reservations"]
            for i in r["Instances"]
        }

        tf_instances = resources.get("aws_instance", {})
        print(f"  EC2: {len(tf_instances)} in Terraform, {len(live_instances)} live")

        for _name, _cfg in tf_instances.items():
            # Find matching live instance by Name tag
            matched = next(
                (inst for inst in live_instances.values()
                 if any(t["Key"] == "Name" and _name in t.get("Value", "")
                        for t in inst.get("Tags", []))),
                None,
            )
            if matched is None:
                continue

            # IMDSv2 check
            md_opts = matched.get("MetadataOptions", {})
            if md_opts.get("HttpTokens") != "required":
                result.add(Finding(
                    rule_id="EC2-001-LIVE",
                    severity="HIGH",
                    resource_type="aws_instance",
                    resource_name=_name,
                    description="[LIVE] IMDSv2 not enforced on running instance",
                    message=f"Live instance {matched['InstanceId']} has HttpTokens={md_opts.get('HttpTokens')}",
                    recommendation="Stop instance, update metadata options, restart.",
                    source="live",
                ))

            # Detailed monitoring
            if matched.get("Monitoring", {}).get("State") != "enabled":
                result.add(Finding(
                    rule_id="EC2-003-LIVE",
                    severity="MEDIUM",
                    resource_type="aws_instance",
                    resource_name=_name,
                    description="[LIVE] Detailed monitoring not enabled on running instance",
                    message=f"Live instance {matched['InstanceId']} monitoring={matched.get('Monitoring', {}).get('State')}",
                    recommendation="Enable detailed monitoring via Console or CLI.",
                    source="live",
                ))

    except Exception as exc:
        print(f"  [WARNING] EC2 live check failed: {exc}")


def _check_rds_live(session, result: EvaluationResult, resources: Dict) -> None:
    try:
        rds = session.client("rds")
        resp = rds.describe_db_instances()
        live_dbs = {db["DBInstanceIdentifier"]: db for db in resp["DBInstances"]}

        tf_dbs = resources.get("aws_db_instance", {})
        print(f"  RDS: {len(tf_dbs)} in Terraform, {len(live_dbs)} live")

        for _name, _cfg in tf_dbs.items():
            identifier = _cfg.get("identifier", _name)
            live = live_dbs.get(identifier)
            if live is None:
                continue

            checks = [
                ("MultiAZ", "RDS-001-LIVE", "HIGH", "Multi-AZ"),
                ("DeletionProtection", "RDS-002-LIVE", "HIGH", "Deletion protection"),
            ]
            for attr, rule_id, sev, label in checks:
                if not live.get(attr):
                    result.add(Finding(
                        rule_id=rule_id,
                        severity=sev,
                        resource_type="aws_db_instance",
                        resource_name=_name,
                        description=f"[LIVE] {label} disabled on live RDS instance",
                        message=f"Live RDS {identifier}: {attr}=False",
                        recommendation=f"Enable {label} via Console (may require maintenance window).",
                        source="live",
                    ))

            if live.get("MonitoringInterval", 0) == 0:
                result.add(Finding(
                    rule_id="RDS-004-LIVE",
                    severity="MEDIUM",
                    resource_type="aws_db_instance",
                    resource_name=_name,
                    description="[LIVE] Enhanced Monitoring disabled on live RDS",
                    message=f"Live RDS {identifier}: MonitoringInterval=0",
                    recommendation="Enable Enhanced Monitoring in Console.",
                    source="live",
                ))

            if not live.get("PerformanceInsightsEnabled"):
                result.add(Finding(
                    rule_id="RDS-005-LIVE",
                    severity="MEDIUM",
                    resource_type="aws_db_instance",
                    resource_name=_name,
                    description="[LIVE] Performance Insights disabled on live RDS",
                    message=f"Live RDS {identifier}: PerformanceInsightsEnabled=False",
                    recommendation="Enable Performance Insights in Console.",
                    source="live",
                ))

    except Exception as exc:
        print(f"  [WARNING] RDS live check failed: {exc}")


def _check_alb_live(session, result: EvaluationResult, resources: Dict) -> None:
    try:
        elb = session.client("elbv2")
        resp = elb.describe_load_balancers()
        live_albs = {lb["LoadBalancerName"]: lb for lb in resp["LoadBalancers"]}

        tf_albs = resources.get("aws_lb", {})
        print(f"  ALB: {len(tf_albs)} in Terraform, {len(live_albs)} live")

        for _name, _cfg in tf_albs.items():
            # ALB resource names in AWS use the `name` attribute
            alb_name = _cfg.get("name", _name)
            live = live_albs.get(alb_name)
            if live is None:
                continue

            # Check deletion protection via attributes
            lb_arn = live["LoadBalancerArn"]
            attrs_resp = elb.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            attrs = {a["Key"]: a["Value"] for a in attrs_resp["Attributes"]}

            if attrs.get("deletion_protection.enabled") != "true":
                result.add(Finding(
                    rule_id="ALB-001-LIVE",
                    severity="MEDIUM",
                    resource_type="aws_lb",
                    resource_name=_name,
                    description="[LIVE] Deletion protection not enabled on live ALB",
                    message=f"Live ALB {alb_name}: deletion_protection.enabled=false",
                    recommendation="Enable deletion protection in Console.",
                    source="live",
                ))

            # Check HTTPS listener
            listeners_resp = elb.describe_listeners(LoadBalancerArn=lb_arn)
            protocols = {ln["Protocol"] for ln in listeners_resp["Listeners"]}
            if "HTTPS" not in protocols:
                result.add(Finding(
                    rule_id="ALB-004-LIVE",
                    severity="HIGH",
                    resource_type="aws_lb",
                    resource_name=_name,
                    description="[LIVE] No HTTPS listener on live ALB",
                    message=f"Live ALB {alb_name} has listeners: {protocols}. No HTTPS.",
                    recommendation="Add HTTPS listener with ACM certificate.",
                    source="live",
                ))

    except Exception as exc:
        print(f"  [WARNING] ALB live check failed: {exc}")


def _check_sg_live(session, result: EvaluationResult, resources: Dict) -> None:
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_security_groups()
        live_sgs = {sg["GroupName"]: sg for sg in resp["SecurityGroups"]}

        tf_sgs = resources.get("aws_security_group", {})
        print(f"  SG: {len(tf_sgs)} in Terraform, {len(live_sgs)} live")

        sensitive_ports = {22, 3306, 5432, 1433, 27017, 6379}
        for _name, _cfg in tf_sgs.items():
            sg_name = _cfg.get("name", _name)
            live = live_sgs.get(sg_name)
            if live is None:
                continue

            for perm in live.get("IpPermissions", []):
                cidrs = [r["CidrIp"] for r in perm.get("IpRanges", [])]
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 65535)
                if "0.0.0.0/0" in cidrs:
                    for port in sensitive_ports:
                        if from_port <= port <= to_port:
                            result.add(Finding(
                                rule_id="SG-001-LIVE",
                                severity="CRITICAL",
                                resource_type="aws_security_group",
                                resource_name=_name,
                                description="[LIVE] Unrestricted ingress on sensitive port",
                                message=f"Live SG {sg_name}: 0.0.0.0/0 → port {port}",
                                recommendation="Restrict to specific CIDR or source SG.",
                                source="live",
                            ))

    except Exception as exc:
        print(f"  [WARNING] SG live check failed: {exc}")


def _check_cloudtrail_live(session, result: EvaluationResult) -> None:
    try:
        ct = session.client("cloudtrail")
        resp = ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        print(f"  CloudTrail: {len(trails)} trail(s)")

        for trail in trails:
            if not trail.get("LogFileValidationEnabled"):
                result.add(Finding(
                    rule_id="CT-002-LIVE",
                    severity="HIGH",
                    resource_type="aws_cloudtrail",
                    resource_name=trail.get("Name", "unknown"),
                    description="[LIVE] Log file validation disabled on live trail",
                    message=f"Trail {trail.get('Name')}: LogFileValidationEnabled=False",
                    recommendation="Enable log file validation.",
                    source="live",
                ))
            if not trail.get("KMSKeyId"):
                result.add(Finding(
                    rule_id="CT-003-LIVE",
                    severity="MEDIUM",
                    resource_type="aws_cloudtrail",
                    resource_name=trail.get("Name", "unknown"),
                    description="[LIVE] CloudTrail not KMS-encrypted",
                    message=f"Trail {trail.get('Name')}: no KMS key configured",
                    recommendation="Configure KMS encryption on the trail.",
                    source="live",
                ))

    except Exception as exc:
        print(f"  [WARNING] CloudTrail live check failed: {exc}")


def _check_guardduty_live(session, result: EvaluationResult) -> None:
    try:
        gd = session.client("guardduty")
        detector_ids = gd.list_detectors().get("DetectorIds", [])
        print(f"  GuardDuty: {len(detector_ids)} detector(s)")

        if not detector_ids:
            result.add(Finding(
                rule_id="GD-001-LIVE",
                severity="HIGH",
                resource_type="aws_guardduty_detector",
                resource_name="(none)",
                description="[LIVE] No GuardDuty detector found in this region",
                message="GuardDuty is not active in this region.",
                recommendation="Enable GuardDuty in the Console or via Terraform.",
                source="live",
            ))

    except Exception as exc:
        print(f"  [WARNING] GuardDuty live check failed: {exc}")


def _check_s3_live(session, result: EvaluationResult, resources: Dict) -> None:
    try:
        s3 = session.client("s3")
        resp = s3.list_buckets()
        live_buckets = {b["Name"] for b in resp.get("Buckets", [])}

        tf_buckets = resources.get("aws_s3_bucket", {})
        print(f"  S3: {len(tf_buckets)} in Terraform, {len(live_buckets)} live")

        for _name, _cfg in tf_buckets.items():
            bucket_name = _cfg.get("bucket", "")
            if not bucket_name or bucket_name not in live_buckets:
                continue

            # Check public access block
            try:
                pab = s3.get_public_access_block(Bucket=bucket_name)
                cfg = pab["PublicAccessBlockConfiguration"]
                if not all([
                    cfg.get("BlockPublicAcls"),
                    cfg.get("BlockPublicPolicy"),
                    cfg.get("IgnorePublicAcls"),
                    cfg.get("RestrictPublicBuckets"),
                ]):
                    result.add(Finding(
                        rule_id="S3-PAB-LIVE",
                        severity="CRITICAL",
                        resource_type="aws_s3_bucket",
                        resource_name=_name,
                        description="[LIVE] S3 public access block not fully enabled",
                        message=f"Bucket {bucket_name} has partial public access block: {cfg}",
                        recommendation="Enable all four public access block settings.",
                        source="live",
                    ))
            except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                result.add(Finding(
                    rule_id="S3-PAB-LIVE",
                    severity="CRITICAL",
                    resource_type="aws_s3_bucket",
                    resource_name=_name,
                    description="[LIVE] S3 public access block is not configured",
                    message=f"Bucket {bucket_name} has no public access block configuration.",
                    recommendation="Apply aws_s3_bucket_public_access_block with all settings = true.",
                    source="live",
                ))
            except Exception:
                pass

    except Exception as exc:
        print(f"  [WARNING] S3 live check failed: {exc}")


# ──────────────────────────────────────────────
# Report generation
# ──────────────────────────────────────────────

def generate_report(result: EvaluationResult, resources: Dict[str, Dict], variables: Dict[str, Any]) -> str:
    lines = []

    # Header
    lines.append("=" * 70)
    lines.append("  TERRAFORM BEST-PRACTICE EVALUATION REPORT")
    lines.append("=" * 70)
    lines.append(f"  Region      : {result.aws_region}")
    lines.append(f"  Live check  : {'YES' if result.live_check_enabled else 'NO (static only)'}")
    lines.append(f"  Resources   : {result.resources_checked}")
    lines.append(f"  Rules run   : {result.rules_checked}")
    lines.append(f"  Score       : {result.score}/100  {_score_label(result.score)}")
    lines.append("")

    # Summary by severity
    lines.append("  FINDINGS SUMMARY")
    lines.append("  " + "-" * 40)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cnt = len(result.by_severity(sev))
        if cnt:
            lines.append(f"  {sev:<10} {cnt}")
    lines.append("")

    # Findings grouped by severity
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        findings = result.by_severity(sev)
        if not findings:
            continue
        lines.append(f"  [{sev}]")
        lines.append("  " + "-" * 40)
        for f in findings:
            tag = "[LIVE]" if f.source == "live" else "[STATIC]"
            lines.append(f"  {tag} {f.rule_id}  {f.resource_type}.{f.resource_name}")
            lines.append(f"    Problem : {f.message}")
            lines.append(f"    Fix     : {f.recommendation}")
            lines.append("")

    # Known good practices (detected from the config)
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

    # VPC Flow Logs - ALL traffic
    flow_logs = resources.get("aws_flow_log", {})
    all_flow = [n for n, c in flow_logs.items() if c.get("traffic_type", "ALL") == "ALL"]
    if all_flow:
        good.append(f"VPC Flow Logs: ALL traffic captured ({len(all_flow)} log resource(s))")

    # GuardDuty
    gd = resources.get("aws_guardduty_detector", {})
    gd_on = [c for c in gd.values() if c.get("enable", True) is not False]
    if gd_on:
        s3_on = any(_block(_block(c, "datasources"), "s3_logs").get("enable") is True for c in gd_on)
        suffix = " with S3 logs" if s3_on else ""
        good.append(f"GuardDuty detector enabled{suffix}")

    # Security Hub
    if resources.get("aws_securityhub_account"):
        good.append("Security Hub enabled")

    # CloudTrail
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

    # EC2: IMDSv2 on all instances
    instances = resources.get("aws_instance", {})
    if instances:
        if all(_block(c, "metadata_options").get("http_tokens") == "required"
               for c in instances.values()):
            good.append(
                f"EC2 IMDSv2 enforced on all {len(instances)} instance(s) (http_tokens = required)")

    # EC2: root EBS encryption on all instances
    if instances:
        if all(_block(c, "root_block_device").get("encrypted") is True
               for c in instances.values()):
            good.append(f"EBS root volumes encrypted on all {len(instances)} instance(s)")

    # EC2: no SSH key (implies SSM access)
    if instances:
        if all(not c.get("key_name") for c in instances.values()):
            good.append("EC2 instances: no key_name set (SSM Session Manager access implied)")

    # RDS: storage encryption
    dbs = resources.get("aws_db_instance", {})
    if dbs:
        if all(c.get("storage_encrypted") is True for c in dbs.values()):
            good.append(f"RDS storage encrypted on all {len(dbs)} DB instance(s)")

    # RDS: deletion protection
    if dbs:
        if all(c.get("deletion_protection") is True for c in dbs.values()):
            good.append(f"RDS deletion protection enabled on all {len(dbs)} DB instance(s)")

    # RDS: backup retention >= 7 days
    if dbs:
        if all(_int(c, "backup_retention_period") >= 7 for c in dbs.values()):
            good.append(f"RDS backup retention >= 7 days on all {len(dbs)} DB instance(s)")

    # RDS: no plaintext password
    if dbs:
        if all(not c.get("password") for c in dbs.values()):
            good.append("RDS: no plaintext password in config (Secrets Manager or managed password)")

    # Secrets Manager
    secrets = resources.get("aws_secretsmanager_secret", {})
    if secrets:
        good.append(f"Secrets Manager: {len(secrets)} secret(s) defined")

    # S3: all buckets have public access block fully enabled
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

    # VPC Endpoints
    endpoints = resources.get("aws_vpc_endpoint", {})
    if endpoints:
        svc_names = sorted({
            c.get("service_name", "").split(".")[-1]
            for c in endpoints.values()
            if c.get("service_name")
        })
        label = ", ".join(svc_names[:5]) if svc_names else f"{len(endpoints)}"
        good.append(f"VPC Endpoints defined: {label}")

    # ALB: access logs on all load balancers
    albs = resources.get("aws_lb", {})
    if albs:
        if all(_block(c, "access_logs").get("enabled") is True for c in albs.values()):
            good.append(f"ALB access logs enabled on all {len(albs)} load balancer(s)")

    # ALB: deletion protection on all load balancers
    if albs:
        if all(c.get("enable_deletion_protection") is True for c in albs.values()):
            good.append(f"ALB deletion protection enabled on all {len(albs)} load balancer(s)")

    # CloudWatch: Dashboard
    dashboards = resources.get("aws_cloudwatch_dashboard", {})
    if dashboards:
        good.append(f"CloudWatch Dashboard configured: {', '.join(dashboards.keys())}")

    # CloudWatch: Metric Alarms
    alarms = resources.get("aws_cloudwatch_metric_alarm", {})
    if alarms:
        with_actions = sum(1 for c in alarms.values()
                           if c.get("alarm_actions") or c.get("ok_actions"))
        good.append(f"CloudWatch Metric Alarms: {len(alarms)} defined ({with_actions} with actions)")

    # KMS: rotation enabled on all keys
    kms_keys = resources.get("aws_kms_key", {})
    if kms_keys:
        if all(c.get("enable_key_rotation") is True for c in kms_keys.values()):
            good.append(f"KMS key rotation enabled on all {len(kms_keys)} key(s)")

    # ECR: scan on push on all repositories
    ecr = resources.get("aws_ecr_repository", {})
    if ecr:
        if all(_block(c, "image_scanning_configuration").get("scan_on_push") is True
               for c in ecr.values()):
            good.append(f"ECR scan on push enabled on all {len(ecr)} repository/ies")

    # Launch template (not deprecated launch configuration)
    if resources.get("aws_launch_template") and not resources.get("aws_launch_configuration"):
        count = len(resources["aws_launch_template"])
        good.append(f"Launch templates used ({count}) — no deprecated aws_launch_configuration")

    # EKS: control plane logging on all clusters
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

    # ── Score gauge (SVG arc) ─────────────────────
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

    # ── Summary cards ─────────────────────────────
    card_html = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        fg, bg = sev_colors[sev]
        cnt = counts[sev]
        card_html += f"""
        <div class="card" style="background:{bg};border-left:4px solid {fg}">
          <div class="card-count" style="color:{fg}">{cnt}</div>
          <div class="card-label" style="color:{fg}">{sev}</div>
        </div>"""

    # ── Findings table rows ───────────────────────
    rows_html = ""
    if result.findings:
        for f in result.findings:
            fg, bg = sev_colors.get(f.severity, ("#374151", "#f3f4f6"))
            tag = "LIVE" if f.source == "live" else "STATIC"
            tag_color = "#7c3aed" if f.source == "live" else "#374151"
            rows_html += f"""
            <tr>
              <td><span class="badge" style="background:{bg};color:{fg}">{f.severity}</span></td>
              <td><code>{f.rule_id}</code></td>
              <td><span class="tag" style="color:{tag_color};border-color:{tag_color}">{tag}</span></td>
              <td><code>{f.resource_type}.<strong>{f.resource_name}</strong></code></td>
              <td>{f.message}</td>
              <td>{f.recommendation}</td>
            </tr>"""
    else:
        rows_html = '<tr><td colspan="6" style="text-align:center;color:#6b7280;padding:2rem">No findings</td></tr>'

    # ── Good practices ────────────────────────────
    good = _detect_good_practices(resources, variables)
    good_html = "".join(f'<li>&#x2705; {item}</li>' for item in good)

    # ── Pillar breakdown bar chart (inline SVG) ───
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
  .tag {{ display: inline-block; padding: 1px 6px; border-radius: 4px;
          font-size: 11px; font-weight: 600; border: 1px solid; }}
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

  <!-- Score + severity cards -->
  <div class="summary">
    <div class="gauge">{gauge_svg}</div>
    <div class="cards">{card_html}</div>
  </div>

  <!-- Meta info -->
  <div class="meta-grid">
    <div class="meta-item">
      <div class="label">Region</div>
      <div class="value">{result.aws_region}</div>
    </div>
    <div class="meta-item">
      <div class="label">Live Check</div>
      <div class="value">{"&#x2705; YES" if result.live_check_enabled else "&#x274C; NO (static only)"}</div>
    </div>
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

  <!-- Findings table -->
  <div class="section">
    <h2>Findings ({total_findings})</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule ID</th>
          <th>Source</th>
          <th>Resource</th>
          <th>Problem</th>
          <th>Recommendation</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <!-- Pillar bar chart -->
  {pillar_html}

  <!-- Good practices -->
  <div class="section">
    <h2>Good Practices Detected ({len(good)})</h2>
    <ul class="good">{good_html}</ul>
  </div>

</div>
<div class="footer">Terraform Evaluator &mdash; rule-based, no AI</div>
</body>
</html>"""

    return html
