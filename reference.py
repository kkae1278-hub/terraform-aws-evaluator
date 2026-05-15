"""
Terraform AWS best-practice rules dictionary.
Based on AWS Well-Architected Framework (WAF) 5 pillars:
  SEC  = Security
  REL  = Reliability
  OPS  = Operational Excellence
  PERF = Performance Efficiency
  COST = Cost Optimization
"""

# Severity weights for scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 15,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}

# ──────────────────────────────────────────────
# Helpers: safely access nested HCL2 blocks
# ──────────────────────────────────────────────
def _block(config, key):
    val = config.get(key, {})
    if isinstance(val, list):
        return val[0] if val else {}
    return val if isinstance(val, dict) else {}


def _blocks(config, key):
    val = config.get(key, [])
    if isinstance(val, list):
        return val
    return [val] if isinstance(val, dict) else []


def _int(config, key, default=0):
    try:
        return int(config.get(key, default))
    except (TypeError, ValueError):
        return default


# ──────────────────────────────────────────────
# Rules dictionary  (resource_type → list of rules)
# ──────────────────────────────────────────────
TERRAFORM_RULES = {

    # ================================================================
    # EC2  (WAF: SEC03, SEC05, REL01, OPS02, PERF01)
    # ================================================================
    "aws_instance": [
        {
            "id": "EC2-001",
            "pillar": "SEC",
            "description": "IMDSv2 (http_tokens=required) must be enforced",
            "severity": "HIGH",
            "check": lambda c: _block(c, "metadata_options").get("http_tokens") == "required",
            "message": "IMDSv2 is not required. http_tokens != 'required' exposes the instance to SSRF-based metadata theft.",
            "recommendation": "Set metadata_options { http_tokens = \"required\" http_put_response_hop_limit = 1 }",
        },
        {
            "id": "EC2-002",
            "pillar": "SEC",
            "description": "Root EBS volume must be encrypted at rest",
            "severity": "HIGH",
            "check": lambda c: _block(c, "root_block_device").get("encrypted") is True,
            "message": "Root EBS volume is not encrypted at rest. Violates SEC05 (protect data at rest).",
            "recommendation": "Set root_block_device { encrypted = true }",
        },
        {
            "id": "EC2-003",
            "pillar": "OPS",
            "description": "Detailed (1-minute) CloudWatch monitoring should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: c.get("monitoring") is True,
            "message": "Detailed monitoring is disabled. Default 5-minute intervals reduce alerting granularity.",
            "recommendation": "Set monitoring = true",
        },
        {
            "id": "EC2-004",
            "pillar": "COST",
            "description": "EBS root volume type should be gp3",
            "severity": "LOW",
            "check": lambda c: _block(c, "root_block_device").get("volume_type", "gp2") == "gp3",
            "message": "Root EBS volume is not gp3 (default is gp2). gp3 costs 20% less than gp2 with higher baseline throughput.",
            "recommendation": "Set root_block_device { volume_type = \"gp3\" }",
        },
        {
            "id": "EC2-005",
            "pillar": "SEC",
            "description": "EC2 instance should not have a public IP (prefer private subnet + NAT/VPC Endpoint)",
            "severity": "MEDIUM",
            "check": lambda c: c.get("associate_public_ip_address") is not True,
            "message": "associate_public_ip_address = true. Instance is directly reachable from the internet.",
            "recommendation": "Place instance in a private subnet and use NAT Gateway or VPC Endpoints for outbound access.",
        },
        {
            "id": "EC2-006",
            "pillar": "REL",
            "description": "EBS volume delete_on_termination should be explicit",
            "severity": "LOW",
            "check": lambda c: "delete_on_termination" in _block(c, "root_block_device"),
            "message": "delete_on_termination is not explicitly set. Default (true) may cause unexpected data loss on termination.",
            "recommendation": "Explicitly set root_block_device { delete_on_termination = false } for data volumes.",
        },
        {
            "id": "EC2-007",
            "pillar": "PERF",
            "description": "Avoid previous-generation instance types (t2, m3, c3, r3)",
            "severity": "LOW",
            "check": lambda c: not str(c.get("instance_type", "")).startswith(("t2.", "m3.", "c3.", "r3.", "i2.")),
            "message": "Previous-generation instance type detected. Newer generations offer better performance per cost.",
            "recommendation": "Migrate to t3/t4g, m5/m6i, c5/c6i or equivalent current-generation types.",
        },
    ],

    # ================================================================
    # RDS  (WAF: SEC05, REL01, REL02, OPS02, PERF01)
    # ================================================================
    "aws_db_instance": [
        {
            "id": "RDS-001",
            "pillar": "REL",
            "description": "Multi-AZ must be enabled for high availability",
            "severity": "HIGH",
            "check": lambda c: c.get("multi_az") is True,
            "message": "multi_az = false. Single-AZ has no automatic failover — failover takes 1-2 minutes manually.",
            "recommendation": "Set multi_az = true",
        },
        {
            "id": "RDS-002",
            "pillar": "REL",
            "description": "Deletion protection must be enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("deletion_protection") is True,
            "message": "deletion_protection = false. The DB instance can be accidentally deleted.",
            "recommendation": "Set deletion_protection = true",
        },
        {
            "id": "RDS-003",
            "pillar": "REL",
            "description": "Final snapshot must not be skipped on deletion",
            "severity": "HIGH",
            "check": lambda c: c.get("skip_final_snapshot") is not True,
            "message": "skip_final_snapshot = true. No backup is created on deletion — permanent data loss risk.",
            "recommendation": "Set skip_final_snapshot = false and specify final_snapshot_identifier",
        },
        {
            "id": "RDS-004",
            "pillar": "OPS",
            "description": "Enhanced Monitoring should be enabled (monitoring_interval > 0)",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "monitoring_interval") > 0,
            "message": "monitoring_interval = 0 disables Enhanced Monitoring. OS-level metrics (memory, swap, disk I/O) unavailable.",
            "recommendation": "Set monitoring_interval = 60 and provide monitoring_role_arn",
        },
        {
            "id": "RDS-005",
            "pillar": "OPS",
            "description": "Performance Insights should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: c.get("performance_insights_enabled") is True,
            "message": "performance_insights_enabled = false. SQL-level wait analysis and top SQL statements unavailable.",
            "recommendation": "Set performance_insights_enabled = true",
        },
        {
            "id": "RDS-006",
            "pillar": "SEC",
            "description": "Storage must be encrypted at rest",
            "severity": "HIGH",
            "check": lambda c: c.get("storage_encrypted") is True,
            "message": "RDS storage is not encrypted at rest. Violates SEC05.",
            "recommendation": "Set storage_encrypted = true",
        },
        {
            "id": "RDS-007",
            "pillar": "REL",
            "description": "Backup retention period should be >= 7 days",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "backup_retention_period") >= 7,
            "message": "Backup retention < 7 days. Recovery window is too short for most incident investigations.",
            "recommendation": "Set backup_retention_period >= 7",
        },
        {
            "id": "RDS-008",
            "pillar": "SEC",
            "description": "Auto minor version upgrade should be enabled",
            "severity": "LOW",
            "check": lambda c: c.get("auto_minor_version_upgrade", True) is not False,
            "message": "auto_minor_version_upgrade = false. Security patches for minor versions won't apply automatically.",
            "recommendation": "Set auto_minor_version_upgrade = true",
        },
        {
            "id": "RDS-009",
            "pillar": "SEC",
            "description": "RDS should not be publicly accessible",
            "severity": "CRITICAL",
            "check": lambda c: c.get("publicly_accessible") is not True,
            "message": "publicly_accessible = true. RDS instance is reachable from the internet.",
            "recommendation": "Set publicly_accessible = false and place RDS in a private subnet.",
        },
        {
            "id": "RDS-010",
            "pillar": "REL",
            "description": "Storage autoscaling (max_allocated_storage) should be configured",
            "severity": "LOW",
            "check": lambda c: _int(c, "max_allocated_storage", 0) > 0,
            "message": "max_allocated_storage is not set. Storage cannot autoscale — disk full risk under load.",
            "recommendation": "Set max_allocated_storage to an appropriate ceiling (e.g., 500)",
        },
        {
            "id": "RDS-011",
            "pillar": "COST",
            "description": "RDS storage type should be gp3 for cost efficiency",
            "severity": "LOW",
            "check": lambda c: c.get("storage_type", "gp2") == "gp3",
            "message": "storage_type is not gp3 (default is gp2). gp3 is cheaper and provides configurable IOPS/throughput.",
            "recommendation": "Set storage_type = \"gp3\"",
        },
        {
            "id": "RDS-012",
            "pillar": "SEC",
            "description": "CA certificate should be updated to rds-ca-rsa2048-g1 or newer",
            "severity": "MEDIUM",
            "check": lambda c: c.get("ca_cert_identifier", "rds-ca-rsa2048-g1") not in ["rds-ca-2015", "rds-ca-2019"],
            "message": "Using an old CA certificate (rds-ca-2015 or rds-ca-2019) that may expire soon.",
            "recommendation": "Set ca_cert_identifier = \"rds-ca-rsa2048-g1\" or \"rds-ca-ecc384-g1\"",
        },
    ],

    # ================================================================
    # Aurora RDS Cluster  (WAF: SEC05, REL01)
    # ================================================================
    "aws_rds_cluster": [
        {
            "id": "AUR-001",
            "pillar": "REL",
            "description": "Aurora cluster deletion protection must be enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("deletion_protection") is True,
            "message": "Aurora cluster has deletion_protection = false.",
            "recommendation": "Set deletion_protection = true",
        },
        {
            "id": "AUR-002",
            "pillar": "SEC",
            "description": "Aurora cluster storage must be encrypted",
            "severity": "HIGH",
            "check": lambda c: c.get("storage_encrypted") is True,
            "message": "Aurora storage is not encrypted at rest.",
            "recommendation": "Set storage_encrypted = true",
        },
        {
            "id": "AUR-003",
            "pillar": "REL",
            "description": "Aurora backup retention should be >= 7 days",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "backup_retention_period") >= 7,
            "message": "Aurora backup_retention_period < 7 days.",
            "recommendation": "Set backup_retention_period >= 7",
        },
        {
            "id": "AUR-004",
            "pillar": "SEC",
            "description": "Aurora cluster instances should not be publicly accessible",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "publicly_accessible is controlled on aws_rds_cluster_instance, not aws_rds_cluster. "
                       "Verify each cluster instance has publicly_accessible = false.",
            "recommendation": "Set publicly_accessible = false on each aws_rds_cluster_instance resource.",
        },
        {
            "id": "AUR-005",
            "pillar": "SEC",
            "description": "Aurora should enable IAM database authentication",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("iam_database_authentication_enabled")),
            "message": "IAM database authentication is not enabled. Password-only auth increases credential exposure risk.",
            "recommendation": "Set iam_database_authentication_enabled = true to allow IAM-based passwordless auth",
        },
    ],

    # ================================================================
    # ALB  (WAF: SEC03, SEC05, REL01, OPS02)
    # ================================================================
    "aws_lb": [
        {
            "id": "ALB-001",
            "pillar": "REL",
            "description": "ALB deletion protection should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: c.get("enable_deletion_protection") is True,
            "message": "ALB deletion protection is disabled. The load balancer can be accidentally removed.",
            "recommendation": "Set enable_deletion_protection = true",
        },
        {
            "id": "ALB-002",
            "pillar": "SEC",
            "description": "ALB should drop invalid HTTP headers",
            "severity": "MEDIUM",
            "check": lambda c: c.get("drop_invalid_header_fields") is True,
            "message": "drop_invalid_header_fields is not set. Protects against HTTP request-smuggling attacks.",
            "recommendation": "Set drop_invalid_header_fields = true",
        },
        {
            "id": "ALB-003",
            "pillar": "OPS",
            "description": "ALB access logs should be enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "access_logs").get("enabled") is True,
            "message": "ALB access logging is not enabled. Request-level audit trail is missing.",
            "recommendation": "Set access_logs { bucket = ... enabled = true }",
        },
        {
            "id": "ALB-005",
            "pillar": "SEC",
            "description": "Internet-facing ALB detected — verify this is intentional",
            "severity": "MEDIUM",
            "check": lambda c: not (
                c.get("internal") is False and
                c.get("load_balancer_type", "application") == "application"
            ),
            "message": "ALB is explicitly set to internet-facing (internal = false). "
                       "If this ALB is intentionally public (e.g. serving end users), this finding can be ignored.",
            "recommendation": "Set internal = true for ALBs that do not need public internet access. "
                              "If intentionally public, add a comment or suppress this finding.",
        },
    ],

    "aws_lb_listener": [
        {
            "id": "ALB-004",
            "pillar": "SEC",
            "description": "ALB listener should use HTTPS or redirect HTTP to HTTPS",
            "severity": "HIGH",
            "check": lambda c: (
                str(c.get("port", "")) == "443" or
                c.get("protocol", "") == "HTTPS" or
                (
                    _block(c, "default_action").get("type") == "redirect" and
                    _block(_block(c, "default_action"), "redirect").get("protocol") == "HTTPS"
                )
            ),
            "message": "Listener is HTTP-only with no HTTPS redirect. Data in transit is unencrypted. Violates SEC05.",
            "recommendation": "Use HTTPS (port 443) with an ACM certificate, or add a redirect default_action "
                              "{ type = \"redirect\" redirect { protocol = \"HTTPS\" status_code = \"HTTP_301\" } }",
        },
        {
            "id": "ALB-006",
            "pillar": "SEC",
            "description": "HTTPS listener should use a modern SSL policy",
            "severity": "MEDIUM",
            "check": lambda c: c.get("protocol", "") != "HTTPS" or
                c.get("ssl_policy", "ELBSecurityPolicy-TLS13-1-2-2021-06") not in [
                    "ELBSecurityPolicy-2015-05",
                    "ELBSecurityPolicy-TLS-1-0-2015-04",
                    "ELBSecurityPolicy-TLS-1-1-2017-01",
                ],
            "message": "HTTPS listener is using a deprecated SSL policy that supports TLS 1.0 or 1.1.",
            "recommendation": "Set ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\" (TLS 1.3 preferred)",
        },
    ],

    "aws_lb_target_group": [
        {
            "id": "TG-001",
            "pillar": "REL",
            "description": "Target group health check should be explicitly configured",
            "severity": "MEDIUM",
            "check": lambda c: "health_check" in c,
            "message": "No explicit health_check block. Default settings may not reflect actual application health.",
            "recommendation": "Define health_check { path = \"/health\" healthy_threshold = 2 unhealthy_threshold = 3 }",
        },
        {
            "id": "TG-002",
            "pillar": "REL",
            "description": "Deregistration delay should be tuned for fast deployments",
            "severity": "LOW",
            "check": lambda c: _int(c, "deregistration_delay", 300) <= 300,
            "message": "deregistration_delay > 300 seconds. Slow draining extends deployment time unnecessarily.",
            "recommendation": "Set deregistration_delay = 30~60 for stateless services",
        },
        {
            "id": "TG-003",
            "pillar": "PERF",
            "description": "Target group should enable stickiness only when required",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify whether stickiness is needed. Stickiness can unbalance load across targets.",
            "recommendation": "Use stickiness only for stateful sessions; prefer stateless design.",
        },
    ],

    # ================================================================
    # Auto Scaling  (WAF: REL03, REL04, COST01)
    # ================================================================
    "aws_autoscaling_group": [
        {
            "id": "ASG-001",
            "pillar": "REL",
            "description": "Health check type should be ELB (not EC2) when behind a load balancer",
            "severity": "MEDIUM",
            "check": lambda c: c.get("health_check_type", "EC2") == "ELB",
            "message": "health_check_type = EC2. EC2 checks only detect OS-level failure, not application failure.",
            "recommendation": "Set health_check_type = \"ELB\" when instances are behind an ALB/NLB",
        },
        {
            "id": "ASG-002",
            "pillar": "REL",
            "description": "Minimum instance count should be >= 2 for high availability",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "min_size", 1) >= 2,
            "message": "min_size < 2. A single-instance ASG has no redundancy — one AZ failure takes down the service.",
            "recommendation": "Set min_size >= 2 and use multiple availability_zones",
        },
        {
            "id": "ASG-003",
            "pillar": "REL",
            "description": "ASG should span multiple Availability Zones",
            "severity": "HIGH",
            "check": lambda c: len(c.get("availability_zones", c.get("vpc_zone_identifier", []))) >= 2,
            "message": "ASG is configured for a single AZ. One AZ outage removes all capacity.",
            "recommendation": "Set vpc_zone_identifier to subnets in at least 2 AZs",
        },
        {
            "id": "ASG-004",
            "pillar": "REL",
            "description": "Instance refresh should be configured for safe deployments",
            "severity": "LOW",
            "check": lambda c: "instance_refresh" in c,
            "message": "No instance_refresh block. AMI updates replace all instances simultaneously without health checks.",
            "recommendation": "Add instance_refresh { strategy = \"Rolling\" preferences { min_healthy_percentage = 90 } }",
        },
        {
            "id": "ASG-005",
            "pillar": "COST",
            "description": "Consider using mixed instances policy with Spot for cost savings",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Using On-Demand only. Mixed instances policy with Spot can reduce EC2 costs by 60-90%.",
            "recommendation": "Evaluate mixed_instances_policy with Spot for non-critical workloads.",
        },
    ],

    # ================================================================
    # S3  (WAF: SEC05, REL01, COST01)
    # ================================================================
    "aws_s3_bucket": [
        {
            "id": "S3-001",
            "pillar": "REL",
            "description": "force_destroy should be false on data-bearing buckets",
            "severity": "MEDIUM",
            "check": lambda c: c.get("force_destroy") is not True,
            "message": "force_destroy = true. All objects deleted when bucket is destroyed — data loss risk.",
            "recommendation": "Set force_destroy = false for buckets holding audit logs or production data",
        },
    ],

    "aws_s3_bucket_versioning": [
        {
            "id": "S3-002",
            "pillar": "REL",
            "description": "S3 versioning should be enabled on important buckets",
            "severity": "LOW",
            "check": lambda c: _block(c, "versioning_configuration").get("status", "") == "Enabled",
            "message": "S3 versioning is not enabled. Overwrites and accidental deletes are not recoverable.",
            "recommendation": "Set versioning_configuration { status = \"Enabled\" }",
        },
    ],

    "aws_s3_bucket_server_side_encryption_configuration": [
        {
            "id": "S3-003",
            "pillar": "SEC",
            "description": "S3 bucket should have server-side encryption configured",
            "severity": "MEDIUM",
            "check": lambda c: bool(_blocks(c, "rule")),
            "message": "No server-side encryption configuration. Data at rest may be unprotected.",
            "recommendation": "Add server_side_encryption_configuration with AES256 or aws:kms",
        },
    ],

    "aws_s3_bucket_public_access_block": [
        {
            "id": "S3-004",
            "pillar": "SEC",
            "description": "All four public access block settings must be true",
            "severity": "CRITICAL",
            "check": lambda c: all([
                c.get("block_public_acls") is True,
                c.get("block_public_policy") is True,
                c.get("ignore_public_acls") is True,
                c.get("restrict_public_buckets") is True,
            ]),
            "message": "One or more public access block settings are not enabled. Bucket may be publicly accessible.",
            "recommendation": "Set all four: block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets = true",
        },
    ],

    "aws_s3_bucket_lifecycle_configuration": [
        {
            "id": "S3-005",
            "pillar": "COST",
            "description": "S3 lifecycle rules should transition or expire objects to reduce cost",
            "severity": "INFO",
            "check": lambda c: bool(_blocks(c, "rule")),
            "message": "No lifecycle configuration found. Objects grow indefinitely and incur increasing storage costs.",
            "recommendation": "Add transition to S3-IA after 30 days, Glacier after 90 days, or set expiration.",
        },
    ],

    # ================================================================
    # Security Groups  (WAF: SEC03)
    # ================================================================
    "aws_security_group": [
        {
            "id": "SG-001",
            "pillar": "SEC",
            "description": "No unrestricted ingress on admin/DB ports (22, 3306, 5432, 1433, 27017, 6379)",
            "severity": "CRITICAL",
            "check": lambda c: not any(
                ("0.0.0.0/0" in (i.get("cidr_blocks") or []) or "::/0" in (i.get("ipv6_cidr_blocks") or []))
                and int(i.get("from_port", 0)) in [22, 3306, 5432, 1433, 27017, 6379, 5439, 9200]
                for i in _blocks(c, "ingress")
            ),
            "message": "Security group allows unrestricted 0.0.0.0/0 access on sensitive admin/DB ports.",
            "recommendation": "Restrict ingress to specific CIDR blocks or source security groups",
        },
        {
            "id": "SG-002",
            "pillar": "SEC",
            "description": "No unrestricted ingress on all ports (from_port=0, to_port=0, protocol=-1)",
            "severity": "CRITICAL",
            "check": lambda c: not any(
                ("0.0.0.0/0" in (i.get("cidr_blocks") or []))
                and str(i.get("protocol", "")) == "-1"
                for i in _blocks(c, "ingress")
            ),
            "message": "Security group allows ALL traffic from 0.0.0.0/0 (protocol = -1). Completely open ingress.",
            "recommendation": "Restrict to specific ports and source CIDR blocks or security groups.",
        },
        {
            "id": "SG-003",
            "pillar": "SEC",
            "description": "Security group description should not be the default placeholder",
            "severity": "LOW",
            "check": lambda c: c.get("description", "") not in ["", "Managed by Terraform", "default"],
            "message": "Security group has no meaningful description. Hard to audit purpose during incident response.",
            "recommendation": "Set a descriptive description explaining the SG's purpose and associated resource.",
        },
    ],

    # ================================================================
    # VPC / Networking  (WAF: SEC03, REL01)
    # ================================================================
    "aws_vpc": [
        {
            "id": "VPC-002",
            "pillar": "REL",
            "description": "VPC DNS hostnames should be enabled",
            "severity": "LOW",
            "check": lambda c: c.get("enable_dns_hostnames") is True,
            "message": "enable_dns_hostnames = false. EC2 instances won't get public DNS names; some AWS services may break.",
            "recommendation": "Set enable_dns_hostnames = true",
        },
        {
            "id": "VPC-003",
            "pillar": "REL",
            "description": "VPC DNS support should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: c.get("enable_dns_support") is not False,
            "message": "enable_dns_support = false. Route53, VPC Endpoints, and ECS service discovery will not function.",
            "recommendation": "Set enable_dns_support = true",
        },
        {
            "id": "VPC-005",
            "pillar": "COST",
            "description": "VPC should have required cost allocation tags",
            "severity": "LOW",
            "check": lambda c: bool(c.get("tags")),
            "message": "VPC has no tags. Cost allocation and ownership tracking is not possible.",
            "recommendation": "Add tags = { Environment = ... Owner = ... CostCenter = ... }",
        },
    ],

    "aws_flow_log": [
        {
            "id": "VPC-001",
            "pillar": "SEC",
            "description": "VPC Flow Logs traffic type should capture ALL traffic",
            "severity": "MEDIUM",
            "check": lambda c: c.get("traffic_type", "ALL") == "ALL",
            "message": "Flow Logs traffic_type is not ALL. ACCEPT-only or REJECT-only misses half of network activity.",
            "recommendation": "Set traffic_type = \"ALL\"",
        },
        {
            "id": "VPC-004",
            "pillar": "OPS",
            "description": "VPC Flow Logs should use a custom format for richer fields",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Consider adding log_format with fields like pkt-srcaddr, pkt-dstaddr, flow-direction for deeper analysis.",
            "recommendation": "Set log_format to include extended fields: pkt-src-aws-service, pkt-dst-aws-service, etc.",
        },
    ],

    "aws_subnet": [
        {
            "id": "NET-001",
            "pillar": "SEC",
            "description": "Subnets should not auto-assign public IPs unless explicitly a public subnet",
            "severity": "MEDIUM",
            "check": lambda c: c.get("map_public_ip_on_launch") is not True,
            "message": "map_public_ip_on_launch = true. Instances in this subnet get public IPs automatically. "
                       "Acceptable for intentional public subnets (e.g. NAT Gateway, bastion); suppress if intentional.",
            "recommendation": "Set map_public_ip_on_launch = false for private subnets.",
        },
    ],

    "aws_vpc_endpoint": [
        {
            "id": "NET-002",
            "pillar": "SEC",
            "description": "Interface VPC endpoints should have private DNS enabled",
            "severity": "MEDIUM",
            "check": lambda c: (
                c.get("vpc_endpoint_type", "Interface") != "Interface" or
                c.get("private_dns_enabled") is True
            ),
            "message": "Interface endpoint has private_dns_enabled = false. Services may route traffic through the internet.",
            "recommendation": "Set private_dns_enabled = true for Interface endpoints.",
        },
    ],

    # ================================================================
    # IAM  (WAF: SEC01, SEC02)
    # ================================================================
    "aws_iam_role": [
        {
            "id": "IAM-001",
            "pillar": "SEC",
            "description": "IAM role assume_role_policy should not allow all principals (*)",
            "severity": "CRITICAL",
            "check": lambda c: '"AWS": "*"' not in str(c.get("assume_role_policy", ""))
                and "'AWS': '*'" not in str(c.get("assume_role_policy", "")),
            "message": "assume_role_policy allows any AWS principal (*). Any AWS account can assume this role.",
            "recommendation": "Restrict Principal to specific account IDs, roles, or services.",
        },
        {
            "id": "IAM-002",
            "pillar": "SEC",
            "description": "IAM role should have a meaningful description",
            "severity": "LOW",
            "check": lambda c: bool(c.get("description", "").strip()),
            "message": "IAM role has no description. Hard to audit purpose during access reviews.",
            "recommendation": "Set description = \"Purpose of this role and which service/team uses it\"",
        },
        {
            "id": "IAM-003",
            "pillar": "SEC",
            "description": "IAM role max_session_duration should be <= 4 hours",
            "severity": "LOW",
            "check": lambda c: _int(c, "max_session_duration", 3600) <= 14400,
            "message": "max_session_duration > 4 hours. Long-lived credentials increase blast radius if compromised.",
            "recommendation": "Set max_session_duration <= 14400 (4 hours) for interactive roles",
        },
    ],

    "aws_iam_policy": [
        {
            "id": "IAM-004",
            "pillar": "SEC",
            "description": "IAM policy should not use wildcard Action (*) on sensitive services",
            "severity": "HIGH",
            "check": lambda c: not any(
                '"Action": "*"' in str(c.get("policy", "")) or
                "'Action': '*'" in str(c.get("policy", "")) or
                '"Action":"*"' in str(c.get("policy", ""))
                for _ in [1]
            ),
            "message": "IAM policy contains Action: '*' (all actions). Violates least-privilege principle (SEC01).",
            "recommendation": "Enumerate only the specific actions required (e.g., s3:GetObject, rds:DescribeDBInstances).",
        },
    ],

    "aws_iam_role_policy": [
        {
            "id": "IAM-005",
            "pillar": "SEC",
            "description": "Inline IAM policy should not use wildcard Action on sensitive services",
            "severity": "HIGH",
            "check": lambda c: '"Action": "*"' not in str(c.get("policy", "")),
            "message": "Inline policy contains Action: '*'. Least-privilege principle violated.",
            "recommendation": "Replace '*' with specific required actions.",
        },
    ],

    # ================================================================
    # KMS  (WAF: SEC05)
    # ================================================================
    "aws_kms_key": [
        {
            "id": "KMS-001",
            "pillar": "SEC",
            "description": "KMS key automatic rotation should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: c.get("enable_key_rotation") is True,
            "message": "KMS key rotation is disabled. Key material is never rotated, increasing exposure window.",
            "recommendation": "Set enable_key_rotation = true (annual rotation for symmetric keys)",
        },
        {
            "id": "KMS-002",
            "pillar": "SEC",
            "description": "KMS key should have a descriptive description",
            "severity": "LOW",
            "check": lambda c: bool(c.get("description", "").strip()),
            "message": "KMS key has no description. Hard to identify purpose during key management audits.",
            "recommendation": "Set description = \"Purpose and associated resource of this key\"",
        },
        {
            "id": "KMS-003",
            "pillar": "REL",
            "description": "KMS key deletion window should be maximum (30 days)",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "deletion_window_in_days", 30) >= 14,
            "message": "deletion_window_in_days < 14. Short window risks unrecoverable accidental key deletion.",
            "recommendation": "Set deletion_window_in_days = 30",
        },
    ],

    # ================================================================
    # CloudTrail  (WAF: SEC02)
    # ================================================================
    "aws_cloudtrail": [
        {
            "id": "CT-001",
            "pillar": "SEC",
            "description": "CloudTrail must be multi-region",
            "severity": "HIGH",
            "check": lambda c: c.get("is_multi_region_trail") is True,
            "message": "Single-region CloudTrail. API activity in other regions is not recorded.",
            "recommendation": "Set is_multi_region_trail = true",
        },
        {
            "id": "CT-002",
            "pillar": "SEC",
            "description": "Log file validation must be enabled (tamper detection)",
            "severity": "HIGH",
            "check": lambda c: c.get("enable_log_file_validation") is True,
            "message": "Log file validation disabled. Deleted or modified CloudTrail logs cannot be detected.",
            "recommendation": "Set enable_log_file_validation = true",
        },
        {
            "id": "CT-003",
            "pillar": "SEC",
            "description": "CloudTrail logs should be KMS-encrypted",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("kms_key_id")),
            "message": "CloudTrail logs are not KMS-encrypted. SSE-S3 only.",
            "recommendation": "Set kms_key_id = <aws_kms_key ARN>",
        },
        {
            "id": "CT-004",
            "pillar": "SEC",
            "description": "Global service events (IAM, STS, Route53) must be captured",
            "severity": "MEDIUM",
            "check": lambda c: c.get("include_global_service_events", True) is not False,
            "message": "include_global_service_events = false. IAM, STS, and Route53 API calls are not logged.",
            "recommendation": "Set include_global_service_events = true (default is true; explicitly set to avoid accidental disable)",
        },
        {
            "id": "CT-005",
            "pillar": "OPS",
            "description": "CloudTrail should be delivered to CloudWatch Logs for real-time alerting",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("cloud_watch_logs_group_arn")),
            "message": "CloudTrail is not delivering to CloudWatch Logs. Real-time metric filters and alarms cannot be set.",
            "recommendation": "Set cloud_watch_logs_group_arn and cloud_watch_logs_role_arn",
        },
    ],

    # ================================================================
    # Secrets Manager  (WAF: SEC05)
    # ================================================================
    "aws_secretsmanager_secret": [
        {
            "id": "SM-001",
            "pillar": "REL",
            "description": "Secret recovery window should be >= 7 days",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "recovery_window_in_days", 30) >= 7,
            "message": "recovery_window_in_days = 0 allows immediate unrecoverable deletion.",
            "recommendation": "Set recovery_window_in_days = 7 minimum",
        },
        {
            "id": "SM-002",
            "pillar": "SEC",
            "description": "Secrets Manager secret should be encrypted with a CMK",
            "severity": "LOW",
            "check": lambda c: bool(c.get("kms_key_id")),
            "message": "Secret is encrypted with the default AWS-managed key, not a customer-managed KMS key.",
            "recommendation": "Set kms_key_id = <aws_kms_key ARN> for dedicated key control and audit trail",
        },
    ],

    # ================================================================
    # GuardDuty  (WAF: SEC06)
    # ================================================================
    "aws_guardduty_detector": [
        {
            "id": "GD-001",
            "pillar": "SEC",
            "description": "GuardDuty detector must be enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("enable", True) is not False,
            "message": "GuardDuty is not active. ML-based threat detection (recon, crypto-mining, credential theft) is off.",
            "recommendation": "Set enable = true (default is true; explicitly set to avoid accidental disable)",
        },
        {
            "id": "GD-002",
            "pillar": "SEC",
            "description": "GuardDuty S3 protection should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: _block(_block(c, "datasources"), "s3_logs").get("enable") is True,
            "message": "GuardDuty S3 data event monitoring is not enabled. S3-based threats go undetected.",
            "recommendation": "Set datasources { s3_logs { enable = true } }",
        },
        {
            "id": "GD-003",
            "pillar": "SEC",
            "description": "GuardDuty EKS protection should be enabled if EKS is used",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify GuardDuty EKS audit log monitoring is enabled if EKS clusters are present. "
                       "Cannot be verified from the aws_guardduty_detector resource alone.",
            "recommendation": "Set datasources { kubernetes { audit_logs { enable = true } } }",
        },
    ],

    # ================================================================
    # CloudWatch  (WAF: OPS01, OPS02)
    # ================================================================
    "aws_cloudwatch_log_group": [
        {
            "id": "CW-001",
            "pillar": "COST",
            "description": "CloudWatch log group retention should be explicitly set",
            "severity": "LOW",
            "check": lambda c: _int(c, "retention_in_days", 0) > 0,
            "message": "No retention policy — logs stored indefinitely, increasing CloudWatch costs.",
            "recommendation": "Set retention_in_days (e.g., 30 for operational, 365 for security/compliance logs)",
        },
        {
            "id": "CW-002",
            "pillar": "SEC",
            "description": "CloudWatch log group should be KMS-encrypted",
            "severity": "LOW",
            "check": lambda c: bool(c.get("kms_key_id")),
            "message": "CloudWatch log group is not KMS-encrypted. Logs use AWS-managed keys only.",
            "recommendation": "Set kms_key_id = <aws_kms_key ARN>",
        },
    ],

    "aws_cloudwatch_metric_alarm": [
        {
            "id": "CWA-001",
            "pillar": "OPS",
            "description": "CloudWatch alarm must have at least one action configured",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("alarm_actions") or c.get("ok_actions") or c.get("insufficient_data_actions")),
            "message": "CloudWatch alarm has no actions. Alarm fires but no one is notified.",
            "recommendation": "Set alarm_actions = [<sns_topic_arn>]",
        },
        {
            "id": "CWA-002",
            "pillar": "OPS",
            "description": "Alarm evaluation period should be reasonable (not too short or long)",
            "severity": "LOW",
            "check": lambda c: 1 <= _int(c, "evaluation_periods", 1) <= 10,
            "message": "evaluation_periods is outside recommended range (1-10). May cause too many or too few alerts.",
            "recommendation": "Set evaluation_periods = 2~3 for a balance between sensitivity and false positives.",
        },
    ],

    # ================================================================
    # SNS  (WAF: OPS02, SEC05)
    # ================================================================
    "aws_sns_topic": [
        {
            "id": "SNS-001",
            "pillar": "SEC",
            "description": "SNS topic should be encrypted with KMS",
            "severity": "LOW",
            "check": lambda c: bool(c.get("kms_master_key_id")),
            "message": "SNS topic is not KMS-encrypted. Messages at rest are not protected by a CMK.",
            "recommendation": "Set kms_master_key_id = <aws_kms_key ARN or alias>",
        },
    ],

    # ================================================================
    # SSM Parameter Store  (WAF: SEC05)
    # ================================================================
    "aws_ssm_parameter": [
        {
            "id": "SSM-001",
            "pillar": "SEC",
            "description": "Sensitive SSM parameters should use SecureString type",
            "severity": "HIGH",
            "check": lambda c: c.get("type", "String") in ["SecureString", "StringList"]
                or not any(
                    kw in c.get("name", "").lower()
                    for kw in ["password", "secret", "token", "key", "credential", "apikey"]
                ),
            "message": "SSM parameter name suggests sensitive data but type is not SecureString.",
            "recommendation": "Set type = \"SecureString\" and specify key_id for KMS encryption",
        },
    ],

    # ================================================================
    # ElastiCache  (WAF: SEC05, REL01)
    # ================================================================
    "aws_elasticache_replication_group": [
        {
            "id": "EC-001",
            "pillar": "SEC",
            "description": "ElastiCache should have at-rest encryption enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("at_rest_encryption_enabled") is True,
            "message": "at_rest_encryption_enabled = false. Cached data is not protected at rest.",
            "recommendation": "Set at_rest_encryption_enabled = true",
        },
        {
            "id": "EC-002",
            "pillar": "SEC",
            "description": "ElastiCache should have in-transit encryption enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("transit_encryption_enabled") is True,
            "message": "transit_encryption_enabled = false. Data in transit between client and ElastiCache is unencrypted.",
            "recommendation": "Set transit_encryption_enabled = true",
        },
        {
            "id": "EC-003",
            "pillar": "REL",
            "description": "ElastiCache automatic failover should be enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("automatic_failover_enabled") is True,
            "message": "automatic_failover_enabled = false. Redis primary failure requires manual promotion.",
            "recommendation": "Set automatic_failover_enabled = true (requires num_cache_clusters >= 2)",
        },
        {
            "id": "EC-004",
            "pillar": "SEC",
            "description": "ElastiCache Redis should require auth token",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("auth_token")),
            "message": "No auth_token set. Redis is accessible without authentication within the VPC.",
            "recommendation": "Set auth_token = <random strong password> and store in Secrets Manager",
        },
    ],

    "aws_elasticache_cluster": [
        {
            "id": "EC-005",
            "pillar": "PERF",
            "description": "ElastiCache node type should not be previous-generation (cache.t2, cache.m3)",
            "severity": "LOW",
            "check": lambda c: not str(c.get("node_type", "")).startswith(("cache.t2.", "cache.m3.")),
            "message": "Using previous-generation ElastiCache node type.",
            "recommendation": "Migrate to cache.t3 or cache.m5/r6g for better performance per cost.",
        },
    ],

    # ================================================================
    # Lambda  (WAF: SEC01, SEC05, OPS02, REL01)
    # ================================================================
    "aws_lambda_function": [
        {
            "id": "LAM-001",
            "pillar": "SEC",
            "description": "Lambda function should have a reserved concurrency limit",
            "severity": "MEDIUM",
            "check": lambda c: "reserved_concurrent_executions" in c,
            "message": "No reserved_concurrent_executions. Runaway Lambda can exhaust regional concurrency quota.",
            "recommendation": "Set reserved_concurrent_executions = <expected max> to protect other functions",
        },
        {
            "id": "LAM-002",
            "pillar": "OPS",
            "description": "Lambda X-Ray tracing should be enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "tracing_config").get("mode", "PassThrough") == "Active",
            "message": "X-Ray tracing mode is PassThrough or not set. End-to-end request tracing is unavailable.",
            "recommendation": "Set tracing_config { mode = \"Active\" }",
        },
        {
            "id": "LAM-003",
            "pillar": "REL",
            "description": "Lambda should have a dead-letter queue (DLQ) configured",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "dead_letter_config").get("target_arn")),
            "message": "No dead_letter_config set. Failed async invocations are silently discarded.",
            "recommendation": "Set dead_letter_config { target_arn = <sqs_queue_arn or sns_topic_arn> }",
        },
        {
            "id": "LAM-004",
            "pillar": "SEC",
            "description": "Lambda function should not run in a VPC without proper SG/subnet configuration",
            "severity": "INFO",
            "check": lambda c: True,
            "message": "Verify VPC-attached Lambda has appropriate security groups and private subnets with NAT.",
            "recommendation": "If VPC is needed, configure vpc_config with private subnets and appropriate SG.",
        },
        {
            "id": "LAM-005",
            "pillar": "COST",
            "description": "Lambda timeout should be explicitly and conservatively set",
            "severity": "LOW",
            "check": lambda c: 0 < _int(c, "timeout", 3) <= 60,
            "message": "Lambda timeout is either not set or > 60 seconds. Long timeouts waste resources on hangs.",
            "recommendation": "Set timeout to the 99th percentile of expected duration + 20% buffer.",
        },
    ],

    # ================================================================
    # ECS  (WAF: SEC01, SEC05)
    # ================================================================
    "aws_ecs_task_definition": [
        {
            "id": "ECS-001",
            "pillar": "SEC",
            "description": "ECS task definition should use awsvpc network mode",
            "severity": "MEDIUM",
            "check": lambda c: c.get("network_mode", "bridge") == "awsvpc",
            "message": "network_mode != awsvpc. Task shares the host's network namespace — weaker isolation.",
            "recommendation": "Set network_mode = \"awsvpc\" for task-level security group assignment",
        },
        {
            "id": "ECS-002",
            "pillar": "SEC",
            "description": "ECS task definition should specify an execution role ARN",
            "severity": "HIGH",
            "check": lambda c: bool(c.get("execution_role_arn")),
            "message": "No execution_role_arn set. ECR image pulls and Secrets Manager access may use broad permissions.",
            "recommendation": "Create a dedicated task execution role with minimum required permissions.",
        },
        {
            "id": "ECS-003",
            "pillar": "SEC",
            "description": "ECS containers should not run as privileged",
            "severity": "HIGH",
            "check": lambda c: '"privileged": true' not in str(c.get("container_definitions", ""))
                and '"privileged":true' not in str(c.get("container_definitions", "")),
            "message": "Container runs with privileged = true. Container can access all host devices.",
            "recommendation": "Remove privileged = true; use specific Linux capabilities if needed.",
        },
    ],

    "aws_ecs_service": [
        {
            "id": "ECS-004",
            "pillar": "REL",
            "description": "ECS service should have multiple tasks for redundancy",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "desired_count", 1) >= 2,
            "message": "desired_count < 2. A single task failure takes down the service.",
            "recommendation": "Set desired_count >= 2 and enable circuit breaker",
        },
        {
            "id": "ECS-005",
            "pillar": "REL",
            "description": "ECS service circuit breaker should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "deployment_circuit_breaker").get("enable") is True,
            "message": "Deployment circuit breaker is not enabled. Bad deployments will keep retrying indefinitely.",
            "recommendation": "Set deployment_circuit_breaker { enable = true rollback = true }",
        },
    ],

    # ================================================================
    # EKS  (WAF: SEC01, SEC03)
    # ================================================================
    "aws_eks_cluster": [
        {
            "id": "EKS-001",
            "pillar": "SEC",
            "description": "EKS API server should not be publicly accessible without IP restrictions",
            "severity": "HIGH",
            "check": lambda c: (
                _block(c, "vpc_config").get("endpoint_public_access") is not True or
                bool(_block(c, "vpc_config").get("public_access_cidrs"))
            ),
            "message": "EKS API endpoint is public with no CIDR restrictions. Anyone can reach the API server.",
            "recommendation": "Set endpoint_private_access = true or restrict public_access_cidrs to known IPs.",
        },
        {
            "id": "EKS-002",
            "pillar": "SEC",
            "description": "EKS control plane logging should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("enabled_cluster_log_types")),
            "message": "EKS control plane logging is not enabled. API server, audit, and authenticator logs unavailable.",
            "recommendation": "Set enabled_cluster_log_types = [\"api\", \"audit\", \"authenticator\", \"controllerManager\", \"scheduler\"]",
        },
        {
            "id": "EKS-003",
            "pillar": "SEC",
            "description": "EKS secrets should be encrypted with a KMS key",
            "severity": "HIGH",
            "check": lambda c: any(
                "secrets" in str(p.get("resources", "")).lower()
                for p in _blocks(c, "encryption_config")
            ),
            "message": "EKS Kubernetes secrets are not encrypted with a CMK. etcd secrets are only base64-encoded.",
            "recommendation": "Add encryption_config { resources = [\"secrets\"] provider { key_arn = ... } }",
        },
    ],

    # ================================================================
    # SQS  (WAF: SEC05, REL01)
    # ================================================================
    "aws_sqs_queue": [
        {
            "id": "SQS-001",
            "pillar": "SEC",
            "description": "SQS queue should be encrypted with a KMS CMK",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("kms_master_key_id")),
            "message": "SQS queue is not KMS-encrypted with a CMK. Messages use AWS-managed SSE-SQS only.",
            "recommendation": "Set kms_master_key_id = <aws_kms_key ARN or alias/aws/sqs>",
        },
        {
            "id": "SQS-002",
            "pillar": "REL",
            "description": "SQS queue should have a Dead Letter Queue configured",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "redrive_policy") or c.get("redrive_policy")),
            "message": "No redrive_policy (DLQ) configured. Unprocessable messages are silently discarded.",
            "recommendation": "Set redrive_policy = jsonencode({ deadLetterTargetArn = ..., maxReceiveCount = 3 })",
        },
        {
            "id": "SQS-003",
            "pillar": "SEC",
            "description": "SQS queue policy should not allow public access",
            "severity": "CRITICAL",
            "check": lambda c: '"Principal": "*"' not in str(c.get("policy", ""))
                and '"Principal":"*"' not in str(c.get("policy", "")),
            "message": "SQS queue policy allows access from any principal (*). Queue is publicly accessible.",
            "recommendation": "Restrict Principal to specific AWS account IDs or IAM roles.",
        },
    ],

    # ================================================================
    # CloudFront  (WAF: SEC03, SEC05, PERF01)
    # ================================================================
    "aws_cloudfront_distribution": [
        {
            "id": "CF-001",
            "pillar": "SEC",
            "description": "CloudFront should use HTTPS-only viewer protocol",
            "severity": "HIGH",
            "check": lambda c: all(
                b.get("viewer_protocol_policy") in ["https-only", "redirect-to-https"]
                for b in _blocks(c, "default_cache_behavior") + _blocks(c, "ordered_cache_behavior")
            ) if (_blocks(c, "default_cache_behavior") or _blocks(c, "ordered_cache_behavior")) else True,
            "message": "CloudFront distribution allows HTTP viewer connections. Data in transit is unencrypted.",
            "recommendation": "Set viewer_protocol_policy = \"redirect-to-https\" or \"https-only\"",
        },
        {
            "id": "CF-002",
            "pillar": "SEC",
            "description": "CloudFront should use TLS 1.2 or later (no SSLv3 or TLS 1.0)",
            "severity": "HIGH",
            "check": lambda c: _block(c, "viewer_certificate").get("minimum_protocol_version", "TLSv1.2_2021")
                not in ["SSLv3", "TLSv1", "TLSv1_2016"],
            "message": "CloudFront allows deprecated SSL/TLS versions (SSLv3, TLS 1.0/1.1).",
            "recommendation": "Set viewer_certificate { minimum_protocol_version = \"TLSv1.2_2021\" }",
        },
        {
            "id": "CF-003",
            "pillar": "OPS",
            "description": "CloudFront access logging should be enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "logging_config").get("bucket", "") != "",
            "message": "CloudFront access logging is not configured. Request-level audit trail is missing.",
            "recommendation": "Set logging_config { bucket = ... include_cookies = false prefix = \"cloudfront/\" }",
        },
        {
            "id": "CF-004",
            "pillar": "SEC",
            "description": "CloudFront should not use the default CloudFront certificate for custom domains",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "viewer_certificate").get("cloudfront_default_certificate") is not True
                or not c.get("aliases"),
            "message": "Custom domain aliases are set but using the default CloudFront certificate.",
            "recommendation": "Set viewer_certificate { acm_certificate_arn = ... ssl_support_method = \"sni-only\" }",
        },
    ],

    # ================================================================
    # WAF  (WAF: SEC03)
    # ================================================================
    "aws_wafv2_web_acl": [
        {
            "id": "WAF-001",
            "pillar": "SEC",
            "description": "WAFv2 Web ACL should have at least one rule",
            "severity": "MEDIUM",
            "check": lambda c: bool(c.get("rule") or _blocks(c, "rule")),
            "message": "WAFv2 Web ACL has no rules. All requests pass through without inspection.",
            "recommendation": "Add AWS managed rule groups: AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet",
        },
        {
            "id": "WAF-002",
            "pillar": "OPS",
            "description": "WAFv2 should have logging enabled",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify WAFv2 has aws_wafv2_web_acl_logging_configuration associated. Blocked requests should be logged. "
                       "Logging is configured via a separate resource and cannot be verified here.",
            "recommendation": "Create aws_wafv2_web_acl_logging_configuration pointing to Kinesis Firehose or S3.",
        },
    ],

    # ================================================================
    # Elastic IP  (WAF: COST01)
    # ================================================================
    "aws_eip": [
        {
            "id": "EIP-001",
            "pillar": "COST",
            "description": "Elastic IP should be tagged to track its purpose",
            "severity": "INFO",
            "check": lambda c: bool(c.get("tags")),
            "message": "EIP has no tags. Untagged EIPs are difficult to audit. "
                       "Note: EIPs used by NAT Gateways or instances may appear unassociated in static analysis.",
            "recommendation": "Add tags = { Name = ... Purpose = ... } to identify ownership.",
        },
    ],

    # ================================================================
    # Backup  (WAF: REL02)
    # ================================================================
    "aws_backup_plan": [
        {
            "id": "BAK-001",
            "pillar": "REL",
            "description": "Backup plan rules should include a lifecycle configuration",
            "severity": "MEDIUM",
            "check": lambda c: any(
                "lifecycle" in str(r) for r in _blocks(c, "rule")
            ),
            "message": "Backup plan has no lifecycle rules. Old backups are kept indefinitely (cost) or deleted too soon (risk).",
            "recommendation": "Add lifecycle { cold_storage_after = 30 delete_after = 365 } to backup rules.",
        },
        {
            "id": "BAK-002",
            "pillar": "REL",
            "description": "Backup plan should have a recovery point in multiple regions",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Consider enabling cross-region backup copy for critical workloads (REL02). "
                       "Cross-region destination vault cannot be verified statically.",
            "recommendation": "Add copy_action { destination_vault_arn = <arn in secondary region> } to backup rules.",
        },
    ],

    # ================================================================
    # DynamoDB  (WAF: SEC05, REL01, REL02, COST01)
    # ================================================================
    "aws_dynamodb_table": [
        {
            "id": "DDB-001",
            "pillar": "REL",
            "description": "DynamoDB point-in-time recovery (PITR) must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "point_in_time_recovery").get("enabled") is True,
            "message": "PITR is disabled. Table cannot be restored to an arbitrary second within the last 35 days.",
            "recommendation": "Set point_in_time_recovery { enabled = true }",
        },
        {
            "id": "DDB-002",
            "pillar": "SEC",
            "description": "DynamoDB table should be encrypted with a CMK",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "server_side_encryption").get("enabled") is True,
            "message": "DynamoDB server-side encryption is not explicitly enabled with a CMK.",
            "recommendation": "Set server_side_encryption { enabled = true kms_key_arn = <aws_kms_key ARN> }",
        },
        {
            "id": "DDB-003",
            "pillar": "REL",
            "description": "DynamoDB deletion protection should be enabled",
            "severity": "HIGH",
            "check": lambda c: c.get("deletion_protection_enabled") is True,
            "message": "deletion_protection_enabled = false. Table can be accidentally deleted.",
            "recommendation": "Set deletion_protection_enabled = true",
        },
        {
            "id": "DDB-004",
            "pillar": "COST",
            "description": "DynamoDB should use on-demand or auto-scaling billing",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Review billing_mode. PAY_PER_REQUEST (on-demand) is recommended for unpredictable workloads; "
                       "PROVISIONED with autoscaling for predictable ones.",
            "recommendation": "Set billing_mode = \"PAY_PER_REQUEST\" or configure autoscaling with aws_appautoscaling_target.",
        },
        {
            "id": "DDB-005",
            "pillar": "OPS",
            "description": "DynamoDB table should have TTL configured for expiring stale data",
            "severity": "INFO",
            "check": lambda c: bool(_block(c, "ttl").get("attribute_name")),
            "message": "No TTL configured. Stale items accumulate, increasing storage costs.",
            "recommendation": "Set ttl { enabled = true attribute_name = \"expiry_time\" } where applicable.",
        },
        {
            "id": "DDB-006",
            "pillar": "OPS",
            "description": "DynamoDB contributor insights should be enabled for large tables",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Consider enabling contributor insights to identify hot partitions. "
                       "Configured via separate aws_dynamodb_contributor_insights resource — verify manually.",
            "recommendation": "Enable aws_dynamodb_contributor_insights for tables with high read/write throughput.",
        },
    ],

    # ================================================================
    # ECR  (WAF: SEC03, SEC05, COST01)
    # ================================================================
    "aws_ecr_repository": [
        {
            "id": "ECR-001",
            "pillar": "SEC",
            "description": "ECR image scanning on push must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "image_scanning_configuration").get("scan_on_push") is True,
            "message": "scan_on_push = false. Container images are not scanned for CVEs on push.",
            "recommendation": "Set image_scanning_configuration { scan_on_push = true }",
        },
        {
            "id": "ECR-002",
            "pillar": "SEC",
            "description": "ECR image tag immutability should be enforced",
            "severity": "MEDIUM",
            "check": lambda c: c.get("image_tag_mutability", "MUTABLE") == "IMMUTABLE",
            "message": "image_tag_mutability = MUTABLE. Tags (e.g., 'latest') can be silently overwritten.",
            "recommendation": "Set image_tag_mutability = \"IMMUTABLE\" to prevent tag overwrites.",
        },
        {
            "id": "ECR-003",
            "pillar": "SEC",
            "description": "ECR repository should be encrypted with a CMK",
            "severity": "LOW",
            "check": lambda c: bool(_block(c, "encryption_configuration").get("kms_key")),
            "message": "ECR repository is encrypted with the default AWS-managed key, not a CMK.",
            "recommendation": "Set encryption_configuration { encryption_type = \"KMS\" kms_key = <aws_kms_key ARN> }",
        },
        {
            "id": "ECR-004",
            "pillar": "COST",
            "description": "ECR repository should have a lifecycle policy to remove old images",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "No aws_ecr_lifecycle_policy associated. Old/untagged images accumulate and increase storage cost. "
                       "This cannot be verified from the aws_ecr_repository resource alone — check manually.",
            "recommendation": "Create aws_ecr_lifecycle_policy to expire untagged images after 14 days and keep last N tagged.",
        },
    ],

    # ================================================================
    # API Gateway  (WAF: SEC03, OPS02, PERF01)
    # ================================================================
    "aws_api_gateway_stage": [
        {
            "id": "APIG-001",
            "pillar": "OPS",
            "description": "API Gateway stage access logging should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "access_log_settings").get("destination_arn")),
            "message": "No access_log_settings. API request/response logs are not captured.",
            "recommendation": "Set access_log_settings { destination_arn = <cloudwatch_log_group_arn> }",
        },
        {
            "id": "APIG-002",
            "pillar": "PERF",
            "description": "API Gateway stage should have throttling configured",
            "severity": "MEDIUM",
            "check": lambda c: (
                _int(c, "throttling_burst_limit", -1) >= 0 or
                _int(c, "throttling_rate_limit", -1) >= 0
            ),
            "message": "No throttling limits set. Unprotected endpoints can be overwhelmed by traffic spikes.",
            "recommendation": "Set throttling_burst_limit and throttling_rate_limit at stage or method level.",
        },
        {
            "id": "APIG-003",
            "pillar": "OPS",
            "description": "API Gateway stage should have CloudWatch metrics enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "default_route_settings").get("metrics_enabled") is True
                or c.get("metrics_enabled") is True,
            "message": "API Gateway metrics (4xx, 5xx, latency) are not enabled.",
            "recommendation": "Set metrics_enabled = true on the stage or default_route_settings.",
        },
        {
            "id": "APIG-004",
            "pillar": "SEC",
            "description": "API Gateway should have a WAF Web ACL associated",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "WAF ACL association cannot be verified from the aws_api_gateway_stage resource alone. "
                       "Check whether aws_wafv2_web_acl_association exists for this stage.",
            "recommendation": "Create aws_wafv2_web_acl_association to protect the API from common threats.",
        },
    ],

    "aws_api_gateway_v2_stage": [
        {
            "id": "APIG2-001",
            "pillar": "OPS",
            "description": "API Gateway v2 stage access logging should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "access_log_settings").get("destination_arn")),
            "message": "No access_log_settings. HTTP API request logs are not captured.",
            "recommendation": "Set access_log_settings { destination_arn = <cloudwatch_log_group_arn> }",
        },
        {
            "id": "APIG2-002",
            "pillar": "PERF",
            "description": "API Gateway v2 stage should have throttling configured",
            "severity": "MEDIUM",
            "check": lambda c: (
                _block(c, "default_route_settings").get("throttling_burst_limit") is not None or
                _block(c, "default_route_settings").get("throttling_rate_limit") is not None
            ),
            "message": "No throttling settings on HTTP API stage.",
            "recommendation": "Set default_route_settings { throttling_burst_limit = 1000 throttling_rate_limit = 500 }",
        },
    ],

    # ================================================================
    # OpenSearch / Elasticsearch  (WAF: SEC03, SEC05)
    # ================================================================
    "aws_opensearch_domain": [
        {
            "id": "OS-001",
            "pillar": "SEC",
            "description": "OpenSearch node-to-node encryption must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "node_to_node_encryption").get("enabled") is True,
            "message": "Node-to-node encryption is disabled. Intra-cluster traffic is unencrypted.",
            "recommendation": "Set node_to_node_encryption { enabled = true }",
        },
        {
            "id": "OS-002",
            "pillar": "SEC",
            "description": "OpenSearch encryption at rest must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "encrypt_at_rest").get("enabled") is True,
            "message": "Encryption at rest is disabled. Domain data is stored unencrypted.",
            "recommendation": "Set encrypt_at_rest { enabled = true }",
        },
        {
            "id": "OS-003",
            "pillar": "SEC",
            "description": "OpenSearch domain should enforce HTTPS only",
            "severity": "HIGH",
            "check": lambda c: _block(c, "domain_endpoint_options").get("enforce_https") is True,
            "message": "enforce_https = false. HTTP connections to OpenSearch are allowed.",
            "recommendation": "Set domain_endpoint_options { enforce_https = true tls_security_policy = \"Policy-Min-TLS-1-2-2019-07\" }",
        },
        {
            "id": "OS-004",
            "pillar": "SEC",
            "description": "OpenSearch should not be publicly accessible",
            "severity": "CRITICAL",
            "check": lambda c: bool(_block(c, "vpc_options").get("subnet_ids") or
                                    _blocks(c, "vpc_options")),
            "message": "OpenSearch domain has no vpc_options. Domain may be publicly accessible.",
            "recommendation": "Set vpc_options { subnet_ids = [...] security_group_ids = [...] }",
        },
        {
            "id": "OS-005",
            "pillar": "REL",
            "description": "OpenSearch should have at least 3 dedicated master nodes",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "cluster_config").get("dedicated_master_enabled") is True,
            "message": "Dedicated master nodes are not enabled. Cluster stability at risk during high indexing load.",
            "recommendation": "Set cluster_config { dedicated_master_enabled = true dedicated_master_count = 3 }",
        },
    ],

    "aws_elasticsearch_domain": [
        {
            "id": "ES-001",
            "pillar": "SEC",
            "description": "Elasticsearch node-to-node encryption must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "node_to_node_encryption").get("enabled") is True,
            "message": "node_to_node_encryption is disabled on Elasticsearch domain.",
            "recommendation": "Set node_to_node_encryption { enabled = true } (migrate to OpenSearch is recommended)",
        },
        {
            "id": "ES-002",
            "pillar": "SEC",
            "description": "Elasticsearch encryption at rest must be enabled",
            "severity": "HIGH",
            "check": lambda c: _block(c, "encrypt_at_rest").get("enabled") is True,
            "message": "Encryption at rest is disabled.",
            "recommendation": "Set encrypt_at_rest { enabled = true }",
        },
    ],

    # ================================================================
    # Redshift  (WAF: SEC05, OPS02, COST01)
    # ================================================================
    "aws_redshift_cluster": [
        {
            "id": "RS-001",
            "pillar": "SEC",
            "description": "Redshift cluster must be encrypted",
            "severity": "HIGH",
            "check": lambda c: c.get("encrypted") is True,
            "message": "Redshift cluster is not encrypted. Data warehouse data stored in plaintext.",
            "recommendation": "Set encrypted = true and kms_key_id = <aws_kms_key ARN>",
        },
        {
            "id": "RS-002",
            "pillar": "SEC",
            "description": "Redshift cluster should not be publicly accessible",
            "severity": "CRITICAL",
            "check": lambda c: c.get("publicly_accessible") is not True,
            "message": "Redshift cluster is publicly accessible from the internet.",
            "recommendation": "Set publicly_accessible = false and place in a private subnet.",
        },
        {
            "id": "RS-003",
            "pillar": "OPS",
            "description": "Redshift audit logging should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "logging").get("enable")),
            "message": "Redshift audit logging is disabled. User activity and connection logs are unavailable.",
            "recommendation": "Set logging { enable = true bucket_name = <s3_bucket> }",
        },
        {
            "id": "RS-004",
            "pillar": "PERF",
            "description": "Redshift should use enhanced VPC routing",
            "severity": "MEDIUM",
            "check": lambda c: c.get("enhanced_vpc_routing") is True,
            "message": "Enhanced VPC routing is disabled. COPY/UNLOAD traffic may route through the internet.",
            "recommendation": "Set enhanced_vpc_routing = true to route traffic through VPC.",
        },
        {
            "id": "RS-005",
            "pillar": "REL",
            "description": "Redshift automated snapshot retention should be >= 7 days",
            "severity": "MEDIUM",
            "check": lambda c: _int(c, "automated_snapshot_retention_period", 1) >= 7,
            "message": "Redshift snapshot retention < 7 days. Recovery window is too short.",
            "recommendation": "Set automated_snapshot_retention_period >= 7",
        },
        {
            "id": "RS-006",
            "pillar": "SEC",
            "description": "Redshift default database password should be managed via Secrets Manager",
            "severity": "MEDIUM",
            "check": lambda c: not bool(c.get("master_password")),
            "message": "master_password is hardcoded in Terraform config. Rotate and move to Secrets Manager.",
            "recommendation": "Use manage_master_password = true (Redshift Serverless) or store in Secrets Manager.",
        },
    ],

    # ================================================================
    # Kinesis  (WAF: SEC05, OPS02)
    # ================================================================
    "aws_kinesis_stream": [
        {
            "id": "KIN-001",
            "pillar": "SEC",
            "description": "Kinesis stream should be encrypted with a KMS CMK",
            "severity": "MEDIUM",
            "check": lambda c: c.get("encryption_type", "NONE") != "NONE",
            "message": "Kinesis stream is not KMS-encrypted. Stream data at rest is unprotected.",
            "recommendation": "Set encryption_type = \"KMS\" and kms_key_id = <aws_kms_key ARN>",
        },
        {
            "id": "KIN-002",
            "pillar": "OPS",
            "description": "Kinesis stream retention should be >= 24 hours (default) and consider extended",
            "severity": "LOW",
            "check": lambda c: _int(c, "retention_period", 24) >= 24,
            "message": "Kinesis retention_period < 24 hours. Data may be lost before consumers can process it.",
            "recommendation": "Set retention_period >= 24 (up to 8760 hours for extended retention).",
        },
        {
            "id": "KIN-003",
            "pillar": "OPS",
            "description": "Kinesis stream shard-level enhanced metrics should be enabled",
            "severity": "LOW",
            "check": lambda c: bool(c.get("shard_level_metrics")),
            "message": "No shard-level metrics configured. Cannot detect individual hot/cold shards.",
            "recommendation": "Set shard_level_metrics = [\"IncomingBytes\", \"OutgoingBytes\", \"ReadProvisionedThroughputExceeded\"]",
        },
    ],

    "aws_kinesis_firehose_delivery_stream": [
        {
            "id": "KFH-001",
            "pillar": "SEC",
            "description": "Kinesis Firehose should encrypt data at rest",
            "severity": "MEDIUM",
            "check": lambda c: bool(
                _block(c, "server_side_encryption").get("enabled") or
                _block(c, "server_side_encryption").get("key_arn")
            ),
            "message": "Kinesis Firehose server-side encryption is not enabled.",
            "recommendation": "Set server_side_encryption { enabled = true key_type = \"CUSTOMER_MANAGED_CMK\" key_arn = ... }",
        },
        {
            "id": "KFH-002",
            "pillar": "OPS",
            "description": "Kinesis Firehose should have error logging enabled",
            "severity": "MEDIUM",
            "check": lambda c: any(
                _block(dest, "cloudwatch_logging_options").get("enabled") is True
                for key in ["s3_configuration", "extended_s3_configuration", "elasticsearch_configuration",
                            "opensearch_configuration", "redshift_configuration", "http_endpoint_configuration"]
                for dest in [_block(c, key)]
                if dest
            ),
            "message": "Firehose delivery error logging to CloudWatch is not enabled. Delivery failures go unnoticed.",
            "recommendation": "Add cloudwatch_logging_options { enabled = true } to the destination configuration.",
        },
    ],

    # ================================================================
    # MSK (Managed Kafka)  (WAF: SEC05, REL01)
    # ================================================================
    "aws_msk_cluster": [
        {
            "id": "MSK-001",
            "pillar": "SEC",
            "description": "MSK cluster should enforce TLS in-transit encryption",
            "severity": "HIGH",
            "check": lambda c: _block(
                _block(c, "encryption_info"), "encryption_in_transit"
            ).get("client_broker", "TLS_PLAINTEXT") == "TLS",
            "message": "MSK client_broker encryption allows PLAINTEXT. Kafka traffic may travel unencrypted.",
            "recommendation": "Set encryption_info { encryption_in_transit { client_broker = \"TLS\" } }",
        },
        {
            "id": "MSK-002",
            "pillar": "SEC",
            "description": "MSK cluster broker storage should be encrypted with a CMK",
            "severity": "MEDIUM",
            "check": lambda c: bool(
                _block(_block(c, "encryption_info"), "encryption_at_rest").get("data_volume_kms_key_id")
            ),
            "message": "MSK broker EBS volumes are not encrypted with a CMK.",
            "recommendation": "Set encryption_info { encryption_at_rest { data_volume_kms_key_id = <kms_key_arn> } }",
        },
        {
            "id": "MSK-003",
            "pillar": "OPS",
            "description": "MSK broker logs should be shipped to CloudWatch/S3",
            "severity": "MEDIUM",
            "check": lambda c: (
                _block(_block(_block(c, "logging_info"), "broker_logs"), "cloudwatch_logs").get("enabled") is True or
                _block(_block(_block(c, "logging_info"), "broker_logs"), "s3").get("enabled") is True
            ),
            "message": "MSK broker logs are not configured. Kafka broker errors and warnings are unobservable.",
            "recommendation": "Set logging_info { broker_logs { cloudwatch_logs { enabled = true log_group = ... } } }",
        },
        {
            "id": "MSK-004",
            "pillar": "SEC",
            "description": "MSK should require client authentication (TLS or SASL)",
            "severity": "HIGH",
            "check": lambda c: bool(
                _block(_block(c, "client_authentication"), "tls").get("certificate_authority_arns") or
                _block(_block(c, "client_authentication"), "sasl").get("scram") or
                _block(_block(c, "client_authentication"), "sasl").get("iam")
            ),
            "message": "MSK has no client authentication configured. Any client in the VPC can connect.",
            "recommendation": "Configure client_authentication with TLS mutual auth or SASL/SCRAM or SASL/IAM.",
        },
    ],

    # ================================================================
    # ACM Certificate  (WAF: SEC05, REL01)
    # ================================================================
    "aws_acm_certificate": [
        {
            "id": "ACM-001",
            "pillar": "SEC",
            "description": "ACM certificate validation method should be DNS (not EMAIL)",
            "severity": "MEDIUM",
            "check": lambda c: c.get("validation_method", "DNS") == "DNS",
            "message": "Certificate uses EMAIL validation. DNS validation is automated and does not expire.",
            "recommendation": "Set validation_method = \"DNS\" and create aws_acm_certificate_validation with Route53.",
        },
        {
            "id": "ACM-002",
            "pillar": "SEC",
            "description": "ACM certificate should have certificate transparency logging enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "options").get("certificate_transparency_logging_preference", "ENABLED") == "ENABLED",
            "message": "Certificate transparency logging is disabled. Mis-issued certs cannot be detected via CT logs.",
            "recommendation": "Set options { certificate_transparency_logging_preference = \"ENABLED\" } (default)",
        },
    ],

    # ================================================================
    # AWS Config  (WAF: OPS01, SEC02)
    # ================================================================
    "aws_config_configuration_recorder": [
        {
            "id": "CFG-001",
            "pillar": "OPS",
            "description": "AWS Config recorder should record all resource types",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "recording_group").get("all_supported") is True,
            "message": "AWS Config is not recording all supported resource types. Configuration drift goes undetected.",
            "recommendation": "Set recording_group { all_supported = true include_global_resource_types = true }",
        },
    ],

    "aws_config_delivery_channel": [
        {
            "id": "CFG-002",
            "pillar": "OPS",
            "description": "AWS Config delivery channel snapshot frequency should be 24h or less",
            "severity": "LOW",
            "check": lambda c: _block(c, "snapshot_delivery_properties").get(
                "delivery_frequency", "TwentyFour_Hours"
            ) in ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"],
            "message": "Config snapshot delivery frequency is not set or outside expected values.",
            "recommendation": "Set snapshot_delivery_properties { delivery_frequency = \"TwentyFour_Hours\" }",
        },
    ],

    # ================================================================
    # Additional EC2 best practices  (WAF: SEC01, REL01, COST01)
    # ================================================================
    "aws_key_pair": [
        {
            "id": "EC2-KP-001",
            "pillar": "SEC",
            "description": "EC2 key pairs indicate SSH is used; prefer SSM Session Manager",
            "severity": "LOW",
            "check": lambda c: False,
            "message": "EC2 key pair defined. SSH access requires port 22 open and key management. "
                       "SSM Session Manager is keyless and auditable.",
            "recommendation": "Remove key_name from aws_instance and use SSM Session Manager for shell access.",
        },
    ],

    "aws_ebs_volume": [
        {
            "id": "EBS-001",
            "pillar": "SEC",
            "description": "Standalone EBS volume must be encrypted",
            "severity": "HIGH",
            "check": lambda c: c.get("encrypted") is True,
            "message": "EBS volume is not encrypted. Data at rest is unprotected.",
            "recommendation": "Set encrypted = true and optionally kms_key_id for CMK.",
        },
        {
            "id": "EBS-002",
            "pillar": "COST",
            "description": "EBS volume type should be gp3 for general workloads",
            "severity": "LOW",
            "check": lambda c: c.get("type", "gp3") == "gp3",
            "message": "EBS volume is not gp3. gp3 provides better performance per dollar than gp2.",
            "recommendation": "Set type = \"gp3\"",
        },
    ],

    "aws_launch_template": [
        {
            "id": "LT-001",
            "pillar": "SEC",
            "description": "Launch template should enforce IMDSv2",
            "severity": "HIGH",
            "check": lambda c: _block(c, "metadata_options").get("http_tokens") == "required",
            "message": "Launch template does not enforce IMDSv2. Instances launched from this template are vulnerable to SSRF.",
            "recommendation": "Set metadata_options { http_tokens = \"required\" http_put_response_hop_limit = 1 }",
        },
        {
            "id": "LT-002",
            "pillar": "SEC",
            "description": "Launch template root volume should be encrypted",
            "severity": "HIGH",
            "check": lambda c: any(
                bd.get("encrypted") is True or bd.get("ebs", {}).get("encrypted") is True
                for bd in _blocks(c, "block_device_mappings")
            ) if _blocks(c, "block_device_mappings") else True,
            "message": "Root EBS volume in launch template is not encrypted.",
            "recommendation": "Set block_device_mappings { ebs { encrypted = true } }",
        },
        {
            "id": "LT-003",
            "pillar": "COST",
            "description": "Launch template should not specify a key name (use SSM instead)",
            "severity": "LOW",
            "check": lambda c: not bool(c.get("key_name")),
            "message": "key_name is set in launch template. SSH access should be replaced with SSM Session Manager.",
            "recommendation": "Remove key_name and configure SSM agent with AmazonSSMManagedInstanceCore policy.",
        },
    ],

    # ================================================================
    # Route 53  (WAF: REL01, SEC03)
    # ================================================================
    "aws_route53_health_check": [
        {
            "id": "R53-001",
            "pillar": "REL",
            "description": "Route53 health check failure threshold should be 3 or fewer",
            "severity": "LOW",
            "check": lambda c: _int(c, "failure_threshold", 3) <= 3,
            "message": "High failure_threshold delays DNS failover. Default is 3 (60 seconds for 20s interval).",
            "recommendation": "Set failure_threshold = 3 and request_interval = 10 for faster detection.",
        },
        {
            "id": "R53-002",
            "pillar": "REL",
            "description": "Route53 health check should have CloudWatch alarms",
            "severity": "LOW",
            "check": lambda c: c.get("cloudwatch_alarm_name") is not None or True,
            "message": "Consider associating a CloudWatch alarm with this health check for proactive alerting.",
            "recommendation": "Link health check to aws_cloudwatch_metric_alarm for HealthCheckStatus metric.",
        },
    ],

    # ================================================================
    # Security Hub / Macie  (WAF: SEC02, SEC06)
    # ================================================================
    "aws_securityhub_account": [
        {
            "id": "SH-001",
            "pillar": "SEC",
            "description": "Security Hub auto-enable controls should be set",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify Security Hub has standards subscriptions (CIS, FSBP) and auto-remediation enabled.",
            "recommendation": "Add aws_securityhub_standards_subscription for CIS 1.4.0 and FSBP.",
        },
    ],

    "aws_macie2_account": [
        {
            "id": "MAC-001",
            "pillar": "SEC",
            "description": "Amazon Macie should be enabled for S3 data classification",
            "severity": "LOW",
            "check": lambda c: c.get("status", "ENABLED") == "ENABLED",
            "message": "Macie is not enabled. PII and sensitive data in S3 buckets goes undetected.",
            "recommendation": "Set status = \"ENABLED\" and configure aws_macie2_classification_job for critical buckets.",
        },
    ],

    # ================================================================
    # VPN / Direct Connect  (WAF: SEC03, REL01)
    # ================================================================
    "aws_vpn_connection": [
        {
            "id": "VPN-001",
            "pillar": "SEC",
            "description": "VPN connection should use IKEv2 and AES256",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify VPN tunnel options use IKEv2, AES-256-GCM, SHA-256, and DH Group 14+. "
                       "Tunnel cipher settings often rely on the peer device and require manual verification.",
            "recommendation": "Set tunnel1_ike_versions = [\"ikev2\"] and tunnel1_phase1_encryption_algorithms = [\"AES256-GCM-16\"]",
        },
    ],

    # ================================================================
    # Cost Optimization patterns  (WAF: COST01, COST02)
    # ================================================================
    "aws_nat_gateway": [
        {
            "id": "NGW-001",
            "pillar": "COST",
            "description": "NAT Gateway count should be reviewed for cost",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Each NAT Gateway costs ~$32/month + $0.045/GB data processed. "
                       "Verify the number of NAT Gateways is appropriate for your HA requirements.",
            "recommendation": "For non-production environments, consider a single NAT Gateway. "
                               "For production, one per AZ is recommended.",
        },
    ],

    "aws_cloudwatch_dashboard": [
        {
            "id": "DASH-001",
            "pillar": "OPS",
            "description": "CloudWatch dashboard is defined (good practice)",
            "severity": "INFO",
            "check": lambda c: True,
            "message": "Dashboard exists. Verify it covers all critical services and SLI/SLO metrics.",
            "recommendation": "Include latency (p50/p99), error rates, saturation (CPU/memory), and traffic metrics.",
        },
    ],

    # ================================================================
    # ECS Cluster  (WAF: OPS02, SEC01)
    # ================================================================
    "aws_ecs_cluster": [
        {
            "id": "ECSC-001",
            "pillar": "OPS",
            "description": "ECS cluster Container Insights should be enabled",
            "severity": "MEDIUM",
            "check": lambda c: any(
                s.get("name") == "containerInsights" and s.get("value") == "enabled"
                for s in _blocks(c, "setting")
            ),
            "message": "Container Insights is not enabled. Cluster-level CPU/memory/network metrics are unavailable.",
            "recommendation": "Set setting { name = \"containerInsights\" value = \"enabled\" }",
        },
        {
            "id": "ECSC-002",
            "pillar": "OPS",
            "description": "ECS cluster execute command logging should be configured",
            "severity": "LOW",
            "check": lambda c: bool(
                _block(_block(c, "configuration"), "execute_command_configuration").get("logging")
            ),
            "message": "ECS Exec command logging is not configured. Interactive exec sessions leave no audit trail.",
            "recommendation": "Set configuration { execute_command_configuration { logging = \"OVERRIDE\" log_configuration { ... } } }",
        },
    ],

    # ================================================================
    # CodeBuild  (WAF: SEC01, SEC05, OPS02)
    # ================================================================
    "aws_codebuild_project": [
        {
            "id": "CB-001",
            "pillar": "SEC",
            "description": "CodeBuild project artifacts should be encrypted",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "artifacts").get("encryption_disabled") is not True,
            "message": "CodeBuild artifact encryption is disabled. Build outputs are stored unencrypted in S3.",
            "recommendation": "Set artifacts { encryption_disabled = false } (default is false; explicitly set to avoid accidental disable)",
        },
        {
            "id": "CB-002",
            "pillar": "SEC",
            "description": "CodeBuild project should not run builds in privileged mode",
            "severity": "HIGH",
            "check": lambda c: _block(c, "environment").get("privileged_mode") is not True,
            "message": "privileged_mode = true in CodeBuild environment. Containers run with elevated host access.",
            "recommendation": "Set environment { privileged_mode = false } unless building Docker images (justify and document).",
        },
        {
            "id": "CB-003",
            "pillar": "SEC",
            "description": "CodeBuild project should run inside a VPC for network isolation",
            "severity": "LOW",
            "check": lambda c: bool(_block(c, "vpc_config").get("vpc_id")),
            "message": "CodeBuild project is not running inside a VPC. Build environment has internet-exposed networking.",
            "recommendation": "Set vpc_config { vpc_id = ... subnets = [...] security_group_ids = [...] }",
        },
        {
            "id": "CB-004",
            "pillar": "OPS",
            "description": "CodeBuild logs should be sent to CloudWatch or S3",
            "severity": "MEDIUM",
            "check": lambda c: (
                _block(_block(c, "logs_config"), "cloudwatch_logs").get("status", "ENABLED") == "ENABLED" or
                _block(_block(c, "logs_config"), "s3_logs").get("status") == "ENABLED"
            ),
            "message": "CodeBuild logs are not configured. Build output and errors are not persisted.",
            "recommendation": "Set logs_config { cloudwatch_logs { group_name = ... stream_name = ... } }",
        },
    ],

    # ================================================================
    # CodePipeline  (WAF: SEC05, OPS02)
    # ================================================================
    "aws_codepipeline": [
        {
            "id": "CP-001",
            "pillar": "SEC",
            "description": "CodePipeline artifact store should be encrypted with a CMK",
            "severity": "MEDIUM",
            "check": lambda c: bool(
                _block(c, "artifact_store").get("encryption_key") or
                any(bool(_block(a, "encryption_key")) for a in _blocks(c, "artifact_store"))
            ),
            "message": "CodePipeline artifact store does not use a KMS CMK. Artifacts use the default S3 SSE key.",
            "recommendation": "Set artifact_store { encryption_key { id = <kms_key_arn> type = \"KMS\" } }",
        },
        {
            "id": "CP-002",
            "pillar": "OPS",
            "description": "CodePipeline should have at least 3 stages (Source, Build, Deploy)",
            "severity": "INFO",
            "check": lambda c: len(_blocks(c, "stage")) >= 3,
            "message": "Pipeline has fewer than 3 stages. A minimal pipeline typically needs Source, Build, and Deploy.",
            "recommendation": "Ensure pipeline has stages for source, build, test, and deploy.",
        },
    ],

    # ================================================================
    # Launch Configuration (deprecated)  (WAF: SEC05, COST01)
    # ================================================================
    "aws_launch_configuration": [
        {
            "id": "LC-001",
            "pillar": "SEC",
            "description": "aws_launch_configuration is deprecated; migrate to aws_launch_template",
            "severity": "MEDIUM",
            "check": lambda c: False,
            "message": "aws_launch_configuration is deprecated by AWS. It lacks support for IMDSv2 enforcement and newer instance features.",
            "recommendation": "Replace aws_launch_configuration with aws_launch_template for full feature support.",
        },
        {
            "id": "LC-002",
            "pillar": "SEC",
            "description": "Launch configuration root EBS volume should be encrypted",
            "severity": "HIGH",
            "check": lambda c: _block(c, "root_block_device").get("encrypted") is True,
            "message": "Root EBS volume in launch configuration is not encrypted. Violates SEC05.",
            "recommendation": "Set root_block_device { encrypted = true }",
        },
        {
            "id": "LC-003",
            "pillar": "SEC",
            "description": "Launch configuration should not assign public IP addresses",
            "severity": "MEDIUM",
            "check": lambda c: c.get("associate_public_ip_address") is not True,
            "message": "associate_public_ip_address = true. Instances get public IPs automatically.",
            "recommendation": "Set associate_public_ip_address = false and use NAT Gateway for outbound access.",
        },
    ],

    # ================================================================
    # Security Group Rule (standalone)  (WAF: SEC03)
    # ================================================================
    "aws_security_group_rule": [
        {
            "id": "SGR-001",
            "pillar": "SEC",
            "description": "Standalone SG rule must not allow 0.0.0.0/0 on admin/DB ports",
            "severity": "CRITICAL",
            "check": lambda c: not (
                c.get("type") == "ingress" and
                ("0.0.0.0/0" in (c.get("cidr_blocks") or []) or "::/0" in (c.get("ipv6_cidr_blocks") or [])) and
                int(c.get("from_port", 0)) in [22, 3306, 5432, 1433, 27017, 6379, 5439, 9200]
            ),
            "message": "Security group rule allows unrestricted 0.0.0.0/0 ingress on a sensitive admin/DB port.",
            "recommendation": "Restrict cidr_blocks to specific known CIDR ranges or use source_security_group_id.",
        },
        {
            "id": "SGR-002",
            "pillar": "SEC",
            "description": "Standalone SG rule must not allow all traffic from 0.0.0.0/0 (protocol=-1)",
            "severity": "CRITICAL",
            "check": lambda c: not (
                c.get("type") == "ingress" and
                "0.0.0.0/0" in (c.get("cidr_blocks") or []) and
                str(c.get("protocol", "")) == "-1"
            ),
            "message": "Security group rule allows ALL ingress traffic from 0.0.0.0/0 (protocol=-1). Completely open.",
            "recommendation": "Restrict to specific protocols, ports, and source CIDR blocks.",
        },
        {
            "id": "SGR-003",
            "pillar": "SEC",
            "description": "Egress rule should not allow unrestricted outbound to all ports",
            "severity": "MEDIUM",
            "check": lambda c: not (
                c.get("type") == "egress" and
                "0.0.0.0/0" in (c.get("cidr_blocks") or []) and
                str(c.get("protocol", "")) == "-1"
            ),
            "message": "Security group rule allows all egress traffic to 0.0.0.0/0. Consider restricting outbound.",
            "recommendation": "Restrict egress to specific protocols and ports required by the application.",
        },
    ],

    # ================================================================
    # Route53 Record  (WAF: REL01)
    # ================================================================
    "aws_route53_record": [
        {
            "id": "R53R-001",
            "pillar": "REL",
            "description": "Non-simple Route53 records should have a health_check_id",
            "severity": "LOW",
            "check": lambda c: (
                not c.get("failover_routing_policy") and
                not c.get("weighted_routing_policy") and
                not c.get("latency_routing_policy")
            ) or bool(c.get("health_check_id")),
            "message": "Failover/weighted/latency routing record has no health_check_id. Unhealthy endpoints may still receive traffic.",
            "recommendation": "Set health_check_id = <aws_route53_health_check.id> on all non-simple routing records.",
        },
        {
            "id": "R53R-002",
            "pillar": "REL",
            "description": "Route53 record TTL should be <= 1 hour for failover agility",
            "severity": "INFO",
            "check": lambda c: c.get("alias") is not None or 0 < _int(c, "ttl", 300) <= 3600,
            "message": "Route53 record TTL is very high (> 1 hour). DNS failover during incidents will be slow.",
            "recommendation": "Set TTL = 60~300 for records that may need failover. Alias records ignore TTL.",
        },
    ],

    # ================================================================
    # Step Functions  (WAF: OPS02, SEC05, REL01)
    # ================================================================
    "aws_sfn_state_machine": [
        {
            "id": "SFN-001",
            "pillar": "OPS",
            "description": "Step Functions state machine logging should be enabled (not OFF)",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "logging_configuration").get("level", "OFF") != "OFF",
            "message": "State machine logging level is OFF. Execution history and errors are not persisted to CloudWatch.",
            "recommendation": "Set logging_configuration { level = \"ALL\" include_execution_data = true log_destination = ... }",
        },
        {
            "id": "SFN-002",
            "pillar": "OPS",
            "description": "Step Functions X-Ray tracing should be enabled",
            "severity": "LOW",
            "check": lambda c: _block(c, "tracing_configuration").get("enabled") is True,
            "message": "X-Ray tracing is not enabled. End-to-end distributed traces across Lambda/ECS tasks are unavailable.",
            "recommendation": "Set tracing_configuration { enabled = true }",
        },
        {
            "id": "SFN-003",
            "pillar": "SEC",
            "description": "Step Functions state machine should be encrypted with a CMK",
            "severity": "MEDIUM",
            "check": lambda c: bool(_block(c, "encryption_configuration").get("kms_key_id")),
            "message": "State machine uses the default AWS-managed key, not a CMK. Execution data at rest has no dedicated key.",
            "recommendation": "Set encryption_configuration { type = \"CUSTOMER_MANAGED_KMS_KEY\" kms_key_id = <aws_kms_key ARN> }",
        },
    ],

    # ================================================================
    # SNS Topic Subscription  (WAF: REL01, OPS02)
    # ================================================================
    "aws_sns_topic_subscription": [
        {
            "id": "SNSS-001",
            "pillar": "REL",
            "description": "SNS subscription should have a dead-letter queue (redrive_policy)",
            "severity": "LOW",
            "check": lambda c: bool(c.get("redrive_policy")),
            "message": "No redrive_policy on SNS subscription. Failed message deliveries are silently discarded.",
            "recommendation": "Set redrive_policy = jsonencode({ deadLetterTargetArn = <sqs_queue_arn> })",
        },
        {
            "id": "SNSS-002",
            "pillar": "SEC",
            "description": "HTTPS SNS subscriptions should have delivery status logging enabled",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify SNS topic has delivery status logging enabled (on the aws_sns_topic side) for this subscription protocol.",
            "recommendation": "Set <protocol>_success_feedback_role_arn and <protocol>_failure_feedback_role_arn on aws_sns_topic.",
        },
    ],

    # ================================================================
    # IAM Policy Attachment  (WAF: SEC01, SEC02)
    # ================================================================
    "aws_iam_policy_attachment": [
        {
            "id": "IAMA-001",
            "pillar": "SEC",
            "description": "aws_iam_policy_attachment is exclusive and should be replaced with targeted attachment resources",
            "severity": "MEDIUM",
            "check": lambda c: False,
            "message": "aws_iam_policy_attachment is an exclusive resource — it will silently detach the policy from any "
                       "user/role/group not in its lists. This causes unexpected permission loss in shared environments.",
            "recommendation": "Replace with aws_iam_role_policy_attachment, aws_iam_user_policy_attachment, "
                               "or aws_iam_group_policy_attachment for non-exclusive, safe attachment.",
        },
    ],

    "aws_iam_role_policy_attachment": [
        {
            "id": "IAMRPA-001",
            "pillar": "SEC",
            "description": "IAM role should not attach overly broad AWS managed policies",
            "severity": "HIGH",
            "check": lambda c: not any(
                p in str(c.get("policy_arn", ""))
                for p in [
                    "AdministratorAccess",
                    "PowerUserAccess",
                    "IAMFullAccess",
                    "arn:aws:iam::aws:policy/AdministratorAccess",
                ]
            ),
            "message": "IAM role is attached to an overly broad AWS managed policy (AdministratorAccess / PowerUserAccess / IAMFullAccess).",
            "recommendation": "Replace with a least-privilege inline or customer-managed policy scoped to required actions.",
        },
    ],

    # ================================================================
    # CodeDeploy  (WAF: REL01, OPS02)
    # ================================================================
    "aws_codedeploy_deployment_group": [
        {
            "id": "CD-001",
            "pillar": "REL",
            "description": "CodeDeploy deployment group should have auto rollback configured",
            "severity": "MEDIUM",
            "check": lambda c: _block(c, "auto_rollback_configuration").get("enabled") is True,
            "message": "Auto rollback is not enabled. Failed deployments require manual intervention to recover.",
            "recommendation": "Set auto_rollback_configuration { enabled = true events = [\"DEPLOYMENT_FAILURE\"] }",
        },
        {
            "id": "CD-002",
            "pillar": "REL",
            "description": "CodeDeploy ECS/Lambda deployment should use blue/green strategy",
            "severity": "INFO",
            "check": lambda c: False,
            "message": "Verify deployment_style is BLUE_GREEN for ECS/Lambda deployments to minimize downtime. "
                       "Applicability depends on compute type (ECS/Lambda vs EC2) — verify manually.",
            "recommendation": "Set deployment_style { deployment_option = \"WITH_TRAFFIC_CONTROL\" deployment_type = \"BLUE_GREEN\" }",
        },
        {
            "id": "CD-003",
            "pillar": "OPS",
            "description": "CodeDeploy deployment group should have CloudWatch alarm monitoring",
            "severity": "LOW",
            "check": lambda c: bool(_block(c, "alarm_configuration").get("alarms")),
            "message": "No CloudWatch alarm_configuration on deployment group. Failed deployments may go undetected.",
            "recommendation": "Set alarm_configuration { enabled = true alarms = [<cloudwatch_alarm_name>] }",
        },
    ],

}

