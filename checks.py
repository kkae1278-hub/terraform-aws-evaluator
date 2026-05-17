"""Complex check functions referenced by YAML rules via op: fn."""

from helpers import _block, _blocks, _int


# ── Constant helpers ──────────────────────────────────────────────────────────

def always_false(c):
    """Used for informational / advisory rules that always fire."""
    return False


def always_true(c):
    """Used for positive-signal rules that always pass."""
    return True


# ── Security Group / SG Rule ────────────────────────────────────────────────

def sg_no_admin_ports_open(c):
    for i in _blocks(c, "ingress"):
        if (
            ("0.0.0.0/0" in (i.get("cidr_blocks") or []) or "::/0" in (i.get("ipv6_cidr_blocks") or []))
            and int(i.get("from_port", 0)) in [22, 3306, 5432, 1433, 27017, 6379, 5439, 9200]
        ):
            return False
    return True


def sg_no_all_traffic_open(c):
    for i in _blocks(c, "ingress"):
        if (
            "0.0.0.0/0" in (i.get("cidr_blocks") or [])
            and str(i.get("protocol", "")) == "-1"
        ):
            return False
    return True


def sgr_no_admin_ports_open(c):
    return not (
        c.get("type") == "ingress"
        and ("0.0.0.0/0" in (c.get("cidr_blocks") or []) or "::/0" in (c.get("ipv6_cidr_blocks") or []))
        and int(c.get("from_port", 0)) in [22, 3306, 5432, 1433, 27017, 6379, 5439, 9200]
    )


def sgr_no_all_traffic_open(c):
    return not (
        c.get("type") == "ingress"
        and "0.0.0.0/0" in (c.get("cidr_blocks") or [])
        and str(c.get("protocol", "")) == "-1"
    )


def sgr_no_unrestricted_egress(c):
    return not (
        c.get("type") == "egress"
        and "0.0.0.0/0" in (c.get("cidr_blocks") or [])
        and str(c.get("protocol", "")) == "-1"
    )


# ── VPC Endpoint ─────────────────────────────────────────────────────────────

def vpc_endpoint_private_dns(c):
    return (
        c.get("vpc_endpoint_type", "Interface") != "Interface"
        or c.get("private_dns_enabled") is True
    )


# ── ALB Listener ─────────────────────────────────────────────────────────────

def alb_listener_https_or_redirect(c):
    return (
        str(c.get("port", "")) == "443"
        or c.get("protocol", "") == "HTTPS"
        or (
            _block(c, "default_action").get("type") == "redirect"
            and _block(_block(c, "default_action"), "redirect").get("protocol") == "HTTPS"
        )
    )


def alb_listener_modern_ssl_policy(c):
    return (
        c.get("protocol", "") != "HTTPS"
        or c.get("ssl_policy", "ELBSecurityPolicy-TLS13-1-2-2021-06") not in [
            "ELBSecurityPolicy-2015-05",
            "ELBSecurityPolicy-TLS-1-0-2015-04",
            "ELBSecurityPolicy-TLS-1-1-2017-01",
        ]
    )


def alb_not_internet_facing(c):
    return not (
        c.get("internal") is False
        and c.get("load_balancer_type", "application") == "application"
    )


# ── ASG ───────────────────────────────────────────────────────────────────────

def asg_multi_az(c):
    return len(c.get("availability_zones", c.get("vpc_zone_identifier", []))) >= 2


# ── IAM ───────────────────────────────────────────────────────────────────────

def iam_no_wildcard_principal(c):
    return (
        '"AWS": "*"' not in str(c.get("assume_role_policy", ""))
        and "'AWS': '*'" not in str(c.get("assume_role_policy", ""))
    )


def iam_no_wildcard_action(c):
    return not any(
        '"Action": "*"' in str(c.get("policy", ""))
        or "'Action': '*'" in str(c.get("policy", ""))
        or '"Action":"*"' in str(c.get("policy", ""))
        for _ in [1]
    )


def iam_inline_no_wildcard_action(c):
    return '"Action": "*"' not in str(c.get("policy", ""))


def iam_role_description_set(c):
    return bool(c.get("description", "").strip())


def iam_kms_description_set(c):
    return bool(c.get("description", "").strip())


def iam_rpa_no_broad_policies(c):
    return not any(
        p in str(c.get("policy_arn", ""))
        for p in [
            "AdministratorAccess",
            "PowerUserAccess",
            "IAMFullAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess",
        ]
    )


# ── S3 ────────────────────────────────────────────────────────────────────────

def s3_all_public_access_blocked(c):
    return all([
        c.get("block_public_acls") is True,
        c.get("block_public_policy") is True,
        c.get("ignore_public_acls") is True,
        c.get("restrict_public_buckets") is True,
    ])


# ── SQS ───────────────────────────────────────────────────────────────────────

def sqs_no_public_policy(c):
    return (
        '"Principal": "*"' not in str(c.get("policy", ""))
        and '"Principal":"*"' not in str(c.get("policy", ""))
    )


def sqs_has_dlq(c):
    return bool(_block(c, "redrive_policy") or c.get("redrive_policy"))


# ── ECS ───────────────────────────────────────────────────────────────────────

def ecs_no_privileged_containers(c):
    return (
        '"privileged": true' not in str(c.get("container_definitions", ""))
        and '"privileged":true' not in str(c.get("container_definitions", ""))
    )


def ecs_cluster_container_insights(c):
    return any(
        s.get("name") == "containerInsights" and s.get("value") == "enabled"
        for s in _blocks(c, "setting")
    )


def ecs_cluster_exec_logging(c):
    return bool(
        _block(_block(c, "configuration"), "execute_command_configuration").get("logging")
    )


# ── EKS ───────────────────────────────────────────────────────────────────────

def eks_api_not_public_unrestricted(c):
    return (
        _block(c, "vpc_config").get("endpoint_public_access") is not True
        or bool(_block(c, "vpc_config").get("public_access_cidrs"))
    )


def eks_secrets_encrypted(c):
    return any(
        "secrets" in str(p.get("resources", "")).lower()
        for p in _blocks(c, "encryption_config")
    )


# ── GuardDuty ─────────────────────────────────────────────────────────────────

def guardduty_s3_protection_enabled(c):
    return _block(_block(c, "datasources"), "s3_logs").get("enable") is True


# ── CloudWatch Alarm ─────────────────────────────────────────────────────────

def cwa_has_action(c):
    return bool(
        c.get("alarm_actions")
        or c.get("ok_actions")
        or c.get("insufficient_data_actions")
    )


def cwa_evaluation_periods_reasonable(c):
    return 1 <= _int(c, "evaluation_periods", 1) <= 10


# ── SSM Parameter ─────────────────────────────────────────────────────────────

def ssm_secure_string_for_sensitive(c):
    return c.get("type", "String") in ["SecureString", "StringList"] or not any(
        kw in c.get("name", "").lower()
        for kw in ["password", "secret", "token", "key", "credential", "apikey"]
    )


# ── AWS Config ────────────────────────────────────────────────────────────────

def config_delivery_frequency_valid(c):
    return _block(c, "snapshot_delivery_properties").get(
        "delivery_frequency", "TwentyFour_Hours"
    ) in ["One_Hour", "Three_Hours", "Six_Hours", "Twelve_Hours", "TwentyFour_Hours"]


# ── Backup ────────────────────────────────────────────────────────────────────

def backup_has_lifecycle(c):
    return any("lifecycle" in str(r) for r in _blocks(c, "rule"))


# ── Kinesis Firehose ──────────────────────────────────────────────────────────

def kfh_sse_enabled(c):
    return bool(
        _block(c, "server_side_encryption").get("enabled")
        or _block(c, "server_side_encryption").get("key_arn")
    )


def kfh_error_logging_enabled(c):
    return any(
        _block(dest, "cloudwatch_logging_options").get("enabled") is True
        for key in [
            "s3_configuration",
            "extended_s3_configuration",
            "elasticsearch_configuration",
            "opensearch_configuration",
            "redshift_configuration",
            "http_endpoint_configuration",
        ]
        for dest in [_block(c, key)]
        if dest
    )


# ── MSK ───────────────────────────────────────────────────────────────────────

def msk_tls_in_transit(c):
    return _block(
        _block(c, "encryption_info"), "encryption_in_transit"
    ).get("client_broker", "TLS_PLAINTEXT") == "TLS"


def msk_at_rest_cmk(c):
    return bool(
        _block(_block(c, "encryption_info"), "encryption_at_rest").get("data_volume_kms_key_id")
    )


def msk_broker_logs_enabled(c):
    return (
        _block(_block(_block(c, "logging_info"), "broker_logs"), "cloudwatch_logs").get("enabled") is True
        or _block(_block(_block(c, "logging_info"), "broker_logs"), "s3").get("enabled") is True
    )


def msk_client_auth_configured(c):
    return bool(
        _block(_block(c, "client_authentication"), "tls").get("certificate_authority_arns")
        or _block(_block(c, "client_authentication"), "sasl").get("scram")
        or _block(_block(c, "client_authentication"), "sasl").get("iam")
    )


# ── Redshift ──────────────────────────────────────────────────────────────────

def redshift_no_master_password(c):
    return not bool(c.get("master_password"))


# ── OpenSearch ────────────────────────────────────────────────────────────────

def opensearch_in_vpc(c):
    return bool(
        _block(c, "vpc_options").get("subnet_ids")
        or _blocks(c, "vpc_options")
    )


# ── Lambda ────────────────────────────────────────────────────────────────────

def lambda_timeout_reasonable(c):
    return 0 < _int(c, "timeout", 3) <= 60


# ── Step Functions ────────────────────────────────────────────────────────────

def sfn_logging_not_off(c):
    return _block(c, "logging_configuration").get("level", "OFF") != "OFF"


# ── API Gateway ───────────────────────────────────────────────────────────────

def apig_throttling_configured(c):
    return (
        _int(c, "throttling_burst_limit", -1) >= 0
        or _int(c, "throttling_rate_limit", -1) >= 0
    )


def apig_metrics_enabled(c):
    return (
        _block(c, "default_route_settings").get("metrics_enabled") is True
        or c.get("metrics_enabled") is True
    )


def apig2_throttling_configured(c):
    return (
        _block(c, "default_route_settings").get("throttling_burst_limit") is not None
        or _block(c, "default_route_settings").get("throttling_rate_limit") is not None
    )


# ── Route 53 ──────────────────────────────────────────────────────────────────

def r53_record_has_health_check(c):
    return (
        not c.get("failover_routing_policy")
        and not c.get("weighted_routing_policy")
        and not c.get("latency_routing_policy")
    ) or bool(c.get("health_check_id"))


def r53_record_ttl_low(c):
    return c.get("alias") is not None or 0 < _int(c, "ttl", 300) <= 3600


# ── Launch Template ───────────────────────────────────────────────────────────

def lt_no_key_name(c):
    return not bool(c.get("key_name"))


def lt_root_volume_encrypted(c):
    if _blocks(c, "block_device_mappings"):
        return any(
            bd.get("encrypted") is True or bd.get("ebs", {}).get("encrypted") is True
            for bd in _blocks(c, "block_device_mappings")
        )
    return True


# ── CodeBuild ─────────────────────────────────────────────────────────────────

def cb_artifacts_encrypted(c):
    return _block(c, "artifacts").get("encryption_disabled") is not True


def cb_not_privileged(c):
    return _block(c, "environment").get("privileged_mode") is not True


def cb_logs_configured(c):
    return (
        _block(_block(c, "logs_config"), "cloudwatch_logs").get("status", "ENABLED") == "ENABLED"
        or _block(_block(c, "logs_config"), "s3_logs").get("status") == "ENABLED"
    )


# ── CodePipeline ──────────────────────────────────────────────────────────────

def cp_has_three_stages(c):
    return len(_blocks(c, "stage")) >= 3


def cp_artifact_store_encrypted(c):
    return bool(
        _block(c, "artifact_store").get("encryption_key")
        or any(bool(_block(a, "encryption_key")) for a in _blocks(c, "artifact_store"))
    )


# ── CloudFront ────────────────────────────────────────────────────────────────

def cf_modern_tls(c):
    return _block(c, "viewer_certificate").get(
        "minimum_protocol_version", "TLSv1.2_2021"
    ) not in ["SSLv3", "TLSv1", "TLSv1_2016"]


def cf_access_logging_enabled(c):
    return _block(c, "logging_config").get("bucket", "") != ""


def cf_https_only(c):
    behaviors = _blocks(c, "default_cache_behavior") + _blocks(c, "ordered_cache_behavior")
    if behaviors:
        return all(
            b.get("viewer_protocol_policy") in ["https-only", "redirect-to-https"]
            for b in behaviors
        )
    return True


def cf_no_default_cert_with_aliases(c):
    return (
        _block(c, "viewer_certificate").get("cloudfront_default_certificate") is not True
        or not c.get("aliases")
    )


# ── WAF ───────────────────────────────────────────────────────────────────────

def waf_has_rules(c):
    return bool(c.get("rule") or _blocks(c, "rule"))
