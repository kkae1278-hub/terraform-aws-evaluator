"""
Automated tests for terraform_evaluator.
Run with: pytest tests/
"""

import sys
from pathlib import Path

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from reference import TERRAFORM_RULES, SEVERITY_WEIGHTS, _block, _blocks, _int
from evaluator import evaluate_static, EvaluationResult


# ──────────────────────────────────────────────
# Rule dictionary structural integrity
# ──────────────────────────────────────────────

class TestRuleStructure:
    REQUIRED_KEYS = {"id", "pillar", "description", "severity", "check", "message", "recommendation"}
    VALID_SEVERITIES = set(SEVERITY_WEIGHTS.keys())
    VALID_PILLARS = {"SEC", "REL", "OPS", "PERF", "COST"}

    def test_all_resource_types_have_rules(self):
        assert len(TERRAFORM_RULES) >= 72, "Expected at least 72 resource types"

    def test_total_rule_count(self):
        total = sum(len(v) for v in TERRAFORM_RULES.values())
        assert total >= 188, "Expected at least 188 rules"

    def test_required_keys_present(self):
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                missing = self.REQUIRED_KEYS - rule.keys()
                assert not missing, f"{rtype}/{rule.get('id','?')} missing keys: {missing}"

    def test_no_duplicate_rule_ids(self):
        seen = {}
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                rid = rule["id"]
                assert rid not in seen, f"Duplicate rule ID {rid} in {rtype} and {seen[rid]}"
                seen[rid] = rtype

    def test_valid_severities(self):
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                assert rule["severity"] in self.VALID_SEVERITIES, (
                    f"{rule['id']} has unknown severity {rule['severity']!r}"
                )

    def test_valid_pillars(self):
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                assert rule["pillar"] in self.VALID_PILLARS, (
                    f"{rule['id']} has unknown pillar {rule['pillar']!r}"
                )

    def test_check_is_callable(self):
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                assert callable(rule["check"]), f"{rule['id']} check is not callable"


# ──────────────────────────────────────────────
# Check function robustness (no crash on edge inputs)
# ──────────────────────────────────────────────

class TestCheckRobustness:
    def test_empty_config_does_not_crash(self):
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                try:
                    result = rule["check"]({})
                    assert isinstance(result, bool), f"{rule['id']} returned non-bool on empty config"
                except Exception as e:
                    pytest.fail(f"{rule['id']} crashed on empty config: {e}")

    def test_extra_unknown_keys_do_not_crash(self):
        extra_config = {"unknown_key_a": "x", "unknown_key_b": 42, "unknown_key_c": True}
        for rtype, rules in TERRAFORM_RULES.items():
            for rule in rules:
                try:
                    rule["check"](extra_config)
                except Exception as e:
                    pytest.fail(f"{rule['id']} crashed on extra-key config: {e}")


# ──────────────────────────────────────────────
# Specific rule correctness
# ──────────────────────────────────────────────

def _find_rule(rule_id: str):
    for rules in TERRAFORM_RULES.values():
        for rule in rules:
            if rule["id"] == rule_id:
                return rule
    pytest.fail(f"Rule {rule_id} not found")


class TestEC2Rules:
    def test_ec2_001_imdsv2_required(self):
        rule = _find_rule("EC2-001")
        good = {"metadata_options": {"http_tokens": "required"}}
        bad = {"metadata_options": {"http_tokens": "optional"}}
        assert rule["check"](good) is True
        assert rule["check"](bad) is False
        assert rule["check"]({}) is False

    def test_ec2_002_root_encrypted(self):
        rule = _find_rule("EC2-002")
        good = {"root_block_device": {"encrypted": True}}
        bad = {"root_block_device": {"encrypted": False}}
        assert rule["check"](good) is True
        assert rule["check"](bad) is False
        assert rule["check"]({}) is False

    def test_ec2_003_monitoring(self):
        rule = _find_rule("EC2-003")
        assert rule["check"]({"monitoring": True}) is True
        assert rule["check"]({"monitoring": False}) is False
        assert rule["check"]({}) is False

    def test_ec2_005_no_public_ip(self):
        rule = _find_rule("EC2-005")
        assert rule["check"]({}) is True  # default: no public IP
        assert rule["check"]({"associate_public_ip_address": False}) is True
        assert rule["check"]({"associate_public_ip_address": True}) is False


class TestRDSRules:
    def test_rds_001_multi_az(self):
        rule = _find_rule("RDS-001")
        assert rule["check"]({"multi_az": True}) is True
        assert rule["check"]({"multi_az": False}) is False
        assert rule["check"]({}) is False

    def test_rds_002_deletion_protection(self):
        rule = _find_rule("RDS-002")
        assert rule["check"]({"deletion_protection": True}) is True
        assert rule["check"]({"deletion_protection": False}) is False

    def test_rds_006_storage_encrypted(self):
        rule = _find_rule("RDS-006")
        assert rule["check"]({"storage_encrypted": True}) is True
        assert rule["check"]({"storage_encrypted": False}) is False
        assert rule["check"]({}) is False

    def test_rds_007_backup_retention(self):
        rule = _find_rule("RDS-007")
        assert rule["check"]({"backup_retention_period": 7}) is True
        assert rule["check"]({"backup_retention_period": 30}) is True
        assert rule["check"]({"backup_retention_period": 6}) is False
        assert rule["check"]({"backup_retention_period": 0}) is False

    def test_rds_009_not_publicly_accessible(self):
        rule = _find_rule("RDS-009")
        assert rule["check"]({}) is True  # default: not public
        assert rule["check"]({"publicly_accessible": False}) is True
        assert rule["check"]({"publicly_accessible": True}) is False


class TestS3Rules:
    def test_s3_004_public_access_block_all_true(self):
        rule = _find_rule("S3-004")
        good = {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": True,
        }
        assert rule["check"](good) is True

    def test_s3_004_partial_settings_fail(self):
        rule = _find_rule("S3-004")
        partial = {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": True,
            "restrict_public_buckets": False,
        }
        assert rule["check"](partial) is False

    def test_s3_004_empty_fails(self):
        rule = _find_rule("S3-004")
        assert rule["check"]({}) is False


class TestSecurityGroupRules:
    def test_sg_001_ssh_open_fails(self):
        rule = _find_rule("SG-001")
        bad = {
            "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
        }
        assert rule["check"](bad) is False

    def test_sg_001_restricted_ssh_passes(self):
        rule = _find_rule("SG-001")
        good = {
            "ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["10.0.0.0/8"]}]
        }
        assert rule["check"](good) is True

    def test_sg_001_empty_passes(self):
        rule = _find_rule("SG-001")
        assert rule["check"]({}) is True

    def test_sg_002_all_protocol_open_fails(self):
        rule = _find_rule("SG-002")
        bad = {
            "ingress": [{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]}]
        }
        assert rule["check"](bad) is False

    def test_sg_002_restricted_passes(self):
        rule = _find_rule("SG-002")
        good = {
            "ingress": [{"from_port": 443, "to_port": 443, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]
        }
        assert rule["check"](good) is True


class TestIAMRules:
    def test_iam_001_wildcard_principal_fails(self):
        rule = _find_rule("IAM-001")
        bad = {"assume_role_policy": '{"Principal": {"AWS": "*"}}'}
        assert rule["check"](bad) is False

    def test_iam_001_specific_principal_passes(self):
        rule = _find_rule("IAM-001")
        good = {"assume_role_policy": '{"Principal": {"Service": "lambda.amazonaws.com"}}'}
        assert rule["check"](good) is True

    def test_iam_005_wildcard_action_fails(self):
        rule = _find_rule("IAM-005")
        bad = {"policy": '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'}
        assert rule["check"](bad) is False

    def test_iam_005_specific_action_passes(self):
        rule = _find_rule("IAM-005")
        good = {"policy": '{"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]}'}
        assert rule["check"](good) is True


class TestKMSRules:
    def test_kms_001_rotation_enabled(self):
        rule = _find_rule("KMS-001")
        assert rule["check"]({"enable_key_rotation": True}) is True
        assert rule["check"]({"enable_key_rotation": False}) is False
        assert rule["check"]({}) is False


# ──────────────────────────────────────────────
# evaluate_static integration tests
# ──────────────────────────────────────────────

class TestEvaluateStatic:
    def test_empty_resources_returns_perfect_score(self):
        result = evaluate_static({})
        assert result.score == 100
        assert result.findings == []
        assert result.resources_checked == 0

    def test_unknown_resource_type_is_ignored(self):
        resources = {"aws_unknown_resource": {"res1": {"some_key": "value"}}}
        result = evaluate_static(resources)
        assert result.score == 100
        assert result.findings == []

    def test_imdsv2_violation_detected(self):
        resources = {
            "aws_instance": {
                "web": {}  # No metadata_options -> EC2-001 fails
            }
        }
        result = evaluate_static(resources)
        ids = [f.rule_id for f in result.findings]
        assert "EC2-001" in ids

    def test_good_ec2_no_high_findings(self):
        resources = {
            "aws_instance": {
                "web": {
                    "metadata_options": {"http_tokens": "required", "http_put_response_hop_limit": 1},
                    "monitoring": True,
                    "root_block_device": {"encrypted": True, "volume_type": "gp3", "delete_on_termination": False},
                    "instance_type": "t3.micro",
                }
            }
        }
        result = evaluate_static(resources)
        high_ids = [f.rule_id for f in result.findings if f.severity == "HIGH"]
        assert "EC2-001" not in high_ids
        assert "EC2-002" not in high_ids

    def test_score_decreases_per_severity(self):
        resources = {
            "aws_db_instance": {
                "db": {
                    "storage_encrypted": False,    # RDS-006 HIGH -10
                    "multi_az": False,             # RDS-001 HIGH -10
                    "deletion_protection": False,  # RDS-002 HIGH -10
                }
            }
        }
        result = evaluate_static(resources)
        assert result.score < 100
        high_findings = [f for f in result.findings if f.severity == "HIGH"]
        assert len(high_findings) >= 3

    def test_score_never_goes_below_zero(self):
        # Pile on many violations
        resources = {
            "aws_instance": {"i": {}},
            "aws_db_instance": {
                "db": {
                    "storage_encrypted": False,
                    "multi_az": False,
                    "deletion_protection": False,
                    "publicly_accessible": True,
                }
            },
            "aws_security_group": {
                "sg": {
                    "ingress": [
                        {"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]},
                        {"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": ["0.0.0.0/0"]},
                    ]
                }
            },
        }
        result = evaluate_static(resources)
        assert result.score >= 0

    def test_result_resources_checked_count(self):
        resources = {
            "aws_instance": {"i1": {}, "i2": {}},
            "aws_kms_key": {"k1": {}},
        }
        result = evaluate_static(resources)
        assert result.resources_checked == 3

    def test_finding_fields_populated(self):
        resources = {"aws_instance": {"my_server": {}}}
        result = evaluate_static(resources)
        ec2_finding = next((f for f in result.findings if f.rule_id == "EC2-001"), None)
        assert ec2_finding is not None
        assert ec2_finding.resource_type == "aws_instance"
        assert ec2_finding.resource_name == "my_server"
        assert ec2_finding.severity == "HIGH"
        assert ec2_finding.description
        assert ec2_finding.message
        assert ec2_finding.recommendation


# ──────────────────────────────────────────────
# Fixture-based integration tests
# ──────────────────────────────────────────────

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFixtures:
    def _parse_fixture(self, name: str):
        fixture_dir = FIXTURES_DIR / name
        if not fixture_dir.exists():
            pytest.skip(f"Fixture {name} not found")
        try:
            from hcl_parser import parse_tf_directory
        except ImportError:
            pytest.skip("hcl_parser not importable")
        resources, variables = parse_tf_directory(str(fixture_dir))
        return resources, variables

    def test_sample_good_has_low_findings(self):
        resources, _ = self._parse_fixture("sample_good")
        result = evaluate_static(resources)
        critical = result.by_severity("CRITICAL")
        high = result.by_severity("HIGH")
        assert len(critical) == 0, f"Unexpected CRITICAL findings: {[f.rule_id for f in critical]}"
        assert len(high) == 0, f"Unexpected HIGH findings: {[f.rule_id for f in high]}"

    def test_sample_bad_has_critical_findings(self):
        resources, _ = self._parse_fixture("sample_bad")
        result = evaluate_static(resources)
        critical_and_high = result.by_severity("CRITICAL") + result.by_severity("HIGH")
        assert len(critical_and_high) >= 3, (
            f"Expected >= 3 CRITICAL/HIGH findings, got {len(critical_and_high)}: "
            f"{[f.rule_id for f in critical_and_high]}"
        )

    def test_sample_bad_score_below_good(self):
        good_resources, _ = self._parse_fixture("sample_good")
        bad_resources, _ = self._parse_fixture("sample_bad")
        good_result = evaluate_static(good_resources)
        bad_result = evaluate_static(bad_resources)
        assert bad_result.score < good_result.score
