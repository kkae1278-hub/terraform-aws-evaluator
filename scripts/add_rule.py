"""
Interactive rule-addition wizard for rules/rules.yml.

Usage:
    python scripts/add_rule.py

The wizard will:
  1. Ask for resource type, rule metadata, and check definition
  2. Auto-suggest the next rule ID for that resource
  3. Append the rule to rules/rules.yml (text-append; preserves comments and formatting)
  4. Run a quick smoke-test to confirm the rule loads without errors

Supported check operators (see rule_loader.py for full reference):
  is_true, not_true, not_false, truthy
  eq, not_in
  gte, gt, lte
  has_key
  block_is_true, block_eq, block_truthy, block_has_key
  has_blocks, not_startswith
  fn
"""

import re
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import yaml

RULES_FILE = project_root / "rules" / "rules.yml"

CATEGORIES = [
    "compute", "database", "network", "storage",
    "security", "monitoring", "messaging", "cicd", "serverless", "other",
]
PILLARS = ["SEC", "REL", "OPS", "PERF", "COST"]
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

FIELD_ONLY_OPS  = {"is_true", "not_true", "not_false", "truthy", "has_key", "has_blocks"}
BLOCK_FIELD_OPS = {"block_is_true", "block_truthy", "block_has_key"}
BLOCK_VALUE_OPS = {"block_eq"}
VALUE_OPS       = {"eq", "gte", "gt", "lte"}
VALUES_LIST_OPS = {"not_in"}
PREFIXES_OPS    = {"not_startswith"}
FN_OPS          = {"fn"}
ALL_OPS = (FIELD_ONLY_OPS | BLOCK_FIELD_OPS | BLOCK_VALUE_OPS |
           VALUE_OPS | VALUES_LIST_OPS | PREFIXES_OPS | FN_OPS)


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def ask(prompt: str, choices: list = None, default: str = None) -> str:
    if choices:
        print(f"  Options: {', '.join(choices)}")
    display = f"{prompt} [{default}]" if default else prompt
    while True:
        answer = input(f"  {display}: ").strip()
        if not answer and default:
            return default
        if choices and answer not in choices:
            print(f"  !! Choose one of: {', '.join(choices)}")
            continue
        if answer:
            return answer
        print("  !! This field is required.")


def ask_list(prompt: str) -> list:
    while True:
        raw = input(f"  {prompt} (comma-separated): ").strip()
        items = [x.strip() for x in raw.split(",") if x.strip()]
        if items:
            return items
        print("  !! At least one value is required.")


# ---------------------------------------------------------------------------
# Rule-ID suggestion
# ---------------------------------------------------------------------------

_PREFIX_MAP = {
    "aws_instance": "EC2",
    "aws_launch_template": "LT",
    "aws_launch_configuration": "LC",
    "aws_autoscaling_group": "ASG",
    "aws_db_instance": "RDS",
    "aws_rds_cluster": "AUR",
    "aws_dynamodb_table": "DDB",
    "aws_elasticache_cluster": "EC",
    "aws_elasticache_replication_group": "ECR",
    "aws_redshift_cluster": "RS",
    "aws_s3_bucket": "S3",
    "aws_ebs_volume": "EBS",
    "aws_ecr_repository": "ECR",
    "aws_lambda_function": "LAM",
    "aws_ecs_cluster": "ECS",
    "aws_ecs_service": "ECS",
    "aws_ecs_task_definition": "ECS",
    "aws_eks_cluster": "EKS",
    "aws_iam_role": "IAM",
    "aws_iam_policy": "IAM",
    "aws_kms_key": "KMS",
    "aws_secretsmanager_secret": "SM",
    "aws_security_group": "SG",
    "aws_security_group_rule": "SGR",
    "aws_lb": "ALB",
    "aws_lb_listener": "ALB",
    "aws_lb_target_group": "TG",
    "aws_cloudtrail": "CT",
    "aws_cloudwatch_log_group": "CW",
    "aws_vpc": "VPC",
    "aws_flow_log": "VPC",
    "aws_kinesis_stream": "KIN",
    "aws_sqs_queue": "SQS",
    "aws_sns_topic": "SNS",
    "aws_wafv2_web_acl": "WAF",
    "aws_guardduty_detector": "GD",
    "aws_cloudfront_distribution": "CF",
    "aws_msk_cluster": "MSK",
}


def suggest_rule_id(data: dict, resource_type: str) -> str:
    prefix = _PREFIX_MAP.get(resource_type,
                             resource_type.upper().replace("AWS_", "")[:5])
    existing_nums = []
    for cat_resources in data.values():
        if not isinstance(cat_resources, dict):
            continue
        for rules in cat_resources.values():
            if not isinstance(rules, list):
                continue
            for rule in rules:
                rid = rule.get("id", "")
                if rid.startswith(prefix + "-"):
                    try:
                        existing_nums.append(int(rid.split("-")[1]))
                    except (IndexError, ValueError):
                        pass
    return f"{prefix}-{max(existing_nums, default=0) + 1:03d}"


# ---------------------------------------------------------------------------
# Check spec builder
# ---------------------------------------------------------------------------

def build_check_spec() -> dict:
    print()
    print("  --- Check definition ---")
    print(f"  Available operators: {', '.join(sorted(ALL_OPS))}")
    op = ask("operator (op)")
    spec = {"op": op}

    if op in FN_OPS:
        spec["name"] = ask("function name (must exist in checks.py)")
        return spec

    if op in BLOCK_FIELD_OPS | BLOCK_VALUE_OPS:
        spec["block"] = ask("block name (e.g. metadata_options)")
        spec["field"] = ask("field name inside block")
    else:
        spec["field"] = ask("field name")

    if op in BLOCK_VALUE_OPS | VALUE_OPS:
        spec["value"] = ask("expected value")
        d = input("  default (leave blank for none): ").strip()
        if d:
            spec["default"] = d

    if op in VALUES_LIST_OPS:
        spec["values"] = ask_list("list of disallowed values")
        d = input("  default (leave blank for none): ").strip()
        if d:
            spec["default"] = d

    if op in PREFIXES_OPS:
        spec["prefixes"] = ask_list("list of forbidden prefixes")
        d = input("  default (leave blank for none): ").strip()
        if d:
            spec["default"] = d

    if op in {"gte", "gt", "lte"}:
        d = input("  default numeric value (leave blank for 0): ").strip()
        if d:
            spec["default"] = d

    return spec


# ---------------------------------------------------------------------------
# YAML text-append (preserves comments and existing formatting)
# ---------------------------------------------------------------------------

def _quote(s: str) -> str:
    """Wrap in double quotes and escape internal quotes."""
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _render_rule_yaml(rule: dict) -> str:
    """
    Render one rule entry as indented YAML text (4-space indent for list item,
    6-space indent for fields).  Matches the style used in rules.yml.
    """
    check = rule["check"]
    lines = [
        f"    - id: {rule['id']}",
        f"      pillar: {rule['pillar']}",
        f"      severity: {rule['severity']}",
        f"      description: {_quote(rule['description'])}",
        f"      message: {_quote(rule['message'])}",
        f"      recommendation: {_quote(rule['recommendation'])}",
        f"      check:",
        f"        op: {check['op']}",
    ]
    for k, v in check.items():
        if k == "op":
            continue
        if isinstance(v, list):
            lines.append(f"        {k}:")
            for item in v:
                lines.append(f"          - {item}")
        else:
            lines.append(f"        {k}: {v}")
    return "\n".join(lines) + "\n"


def append_rule_text(category: str, resource_type: str, rule: dict) -> None:
    """
    Append the rule into rules.yml without touching existing text.

    Strategy (text-based, no full re-dump):
    - If the resource block already exists  -> find its last line and insert after
    - If the category exists but not the resource -> append resource + rule at end of category
    - If neither exists -> append both category and resource at end of file
    """
    text = RULES_FILE.read_text(encoding="utf-8")
    rule_yaml = _render_rule_yaml(rule)

    # Does the resource block already exist?
    res_pattern = re.compile(
        r"^  " + re.escape(resource_type) + r":\s*$", re.MULTILINE
    )
    res_match = re.search(res_pattern, text)

    if res_match:
        # Find the start of the NEXT resource or category (line at indent 0 or 2
        # that isn't part of the current resource's list)
        after_res = text[res_match.end():]
        # Next line that starts with 0 or 2 spaces and is a key (not list item)
        next_block = re.search(r"\n(?=  \w|\w)", after_res)
        if next_block:
            insert_pos = res_match.end() + next_block.start()
        else:
            insert_pos = len(text)
        new_text = text[:insert_pos] + "\n" + rule_yaml + text[insert_pos:]

    else:
        # Does the category block already exist?
        cat_pattern = re.compile(r"^" + re.escape(category) + r":\s*$", re.MULTILINE)
        cat_match = re.search(cat_pattern, text)

        resource_block = f"\n  {resource_type}:\n{rule_yaml}"

        if cat_match:
            # Find end of this category (next top-level key)
            after_cat = text[cat_match.end():]
            next_cat = re.search(r"\n(?=\w)", after_cat)
            if next_cat:
                insert_pos = cat_match.end() + next_cat.start()
            else:
                insert_pos = len(text)
            new_text = text[:insert_pos] + resource_block + text[insert_pos:]
        else:
            # Append both category and resource
            new_text = text.rstrip("\n") + f"\n\n{category}:\n  {resource_type}:\n{rule_yaml}"

    RULES_FILE.write_text(new_text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

def smoke_test(resource_type: str, rule_id: str) -> bool:
    try:
        import importlib
        import rule_loader
        importlib.reload(rule_loader)
        rules = rule_loader.load_rules()
        for rule in rules.get(resource_type, []):
            if rule["id"] == rule_id:
                rule["check"]({})   # call with empty config — must not raise
                return True
        print(f"  !! {rule_id} not found after reload — check rules.yml manually.")
        return False
    except Exception as e:
        print(f"  !! Smoke test failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  Terraform Rule Addition Wizard")
    print("=" * 60)
    print()

    data = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8")) or {}

    print("Step 1: Resource")
    resource_type = ask("AWS resource type (e.g. aws_instance)")
    category = ask("Category", choices=CATEGORIES)

    print()
    print("Step 2: Rule metadata")
    suggested_id = suggest_rule_id(data, resource_type)
    rule_id      = ask("Rule ID", default=suggested_id)
    pillar       = ask("Pillar", choices=PILLARS)
    severity     = ask("Severity", choices=SEVERITIES)
    description  = ask("Short description")
    message      = ask("Problem message (shown when rule fails)")
    recommendation = ask("Fix recommendation")

    print()
    print("Step 3: Check logic")
    check_spec = build_check_spec()

    rule = {
        "id": rule_id,
        "pillar": pillar,
        "severity": severity,
        "description": description,
        "message": message,
        "recommendation": recommendation,
        "check": check_spec,
    }

    print()
    print("=" * 60)
    print("  Rule to be added:")
    print()
    print(_render_rule_yaml(rule))
    print("=" * 60)
    confirm = input("  Add this rule? [y/N]: ").strip().lower()
    if confirm != "y":
        print("  Aborted.")
        return

    append_rule_text(category, resource_type, rule)
    print(f"  -> Appended to rules/rules.yml")

    print("  Running smoke test...")
    if smoke_test(resource_type, rule_id):
        print(f"  [OK] Rule {rule_id} loaded and verified successfully.")
    else:
        print("  !! Rule was written but failed smoke test. Check rules.yml manually.")
        return

    print()
    print("  Next steps:")
    print(f"    1. Add a test in tests/test_rules.py for {rule_id}")
    print(f"    2. pytest tests/ -v")
    print(f"    3. git add rules/rules.yml && git commit -m 'Add rule {rule_id}'")


if __name__ == "__main__":
    main()
