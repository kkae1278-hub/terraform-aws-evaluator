"""
Terraform AWS best-practice rules.

Rule definitions live in YAML files under rules/.
Complex check functions live in checks.py.
This module loads everything and re-exports the public API
so all existing imports continue to work unchanged.
"""

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

__all__ = ["TERRAFORM_RULES", "SEVERITY_WEIGHTS", "_block", "_blocks", "_int"]
