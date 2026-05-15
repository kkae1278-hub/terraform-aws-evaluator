"""Print resource type count and rule count from reference.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from reference import TERRAFORM_RULES

total = sum(len(v) for v in TERRAFORM_RULES.values())
print(f"リソースタイプ数: {len(TERRAFORM_RULES)}")
print(f"ルール総数      : {total}")
print()
for rtype, rules in sorted(TERRAFORM_RULES.items()):
    pillars = sorted(set(r.get("pillar", "-") for r in rules))
    print(f"  {rtype:<52} {len(rules):>3}件  {pillars}")
