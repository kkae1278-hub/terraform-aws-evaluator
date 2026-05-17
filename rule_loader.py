"""
Load TERRAFORM_RULES from YAML files under rules/.

Each YAML file has the schema:
  resources:
    aws_resource_type:
      - id: RULE-001
        pillar: SEC
        severity: HIGH
        description: "..."
        message: "..."
        recommendation: "..."
        check:
          op: <operator>
          ...operator-specific fields...

Supported operators
-------------------
is_true       field: X                        c.get(X) is True
not_true      field: X                        c.get(X) is not True
not_false     field: X                        c.get(X, True) is not False
truthy        field: X                        bool(c.get(X))
eq            field: X, value: V [default: D] c.get(X, D) == V
not_in        field: X, values: [...] [default: D]  c.get(X, D) not in values
gte           field: X, value: N              _int(c, X) >= N
gt            field: X, value: N              _int(c, X) > N
lte           field: X, value: N              _int(c, X) <= N
has_key       field: X                        X in c
block_is_true block: B, field: X              _block(c, B).get(X) is True
block_eq      block: B, field: X, value: V [default: D]  _block(c, B).get(X, D) == V
block_truthy  block: B, field: X              bool(_block(c, B).get(X))
block_has_key block: B, field: X              X in _block(c, B)
has_blocks    field: X                        bool(_blocks(c, X))
not_startswith field: X, prefixes: [...] [default: ""]  not str(c.get(X, "")).startswith(prefixes)
fn            name: func_name                 checks.func_name(c)
"""

from pathlib import Path
import yaml

from helpers import _block, _blocks, _int

_RULES_DIR = Path(__file__).parent / "rules"


def _resolve_check(spec: dict):
    """Convert a YAML check spec to a callable (config: dict) -> bool."""
    op = spec.get("op")

    if op == "is_true":
        f = spec["field"]
        return lambda c, f=f: c.get(f) is True

    if op == "not_true":
        f = spec["field"]
        return lambda c, f=f: c.get(f) is not True

    if op == "not_false":
        f = spec["field"]
        return lambda c, f=f: c.get(f, True) is not False

    if op == "truthy":
        f = spec["field"]
        return lambda c, f=f: bool(c.get(f))

    if op == "eq":
        f, v = spec["field"], spec["value"]
        d = spec.get("default")
        return lambda c, f=f, v=v, d=d: c.get(f, d) == v

    if op == "not_in":
        f = spec["field"]
        vs = tuple(spec["values"])
        d = spec.get("default")
        return lambda c, f=f, vs=vs, d=d: c.get(f, d) not in vs

    if op == "gte":
        f, v = spec["field"], int(spec["value"])
        return lambda c, f=f, v=v: _int(c, f) >= v

    if op == "gt":
        f, v = spec["field"], int(spec["value"])
        return lambda c, f=f, v=v: _int(c, f) > v

    if op == "lte":
        f, v = spec["field"], int(spec["value"])
        return lambda c, f=f, v=v: _int(c, f) <= v

    if op == "has_key":
        f = spec["field"]
        return lambda c, f=f: f in c

    if op == "block_is_true":
        b, f = spec["block"], spec["field"]
        return lambda c, b=b, f=f: _block(c, b).get(f) is True

    if op == "block_eq":
        b, f, v = spec["block"], spec["field"], spec["value"]
        d = spec.get("default")
        return lambda c, b=b, f=f, v=v, d=d: _block(c, b).get(f, d) == v

    if op == "block_truthy":
        b, f = spec["block"], spec["field"]
        return lambda c, b=b, f=f: bool(_block(c, b).get(f))

    if op == "block_has_key":
        b, f = spec["block"], spec["field"]
        return lambda c, b=b, f=f: f in _block(c, b)

    if op == "has_blocks":
        f = spec["field"]
        return lambda c, f=f: bool(_blocks(c, f))

    if op == "not_startswith":
        f = spec["field"]
        ps = tuple(spec["prefixes"])
        d = spec.get("default", "")
        return lambda c, f=f, ps=ps, d=d: not str(c.get(f, d)).startswith(ps)

    if op == "fn":
        import checks as _checks_mod
        return getattr(_checks_mod, spec["name"])

    raise ValueError(f"Unknown check op: {op!r}")


def load_rules() -> dict:
    """Load rules/rules.yml and return the TERRAFORM_RULES dict."""
    rules_file = _RULES_DIR / "rules.yml"
    data = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
    result = {}
    for _category, resources in data.items():
        if not isinstance(resources, dict):
            continue
        for resource_type, rules in resources.items():
            rule_list = []
            for raw in rules:
                rule = dict(raw)
                rule["check"] = _resolve_check(rule.pop("check"))
                rule_list.append(rule)
            result[resource_type] = rule_list
    return result
