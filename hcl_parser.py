"""
HCL2 parser for Terraform .tf files.
Extracts resource blocks and resolves variable references to their defaults.
Requires: python-hcl2>=4.3.0  (pip install python-hcl2)
"""

import re
import sys
from pathlib import Path
from typing import Any, Dict, Tuple

try:
    import hcl2
except ImportError:
    print("ERROR: python-hcl2 is required but not installed.")
    print("       Run: pip install python-hcl2")
    sys.exit(1)


def parse_tf_directory(terraform_dir: str) -> Tuple[Dict[str, Dict], Dict[str, Any]]:
    """
    Parse all *.tf files in terraform_dir.

    Returns:
        resources  - {resource_type: {resource_name: config_dict}}
        variables  - {var_name: default_value}
    """
    tf_path = Path(terraform_dir)
    if not tf_path.exists():
        raise FileNotFoundError(f"Directory not found: {terraform_dir}")

    tf_files = sorted(tf_path.glob("*.tf"))
    if not tf_files:
        raise ValueError(f"No .tf files found in {terraform_dir}")

    variables: Dict[str, Any] = {}
    resources: Dict[str, Dict] = {}

    # Parse every file up front. A file that cannot be parsed must fail the run:
    # silently skipping it would evaluate an empty set and report a perfect score.
    parsed_files = []
    errors = []
    for f in tf_files:
        try:
            parsed_files.append(_load_hcl2(f))
        except Exception as exc:
            errors.append(f"{f.name}: {exc}")
    if errors:
        raise ValueError("Failed to parse Terraform file(s):\n  " + "\n  ".join(errors))

    # Pass 1 - collect variable defaults from all files
    for parsed in parsed_files:
        for block in parsed.get("variable", []):
            for raw_var_name, var_cfg in block.items():
                var_name = _strip_q(raw_var_name)
                cfg = var_cfg[0] if isinstance(var_cfg, list) and var_cfg else var_cfg
                if isinstance(cfg, dict) and "default" in cfg:
                    variables[var_name] = cfg["default"]

    # Pass 2 - collect resource blocks from all files
    for parsed in parsed_files:
        _merge_resources(parsed, resources)

    # Resolve var.X references using collected defaults
    resources = _resolve(resources, variables)
    return resources, variables


# ──────────────────────────────────────────────
# Loader
# ──────────────────────────────────────────────

def _load_hcl2(path: Path) -> Dict:
    with open(path, "r", encoding="utf-8") as fh:
        return hcl2.load(fh)


# ──────────────────────────────────────────────
# Resource merging
# ──────────────────────────────────────────────

def _strip_q(s: str) -> str:
    """Remove surrounding HCL label quotes that python-hcl2 may preserve."""
    return s.strip('"').strip("'")


def _merge_resources(parsed: Dict, resources: Dict) -> None:
    for block in parsed.get("resource", []):
        for raw_rtype, instances in block.items():
            rtype = _strip_q(raw_rtype)
            if rtype not in resources:
                resources[rtype] = {}
            if isinstance(instances, dict):
                for raw_name, cfg in instances.items():
                    name = _strip_q(raw_name)
                    resources[rtype][name] = _flatten_config(cfg)
            elif isinstance(instances, list):
                for item in instances:
                    if isinstance(item, dict):
                        for raw_name, cfg in item.items():
                            name = _strip_q(raw_name)
                            resources[rtype][name] = _flatten_config(cfg)


def _flatten_config(cfg: Any) -> Dict:
    if isinstance(cfg, list):
        return cfg[0] if cfg and isinstance(cfg[0], dict) else {}
    return cfg if isinstance(cfg, dict) else {}


# ──────────────────────────────────────────────
# Variable reference resolution
# ──────────────────────────────────────────────

_VAR_RE = re.compile(r'\$\{var\.([^}]+)\}|(?<!["\w])var\.(\w+)(?!["\w])')


def _unquote(s: str) -> str:
    """
    python-hcl2 sometimes returns string literals with their HCL quotes preserved
    e.g. '"required"' -> 'required', '"gp3"' -> 'gp3'.
    Only strip when the outer " pair wraps a simple literal (no inner " or interpolation).
    """
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        if '"' not in inner:
            return inner
    return s


def _resolve(obj: Any, variables: Dict[str, Any]) -> Any:
    if isinstance(obj, str):
        obj = _unquote(obj)
        def _replace(m):
            vname = m.group(1) or m.group(2)
            return str(variables.get(vname, m.group(0)))
        return _VAR_RE.sub(_replace, obj)
    if isinstance(obj, dict):
        return {k: _resolve(v, variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_resolve(item, variables) for item in obj]
    return obj
