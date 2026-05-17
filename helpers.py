"""Shared helpers for safely navigating HCL2-parsed config dicts."""


def _block(config, key):
    """Return a single nested block dict, handling list-wrapped form."""
    val = config.get(key, {})
    if isinstance(val, list):
        return val[0] if val else {}
    return val if isinstance(val, dict) else {}


def _blocks(config, key):
    """Return a list of nested block dicts."""
    val = config.get(key, [])
    if isinstance(val, list):
        return val
    return [val] if isinstance(val, dict) else []


def _int(config, key, default=0):
    """Safely coerce a config field to int."""
    try:
        return int(config.get(key, default))
    except (TypeError, ValueError):
        return default
