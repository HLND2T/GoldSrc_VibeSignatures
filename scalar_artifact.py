"""Version-bound numeric scalar artifacts; consumers use the verified value directly."""

from collections.abc import Mapping

SCALAR_FIELDS = ("scalar_name", "scalar_value")


def validate_scalar_artifact(payload):
    if not isinstance(payload, Mapping) or set(payload) != set(SCALAR_FIELDS):
        raise ValueError("scalar artifact requires exactly scalar_name and scalar_value")
    if not isinstance(payload["scalar_name"], str) or not payload["scalar_name"].strip():
        raise ValueError("scalar_name must be nonempty")
    value = payload["scalar_value"]
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError("scalar_value must be uint32")


def resolve_scalar(payload):
    validate_scalar_artifact(payload)
    return payload["scalar_value"]


def select_scalar_value(name, entries, expected_value):
    """Require agreement with independently verified current-binary evidence."""
    validate_scalar_artifact({"scalar_name": name, "scalar_value": expected_value})
    values = []
    for entry in entries:
        if entry.get("scalar_name") != name:
            raise ValueError("unexpected scalar identity")
        value = entry.get("scalar_value")
        if isinstance(value, str):
            value = int(value, 0)
        candidate = {"scalar_name": name, "scalar_value": value}
        validate_scalar_artifact(candidate)
        values.append(value)
    if not values or set(values) != {expected_value}:
        raise ValueError("scalar values are absent, conflicting, or disagree with current-binary evidence")
    return {"scalar_name": name, "scalar_value": expected_value}
