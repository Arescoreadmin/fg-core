from __future__ import annotations

from typing import Any


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def validate_payload_against_schema(payload: dict[str, Any], schema: dict[str, Any]) -> None:
    required = schema.get("required") or []
    for key in required:
        if key not in payload:
            raise ValueError(f"SCHEMA_REQUIRED_FIELD_MISSING:{key}")

    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    additional = bool(schema.get("additionalProperties", True))

    if not additional:
        for key in payload:
            if key not in properties:
                raise ValueError(f"SCHEMA_ADDITIONAL_PROPERTY_FORBIDDEN:{key}")

    for key, rule in properties.items():
        if key not in payload or not isinstance(rule, dict):
            continue
        value = payload[key]
        if "type" in rule:
            type_rule = rule["type"]
            if isinstance(type_rule, list):
                if not any(_matches_type(value, str(t)) for t in type_rule):
                    raise ValueError(f"SCHEMA_TYPE_MISMATCH:{key}")
            else:
                if not _matches_type(value, str(type_rule)):
                    raise ValueError(f"SCHEMA_TYPE_MISMATCH:{key}")
