from __future__ import annotations

from typing import Any


def _matches_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, int) or isinstance(value, float)) and not isinstance(
            value, bool
        )
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "null":
        return value is None
    return True


def validate_payload_against_schema(
    payload: dict[str, Any], schema: dict[str, Any]
) -> None:
    _validate_value(payload, schema, "$")


def _validate_value(value: Any, schema: dict[str, Any], path: str) -> None:
    if "type" in schema:
        type_rule = schema["type"]
        if isinstance(type_rule, list):
            if not any(_matches_type(value, str(t)) for t in type_rule):
                raise ValueError(f"SCHEMA_TYPE_MISMATCH:{path}")
        elif not _matches_type(value, str(type_rule)):
            raise ValueError(f"SCHEMA_TYPE_MISMATCH:{path}")

    if "enum" in schema:
        enum_values = schema["enum"]
        if isinstance(enum_values, list) and value not in enum_values:
            raise ValueError(f"SCHEMA_ENUM_MISMATCH:{path}")

    if (
        "minimum" in schema
        and isinstance(value, int | float)
        and not isinstance(value, bool)
    ):
        minimum = schema["minimum"]
        if isinstance(minimum, int | float) and value < minimum:
            raise ValueError(f"SCHEMA_MINIMUM_VIOLATION:{path}")

    if isinstance(value, dict):
        _validate_object(value, schema, path)
    elif isinstance(value, list):
        _validate_array(value, schema, path)


def _validate_object(value: dict[str, Any], schema: dict[str, Any], path: str) -> None:
    required = schema.get("required") or []
    for key in required:
        if key not in value:
            raise ValueError(f"SCHEMA_REQUIRED_FIELD_MISSING:{path}.{key}")

    raw_properties = schema.get("properties")
    properties: dict[Any, Any]
    if isinstance(raw_properties, dict):
        properties = raw_properties
    else:
        properties = {}
    additional = bool(schema.get("additionalProperties", True))

    if not additional:
        for key in value:
            if key not in properties:
                raise ValueError(f"SCHEMA_ADDITIONAL_PROPERTY_FORBIDDEN:{path}.{key}")

    for key, rule in properties.items():
        if key not in value or not isinstance(rule, dict):
            continue
        _validate_value(value[key], rule, f"{path}.{key}")


def _validate_array(value: list[Any], schema: dict[str, Any], path: str) -> None:
    item_schema = schema.get("items")
    if not isinstance(item_schema, dict):
        return
    for index, item in enumerate(value):
        _validate_value(item, item_schema, f"{path}[{index}]")
