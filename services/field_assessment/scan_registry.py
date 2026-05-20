"""Scan source registry: per-source-type schema versions, required fields, quarantine rules.

Every ScanSourceType has:
- A set of accepted schema_version strings (unknown versions are rejected with 422).
- A list of required top-level payload keys (absence is rejected with 422).
- Expected field types for required keys (wrong type is rejected with 422).
- Optional quarantine threshold overrides (sources with large expected payloads).
- Optional deprecation notices (old versions still accepted but warned in audit).

Global quarantine thresholds apply when a source type has no override:
- Max nesting depth: 12 levels
- Max total field count: 2 000 (primitive scalars + dict keys + list items)
- Max single-field string size: 64 KiB
"""

from __future__ import annotations

from typing import Any

from services.field_assessment.models import (
    ScanQuarantinedError,
    ScanSourceType,
    ScanValidationError,
)

# ---------------------------------------------------------------------------
# Schema version allowlist per source type
# ---------------------------------------------------------------------------

SUPPORTED_SCHEMA_VERSIONS: dict[str, set[str]] = {
    ScanSourceType.MICROSOFT_GRAPH.value: {"1.0", "1.1", "2.0"},
    ScanSourceType.GOOGLE_WORKSPACE.value: {"1.0", "1.1"},
    ScanSourceType.AWS.value: {"1.0", "1.1", "2.0"},
    ScanSourceType.AZURE.value: {"1.0", "1.1"},
    ScanSourceType.GCP.value: {"1.0", "1.1"},
    ScanSourceType.NETWORK_SCAN.value: {"1.0"},
    ScanSourceType.ENDPOINT_INVENTORY.value: {"1.0"},
    ScanSourceType.OAUTH_INVENTORY.value: {"1.0", "1.1"},
}

# ---------------------------------------------------------------------------
# Deprecation notices — accepted but callers should migrate.
# Values: {schema_version: human-readable migration hint}
# ---------------------------------------------------------------------------

DEPRECATED_SCHEMA_VERSIONS: dict[str, dict[str, str]] = {
    # Example (uncomment when a version is sunsetted):
    # ScanSourceType.MICROSOFT_GRAPH.value: {
    #     "1.0": "microsoft_graph 1.0 is deprecated; migrate to 2.0 by 2027-01-01",
    # },
}

# ---------------------------------------------------------------------------
# Required top-level payload fields per source type
# Key: field name, Value: expected Python type (list, dict, str, int)
# ---------------------------------------------------------------------------

REQUIRED_FIELDS: dict[str, dict[str, type]] = {
    ScanSourceType.MICROSOFT_GRAPH.value: {"users": list},
    ScanSourceType.GOOGLE_WORKSPACE.value: {"users": list},
    ScanSourceType.AWS.value: {"accounts": list},
    ScanSourceType.AZURE.value: {"subscriptions": list},
    ScanSourceType.GCP.value: {"projects": list},
    ScanSourceType.NETWORK_SCAN.value: {"hosts": list},
    ScanSourceType.ENDPOINT_INVENTORY.value: {"endpoints": list},
    ScanSourceType.OAUTH_INVENTORY.value: {"apps": list},
}

# ---------------------------------------------------------------------------
# Global quarantine thresholds
# ---------------------------------------------------------------------------

MAX_PAYLOAD_DEPTH = 12
MAX_FIELD_COUNT = 2_000
MAX_FIELD_SIZE_BYTES = 64 * 1024  # 64 KiB per field

# Per-source-type overrides — only the keys present are overridden.
_SOURCE_QUARANTINE_OVERRIDES: dict[str, dict[str, int]] = {
    # AWS can have hundreds of accounts each with many IAM resources.
    ScanSourceType.AWS.value: {"MAX_FIELD_COUNT": 8_000},
    # Large endpoint fleets (EDR, MDM) can easily exceed 2K entries.
    ScanSourceType.ENDPOINT_INVENTORY.value: {"MAX_FIELD_COUNT": 10_000},
    # Google Workspace tenants with many users/groups.
    ScanSourceType.GOOGLE_WORKSPACE.value: {"MAX_FIELD_COUNT": 5_000},
    # OAuth inventories across many apps and scopes.
    ScanSourceType.OAUTH_INVENTORY.value: {"MAX_FIELD_COUNT": 5_000},
}


def _get_threshold(source_type: str, key: str, default: int) -> int:
    return _SOURCE_QUARANTINE_OVERRIDES.get(source_type, {}).get(key, default)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _depth(obj: Any, current: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_depth(item, current + 1) for item in obj)
    return current


def _field_count(obj: Any) -> int:
    """Count every node (dict key, list item, scalar) in the payload tree.

    Bug fix over PR-3 original: list items are now counted so that a flat
    array of 5 000 scalar strings correctly contributes to the total.
    """
    if isinstance(obj, dict):
        return len(obj) + sum(_field_count(v) for v in obj.values())
    if isinstance(obj, list):
        # Count the items themselves plus any nested structure they contain.
        return len(obj) + sum(_field_count(item) for item in obj)
    return 0


def _check_field_sizes(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            child = f"{path}.{k}" if path else str(k)
            _check_field_sizes(v, child)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _check_field_sizes(item, f"{path}[{i}]")
    elif isinstance(obj, str):
        size = len(obj.encode("utf-8"))
        if size > MAX_FIELD_SIZE_BYTES:
            raise ScanQuarantinedError(
                f"field '{path}' size {size} bytes exceeds {MAX_FIELD_SIZE_BYTES // 1024} KiB limit"
            )


# ---------------------------------------------------------------------------
# Public validators
# ---------------------------------------------------------------------------


def validate_schema_version(source_type: str, schema_version: str) -> str | None:
    """Reject schema_version values not on the allowlist for this source type.

    Returns a deprecation notice string if the version is deprecated but still
    accepted, or None if the version is current.
    """
    allowed = SUPPORTED_SCHEMA_VERSIONS.get(source_type, set())
    if schema_version not in allowed:
        allowed_str = ", ".join(sorted(allowed)) or "(none registered)"
        raise ScanValidationError(
            f"schema_version '{schema_version}' is not supported for source_type "
            f"'{source_type}'; accepted: [{allowed_str}]"
        )
    deprecated = DEPRECATED_SCHEMA_VERSIONS.get(source_type, {})
    return deprecated.get(schema_version)


def validate_required_fields(source_type: str, payload: dict[str, Any]) -> None:
    """Reject payloads missing required fields or with wrong types."""
    required = REQUIRED_FIELDS.get(source_type, {})
    for field_name, expected_type in required.items():
        if field_name not in payload:
            raise ScanValidationError(
                f"payload for source_type '{source_type}' is missing required field: '{field_name}'"
            )
        value = payload[field_name]
        if not isinstance(value, expected_type):
            type_name = expected_type.__name__
            actual_name = type(value).__name__
            raise ScanValidationError(
                f"payload field '{field_name}' for source_type '{source_type}' "
                f"must be {type_name}, got {actual_name}"
            )


def quarantine_check(payload: dict[str, Any], source_type: str = "") -> None:
    """Reject structurally suspect payloads that exceed depth, count, or field-size limits.

    Per-source-type overrides are applied when *source_type* is provided.
    """
    d = _depth(payload)
    if d > MAX_PAYLOAD_DEPTH:
        raise ScanQuarantinedError(
            f"payload nesting depth {d} exceeds limit {MAX_PAYLOAD_DEPTH}"
        )

    max_fields = _get_threshold(source_type, "MAX_FIELD_COUNT", MAX_FIELD_COUNT)
    count = _field_count(payload)
    if count > max_fields:
        raise ScanQuarantinedError(
            f"payload field count {count} exceeds limit {max_fields} for source_type '{source_type}'"
        )

    _check_field_sizes(payload)


def validate_scan_payload(
    source_type: str,
    schema_version: str,
    payload: dict[str, Any],
) -> str | None:
    """Full validation pipeline: schema version → quarantine check → required fields.

    Returns a deprecation notice string if the schema_version is deprecated,
    or None if everything is current and clean.
    """
    deprecation_notice = validate_schema_version(source_type, schema_version)
    quarantine_check(payload, source_type)
    validate_required_fields(source_type, payload)
    return deprecation_notice
