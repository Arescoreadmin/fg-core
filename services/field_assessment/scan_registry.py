"""Scan source registry: per-source-type schema versions, required fields, quarantine rules.

Every ScanSourceType has:
- A set of accepted schema_version strings (unknown versions are rejected with 422).
- A list of required top-level payload keys (absence is rejected with 422).

Quarantine thresholds apply globally across all source types:
- Max nesting depth: 12 levels
- Max total field count: 2 000
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
# Required top-level payload fields per source type
# ---------------------------------------------------------------------------

REQUIRED_FIELDS: dict[str, list[str]] = {
    ScanSourceType.MICROSOFT_GRAPH.value: ["users"],
    ScanSourceType.GOOGLE_WORKSPACE.value: ["users"],
    ScanSourceType.AWS.value: ["accounts"],
    ScanSourceType.AZURE.value: ["subscriptions"],
    ScanSourceType.GCP.value: ["projects"],
    ScanSourceType.NETWORK_SCAN.value: ["hosts"],
    ScanSourceType.ENDPOINT_INVENTORY.value: ["endpoints"],
    ScanSourceType.OAUTH_INVENTORY.value: ["apps"],
}

# ---------------------------------------------------------------------------
# Quarantine thresholds
# ---------------------------------------------------------------------------

MAX_PAYLOAD_DEPTH = 12
MAX_FIELD_COUNT = 2_000
MAX_FIELD_SIZE_BYTES = 64 * 1024  # 64 KiB per field


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
    if isinstance(obj, dict):
        return len(obj) + sum(_field_count(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(_field_count(item) for item in obj)
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


def validate_schema_version(source_type: str, schema_version: str) -> None:
    """Reject schema_version values not on the allowlist for this source type."""
    allowed = SUPPORTED_SCHEMA_VERSIONS.get(source_type, set())
    if schema_version not in allowed:
        allowed_str = ", ".join(sorted(allowed)) or "(none registered)"
        raise ScanValidationError(
            f"schema_version '{schema_version}' is not supported for source_type "
            f"'{source_type}'; accepted: [{allowed_str}]"
        )


def validate_required_fields(source_type: str, payload: dict[str, Any]) -> None:
    """Reject payloads missing required top-level fields for this source type."""
    required = REQUIRED_FIELDS.get(source_type, [])
    missing = [f for f in required if f not in payload]
    if missing:
        raise ScanValidationError(
            f"payload for source_type '{source_type}' is missing required fields: {missing}"
        )


def quarantine_check(payload: dict[str, Any]) -> None:
    """Reject structurally suspect payloads that exceed depth, count, or field-size limits."""
    d = _depth(payload)
    if d > MAX_PAYLOAD_DEPTH:
        raise ScanQuarantinedError(
            f"payload nesting depth {d} exceeds limit {MAX_PAYLOAD_DEPTH}"
        )

    count = _field_count(payload)
    if count > MAX_FIELD_COUNT:
        raise ScanQuarantinedError(
            f"payload field count {count} exceeds limit {MAX_FIELD_COUNT}"
        )

    _check_field_sizes(payload)


def validate_scan_payload(
    source_type: str,
    schema_version: str,
    payload: dict[str, Any],
) -> None:
    """Full validation pipeline: schema version → quarantine check → required fields."""
    validate_schema_version(source_type, schema_version)
    quarantine_check(payload)
    validate_required_fields(source_type, payload)
