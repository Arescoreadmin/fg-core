"""Canonical CGIN privacy helpers. Single source of truth for tenant anonymization."""

import hashlib

CGIN_FINGERPRINT_VERSION = "v1"
CGIN_SCHEMA_VERSION = "2"
CGIN_PRIVACY_VERSION = "1.0"


def fingerprint_tenant(tenant_id: str) -> str:
    """Deterministic, irreversible tenant fingerprint. sha256("cgin:v1:{tenant_id}")[:32].

    Identical for same tenant_id. Different for different tenant_id.
    Never reversible. Stable across builds.
    """
    return hashlib.sha256(
        f"cgin:{CGIN_FINGERPRINT_VERSION}:{tenant_id}".encode()
    ).hexdigest()[:32]


def assert_snapshot_safe(snapshot_dict: dict, tenant_id: str) -> None:
    """Raise ValueError if snapshot_dict contains raw tenant_id or other PII fields.

    Call this in tests and validation to prove snapshots are safe.
    """
    forbidden_keys = {"tenant_id", "organization_name", "customer_name", "tenant_slug"}
    found = forbidden_keys & set(snapshot_dict.keys())
    if found:
        raise ValueError(f"CGIN snapshot contains forbidden fields: {found}")
    # Also check values recursively
    _check_value(snapshot_dict, tenant_id)


def _check_value(obj, tenant_id: str) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _check_value(v, tenant_id)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_value(v, tenant_id)
    elif isinstance(obj, str) and tenant_id and tenant_id in obj:
        raise ValueError("CGIN snapshot value contains raw tenant_id")
