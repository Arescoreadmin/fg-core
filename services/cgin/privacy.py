"""Canonical CGIN privacy helpers. Single source of truth for tenant anonymization.

Cryptographic agility: all callers reference FingerprintAlgorithm and the
CGIN_NAMESPACE constants — never hardcoded strings — so algorithm rotation
requires changes only in this file.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Namespace constants — one place to update if the namespace ever rotates
# ---------------------------------------------------------------------------

CGIN_NAMESPACE = "cgin"
CGIN_FINGERPRINT_VERSION = "v1"
CGIN_FINGERPRINT_NAMESPACE = f"{CGIN_NAMESPACE}:{CGIN_FINGERPRINT_VERSION}"

CGIN_SCHEMA_VERSION = "2"
CGIN_PRIVACY_VERSION = "1.0"
CGIN_BENCHMARK_VERSION = "1.0"

# Forbidden field names in any CGIN snapshot payload
CGIN_FORBIDDEN_FIELDS = frozenset(
    {
        "tenant_id",
        "organization_name",
        "customer_name",
        "tenant_slug",
        "account_id",
        "raw_account_id",
    }
)


# ---------------------------------------------------------------------------
# Algorithm registry — cryptographic agility
# ---------------------------------------------------------------------------


class FingerprintAlgorithm(str, Enum):
    """Supported tenant fingerprint algorithms.

    Add new values here when rotating algorithms; callers never reference
    raw strings.
    """

    SHA256_CGIN_V1 = "sha256-cgin-v1"
    # Future slots (not yet active):
    # SHA256_CGIN_V2 = "sha256-cgin-v2"
    # BLAKE3_CGIN_V1 = "blake3-cgin-v1"


# The active algorithm used by fingerprint_tenant(). Changing this value here
# is the only action needed to rotate the algorithm platform-wide.
ACTIVE_FINGERPRINT_ALGORITHM = FingerprintAlgorithm.SHA256_CGIN_V1


# ---------------------------------------------------------------------------
# Core fingerprinting
# ---------------------------------------------------------------------------


def fingerprint_tenant(
    tenant_id: str,
    algorithm: FingerprintAlgorithm = ACTIVE_FINGERPRINT_ALGORITHM,
) -> str:
    """Return a deterministic, irreversible 32-char hex fingerprint for tenant_id.

    Algorithm SHA256_CGIN_V1: sha256(f"{CGIN_FINGERPRINT_NAMESPACE}:{tenant_id}")[:32]

    Properties:
    - Deterministic: same input always produces same output.
    - Unique: different tenant_ids produce different fingerprints (collision resistant).
    - Irreversible: cannot recover tenant_id from fingerprint.
    - Stable: reproducible across builds, runtimes, and deployments.
    """
    if algorithm is FingerprintAlgorithm.SHA256_CGIN_V1:
        return hashlib.sha256(
            f"{CGIN_FINGERPRINT_NAMESPACE}:{tenant_id}".encode()
        ).hexdigest()[:32]
    raise NotImplementedError(f"Unsupported fingerprint algorithm: {algorithm}")


# ---------------------------------------------------------------------------
# Canonical snapshot metadata builder
# ---------------------------------------------------------------------------


def build_cgin_metadata(
    *,
    tenant_id: str,
    authority_name: str,
    authority_version: str = "1.0",
    algorithm: FingerprintAlgorithm = ACTIVE_FINGERPRINT_ALGORITHM,
) -> dict[str, Any]:
    """Return the standard CGIN metadata block every snapshot should include.

    Authorities call this and merge the result into their snapshot payload so
    that metadata is injected consistently without each engine duplicating it.

    Returns:
        {
            "tenant_fingerprint": <32-char hex>,
            "schema_version": CGIN_SCHEMA_VERSION,
            "privacy_version": CGIN_PRIVACY_VERSION,
            "benchmark_version": CGIN_BENCHMARK_VERSION,
            "fingerprint_algorithm": algorithm.value,
            "authority_name": authority_name,
            "authority_version": authority_version,
            "generated_at": <ISO UTC timestamp>,
        }
    """
    return {
        "tenant_fingerprint": fingerprint_tenant(tenant_id, algorithm),
        "schema_version": CGIN_SCHEMA_VERSION,
        "privacy_version": CGIN_PRIVACY_VERSION,
        "benchmark_version": CGIN_BENCHMARK_VERSION,
        "fingerprint_algorithm": algorithm.value,
        "authority_name": authority_name,
        "authority_version": authority_version,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Snapshot safety validation
# ---------------------------------------------------------------------------


def assert_snapshot_safe(snapshot_dict: dict, tenant_id: str) -> None:
    """Raise ValueError if snapshot_dict contains raw tenant_id or forbidden PII fields.

    Checks:
    - No top-level key in CGIN_FORBIDDEN_FIELDS
    - No string value anywhere in the nested structure equals tenant_id

    Use in tests and CI validation to prove snapshots are privacy-safe.
    """
    found = CGIN_FORBIDDEN_FIELDS & set(snapshot_dict.keys())
    if found:
        raise ValueError(f"CGIN snapshot contains forbidden fields: {found}")
    _check_value(snapshot_dict, tenant_id)


def _check_value(obj: Any, tenant_id: str) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _check_value(v, tenant_id)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_value(v, tenant_id)
    elif isinstance(obj, str) and tenant_id and tenant_id in obj:
        raise ValueError("CGIN snapshot value contains raw tenant_id")
