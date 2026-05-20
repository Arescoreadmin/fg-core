"""Deterministic finding_id derivation.

finding_id = sha256(sha256(tenant_id) + control_id + evidence_key)

Same tenant + control + evidence always produces the same ID, enabling
delta comparison across rescans.  The tenant_id is hashed before use so
the plaintext tenant identifier is never embedded in finding IDs.
"""

from __future__ import annotations

import hashlib


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def derive_finding_id(
    *,
    tenant_id: str,
    control_id: str,
    evidence_key: str,
) -> str:
    """Return the deterministic finding_id for the given inputs."""
    tenant_hash = _sha256_hex(tenant_id)
    raw = tenant_hash + control_id + evidence_key
    return _sha256_hex(raw)


def hash_tenant_id(tenant_id: str) -> str:
    """Return sha256(tenant_id) for safe storage."""
    return _sha256_hex(tenant_id)
