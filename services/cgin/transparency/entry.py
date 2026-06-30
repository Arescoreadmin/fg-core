"""Transparency entry data types — frozen, deterministic, append-only."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

TRANSPARENCY_VERSION = "1.0"
TRANSPARENCY_SCHEMA_VERSION = "1.0"


def _compute_entry_id(
    entry_type: str, artifact_digest: str, sequence_number: int
) -> str:
    """Compute a deterministic entry_id from entry_type, artifact_digest, and sequence_number."""
    raw = f"{entry_type}:{artifact_digest}:{sequence_number}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TransparencyEntry:
    """Immutable record of a single transparency log entry.

    The entry_id is computed deterministically from entry_type, artifact_digest,
    and sequence_number via _compute_entry_id().
    """

    entry_id: (
        str  # SHA-256 hex of canonical(entry_type + artifact_digest + sequence_number)
    )
    entry_type: (
        str  # "cgin_snapshot", "trust_manifest", "governance_recommendation", etc.
    )
    authority_name: str
    authority_version: str
    artifact_digest: str  # SHA-256 hex of the artifact being logged
    parent_digest: str | None  # SHA-256 of prior entry, for cross-artifact linking
    sequence_number: int  # monotonically increasing, assigned by ledger
    generated_at: str  # ISO 8601 UTC
    tenant_fingerprint: str  # anonymized tenant identifier (NOT raw tenant_id)
    signature_algorithm: str
    signature_provider: str
    schema_version: str
    transparency_version: str
