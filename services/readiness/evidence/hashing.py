"""Deterministic evidence hash computation.

All functions in this module are:
  - Pure Python. No I/O. No randomness.
  - Deterministic: identical inputs always produce identical outputs.
  - Ordering-stable: dict key ordering never affects the output.
  - Replay-safe: inputs_canonical is sufficient to reproduce hash_value.
  - Timestamp-safe: nondeterministic timestamps are NEVER part of hash inputs.

Hash algorithm: SHA-256 (upgradable via algorithm parameter without redesign).

Canonical form:
  - JSON with sort_keys=True, separators=(",", ":"), no whitespace.
  - UTF-8 encoded before hashing.

Future extensions:
  - Merkle tree: compute_evidence_hash() returns a leaf node; callers build tree.
  - Signed chains: hash_value is signing target; signer metadata goes in EvidenceLink.
  - External verification: inputs_canonical ships with evidence for independent replay.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Optional

from services.readiness.evidence.models import EvidenceHashRecord

_HASH_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Hash input specification
# ---------------------------------------------------------------------------

# These are the ONLY fields that contribute to the canonical hash of an
# evidence reference. This list is the authoritative documentation of hash inputs.
# Changing this list is a breaking change — bump _HASH_VERSION.
_EVIDENCE_HASH_INPUT_DESCRIPTION = (
    "SHA-256 of canonical JSON (sort_keys=True, no whitespace, UTF-8) of: "
    "evidence_id, assessment_id, tenant_id, evidence_type, evidence_title, "
    "submitted_by, control_ids (sorted), evidence_classification. "
    "EXCLUDED from hash: timestamps, metadata dicts, notes, expiration_date, "
    "effective_date (all nondeterministic or mutable fields). "
    "Hash version: " + _HASH_VERSION
)


def _make_canonical(fields: dict[str, Any]) -> str:
    """Return deterministic JSON string for a field dict.

    Guarantees:
    - Keys are sorted alphabetically.
    - No whitespace (compact separators).
    - UTF-8 compatible (no ensure_ascii=False surprises on non-ASCII IDs).
    - List values are sorted where order is semantically irrelevant.
    """
    return json.dumps(fields, sort_keys=True, separators=(",", ":"))


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def compute_evidence_hash(
    *,
    evidence_id: str,
    assessment_id: str,
    tenant_id: str,
    evidence_type: str,
    evidence_title: str,
    submitted_by: str,
    control_ids: list[str],
    evidence_classification: Optional[str],
    algorithm: str = "sha256",
) -> EvidenceHashRecord:
    """Compute a deterministic hash of the stable evidence identity fields.

    Only stable, caller-supplied identity fields are hashed. Mutable metadata,
    timestamps, and notes are excluded — they do not contribute to integrity.

    The canonical JSON is preserved in EvidenceHashRecord.inputs_canonical so
    that any party with the raw field values can independently verify the hash.

    Args:
        evidence_id: Stable identifier for this evidence record.
        assessment_id: Assessment this evidence is attached to.
        tenant_id: Tenant owner — included to prevent cross-tenant hash collision.
        evidence_type: EvidenceType.value string.
        evidence_title: Submitted title (not raw content).
        submitted_by: Actor who submitted the evidence.
        control_ids: List of control IDs linked to this evidence (sorted for stability).
        evidence_classification: Classification level string or None.
        algorithm: Hash algorithm identifier (default "sha256").

    Returns:
        EvidenceHashRecord with deterministic hash_value and inputs_canonical.
    """
    if algorithm != "sha256":
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm!r}. Only 'sha256' is supported."
        )

    canonical_fields: dict[str, Any] = {
        "evidence_id": evidence_id,
        "assessment_id": assessment_id,
        "tenant_id": tenant_id,
        "evidence_type": evidence_type,
        "evidence_title": evidence_title,
        "submitted_by": submitted_by,
        "control_ids": sorted(control_ids),
        "evidence_classification": evidence_classification,
        "_hash_version": _HASH_VERSION,
    }
    inputs_canonical = _make_canonical(canonical_fields)
    hash_value = _sha256(inputs_canonical)

    return EvidenceHashRecord(
        evidence_id=evidence_id,
        algorithm=algorithm,
        hash_value=hash_value,
        inputs_canonical=inputs_canonical,
        inputs_description=_EVIDENCE_HASH_INPUT_DESCRIPTION,
        computed_at=datetime.now(tz=timezone.utc),
        is_replay_safe=True,
    )


def verify_evidence_hash(
    *,
    evidence_id: str,
    assessment_id: str,
    tenant_id: str,
    evidence_type: str,
    evidence_title: str,
    submitted_by: str,
    control_ids: list[str],
    evidence_classification: Optional[str],
    expected_hash: str,
    algorithm: str = "sha256",
) -> bool:
    """Verify a stored hash matches deterministic recomputation from field values.

    Returns True if the recomputed hash matches expected_hash. Returns False
    (never raises) on mismatch — callers decide whether mismatch is an error.

    This function is replay-safe: it uses only the documented hash inputs and
    is therefore independent of when or where the original hash was computed.
    """
    record = compute_evidence_hash(
        evidence_id=evidence_id,
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        evidence_type=evidence_type,
        evidence_title=evidence_title,
        submitted_by=submitted_by,
        control_ids=control_ids,
        evidence_classification=evidence_classification,
        algorithm=algorithm,
    )
    return record.hash_value == expected_hash


def replay_hash_from_canonical(inputs_canonical: str, algorithm: str = "sha256") -> str:
    """Recompute a hash directly from a stored inputs_canonical string.

    This is the forensic replay path: given only the inputs_canonical string
    (which ships with every EvidenceHashRecord), any party can independently
    verify the hash_value without needing access to the original field values.

    Raises ValueError if algorithm is unsupported.
    """
    if algorithm != "sha256":
        raise ValueError(f"Unsupported hash algorithm: {algorithm!r}.")
    return _sha256(inputs_canonical)
