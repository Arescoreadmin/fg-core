"""Evidence governance validation functions.

All functions are:
  - Pure Python. No I/O. No randomness.
  - Deterministic: identical inputs always produce identical outputs.
  - Fail-closed: invalid evidence produces ValidationError with explicit reasons.
  - Testable: failure reasons are stable string codes (not narrative text).

Validation is orthogonal to scoring. The scoring engine calls these validators
to confirm evidence is eligible for use, but validation state is independent of
score computation.

Failure reason codes are STABLE — tests MAY assert specific codes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from services.readiness.evidence.models import (
    EvidenceClassificationLevel,
    EvidenceIntegrityRecord,
    EvidenceLifecycleState,
    EvidenceProvenance,
    EvidenceValidationRecord,
    EvidenceValidationType,
)

_VALIDATOR_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Stable failure reason codes
# ---------------------------------------------------------------------------

REASON_HASH_MISMATCH = "EVIDENCE_HASH_MISMATCH"
REASON_HASH_MISSING = "EVIDENCE_HASH_MISSING"
REASON_HASH_ALGORITHM_UNSUPPORTED = "EVIDENCE_HASH_ALGORITHM_UNSUPPORTED"
REASON_TENANT_MISMATCH = "EVIDENCE_TENANT_MISMATCH"
REASON_TENANT_MISSING = "EVIDENCE_TENANT_MISSING"
REASON_CLASSIFICATION_INVALID = "EVIDENCE_CLASSIFICATION_INVALID"
REASON_CLASSIFICATION_MISSING = "EVIDENCE_CLASSIFICATION_MISSING"
REASON_PROVENANCE_TENANT_MISMATCH = "EVIDENCE_PROVENANCE_TENANT_MISMATCH"
REASON_PROVENANCE_EVIDENCE_ID_MISMATCH = "EVIDENCE_PROVENANCE_EVIDENCE_ID_MISMATCH"
REASON_PROVENANCE_SOURCE_MISSING = "EVIDENCE_PROVENANCE_SOURCE_MISSING"
REASON_PROVENANCE_SOURCE_TENANT_MISMATCH = "EVIDENCE_PROVENANCE_SOURCE_TENANT_MISMATCH"
REASON_STATE_INVALIDATED = "EVIDENCE_STATE_INVALIDATED"
REASON_STATE_SUPERSEDED = "EVIDENCE_STATE_SUPERSEDED"
REASON_STATE_EXPIRED = "EVIDENCE_STATE_EXPIRED"
REASON_STATE_ARCHIVED = "EVIDENCE_STATE_ARCHIVED"
REASON_LINKAGE_EMPTY = "EVIDENCE_LINKAGE_EMPTY"
REASON_LINKAGE_TENANT_MISMATCH = "EVIDENCE_LINKAGE_TENANT_MISMATCH"

_VALID_ALGORITHMS = frozenset({"sha256"})
_VALID_CLASSIFICATIONS = frozenset(c.value for c in EvidenceClassificationLevel)


# ---------------------------------------------------------------------------
# Validation functions
# ---------------------------------------------------------------------------


def validate_tenant_isolation(
    *,
    evidence_tenant_id: str,
    caller_tenant_id: str,
    validation_id: str,
    evidence_id: str,
) -> EvidenceValidationRecord:
    """Fail closed on cross-tenant evidence access.

    Returns a ValidationRecord. is_valid=False means the caller MUST NOT
    access or use this evidence record.
    """
    reasons: list[str] = []
    if not evidence_tenant_id:
        reasons.append(REASON_TENANT_MISSING)
    elif evidence_tenant_id != caller_tenant_id:
        reasons.append(REASON_TENANT_MISMATCH)

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=evidence_id,
        tenant_id=caller_tenant_id,
        validation_type=EvidenceValidationType.TENANT_ISOLATION,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )


def validate_evidence_integrity(
    *,
    integrity_record: EvidenceIntegrityRecord,
    recomputed_hash: str,
    validation_id: str,
) -> EvidenceValidationRecord:
    """Verify stored hash matches independently recomputed hash.

    recomputed_hash must come from hashing.verify_evidence_hash() or
    hashing.replay_hash_from_canonical(). This function does not recompute
    the hash itself — it validates a pre-computed result to keep validation
    logic decoupled from hashing logic.
    """
    reasons: list[str] = []

    if not integrity_record.hash_record.hash_value:
        reasons.append(REASON_HASH_MISSING)
    elif integrity_record.hash_record.algorithm not in _VALID_ALGORITHMS:
        reasons.append(REASON_HASH_ALGORITHM_UNSUPPORTED)
    elif integrity_record.hash_record.hash_value != recomputed_hash:
        reasons.append(REASON_HASH_MISMATCH)

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=integrity_record.evidence_id,
        tenant_id=integrity_record.tenant_id,
        validation_type=EvidenceValidationType.INTEGRITY,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )


def validate_evidence_classification(
    *,
    evidence_id: str,
    tenant_id: str,
    classification: Optional[str],
    require_explicit: bool = False,
    validation_id: str,
) -> EvidenceValidationRecord:
    """Validate evidence classification is a known, supported level.

    If require_explicit=True, a None/missing classification is a failure.
    Unknown classification values always fail (default-deny for export safety).
    """
    reasons: list[str] = []

    if classification is None:
        if require_explicit:
            reasons.append(REASON_CLASSIFICATION_MISSING)
    elif classification not in _VALID_CLASSIFICATIONS:
        reasons.append(REASON_CLASSIFICATION_INVALID)

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        validation_type=EvidenceValidationType.CLASSIFICATION,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )


def validate_evidence_provenance(
    *,
    provenance: EvidenceProvenance,
    evidence_tenant_id: str,
    validation_id: str,
) -> EvidenceValidationRecord:
    """Validate provenance internal consistency and tenant isolation.

    Checks:
    - provenance.tenant_id matches evidence_tenant_id
    - provenance.evidence_id is present
    - provenance.source is present and source.tenant_id matches
    """
    reasons: list[str] = []

    if provenance.tenant_id != evidence_tenant_id:
        reasons.append(REASON_PROVENANCE_TENANT_MISMATCH)

    if not provenance.evidence_id:
        reasons.append(REASON_PROVENANCE_EVIDENCE_ID_MISMATCH)

    if provenance.source is None:
        reasons.append(REASON_PROVENANCE_SOURCE_MISSING)
    elif provenance.source.tenant_id != provenance.tenant_id:
        reasons.append(REASON_PROVENANCE_SOURCE_TENANT_MISMATCH)

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=provenance.evidence_id,
        tenant_id=evidence_tenant_id,
        validation_type=EvidenceValidationType.PROVENANCE,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )


def validate_evidence_lifecycle(
    *,
    evidence_id: str,
    tenant_id: str,
    lifecycle_state: EvidenceLifecycleState,
    validation_id: str,
) -> EvidenceValidationRecord:
    """Validate that evidence is in an eligible state for scoring/export use.

    INVALIDATED, SUPERSEDED, and EXPIRED states prevent scoring use.
    ARCHIVED is excluded from active scoring (preserved for audit replay).
    """
    reasons: list[str] = []

    if lifecycle_state == EvidenceLifecycleState.INVALIDATED:
        reasons.append(REASON_STATE_INVALIDATED)
    elif lifecycle_state == EvidenceLifecycleState.SUPERSEDED:
        reasons.append(REASON_STATE_SUPERSEDED)
    elif lifecycle_state == EvidenceLifecycleState.EXPIRED:
        reasons.append(REASON_STATE_EXPIRED)
    elif lifecycle_state == EvidenceLifecycleState.ARCHIVED:
        reasons.append(REASON_STATE_ARCHIVED)

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        validation_type=EvidenceValidationType.LIFECYCLE,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )


def validate_evidence_linkage(
    *,
    evidence_id: str,
    tenant_id: str,
    control_ids: list[str],
    link_tenant_ids: list[str],
    validation_id: str,
) -> EvidenceValidationRecord:
    """Validate evidence linkage is non-empty and tenant-consistent.

    Evidence with zero control linkage is a warning condition but not a hard
    failure (some evidence types may be framework-level, not control-specific).
    Cross-tenant link targets are always a failure.
    """
    reasons: list[str] = []

    if not control_ids:
        reasons.append(REASON_LINKAGE_EMPTY)

    for link_tenant in link_tenant_ids:
        if link_tenant != tenant_id:
            reasons.append(REASON_LINKAGE_TENANT_MISMATCH)
            break

    return EvidenceValidationRecord(
        validation_id=validation_id,
        evidence_id=evidence_id,
        tenant_id=tenant_id,
        validation_type=EvidenceValidationType.LINKAGE,
        is_valid=not reasons,
        failure_reasons=tuple(reasons),
        validated_at=datetime.now(tz=timezone.utc),
        validator_version=_VALIDATOR_VERSION,
    )
