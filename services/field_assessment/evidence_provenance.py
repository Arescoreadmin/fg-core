"""Evidence provenance service — chain-of-custody records for FA evidence.

Every provenance record answers:
  Where did this evidence come from?     → source_type, source_system, source_reference
  Who or what collected it?              → collected_by_type, collected_by_id
  When was it collected?                 → collected_at
  What artifact/hash backs it?           → artifact_hash, source_uri_hash
  Has it been reviewed?                  → review_status, reviewed_by, reviewed_at
  Can its chain be verified?             → event_hash, previous_hash
  Was it used in a report?               → used_in_report_ids

Append-only: no UPDATE or DELETE on fa_evidence_provenance. Review decisions
and amendments create a new row linked via previous_hash; the prior row is
never mutated.
"""

from __future__ import annotations

import hashlib
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceProvenance
from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.field_assessment.store import _new_id

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_REVIEW_STATUSES = frozenset(
    {"pending", "approved", "rejected", "needs_clarification"}
)
VALID_CHAIN_STATUSES = frozenset({"active", "superseded", "amended", "purged"})
VALID_TRUST_LEVELS = frozenset(
    {"unverified", "assessor_reviewed", "qa_approved", "externally_audited"}
)

# Keys that must never appear in collection_context_json
_FORBIDDEN_CONTEXT_KEYS = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "bearer",
        "authorization",
        "credential",
        "client_secret",
        "oauth_token",
        "id_token",
        "refresh_token",
        "hmac_secret",
        "signing_key",
        "jwt_secret",
        "sas_token",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sanitize_provenance_payload(context: dict[str, Any]) -> dict[str, Any]:
    """Remove forbidden keys from collection_context_json before storage."""
    return {
        k: v for k, v in context.items() if k.lower() not in _FORBIDDEN_CONTEXT_KEYS
    }


def compute_provenance_hash(payload: dict[str, Any]) -> str:
    """SHA-256 of canonical JSON — used as event_hash for chain verification."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _hash_payload(
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str | None,
    finding_id: str | None,
    source_type: str,
    collection_method: str,
    collected_by_type: str,
    collected_by_id: str | None,
    collected_at: str,
    artifact_hash: str | None,
    previous_hash: str | None,
    created_at: str,
) -> dict[str, Any]:
    """Build the canonical payload used to derive event_hash."""
    return {
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "evidence_id": evidence_id,
        "finding_id": finding_id,
        "source_type": source_type,
        "collection_method": collection_method,
        "collected_by_type": collected_by_type,
        "collected_by_id": collected_by_id,
        "collected_at": collected_at,
        "artifact_hash": artifact_hash,
        "previous_hash": previous_hash,
        "created_at": created_at,
    }


# ---------------------------------------------------------------------------
# Write operations
# ---------------------------------------------------------------------------


def create_evidence_provenance(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str | None = None,
    finding_id: str | None = None,
    source_type: str,
    source_system: str | None = None,
    source_reference: str | None = None,
    source_uri_hash: str | None = None,
    artifact_hash: str | None = None,
    collected_by_type: str,
    collected_by_id: str | None = None,
    collected_at: str | None = None,
    collection_method: str,
    collection_context: dict[str, Any] | None = None,
    classification: str | None = None,
    retention_policy: str | None = None,
    freshness_at_collection: str | None = None,
    trust_level: str = "unverified",
    chain_status: str = "active",
    previous_hash: str | None = None,
) -> FaEvidenceProvenance:
    """Create an append-only provenance record. Caller owns db.commit()."""
    now = utc_iso8601_z_now()
    actual_collected_at = collected_at or now
    safe_context = sanitize_provenance_payload(collection_context or {})

    payload = _hash_payload(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        finding_id=finding_id,
        source_type=source_type,
        collection_method=collection_method,
        collected_by_type=collected_by_type,
        collected_by_id=collected_by_id,
        collected_at=actual_collected_at,
        artifact_hash=artifact_hash,
        previous_hash=previous_hash,
        created_at=now,
    )
    event_hash = compute_provenance_hash(payload)

    # PR 1.3: sign before INSERT — append-only trigger blocks post-flush UPDATE
    authority = _try_sign_new_event(
        event_hash=event_hash,
        previous_hash=previous_hash,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        finding_id=finding_id,
        source_type=source_type,
        collected_at=actual_collected_at,
    )

    record = FaEvidenceProvenance(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        evidence_id=evidence_id,
        finding_id=finding_id,
        source_type=source_type,
        source_system=source_system,
        source_reference=source_reference,
        source_uri_hash=source_uri_hash,
        artifact_hash=artifact_hash,
        collected_by_type=collected_by_type,
        collected_by_id=collected_by_id,
        collected_at=actual_collected_at,
        collection_method=collection_method,
        collection_context_json=safe_context,
        classification=classification,
        retention_policy=retention_policy,
        freshness_at_collection=freshness_at_collection,
        trust_level=trust_level,
        review_status="pending",
        chain_status=chain_status,
        used_in_report_ids=[],
        previous_hash=previous_hash,
        event_hash=event_hash,
        created_at=now,
        schema_version="1.0",
        signature=authority.get("signature"),
        signing_key_id=authority.get("signing_key_id"),
        signed_at=authority.get("signed_at"),
        signature_version=authority.get("signature_version"),
        authority_version=authority.get("authority_version"),
    )
    db.add(record)
    db.flush()
    return record


def mark_provenance_reviewed(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
    reviewed_by: str,
    new_status: str,
    review_notes: str | None = None,
) -> FaEvidenceProvenance:
    """Record a review decision as a new append-only provenance event.

    Creates a new row chained via previous_hash. The prior row is not mutated
    (append_only_guard triggers enforce this at the DB layer).
    """
    terminal_statuses = VALID_REVIEW_STATUSES - {"pending"}
    if new_status not in terminal_statuses:
        raise ValueError(
            f"invalid review status {new_status!r}; must be one of {sorted(terminal_statuses)}"
        )

    prior = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    if prior is None:
        raise ValueError(f"provenance record {provenance_id!r} not found for tenant")

    now = utc_iso8601_z_now()
    payload = _hash_payload(
        tenant_id=tenant_id,
        engagement_id=prior.engagement_id,
        evidence_id=prior.evidence_id,
        finding_id=prior.finding_id,
        source_type=prior.source_type,
        collection_method=prior.collection_method,
        collected_by_type=prior.collected_by_type,
        collected_by_id=prior.collected_by_id,
        collected_at=prior.collected_at,
        artifact_hash=prior.artifact_hash,
        previous_hash=prior.event_hash,
        created_at=now,
    )
    event_hash = compute_provenance_hash(payload)

    # PR 1.3: sign before INSERT — append-only trigger blocks post-flush UPDATE
    authority = _try_sign_new_event(
        event_hash=event_hash,
        previous_hash=prior.event_hash,
        tenant_id=tenant_id,
        engagement_id=prior.engagement_id,
        evidence_id=prior.evidence_id,
        finding_id=prior.finding_id,
        source_type=prior.source_type,
        collected_at=prior.collected_at,
    )

    review_record = FaEvidenceProvenance(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=prior.engagement_id,
        evidence_id=prior.evidence_id,
        finding_id=prior.finding_id,
        source_type=prior.source_type,
        source_system=prior.source_system,
        source_reference=prior.source_reference,
        source_uri_hash=prior.source_uri_hash,
        artifact_hash=prior.artifact_hash,
        collected_by_type=prior.collected_by_type,
        collected_by_id=prior.collected_by_id,
        collected_at=prior.collected_at,
        collection_method=prior.collection_method,
        collection_context_json=prior.collection_context_json,
        classification=prior.classification,
        retention_policy=prior.retention_policy,
        freshness_at_collection=prior.freshness_at_collection,
        trust_level=prior.trust_level,
        review_status=new_status,
        reviewed_by=reviewed_by,
        reviewed_at=now,
        review_notes=review_notes,
        chain_status="active",
        used_in_report_ids=list(prior.used_in_report_ids or []),
        previous_hash=prior.event_hash,
        event_hash=event_hash,
        created_at=now,
        schema_version="1.0",
        signature=authority.get("signature"),
        signing_key_id=authority.get("signing_key_id"),
        signed_at=authority.get("signed_at"),
        signature_version=authority.get("signature_version"),
        authority_version=authority.get("authority_version"),
    )
    db.add(review_record)
    db.flush()
    return review_record


# ---------------------------------------------------------------------------
# Read operations
# ---------------------------------------------------------------------------


def get_evidence_provenance(
    db: Session,
    *,
    provenance_id: str,
    tenant_id: str,
) -> FaEvidenceProvenance | None:
    """Fetch a provenance record. Returns None if not found or wrong tenant."""
    stmt = select(FaEvidenceProvenance).where(
        FaEvidenceProvenance.id == provenance_id,
        FaEvidenceProvenance.tenant_id == tenant_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def list_evidence_provenance_for_engagement(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[FaEvidenceProvenance]:
    """List provenance records for an engagement, newest first."""
    limit = min(limit, 100)
    stmt = (
        select(FaEvidenceProvenance)
        .where(
            FaEvidenceProvenance.tenant_id == tenant_id,
            FaEvidenceProvenance.engagement_id == engagement_id,
        )
        .order_by(FaEvidenceProvenance.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def list_evidence_provenance_for_finding(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    finding_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[FaEvidenceProvenance]:
    """List provenance records for a specific finding."""
    limit = min(limit, 100)
    stmt = (
        select(FaEvidenceProvenance)
        .where(
            FaEvidenceProvenance.tenant_id == tenant_id,
            FaEvidenceProvenance.engagement_id == engagement_id,
            FaEvidenceProvenance.finding_id == finding_id,
        )
        .order_by(FaEvidenceProvenance.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_provenance_chain(
    db: Session,
    *,
    tenant_id: str,
    provenance_id: str,
) -> dict[str, Any]:
    """Verify a provenance record's event_hash matches its stored payload.

    Returns {'valid': bool, 'provenance_id': str, 'reason': str}.
    """
    record = get_evidence_provenance(
        db, provenance_id=provenance_id, tenant_id=tenant_id
    )
    if record is None:
        return {"valid": False, "provenance_id": provenance_id, "reason": "not_found"}

    expected_payload = _hash_payload(
        tenant_id=record.tenant_id,
        engagement_id=record.engagement_id,
        evidence_id=record.evidence_id,
        finding_id=record.finding_id,
        source_type=record.source_type,
        collection_method=record.collection_method,
        collected_by_type=record.collected_by_type,
        collected_by_id=record.collected_by_id,
        collected_at=record.collected_at,
        artifact_hash=record.artifact_hash,
        previous_hash=record.previous_hash,
        created_at=record.created_at,
    )
    expected_hash = compute_provenance_hash(expected_payload)

    if expected_hash != record.event_hash:
        return {
            "valid": False,
            "provenance_id": provenance_id,
            "reason": "hash_mismatch",
        }

    return {"valid": True, "provenance_id": provenance_id, "reason": "ok"}


# ---------------------------------------------------------------------------
# PR 1.3: Evidence Authority integration
# ---------------------------------------------------------------------------


def _try_sign_new_event(
    *,
    event_hash: str,
    previous_hash: str | None,
    tenant_id: str,
    engagement_id: str,
    evidence_id: str | None,
    finding_id: str | None,
    source_type: str,
    collected_at: str,
) -> dict:
    """Return Ed25519 authority fields for a new event, or {} if key not configured.

    Called before the record is flushed — append-only triggers block post-flush
    UPDATE, so authority fields must be set in the initial INSERT.

    In prod: raises if signing key missing (fail-closed).
    In dev/test: returns {} and leaves the record unsigned (legacy-compatible).
    """
    try:
        from services.field_assessment.evidence_authority import (
            sign_new_provenance_event,
        )

        return sign_new_provenance_event(
            event_hash=event_hash,
            previous_hash=previous_hash,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            evidence_id=evidence_id,
            finding_id=finding_id,
            source_type=source_type,
            collected_at=collected_at,
        )
    except Exception as exc:
        from api.config.env import is_production_env

        if is_production_env():
            raise RuntimeError(f"evidence_authority.signing_failed: {exc}") from exc
        return {}
