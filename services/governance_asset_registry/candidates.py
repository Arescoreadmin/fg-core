"""Governance asset candidate lifecycle management.

Candidates are the persistent staging layer between connector detection and
governance asset promotion. This module owns all reads and mutations on
GaAssetCandidate rows.

Identity contract:
  candidate_id = SHA-256(tenant_id:source_type:candidate_type:risk_signal)
  The same signal from the same source in the same tenant always maps to the
  same candidate_id. upsert_candidate() is fully idempotent.

Lifecycle:
  detected → under_review → promoted → rejected
                          → superseded
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_governance_asset_candidates import (
    AUTO_PROMOTE_CONFIDENCE_THRESHOLD,
    GaAssetCandidate,
)
from services.canonical import utc_iso8601_z_now

log = logging.getLogger("frostgate.governance_assets.candidates")


# ---------------------------------------------------------------------------
# Candidate ID
# ---------------------------------------------------------------------------


def _derive_candidate_id(
    tenant_id: str,
    source_type: str,
    candidate_type: str,
    risk_signal: str,
) -> str:
    raw = f"{tenant_id}:{source_type}:{candidate_type}:{risk_signal}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Core upsert
# ---------------------------------------------------------------------------


def upsert_candidate(
    db: Session,
    *,
    tenant_id: str,
    source_type: str,
    candidate_type: str,
    risk_signal: str,
    suggested_name: str,
    suggested_asset_type: str,
    confidence: int,
    manifest_hash: str,
    evidence_ref_ids: list[str],
    engagement_id: str | None = None,
    scan_result_id: str | None = None,
    report_id: str | None = None,
) -> tuple[GaAssetCandidate, bool]:
    """Insert or update a candidate row. Returns (candidate, is_new).

    On re-scan of the same signal:
      - detection_count incremented
      - last_detected_at refreshed
      - peak_confidence updated if current confidence is higher
      - status untouched if already promoted/rejected
    """
    candidate_id = _derive_candidate_id(
        tenant_id, source_type, candidate_type, risk_signal
    )
    now = utc_iso8601_z_now()

    existing = db.execute(
        select(GaAssetCandidate).where(GaAssetCandidate.candidate_id == candidate_id)
    ).scalar_one_or_none()

    if existing is not None:
        existing.detection_count = existing.detection_count + 1
        existing.last_detected_at = now
        existing.confidence = confidence
        if confidence > existing.peak_confidence:
            existing.peak_confidence = confidence
        existing.last_manifest_hash = manifest_hash
        if evidence_ref_ids:
            merged = list({*existing.evidence_ref_ids, *evidence_ref_ids})
            existing.evidence_ref_ids = merged
        if scan_result_id is not None:
            existing.scan_result_id = scan_result_id
        if report_id is not None:
            existing.report_id = report_id
        existing.updated_at = now
        db.flush()
        return existing, False

    candidate = GaAssetCandidate(
        candidate_id=candidate_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scan_result_id=scan_result_id,
        report_id=report_id,
        source_type=source_type,
        candidate_type=candidate_type,
        risk_signal=risk_signal,
        suggested_name=suggested_name,
        suggested_asset_type=suggested_asset_type,
        confidence=confidence,
        peak_confidence=confidence,
        status="detected",
        auto_promoted=False,
        last_manifest_hash=manifest_hash,
        evidence_ref_ids=evidence_ref_ids,
        detection_count=1,
        first_detected_at=now,
        last_detected_at=now,
        schema_version="1.0",
        created_at=now,
        updated_at=now,
    )
    db.add(candidate)
    db.flush()
    return candidate, True


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------


def get_candidate(
    db: Session, *, tenant_id: str, candidate_id: str
) -> GaAssetCandidate | None:
    return db.execute(
        select(GaAssetCandidate).where(
            GaAssetCandidate.candidate_id == candidate_id,
            GaAssetCandidate.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()


def list_candidates(
    db: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    source_type: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[GaAssetCandidate]:
    stmt = select(GaAssetCandidate).where(GaAssetCandidate.tenant_id == tenant_id)
    if status is not None:
        stmt = stmt.where(GaAssetCandidate.status == status)
    if source_type is not None:
        stmt = stmt.where(GaAssetCandidate.source_type == source_type)
    stmt = (
        stmt.order_by(
            GaAssetCandidate.confidence.desc(),
            GaAssetCandidate.last_detected_at.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


def get_inbox(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[GaAssetCandidate]:
    """Candidates awaiting operator decision — detected or under_review."""
    stmt = (
        select(GaAssetCandidate)
        .where(
            GaAssetCandidate.tenant_id == tenant_id,
            GaAssetCandidate.status.in_(["detected", "under_review"]),
        )
        .order_by(
            GaAssetCandidate.confidence.desc(),
            GaAssetCandidate.last_detected_at.desc(),
        )
        .limit(limit)
        .offset(offset)
    )
    return list(db.execute(stmt).scalars().all())


# ---------------------------------------------------------------------------
# Lifecycle mutations
# ---------------------------------------------------------------------------


def mark_under_review(
    db: Session,
    *,
    tenant_id: str,
    candidate_id: str,
    reviewed_by: str,
) -> GaAssetCandidate | None:
    candidate = get_candidate(db, tenant_id=tenant_id, candidate_id=candidate_id)
    if candidate is None or candidate.status not in ("detected",):
        return candidate
    candidate.status = "under_review"
    candidate.reviewed_by = reviewed_by
    candidate.updated_at = utc_iso8601_z_now()
    db.flush()
    return candidate


def mark_promoted(
    db: Session,
    *,
    tenant_id: str,
    candidate_id: str,
    promoted_asset_id: str,
    auto_promoted: bool = False,
    reviewed_by: str | None = None,
) -> GaAssetCandidate | None:
    candidate = get_candidate(db, tenant_id=tenant_id, candidate_id=candidate_id)
    if candidate is None:
        return None
    now = utc_iso8601_z_now()
    candidate.status = "promoted"
    candidate.promoted_asset_id = promoted_asset_id
    candidate.promoted_at = now
    candidate.auto_promoted = auto_promoted
    if reviewed_by is not None:
        candidate.reviewed_by = reviewed_by
    candidate.updated_at = now
    db.flush()
    log.info(
        "candidate.promoted candidate_id=%s asset_id=%s auto=%s",
        candidate_id,
        promoted_asset_id,
        auto_promoted,
    )
    return candidate


def mark_rejected(
    db: Session,
    *,
    tenant_id: str,
    candidate_id: str,
    reason: str,
    reviewed_by: str,
) -> GaAssetCandidate | None:
    candidate = get_candidate(db, tenant_id=tenant_id, candidate_id=candidate_id)
    if candidate is None or candidate.status == "promoted":
        return candidate
    now = utc_iso8601_z_now()
    candidate.status = "rejected"
    candidate.rejected_reason = reason
    candidate.rejected_at = now
    candidate.reviewed_by = reviewed_by
    candidate.updated_at = now
    db.flush()
    log.info("candidate.rejected candidate_id=%s reason=%s", candidate_id, reason)
    return candidate


def supersede_candidate(
    db: Session,
    *,
    tenant_id: str,
    candidate_id: str,
) -> None:
    db.execute(
        update(GaAssetCandidate)
        .where(
            GaAssetCandidate.candidate_id == candidate_id,
            GaAssetCandidate.tenant_id == tenant_id,
            GaAssetCandidate.status == "promoted",
        )
        .values(status="superseded", updated_at=utc_iso8601_z_now())
    )
    db.flush()


# ---------------------------------------------------------------------------
# Auto-promotion gate
# ---------------------------------------------------------------------------


def is_auto_promote_eligible(candidate: GaAssetCandidate) -> bool:
    return candidate.confidence >= AUTO_PROMOTE_CONFIDENCE_THRESHOLD


def candidate_to_dict(candidate: GaAssetCandidate) -> dict[str, Any]:
    return {
        "candidate_id": candidate.candidate_id,
        "tenant_id": candidate.tenant_id,
        "engagement_id": candidate.engagement_id,
        "scan_result_id": candidate.scan_result_id,
        "report_id": candidate.report_id,
        "source_type": candidate.source_type,
        "candidate_type": candidate.candidate_type,
        "risk_signal": candidate.risk_signal,
        "suggested_name": candidate.suggested_name,
        "suggested_asset_type": candidate.suggested_asset_type,
        "confidence": candidate.confidence,
        "peak_confidence": candidate.peak_confidence,
        "status": candidate.status,
        "promoted_asset_id": candidate.promoted_asset_id,
        "promoted_at": candidate.promoted_at,
        "auto_promoted": candidate.auto_promoted,
        "rejected_reason": candidate.rejected_reason,
        "rejected_at": candidate.rejected_at,
        "reviewed_by": candidate.reviewed_by,
        "detection_count": candidate.detection_count,
        "evidence_ref_ids": candidate.evidence_ref_ids,
        "first_detected_at": candidate.first_detected_at,
        "last_detected_at": candidate.last_detected_at,
        "schema_version": candidate.schema_version,
    }
