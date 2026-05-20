"""Governance asset promotion engine.

Handles the deterministic, idempotent transition from GaAssetCandidate
to a live GaAsset, and the bidirectional linkage of FaNormalizedFinding
records to their governing asset.

Promotion contract:
  promote_candidate_to_asset() is fully idempotent.
  If a GaAsset already exists with external_id matching the candidate's
  risk_signal key, the existing asset is returned and the candidate
  record is updated to reflect the promotion without creating a duplicate.

Finding linkage contract:
  link_findings_to_asset() stamps asset_id onto FaNormalizedFinding rows
  that share the same (tenant_id, engagement_id, source_attribution).
  This feeds open_findings_weight into the risk engine on every recompute.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaNormalizedFinding
from api.db_models_governance_assets import GaAsset
from api.db_models_governance_asset_candidates import GaAssetCandidate
from services.canonical import utc_iso8601_z_now
from services.governance_asset_registry.candidates import (
    is_auto_promote_eligible,
    mark_promoted,
)
from services.governance_asset_registry.models import DiscoverySource
from services.governance_asset_registry.registry import create_asset

log = logging.getLogger("frostgate.governance_assets.promotion")

# Severity → weight contribution for open_findings_weight computation.
# Capped at 150 by build_factors().
_FINDING_SEVERITY_WEIGHT = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 1,
    "informational": 0,
}


# ---------------------------------------------------------------------------
# Finding linkage
# ---------------------------------------------------------------------------


def link_findings_to_asset(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    engagement_id: str,
    source_attribution: str,
) -> int:
    """Stamp asset_id onto open findings that match the source attribution.

    Returns the count of rows updated.
    """
    result = db.execute(
        update(FaNormalizedFinding)
        .where(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.source_attribution == source_attribution,
            FaNormalizedFinding.status == "open",
            FaNormalizedFinding.asset_id.is_(None),
        )
        .values(asset_id=asset_id, updated_at=utc_iso8601_z_now())
    )
    count = result.rowcount
    if count > 0:
        log.info(
            "findings.linked asset_id=%s source=%s count=%d",
            asset_id,
            source_attribution,
            count,
        )
    return count


def compute_open_findings_weight(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
) -> int:
    """Compute open_findings_weight from linked open findings.

    Weights: critical=30, high=15, medium=5, low=1. Capped at 150.
    """
    stmt = select(
        FaNormalizedFinding.severity,
    ).where(
        FaNormalizedFinding.tenant_id == tenant_id,
        FaNormalizedFinding.asset_id == asset_id,
        FaNormalizedFinding.status == "open",
    )
    rows = db.execute(stmt).all()
    raw = sum(_FINDING_SEVERITY_WEIGHT.get(r.severity, 0) for r in rows)
    return min(150, raw)


# ---------------------------------------------------------------------------
# Idempotent promotion
# ---------------------------------------------------------------------------


def _find_existing_asset_for_signal(
    db: Session,
    *,
    tenant_id: str,
    risk_signal: str,
    source_type: str,
) -> GaAsset | None:
    """Find an existing GaAsset keyed by the canonical external_id for this signal."""
    external_id = f"{source_type}:{risk_signal}"
    stmt = select(GaAsset).where(
        GaAsset.tenant_id == tenant_id,
        GaAsset.external_id == external_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def promote_candidate_to_asset(
    db: Session,
    *,
    candidate: GaAssetCandidate,
    actor_email: str,
    auto_promoted: bool = False,
) -> GaAsset:
    """Promote a candidate to a live GaAsset — idempotent.

    If a GaAsset already exists for this signal (matched via external_id),
    returns the existing asset and updates the candidate record.
    This preserves owner assignments and attestation history.

    If no asset exists, calls create_asset() which also computes initial
    risk score, creates a version snapshot, and emits an audit event.
    """
    if candidate.status == "promoted" and candidate.promoted_asset_id:
        existing = db.execute(
            select(GaAsset).where(GaAsset.asset_id == candidate.promoted_asset_id)
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    external_id = f"{candidate.source_type}:{candidate.risk_signal}"

    existing = _find_existing_asset_for_signal(
        db,
        tenant_id=candidate.tenant_id,
        risk_signal=candidate.risk_signal,
        source_type=candidate.source_type,
    )
    if existing is not None:
        mark_promoted(
            db,
            tenant_id=candidate.tenant_id,
            candidate_id=candidate.candidate_id,
            promoted_asset_id=existing.asset_id,
            auto_promoted=auto_promoted,
        )
        log.info(
            "promotion.idempotent candidate_id=%s existing_asset_id=%s",
            candidate.candidate_id,
            existing.asset_id,
        )
        return existing

    asset = create_asset(
        db,
        tenant_id=candidate.tenant_id,
        asset_type=candidate.suggested_asset_type,
        name=candidate.suggested_name,
        description=f"Auto-detected via {candidate.source_type} — signal: {candidate.risk_signal}",
        external_id=external_id,
        metadata={
            "candidate_id": candidate.candidate_id,
            "source_type": candidate.source_type,
            "candidate_type": candidate.candidate_type,
            "risk_signal": candidate.risk_signal,
            "confidence": candidate.confidence,
            "peak_confidence": candidate.peak_confidence,
            "detection_count": candidate.detection_count,
            "first_detected_at": candidate.first_detected_at,
        },
        discovery_source=DiscoverySource.discovered.value,
        actor_email=actor_email,
    )

    mark_promoted(
        db,
        tenant_id=candidate.tenant_id,
        candidate_id=candidate.candidate_id,
        promoted_asset_id=asset.asset_id,
        auto_promoted=auto_promoted,
    )

    log.info(
        "promotion.created candidate_id=%s asset_id=%s auto=%s",
        candidate.candidate_id,
        asset.asset_id,
        auto_promoted,
    )
    return asset


def auto_promote_if_eligible(
    db: Session,
    *,
    candidate: GaAssetCandidate,
    actor_email: str = "system@frostgate.auto",
) -> GaAsset | None:
    """Promote if confidence meets the auto-promote threshold.

    Returns the promoted GaAsset if promotion occurred, else None.
    Safe to call after every upsert — returns None for low-confidence candidates.
    """
    if candidate.status in ("promoted", "rejected", "superseded"):
        return None
    if not is_auto_promote_eligible(candidate):
        return None
    return promote_candidate_to_asset(
        db,
        candidate=candidate,
        actor_email=actor_email,
        auto_promoted=True,
    )
