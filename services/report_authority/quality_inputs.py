"""services/report_authority/quality_inputs.py — Live quality input derivation.

Bridges the Report Authority engine to FA evidence data so that
compute_quality_score() receives real measurements instead of the 0.5
placeholder values.

Called once per generate_report() invocation. Read-only queries only.
Returns five floats in [0.0, 1.0]. Falls back to 0.0 on empty engagement.

Metric definitions
------------------
evidence_coverage   Breadth: distinct evidence-linked entities / findings.
                    "How many findings have at least one piece of evidence?"

verification_coverage  Depth: approved provenance rows / total provenance rows.
                       "How much of the collected evidence has been reviewed?"

freshness           Recency: average exponential decay across provenance
                    collected_at timestamps (half-life = 90 days).
                    "How recent is the evidence?"

confidence          Assessor signal: avg(finding.confidence_score) / 100.
                    "How confident is the assessor in each finding?"

completeness        Volume: total evidence links / (findings * 2), capped 1.0.
                    "Does each finding have sufficient evidence depth?"
"""

from __future__ import annotations

import math
from datetime import datetime, timezone

from sqlalchemy import distinct, func
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaEvidenceProvenance,
    FaNormalizedFinding,
)

_FRESHNESS_HALF_LIFE_DAYS: float = 90.0


def compute_quality_inputs(
    db: Session,
    tenant_id: str,
    engagement_id: str,
) -> tuple[float, float, float, float, float]:
    """Return (evidence_coverage, verification_coverage, freshness, confidence, completeness).

    All values are in [0.0, 1.0].
    """
    return (
        _evidence_coverage(db, tenant_id, engagement_id),
        _verification_coverage(db, tenant_id, engagement_id),
        _freshness(db, tenant_id, engagement_id),
        _confidence(db, tenant_id, engagement_id),
        _completeness(db, tenant_id, engagement_id),
    )


def _evidence_coverage(db: Session, tenant_id: str, engagement_id: str) -> float:
    total_findings = (
        db.query(func.count(FaNormalizedFinding.id))
        .filter(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
        )
        .scalar()
        or 0
    )
    if total_findings == 0:
        return 0.0
    linked_entities = (
        db.query(func.count(distinct(FaEvidenceLink.source_entity_id)))
        .filter(
            FaEvidenceLink.tenant_id == tenant_id,
            FaEvidenceLink.engagement_id == engagement_id,
        )
        .scalar()
        or 0
    )
    return min(1.0, linked_entities / total_findings)


def _verification_coverage(db: Session, tenant_id: str, engagement_id: str) -> float:
    total = (
        db.query(func.count(FaEvidenceProvenance.id))
        .filter(
            FaEvidenceProvenance.tenant_id == tenant_id,
            FaEvidenceProvenance.engagement_id == engagement_id,
        )
        .scalar()
        or 0
    )
    if total == 0:
        return 0.0
    approved = (
        db.query(func.count(FaEvidenceProvenance.id))
        .filter(
            FaEvidenceProvenance.tenant_id == tenant_id,
            FaEvidenceProvenance.engagement_id == engagement_id,
            FaEvidenceProvenance.review_status == "approved",
        )
        .scalar()
        or 0
    )
    return approved / total


def _freshness(db: Session, tenant_id: str, engagement_id: str) -> float:
    rows = (
        db.query(FaEvidenceProvenance.collected_at)
        .filter(
            FaEvidenceProvenance.tenant_id == tenant_id,
            FaEvidenceProvenance.engagement_id == engagement_id,
        )
        .all()
    )
    if not rows:
        return 0.0
    now = datetime.now(tz=timezone.utc)
    scores: list[float] = []
    for (collected_at_str,) in rows:
        try:
            collected_at = datetime.fromisoformat(collected_at_str)
            if collected_at.tzinfo is None:
                collected_at = collected_at.replace(tzinfo=timezone.utc)
            age_days = max(0.0, (now - collected_at).total_seconds() / 86400.0)
            scores.append(
                math.exp(-math.log(2) * age_days / _FRESHNESS_HALF_LIFE_DAYS)
            )
        except (ValueError, TypeError):
            scores.append(0.0)
    return sum(scores) / len(scores)


def _confidence(db: Session, tenant_id: str, engagement_id: str) -> float:
    avg = (
        db.query(func.avg(FaNormalizedFinding.confidence_score))
        .filter(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
        )
        .scalar()
    )
    if avg is None:
        return 0.0
    return float(avg) / 100.0


def _completeness(db: Session, tenant_id: str, engagement_id: str) -> float:
    total_findings = (
        db.query(func.count(FaNormalizedFinding.id))
        .filter(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
        )
        .scalar()
        or 0
    )
    if total_findings == 0:
        return 0.0
    total_links = (
        db.query(func.count(FaEvidenceLink.id))
        .filter(
            FaEvidenceLink.tenant_id == tenant_id,
            FaEvidenceLink.engagement_id == engagement_id,
        )
        .scalar()
        or 0
    )
    # Target 2 links per finding for full completeness
    return min(1.0, total_links / (total_findings * 2))
