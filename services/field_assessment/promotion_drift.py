"""Cross-engagement readiness drift detection.

This module is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

detect_readiness_drift() compares a newly completed promotion's readiness score
against the most recent prior completed promotion for the same tenant. Returns
None when no prior promotion exists or when either score is absent.

All queries include tenant_id. No cross-tenant lookups are possible.
Gate snapshot and raw evidence payloads are never returned from this service.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from api.db_models_governance_promotion import GovernancePromotion
from services.canonical import utc_iso8601_z_now

log = logging.getLogger("frostgate.fa.promotion_drift")


@dataclass(frozen=True)
class ReadinessDriftResult:
    prior_engagement_id: str
    prior_score: float
    new_score: float
    delta: float
    pct_change: float | None
    direction: Literal["improved", "degraded", "stable"]
    detected_at: str


def detect_readiness_drift(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    new_score: float | int | None,
) -> ReadinessDriftResult | None:
    """Compare new_score against the most recent prior completed promotion.

    Returns None if:
    - new_score is None
    - no prior completed promotion exists for this tenant (excluding current engagement)
    - prior baseline_readiness_score is None

    Security: every query is scoped to tenant_id. No cross-tenant access.
    Ordering: promoted_at DESC, id DESC — deterministic even when dates are equal.
    """
    if new_score is None:
        return None

    stmt = (
        select(GovernancePromotion)
        .where(
            GovernancePromotion.tenant_id == tenant_id,
            GovernancePromotion.engagement_id != engagement_id,
            GovernancePromotion.status == "completed",
        )
        .order_by(
            desc(GovernancePromotion.promoted_at),
            desc(GovernancePromotion.id),
        )
        .limit(1)
    )
    prior = db.execute(stmt).scalar_one_or_none()

    if prior is None:
        return None

    prior_score = prior.baseline_readiness_score
    if prior_score is None:
        return None

    new_f = float(new_score)
    prior_f = float(prior_score)
    delta = new_f - prior_f

    pct_change: float | None
    if prior_f == 0:
        pct_change = None
    else:
        pct_change = (delta / abs(prior_f)) * 100

    if abs(delta) < 3:
        direction: Literal["improved", "degraded", "stable"] = "stable"
    elif delta > 0:
        direction = "improved"
    else:
        direction = "degraded"

    return ReadinessDriftResult(
        prior_engagement_id=prior.engagement_id,
        prior_score=prior_f,
        new_score=new_f,
        delta=delta,
        pct_change=pct_change,
        direction=direction,
        detected_at=utc_iso8601_z_now(),
    )
