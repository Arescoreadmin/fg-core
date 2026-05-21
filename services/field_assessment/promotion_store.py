"""Promotion store — DB access for GovernancePromotion records.

This module is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

All functions require an explicit tenant_id predicate. The unique constraint
on (tenant_id, engagement_id) is the idempotency guarantee: attempting to
create a second promotion for the same engagement raises IntegrityError, which
the caller should catch and treat as a no-op.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from api.db_models_governance_promotion import GovernancePromotion
from services.canonical import utc_iso8601_z_now
from services.field_assessment.models import PromotionAlreadyExists


def _new_id() -> str:
    return uuid.uuid4().hex


def get_promotion(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
) -> GovernancePromotion | None:
    """Return the promotion record for an engagement, or None if not found."""
    stmt = select(GovernancePromotion).where(
        GovernancePromotion.tenant_id == tenant_id,
        GovernancePromotion.engagement_id == engagement_id,
    )
    return db.execute(stmt).scalar_one_or_none()


def create_promotion(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    gate_snapshot: dict,
    baseline_readiness_score: int,
) -> GovernancePromotion:
    """Create a new promotion record in 'pending' status.

    Raises PromotionAlreadyExists if a record for this engagement already exists.
    The caller transitions status to 'completed' or 'failed' after running the
    promotion steps.
    """
    record = GovernancePromotion(
        id=_new_id(),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        status="pending",
        promoted_at=utc_iso8601_z_now(),
        gate_snapshot_json=gate_snapshot,
        baseline_readiness_score=baseline_readiness_score,
    )
    try:
        with db.begin_nested():
            db.add(record)
            db.flush()
    except IntegrityError:
        raise PromotionAlreadyExists(
            f"promotion already exists for engagement {engagement_id}"
        )
    return record


def complete_promotion(
    db: Session,
    *,
    promotion: GovernancePromotion,
    asset_count: int,
    workflow_count: int,
) -> GovernancePromotion:
    """Mark a pending promotion as completed."""
    promotion.status = "completed"
    promotion.completed_at = utc_iso8601_z_now()
    promotion.asset_count = asset_count
    promotion.workflow_count = workflow_count
    db.flush()
    return promotion


def fail_promotion(
    db: Session,
    *,
    promotion: GovernancePromotion,
    error_detail: str,
) -> GovernancePromotion:
    """Mark a pending promotion as failed with an error detail."""
    promotion.status = "failed"
    promotion.error_detail = error_detail
    db.flush()
    return promotion


def update_corpus_count(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    corpus_entries_added: int,
) -> None:
    """Update corpus_entries_added after the async corpus feed completes.

    No-op if the promotion record no longer exists (defensive).
    """
    record = get_promotion(db, tenant_id=tenant_id, engagement_id=engagement_id)
    if record is not None:
        record.corpus_entries_added = corpus_entries_added
        db.flush()
