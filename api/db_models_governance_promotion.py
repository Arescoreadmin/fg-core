# api/db_models_governance_promotion.py
"""SQLAlchemy ORM model for the Governance Promotion record.

This module is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

The GovernancePromotion record is the authoritative signal that a tenant has
graduated from assessment-only to continuous governance.  It is created
automatically when an engagement transitions to 'delivered' and all gates pass.

One record per (tenant_id, engagement_id).  Idempotency is enforced by the
unique constraint — re-triggering promotion on a completed record is a no-op.

Status lifecycle: pending → completed | failed
  pending   — promotion is in-flight (should resolve in the same request)
  completed — all promotion steps succeeded; corpus feed may still be running
  failed    — promotion encountered an unrecoverable error; retryable via
              POST /field-assessment/engagements/{id}/promote

Tables:
  governance_promotions — one promotion record per delivered engagement
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class GovernancePromotion(Base):
    """Promotion record: assessment → continuous governance.

    Presence of a completed record activates the governance tier for the tenant.
    asset_count, workflow_count, and corpus_entries_added are running totals
    updated as each promotion step completes.
    gate_snapshot_json preserves the full gate evaluation state at delivery time.
    """

    __tablename__ = "governance_promotions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    promoted_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    workflow_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    corpus_entries_added: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    baseline_readiness_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    gate_snapshot_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "engagement_id", name="uq_governance_promotions_engagement"
        ),
        Index("ix_governance_promotions_tenant_status", "tenant_id", "status"),
    )
