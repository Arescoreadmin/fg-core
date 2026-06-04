"""SQLAlchemy ORM model for H14 Governance Event Ledger.

Table: fa_governance_events

Append-only typed event record emitted for every governance action.
DB triggers in migration 0098 prohibit UPDATE and DELETE.

Primary purpose: benchmark intelligence analytics.
Secondary purpose: immutable governance action audit trail.

Event types (examples):
  finding.approved        report.qa_approved
  risk.accepted           exception.granted
  bundle.approved         governance.decision
  vendor.approved         vendor.rejected

All actor attribution fields come from ActorContext (validated JWT or DB
role lookup). They are never accepted from request bodies.

Schema evolution: bump event_version when the event payload shape changes;
bump schema_version when the table columns change. Consumers should handle
unknown versions gracefully rather than failing.
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


class FaGovernanceEvent(Base):
    """Immutable governance event record.

    One row per governance action. Rows are never updated or deleted.
    """

    __tablename__ = "fa_governance_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Event identity — versioned for schema evolution
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    event_version: Mapped[str] = mapped_column(String(16), nullable=False, default="v1")
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="v1"
    )

    # Entity being acted upon
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Actor attribution — all from ActorContext; never from request body
    actor_subject: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # Auth0 sub / key prefix
    actor_email: Mapped[str | None] = mapped_column(String(512), nullable=True)
    actor_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    actor_role: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_auth_source: Mapped[str] = mapped_column(
        String(64), nullable=False, default="api_key"
    )

    # Decision — first-class fields, not buried in payload
    decision_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    event_payload: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON

    # Compliance context
    framework_refs: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # JSON array of control IDs

    # Timing and benchmark intelligence
    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    review_duration_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )  # entity_created_at → occurred_at, in seconds

    # Analytics seed — populated from engagement/org context
    industry_sector: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # "banking" | "healthcare" | "govcon" | ...
    risk_level: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )  # "critical" | "high" | "medium" | "low"
    outcome: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )  # "approved" | "rejected" | "exception_granted"

    # Delegation — schema present; UI not yet built
    delegated_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    delegation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    delegation_expires_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # H13 correlation
    transaction_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )

    __table_args__ = (
        Index("ix_fa_gov_events_tenant_type", "tenant_id", "event_type"),
        Index("ix_fa_gov_events_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_gov_events_entity", "entity_type", "entity_id"),
        Index("ix_fa_gov_events_actor", "tenant_id", "actor_subject"),
        Index("ix_fa_gov_events_occurred", "tenant_id", "occurred_at"),
    )
