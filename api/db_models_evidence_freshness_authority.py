# api/db_models_evidence_freshness_authority.py
"""SQLAlchemy ORM models for PR 14.6.7 — Evidence Freshness Authority.

Tables:
  fa_freshness_policies           — freshness policy definitions per evidence type
  fa_evidence_freshness_records   — per-evidence freshness tracking (unique per tenant+evidence)
  fa_freshness_exceptions         — append-only exception grants (delete-only guard at ORM)

Design principles:
  - Every table carries tenant_id NOT NULL — never query without it.
  - fa_freshness_exceptions is append-only at the PG layer (delete trigger in migration 0131).
    The ORM allows status updates for revocation (engine sets status=REVOKED).
    Only DELETE is blocked at the ORM layer.
  - fa_evidence_freshness_records has a UniqueConstraint on (tenant_id, evidence_id):
    one freshness record per evidence per tenant.

Imported by api.db._ensure_models_imported() so init_db() creates the tables.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — the engine always provides an explicit value.

PR 14.6.7 — Evidence Freshness Authority
"""

from __future__ import annotations

from sqlalchemy import Index, Integer, String, Text, UniqueConstraint, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_freshness_policies — freshness policy definitions
# ---------------------------------------------------------------------------


class FaFreshnessPolicy(Base):
    """Freshness policy — defines review/verification/expiration intervals for evidence."""

    __tablename__ = "fa_freshness_policies"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_interval_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90
    )
    verification_interval_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=180
    )
    expiration_interval_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=365
    )
    criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="MEDIUM"
    )
    enabled: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("idx_fa_freshness_policies_type", "tenant_id", "evidence_type"),
    )


# ---------------------------------------------------------------------------
# fa_evidence_freshness_records — per-evidence freshness state
# ---------------------------------------------------------------------------


class FaEvidenceFreshnessRecord(Base):
    """Freshness record — tracks freshness state and score for a single evidence item.

    UniqueConstraint on (tenant_id, evidence_id): one record per evidence per tenant.
    """

    __tablename__ = "fa_evidence_freshness_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    review_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expiration_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_verified_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    freshness_score: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    freshness_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="CURRENT"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "evidence_id",
            name="uidx_fa_freshness_records_evidence",
        ),
        Index("idx_fa_freshness_records_evidence", "tenant_id", "evidence_id"),
        Index("idx_fa_freshness_records_state", "tenant_id", "freshness_state"),
    )


# ---------------------------------------------------------------------------
# fa_freshness_exceptions — append-only exception grants
# ---------------------------------------------------------------------------


class FaFreshnessException(Base):
    """Freshness exception — an approved exception granting temporary freshness relief.

    Append-only at the PostgreSQL layer (delete trigger in migration 0131).
    At the ORM layer, only DELETE is blocked; UPDATE (for revocation) is allowed
    so the engine can set status=REVOKED without creating duplicate rows.
    """

    __tablename__ = "fa_freshness_exceptions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "idx_fa_freshness_exceptions_evidence",
            "tenant_id",
            "evidence_id",
        ),
    )


@sa_event.listens_for(FaFreshnessException, "before_delete")
def _block_exception_delete(mapper, connection, target):
    raise RuntimeError("fa_freshness_exceptions is append-only (deletion not allowed)")
