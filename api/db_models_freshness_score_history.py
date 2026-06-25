# api/db_models_freshness_score_history.py
"""SQLAlchemy ORM models for PR 14.6.8 — Freshness Score History.

Tables:
  fa_freshness_score_snapshots  — per-evidence per-day freshness snapshots (append-only)
  fa_freshness_daily_snapshots  — daily aggregate snapshots per tenant (append-only)
  fa_freshness_trend_snapshots  — trend period snapshots (append-only)

Design:
  - All three tables are append-only at both ORM and PG trigger level.
  - UniqueConstraints enforce one snapshot per evidence per day and one daily
    aggregate per tenant per day.

PR 14.6.8 — Freshness Score History & Governance Trend Intelligence
"""

from __future__ import annotations

from sqlalchemy import (
    Float,
    Index,
    Integer,
    String,
    UniqueConstraint,
    event as sa_event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_freshness_score_snapshots — per-evidence daily snapshot
# ---------------------------------------------------------------------------


class FaFreshnessScoreSnapshot(Base):
    """Immutable daily freshness score snapshot for a single evidence item."""

    __tablename__ = "fa_freshness_score_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    freshness_record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    freshness_score: Mapped[int] = mapped_column(Integer, nullable=False)
    freshness_state: Mapped[str] = mapped_column(String(32), nullable=False)
    review_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expiration_due_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    captured_at: Mapped[str] = mapped_column(String(64), nullable=False)
    capture_date: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "evidence_id",
            "capture_date",
            name="uidx_fa_score_snapshots_evidence_date",
        ),
        Index(
            "idx_fa_score_snapshots_evidence_date",
            "tenant_id",
            "evidence_id",
            "capture_date",
        ),
    )


@sa_event.listens_for(FaFreshnessScoreSnapshot, "before_update")
def _block_score_snapshot_update(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_score_snapshots is append-only (update not allowed)"
    )


@sa_event.listens_for(FaFreshnessScoreSnapshot, "before_delete")
def _block_score_snapshot_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_score_snapshots is append-only (deletion not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_freshness_daily_snapshots — daily tenant aggregate
# ---------------------------------------------------------------------------


class FaFreshnessDailySnapshot(Base):
    """Immutable daily aggregate freshness snapshot for a tenant."""

    __tablename__ = "fa_freshness_daily_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    average_freshness_score: Mapped[float] = mapped_column(Float, nullable=False)
    fresh_evidence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    due_soon_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    review_required_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    verification_required_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    expired_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    coverage_at_risk_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    total_evidence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    captured_at: Mapped[str] = mapped_column(String(64), nullable=False)
    capture_date: Mapped[str] = mapped_column(String(16), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "capture_date",
            name="uidx_fa_daily_snapshots_tenant_date",
        ),
    )


@sa_event.listens_for(FaFreshnessDailySnapshot, "before_update")
def _block_daily_snapshot_update(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_daily_snapshots is append-only (update not allowed)"
    )


@sa_event.listens_for(FaFreshnessDailySnapshot, "before_delete")
def _block_daily_snapshot_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_daily_snapshots is append-only (deletion not allowed)"
    )


# ---------------------------------------------------------------------------
# fa_freshness_trend_snapshots — trend period snapshot (archive)
# ---------------------------------------------------------------------------


class FaFreshnessTrendSnapshot(Base):
    """Immutable trend snapshot for a specific period (7d, 30d, 90d, 180d, 365d)."""

    __tablename__ = "fa_freshness_trend_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    period: Mapped[str] = mapped_column(String(16), nullable=False)
    average_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_delta: Mapped[float | None] = mapped_column(Float, nullable=True)
    fresh_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    expired_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    coverage_risk_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generated_at: Mapped[str] = mapped_column(String(64), nullable=False)


@sa_event.listens_for(FaFreshnessTrendSnapshot, "before_update")
def _block_trend_snapshot_update(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_trend_snapshots is append-only (update not allowed)"
    )


@sa_event.listens_for(FaFreshnessTrendSnapshot, "before_delete")
def _block_trend_snapshot_delete(mapper, connection, target):
    raise RuntimeError(
        "fa_freshness_trend_snapshots is append-only (deletion not allowed)"
    )
