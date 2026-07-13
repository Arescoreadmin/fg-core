# api/db_models_identity_assurance.py
"""SQLAlchemy ORM models for PR feat/identity-assurance-trust-engine.

Tables:
  actor_identity_assurance   — current assurance record per actor (mutable: is_current flips)
  actor_assurance_snapshots  — append-only per-decision snapshot chain
  actor_assurance_history    — append-only history of assurance events
  actor_trust_metrics        — upsertable rolling trust metrics per (tenant, actor, period)

Design principles:
  - Every table carries tenant_id NOT NULL — never query without it.
  - Snapshots and history are append-only; ORM-level guards + PG triggers in
    migration 0153 block UPDATE and DELETE.
  - actor_identity_assurance is intentionally mutable (only ``is_current`` flips
    between records for the same (tenant_id, actor_id)); the historical record
    is preserved on ``actor_assurance_snapshots``.

Imported by api.db._ensure_models_imported() so init_db() creates the tables.
"""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    event as sa_event,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


# ---------------------------------------------------------------------------
# actor_identity_assurance — current assurance record per actor
# ---------------------------------------------------------------------------


class ActorIdentityAssurance(Base):
    """Current assurance record for an actor.

    One "current" row per (tenant_id, actor_id) — is_current True for the
    latest evaluation, False for superseded rows. The is_current flip is the
    only permitted mutation; every other change lands on the append-only
    ``actor_assurance_snapshots`` chain.

    ``actor_id`` FK to actor_identities.id is documented in the comment but
    left nullable for SQLite compatibility in test environments.
    """

    __tablename__ = "actor_identity_assurance"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True, index=True
    )  # FK actor_identities.id — nullable for SQLite compat

    assurance_level: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False)
    identity_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authentication_method: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    provider_claims_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_assurance_level: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    computed_at: Mapped[str | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        # Composite uniqueness of the current record per (tenant, actor).
        UniqueConstraint(
            "tenant_id",
            "actor_id",
            "decision_fingerprint",
            name="uq_actor_identity_assurance_tenant_actor_fp",
        ),
        Index("ix_actor_identity_assurance_tenant_actor", "tenant_id", "actor_id"),
        Index(
            "ix_actor_identity_assurance_tenant_level",
            "tenant_id",
            "assurance_level",
        ),
        Index("ix_actor_identity_assurance_tenant_current", "tenant_id", "is_current"),
    )


# Note: ActorIdentityAssurance is intentionally mutable — only ``is_current`` flips.
# No ORM before_update / before_delete guard here; enforcement is by convention
# and by the write path in api/actor_assurance.py which only ever toggles is_current.


# ---------------------------------------------------------------------------
# actor_assurance_snapshots — append-only per-decision chain
# ---------------------------------------------------------------------------


class ActorAssuranceSnapshot(Base):
    """Append-only snapshot recorded for every assurance evaluation.

    ``sequence_number`` is monotonic per (tenant_id, actor_id). The chain is
    verifiable via ``chain_hash``: each row's chain_hash is derived from the
    previous row's chain_hash + the current fingerprint.

    Both UPDATE and DELETE are blocked at the ORM layer. PostgreSQL-level
    guards are in migration 0153.
    """

    __tablename__ = "actor_assurance_snapshots"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)

    previous_assurance_level: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    new_assurance_level: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False)
    identity_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authentication_method: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )

    reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    snapshot_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    chain_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index(
            "ix_actor_assurance_snapshots_tenant_actor",
            "tenant_id",
            "actor_id",
        ),
        Index(
            "ix_actor_assurance_snapshots_tenant_seq",
            "tenant_id",
            "actor_id",
            "sequence_number",
        ),
    )


@sa_event.listens_for(ActorAssuranceSnapshot, "before_update")
def _block_assurance_snapshot_update(mapper, connection, target):
    raise RuntimeError("actor_assurance_snapshots rows are append-only")


@sa_event.listens_for(ActorAssuranceSnapshot, "before_delete")
def _block_assurance_snapshot_delete(mapper, connection, target):
    raise RuntimeError("actor_assurance_snapshots rows are append-only")


# ---------------------------------------------------------------------------
# actor_assurance_history — append-only history of assurance events
# ---------------------------------------------------------------------------


class ActorAssuranceHistory(Base):
    """Append-only history of assurance-related events.

    Distinct from ``actor_assurance_snapshots``: history captures general
    events (evaluations, changes, recalculations) with a metadata blob;
    snapshots capture the immutable chain of authoritative decisions.
    """

    __tablename__ = "actor_assurance_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)

    event_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # assurance_computed | assurance_changed | recalculation_requested
    assurance_level: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_score: Mapped[int] = mapped_column(Integer, nullable=False)
    triggered_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_metadata: Mapped[dict | None] = mapped_column("metadata", JSON, nullable=True)

    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        Index(
            "ix_actor_assurance_history_tenant_actor",
            "tenant_id",
            "actor_id",
        ),
        Index(
            "ix_actor_assurance_history_tenant_event",
            "tenant_id",
            "event_type",
        ),
    )


@sa_event.listens_for(ActorAssuranceHistory, "before_update")
def _block_assurance_history_update(mapper, connection, target):
    raise RuntimeError("actor_assurance_history rows are append-only")


@sa_event.listens_for(ActorAssuranceHistory, "before_delete")
def _block_assurance_history_delete(mapper, connection, target):
    raise RuntimeError("actor_assurance_history rows are append-only")


# ---------------------------------------------------------------------------
# actor_trust_metrics — upsertable rolling trust metrics
# ---------------------------------------------------------------------------


class ActorTrustMetrics(Base):
    """Rolling trust metrics per (tenant, actor, period).

    ``period_key`` uses a stable calendar bucket (e.g. ``"2026-07"`` for
    monthly). Upsertable — one row per bucket per actor.
    """

    __tablename__ = "actor_trust_metrics"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    period_key: Mapped[str] = mapped_column(String(32), nullable=False)

    min_trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    avg_trust_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evaluation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    level_changes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    dominant_level: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[str] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "actor_id",
            "period_key",
            name="uq_actor_trust_metrics_tenant_actor_period",
        ),
        Index(
            "ix_actor_trust_metrics_tenant_actor",
            "tenant_id",
            "actor_id",
        ),
    )
