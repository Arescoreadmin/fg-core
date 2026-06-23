"""SQLAlchemy ORM model for Timeline Authority — fa_timeline_events.

PR 14.6.2: Canonical append-only governance ledger with hash chain.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event as sa_event,
)

try:
    from sqlalchemy import JSON
except ImportError:
    from sqlalchemy import JSON  # type: ignore[assignment]

try:
    from api.db_models import Base
except Exception:
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):  # type: ignore[no-redef]
        pass


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TimelineAuthorityEventRecord(Base):
    __tablename__ = "fa_timeline_events"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(255), nullable=False)
    event_id = Column(String(64), nullable=False)
    event_hash = Column(Text, nullable=False, default="")
    prev_event_hash = Column(Text, nullable=False, default="")
    source_system = Column(String(128), nullable=False)
    source_type = Column(String(128), nullable=False, default="")
    entity_type = Column(String(128), nullable=False)
    entity_id = Column(String(255), nullable=False)
    event_type = Column(String(255), nullable=False)
    actor_type = Column(String(64), nullable=False, default="")
    actor_id = Column(String(255), nullable=False, default="")
    occurred_at = Column(DateTime(timezone=True), nullable=False)
    recorded_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    severity = Column(String(16), nullable=False, default="INFO")
    metadata_json = Column(JSON, nullable=False, default=dict)
    correlation_id = Column(String(255), nullable=False, default="")
    causation_id = Column(String(255), nullable=False, default="")
    replay_version = Column(Integer, nullable=False, default=1)
    schema_version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    # P1: authority level
    authority_level = Column(
        String(32), nullable=False, default="SYSTEM", server_default="SYSTEM"
    )
    # P1: signature reservation
    signature_algorithm = Column(
        String(64), nullable=False, default="", server_default=""
    )
    signature_value = Column(Text, nullable=False, default="", server_default="")
    signed_at = Column(DateTime(timezone=True), nullable=True)
    # P1: external references
    external_reference = Column(Text, nullable=False, default="", server_default="")
    external_reference_type = Column(
        String(128), nullable=False, default="", server_default=""
    )
    # P1: federation hooks
    origin_system = Column(String(255), nullable=False, default="", server_default="")
    origin_tenant = Column(String(255), nullable=False, default="", server_default="")
    origin_event_id = Column(String(255), nullable=False, default="", server_default="")

    __table_args__ = (
        UniqueConstraint("tenant_id", "event_id", name="uq_fa_timeline_event_id"),
        Index(
            "ix_fa_timeline_tenant_entity",
            "tenant_id",
            "entity_type",
            "entity_id",
            "occurred_at",
        ),
        Index(
            "ix_fa_timeline_tenant_source", "tenant_id", "source_system", "occurred_at"
        ),
        Index("ix_fa_timeline_tenant_occurred", "tenant_id", "occurred_at"),
        Index("ix_fa_timeline_correlation", "tenant_id", "correlation_id"),
        Index("ix_fa_timeline_event_hash", "event_hash"),
    )


@sa_event.listens_for(TimelineAuthorityEventRecord, "before_update")
def _block_update(mapper, connection, target):
    raise ValueError("fa_timeline_events is append-only — no updates permitted")


@sa_event.listens_for(TimelineAuthorityEventRecord, "before_delete")
def _block_delete(mapper, connection, target):
    raise ValueError("fa_timeline_events is append-only — no deletes permitted")
