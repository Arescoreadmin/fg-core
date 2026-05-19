# api/db_models_timeline.py
"""SQLAlchemy ORM model for governance timeline events.

Infrastructure note (PR 99):
  Extends Base.metadata with governance_timeline_events table.
  Imported by api.db._ensure_models_imported() so init_db() creates the table.

Write contract:
  Append-only.  No UPDATE or DELETE from application layer.
  Duplicate primary keys are silently ignored (idempotent insert).

Tenant isolation:
  All queries must include a tenant_id predicate.
  RLS enabled + forced on governance_timeline_events in migration 0056.

Schema:
  governance_timeline_events(
    id TEXT PK,
    tenant_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,   -- ISO 8601 UTC; lexicographic order == temporal order
    recorded_at TEXT NOT NULL,
    payload JSON NOT NULL,
    classification TEXT NOT NULL DEFAULT 'internal',
    manifest_hash TEXT,
    replay_eligible BOOLEAN DEFAULT FALSE,
    schema_version TEXT DEFAULT '1.0',
    event_version TEXT DEFAULT '1.0'
  )
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class TimelineEventRecord(Base):
    """Append-only governance timeline event record."""

    __tablename__ = "governance_timeline_events"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    occurred_at: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    classification: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal"
    )
    manifest_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    replay_eligible: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    schema_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )
    event_version: Mapped[str] = mapped_column(
        String(16), nullable=False, default="1.0"
    )

    __table_args__ = (
        # Primary list query: tenant feed, newest first
        Index("ix_timeline_tenant_time", "tenant_id", "occurred_at"),
        # Filtered by source type within tenant
        Index("ix_timeline_tenant_source", "tenant_id", "source_type", "occurred_at"),
        # Source entity lookup (all events for a given run/report)
        Index("ix_timeline_source_entity", "tenant_id", "source_id"),
    )
