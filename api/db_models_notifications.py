# api/db_models_notifications.py
"""ORM model for Notification records (PR 13.7).

notifications table: mutable delivery state (PENDING → SENT/FAILED → ACKNOWLEDGED).

Imported by api.db._ensure_models_imported() so init_db() creates the table.

Tenant isolation:
  All queries must include a tenant_id predicate.
  No DEFAULT on tenant_id — store layer always provides an explicit value.
"""

from __future__ import annotations

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class Notification(Base):
    """Notification record: delivery state machine (pending → sent/failed → acknowledged)."""

    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False)
    channel: Mapped[str] = mapped_column(String(32), nullable=False, default="email")
    recipient: Mapped[str] = mapped_column(String(320), nullable=False)
    subject: Mapped[str | None] = mapped_column(String(512), nullable=True)
    delivery_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pending"
    )
    sent_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    acknowledged_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_notifications_tenant_task", "tenant_id", "task_id"),
        Index("ix_notifications_tenant_status", "tenant_id", "delivery_status"),
        Index("ix_notifications_trigger_type", "tenant_id", "trigger_type"),
    )
