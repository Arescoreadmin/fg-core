"""Field assessment audit event emission."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagementAuditEvent
from services.canonical import utc_iso8601_z_now


def emit_engagement_audit_event(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    event_type: str,
    actor: str,
    reason_code: str,
    payload: dict[str, Any],
) -> None:
    """Append an immutable audit event. Never updates existing rows."""
    event_id = hashlib.sha256(
        f"{tenant_id}|{engagement_id}|{event_type}|{utc_iso8601_z_now()}|{uuid.uuid4()}".encode()
    ).hexdigest()[:32]

    db.add(
        FaEngagementAuditEvent(
            id=event_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            event_type=event_type,
            actor=actor,
            reason_code=reason_code,
            payload=payload,
            schema_version="1.0",
            created_at=utc_iso8601_z_now(),
        )
    )
    db.flush()
