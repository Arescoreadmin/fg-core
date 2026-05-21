"""Graph mutation audit event emission."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session


def emit_graph_audit_event(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str | None = None,
    event_type: str,
    payload: dict[str, Any],
) -> None:
    """Emit graph mutation audit events using the FA audit infrastructure.

    If engagement_id is None, uses tenant_id as a synthetic engagement reference
    so the audit record is always tied to something queryable.
    """
    from services.field_assessment.audit import emit_engagement_audit_event

    synthetic_engagement_id = engagement_id or f"tenant:{tenant_id}"
    emit_engagement_audit_event(
        db,
        tenant_id=tenant_id,
        engagement_id=synthetic_engagement_id,
        event_type=event_type,
        actor="governance_graph",
        reason_code="GRAPH_MUTATION",
        payload=payload,
    )
