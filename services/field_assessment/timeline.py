"""Field assessment → governance timeline bridge.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Emits TimelineEvent records into governance_timeline_events for every
significant field assessment mutation. TimelineStore.record() is idempotent —
duplicate event IDs (same tenant+engagement+event_type+occurred_at) are
silently skipped.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from services.canonical import utc_iso8601_z_now
from services.governance.timeline.identity import derive_event_id
from services.governance.timeline.models import SourceType, TimelineEvent
from services.governance.timeline.store import TimelineStore

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

_store = TimelineStore()


def emit_fa_timeline_event(
    db: "Session",
    *,
    tenant_id: str,
    engagement_id: str,
    event_type: str,
    occurred_at: str | None = None,
    payload: dict[str, Any] | None = None,
    replay_eligible: bool = False,
) -> None:
    """Emit a field assessment lifecycle event into the governance timeline."""
    now = occurred_at or utc_iso8601_z_now()
    event_id = derive_event_id(
        tenant_id=tenant_id,
        source_type=SourceType.FIELD_ASSESSMENT.value,
        source_id=engagement_id,
        event_type=event_type,
        occurred_at=now,
    )
    event = TimelineEvent(
        event_id=event_id,
        tenant_id=tenant_id,
        source_type=SourceType.FIELD_ASSESSMENT,
        source_id=engagement_id,
        event_type=event_type,
        occurred_at=now,
        recorded_at=utc_iso8601_z_now(),
        payload=payload or {},
        replay_eligible=replay_eligible,
    )
    _store.record(db, event)
