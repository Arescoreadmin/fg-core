"""Timeline record helpers for remediation tasks.

Maps ORM rows to schema objects. All rows are append-only at the DB level.
"""

from __future__ import annotations

import json
from typing import Any

from services.remediation_authority.schemas import TimelineEventResponse


def timeline_row_to_event(row: Any) -> TimelineEventResponse:
    """Convert a timeline ORM row into a TimelineEventResponse."""
    raw_metadata = getattr(row, "event_metadata", None)
    metadata: dict[str, Any] = {}
    if raw_metadata:
        try:
            parsed = json.loads(raw_metadata)
            if isinstance(parsed, dict):
                metadata = parsed
        except (TypeError, ValueError):
            metadata = {}
    return TimelineEventResponse(
        id=str(getattr(row, "id", "")),
        task_id=str(getattr(row, "task_id", "")),
        event_type=str(getattr(row, "event_type", "")),
        from_state=getattr(row, "from_state", None),
        to_state=getattr(row, "to_state", None),
        actor_id=getattr(row, "actor_id", None),
        reason=getattr(row, "reason", None),
        event_metadata=metadata,
        created_at=str(getattr(row, "created_at", "")),
    )
