"""History tracking helpers for remediation tasks.

Purely a mapping layer between ORM timeline rows and history schema.
"""

from __future__ import annotations

from typing import Any

from services.remediation_authority.schemas import HistoryEntryResponse


def timeline_row_to_history(row: Any) -> HistoryEntryResponse:
    """Map a timeline ORM row to a HistoryEntryResponse."""
    return HistoryEntryResponse(
        id=str(getattr(row, "id", "")),
        task_id=str(getattr(row, "task_id", "")),
        from_state=getattr(row, "from_state", None),
        to_state=getattr(row, "to_state", None),
        actor_id=getattr(row, "actor_id", None),
        reason=getattr(row, "reason", None),
        created_at=str(getattr(row, "created_at", "")),
    )
