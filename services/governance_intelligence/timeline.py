"""Timeline utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.canonical import utc_iso8601_z_now


def build_timeline_event(
    event_type: str,
    entity_id: str,
    entity_type: str,
    actor_id: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Return a dict for a timeline insert."""
    return {
        "event_type": event_type,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "actor_id": actor_id,
        "data": data,
        "created_at": utc_iso8601_z_now(),
    }
