"""Timeline event management for the Governance Orchestration Authority."""

from __future__ import annotations

import json
from typing import Any, Optional

from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)


def append_timeline_event(
    db: Any,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    event_type: str,
    actor_id: Optional[str],
    metadata: Optional[dict[str, Any]],
) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.append_timeline(
        entity_type=entity_type,
        entity_id=entity_id,
        event_type=event_type,
        actor_id=actor_id,
        event_metadata=metadata or {},
    )
    return _to_dict(row)


def get_timeline_for_entity(
    db: Any,
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows, _ = repo.list_timeline(
        entity_type=entity_type,
        entity_id=entity_id,
        limit=limit,
        offset=offset,
    )
    return [_to_dict(r) for r in rows]


def get_governance_timeline(
    db: Any, tenant_id: str, limit: int = 50, offset: int = 0
) -> list[dict[str, Any]]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows, _ = repo.list_timeline(limit=limit, offset=offset)
    return [_to_dict(r) for r in rows]


def _to_dict(row: Any) -> dict[str, Any]:
    raw = getattr(row, "event_metadata", None)
    metadata: dict[str, Any] = {}
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                metadata = parsed
        except (TypeError, ValueError):
            metadata = {}
    return {
        "id": row.id,
        "entity_type": row.entity_type,
        "entity_id": row.entity_id,
        "event_type": row.event_type,
        "actor_id": row.actor_id,
        "event_metadata": metadata,
        "created_at": row.created_at,
    }
