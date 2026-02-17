from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AuditContext:
    agent_id: str
    agent_persistent_id: str
    tenant_id: str | None
    config_hash: str


def build_audit_event(
    *,
    context: AuditContext,
    job_id: str,
    task_type: str,
    stage: str,
    attempt: int,
    outcome: str,
    timestamp: float,
    error_code: str | None = None,
) -> dict[str, Any]:
    event_material = "|".join(
        [
            context.agent_id,
            context.agent_persistent_id,
            context.tenant_id or "",
            context.config_hash,
            job_id,
            task_type,
            str(int(attempt)),
            stage,
            outcome,
            error_code or "",
        ]
    )
    event_id = hashlib.sha256(event_material.encode("utf-8")).hexdigest()
    payload = {
        "event_id": event_id,
        "agent_id": context.agent_id,
        "agent_persistent_id": context.agent_persistent_id,
        "tenant_id": context.tenant_id,
        "config_hash": context.config_hash,
        "attempt": int(attempt),
        "stage": stage,
        "task_type": task_type,
        "timestamp": timestamp,
        "outcome": outcome,
    }
    if error_code:
        payload["error_code"] = error_code
    return json.loads(json.dumps(payload, sort_keys=True, separators=(",", ":")))
