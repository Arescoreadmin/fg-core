"""services/governance_chain/events.py — Event helpers for Governance Chain Authority.

PR 17.6 — Canonical Governance Chain Authority
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def chain_event_payload(
    *,
    bridge_type: str,
    source_authority: str,
    target_authority: str,
    trigger_object_id: str,
    trigger_reason: str,
    extra: dict | None = None,
) -> str:
    data: dict = {
        "bridge_type": bridge_type,
        "source_authority": source_authority,
        "target_authority": target_authority,
        "trigger_object_id": trigger_object_id,
        "trigger_reason": trigger_reason,
    }
    if extra:
        data.update(extra)
    return json.dumps(data, sort_keys=True)


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()
