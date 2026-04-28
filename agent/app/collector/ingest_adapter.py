"""
agent.app.collector.ingest_adapter — Convert CollectorEvent to ingest payload.

Bridges the 17.1 collector framework to the existing POST /ingest surface.

Design invariants:
- tenant_id and agent_id come exclusively from CollectorEvent fields.
- Any tenant_id or agent_id keys present in CollectorEvent.payload are stripped
  before submission; they cannot override the explicit identity fields.
- event_id is derived deterministically from (collector_name, agent_id, event_type,
  occurred_at) via SHA-256; idempotent replay works correctly for same event
  occurrence. event_type is included to prevent collision when a collector emits
  multiple event types sharing the same timestamp.
- CollectorEvent.validate() is called before conversion; malformed events raise
  ValueError and are not converted.
- No broad except/pass; failures propagate to caller.
- Sensitive data minimization from 17.2 is preserved (payload is passed as-is
  after stripping forbidden identity keys; no new sensitive fields added).
"""

from __future__ import annotations

import hashlib
from typing import Any

from agent.app.collector.base import CollectorEvent

# Keys that must never be accepted from CollectorEvent.payload because they
# would attempt to override the explicit identity fields on the ingest request.
_FORBIDDEN_PAYLOAD_KEYS: frozenset[str] = frozenset({"tenant_id", "agent_id"})

# source prefix used in ingest submissions; kept in one place for tests.
AGENT_SOURCE_PREFIX: str = "agent"


def _derive_event_id(
    collector_name: str, agent_id: str, occurred_at: str, event_type: str
) -> str:
    """
    Derive a deterministic event_id for POST /ingest.

    Uses SHA-256 of the canonical string
    "collector_name:agent_id:event_type:occurred_at".
    Returns the first 32 hex characters (lowercase), which matches the
    /ingest event_id pattern ^[A-Za-z0-9._:-]+$ and is within the 128-char limit.

    event_type is included so collectors that emit multiple event types in one
    run (the Collector contract returns a list) do not collide on a shared
    timestamp — a collision would cause /ingest's idempotency guard to silently
    drop the later event.

    Determinism: same (collector_name, agent_id, event_type, occurred_at) always
    produces the same event_id, enabling idempotent replay on the ingest endpoint.
    """
    raw = f"{collector_name}:{agent_id}:{event_type}:{occurred_at}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def collector_event_to_ingest_payload(evt: CollectorEvent) -> dict[str, Any]:
    """
    Convert a CollectorEvent into a POST /ingest request payload dict.

    Tenant binding rule:
    - tenant_id comes from evt.tenant_id (required, validated by CollectorEvent.validate()).
    - agent_id comes from evt.agent_id (required, validated by CollectorEvent.validate()).
    - Any tenant_id or agent_id keys in evt.payload are stripped to prevent override.

    Args:
        evt: A CollectorEvent from the 17.1 collector framework.

    Returns:
        A dict suitable for use as the JSON body of POST /ingest.
        Keys: event_id, tenant_id, source, event_type, timestamp, payload.

    Raises:
        ValueError: If evt fails CollectorEvent.validate() (missing/empty required fields,
                    malformed payload type).
    """
    # Fail-fast: raises ValueError on malformed event before any conversion.
    evt.validate()

    # Strip forbidden identity-override keys from payload.
    safe_payload: dict[str, Any] = {
        k: v for k, v in evt.payload.items() if k not in _FORBIDDEN_PAYLOAD_KEYS
    }

    # Embed collector identity metadata for operator visibility.
    # Uses a namespaced key to avoid collision with domain payload keys.
    safe_payload["_collector"] = {
        "name": evt.collector_name,
        "agent_id": evt.agent_id,
        "schema_version": evt.schema_version,
    }

    return {
        "event_id": _derive_event_id(
            evt.collector_name, evt.agent_id, evt.occurred_at, evt.event_type
        ),
        "tenant_id": evt.tenant_id,
        "source": f"{AGENT_SOURCE_PREFIX}:{evt.agent_id}",
        "event_type": evt.event_type,
        "timestamp": evt.occurred_at,
        "payload": safe_payload,
    }
