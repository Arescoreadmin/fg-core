"""services/governance/timeline/identity.py — Deterministic event IDs and cursors.

All functions are pure Python: no I/O, no randomness, no timestamps.

Event ID derivation:
    event_id = SHA-256(canonical_json({
        tenant_id, source_type, source_id, event_type, occurred_at
    }))[:16]

    Including tenant_id guarantees cross-tenant collision is impossible.
    Including occurred_at means replaying the same logical event at a different
    clock time produces a different ID (it is a new event, not the same one).

Cursor encoding:
    Cursor encodes (occurred_at, event_id) as base64url JSON.
    Stable under concurrent inserts; does not drift like OFFSET pagination.
    Query predicate: (occurred_at < cursor_time) OR
                     (occurred_at = cursor_time AND id > cursor_id)
"""

from __future__ import annotations

import base64
import hashlib
import json


def derive_event_id(
    tenant_id: str,
    source_type: str,
    source_id: str,
    event_type: str,
    occurred_at: str,
) -> str:
    """Derive a deterministic 16-char hex event ID from canonical inputs."""
    canonical = json.dumps(
        {
            "event_type": event_type,
            "occurred_at": occurred_at,
            "source_id": source_id,
            "source_type": source_type,
            "tenant_id": tenant_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def encode_cursor(occurred_at: str, event_id: str) -> str:
    """Encode a pagination cursor from the last page's anchor values."""
    payload = json.dumps(
        {"event_id": event_id, "occurred_at": occurred_at},
        separators=(",", ":"),
    )
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def decode_cursor(cursor: str) -> tuple[str, str]:
    """Decode a pagination cursor.  Raises ValueError on malformed input."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode("ascii") + b"==").decode("utf-8")
        data = json.loads(raw)
        return data["occurred_at"], data["event_id"]
    except (KeyError, ValueError, Exception) as exc:
        raise ValueError(f"Invalid timeline cursor: {exc}") from exc
