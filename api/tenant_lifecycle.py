# api/tenant_lifecycle.py
"""
R3 — Tenant Lifecycle Authority.

Single authority for all tenant state transitions.  Every call goes through
execute_transition(); nothing writes lifecycle_state directly.

Valid state machine:
    active      → suspended | archived
    suspended   → active    | archived
    archived    → deleted

"deleted" is terminal — no transitions out of it.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from collections.abc import Sequence
from typing import Any, Optional

from sqlalchemy import text
from sqlalchemy.engine import Engine


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

VALID_STATES: frozenset[str] = frozenset({"active", "suspended", "archived", "deleted"})

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    "active": frozenset({"suspended", "archived"}),
    "suspended": frozenset({"active", "archived"}),
    "archived": frozenset({"deleted"}),
    "deleted": frozenset(),
}

# Bumped when the set of fields that make up transition_hash changes.
TRANSITION_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class TenantTransitionRecord:
    transition_id: str
    tenant_id: str
    from_state: str
    to_state: str
    reason: Optional[str]
    actor_id: Optional[str]
    request_id: Optional[str]
    idempotency_key: Optional[str]
    occurred_at: datetime
    transition_hash: Optional[str]
    schema_version: int


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class InvalidTransitionError(ValueError):
    """Raised when the requested state change is not allowed by the state machine."""


class TenantNotFoundError(KeyError):
    """Raised when the tenant_id does not exist."""


def execute_transition(
    engine: Engine,
    *,
    tenant_id: str,
    to_state: str,
    reason: Optional[str] = None,
    actor_id: Optional[str] = None,
    request_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
    transition_id: Optional[str] = None,
) -> TenantTransitionRecord:
    """Execute a tenant lifecycle transition.

    Flow: validate → idempotency check → set_lifecycle_state → audit record.

    Raises:
        TenantNotFoundError:    tenant_id not found.
        InvalidTransitionError: transition not allowed by state machine.
        ValueError:             to_state not a recognised lifecycle state.
    """
    if to_state not in VALID_STATES:
        raise ValueError(f"Unknown lifecycle state: {to_state!r}")

    with engine.begin() as conn:
        # --- idempotency: return existing record if key already processed ---
        # Scoped to tenant_id so a key used by tenant-A cannot be replayed
        # as a no-op against tenant-B.
        if idempotency_key:
            existing = conn.execute(
                text(
                    "SELECT transition_id, tenant_id, from_state, to_state, "
                    "reason, actor_id, request_id, idempotency_key, occurred_at, "
                    "transition_hash, schema_version "
                    "FROM tenant_lifecycle_transitions "
                    "WHERE tenant_id = :tenant_id AND idempotency_key = :key"
                ),
                {"tenant_id": tenant_id, "key": idempotency_key},
            ).fetchone()
            if existing is not None:
                return _row_to_record(existing)

        # --- fetch current state ---
        row = conn.execute(
            text("SELECT lifecycle_state FROM tenants WHERE tenant_id = :tid"),
            {"tid": tenant_id},
        ).fetchone()
        if row is None:
            raise TenantNotFoundError(f"Tenant not found: {tenant_id}")

        from_state: str = row[0]
        if to_state not in ALLOWED_TRANSITIONS.get(from_state, frozenset()):
            raise InvalidTransitionError(
                f"Transition {from_state!r} → {to_state!r} is not allowed. "
                f"Valid successors: {sorted(ALLOWED_TRANSITIONS.get(from_state, []))}"
            )

        # --- apply state change (conditional on from_state to handle concurrency) ---
        # If another request wins the race and changes the state first, rowcount=0
        # and we raise rather than writing a misleading audit record.
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        result = conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = :state, updated_at = :now "
                "WHERE tenant_id = :tid AND lifecycle_state = :from_state"
            ),
            {
                "state": to_state,
                "now": now_iso,
                "tid": tenant_id,
                "from_state": from_state,
            },
        )
        if result.rowcount == 0:
            raise InvalidTransitionError(
                f"Tenant {tenant_id!r} state changed concurrently; "
                f"expected {from_state!r} but row was already updated"
            )
        if to_state == "archived":
            # Conditional: only write archived_at the first time.
            # If somehow called twice, the original timestamp is authoritative.
            conn.execute(
                text(
                    "UPDATE tenants SET archived_at = :now "
                    "WHERE tenant_id = :tid AND archived_at IS NULL"
                ),
                {"now": now_iso, "tid": tenant_id},
            )

        # --- compute transition hash and write audit record ---
        tid = transition_id or str(uuid.uuid4())
        t_hash = _compute_transition_hash(
            transition_id=tid,
            tenant_id=tenant_id,
            from_state=from_state,
            to_state=to_state,
            occurred_at=now_iso,
            request_id=request_id,
            actor_id=actor_id,
        )
        conn.execute(
            text(
                """
                INSERT INTO tenant_lifecycle_transitions
                    (transition_id, tenant_id, from_state, to_state,
                     reason, actor_id, request_id, idempotency_key, occurred_at,
                     transition_hash, schema_version)
                VALUES
                    (:tid, :tenant_id, :from_state, :to_state,
                     :reason, :actor_id, :request_id, :idempotency_key, :occurred_at,
                     :transition_hash, :schema_version)
                """
            ),
            {
                "tid": tid,
                "tenant_id": tenant_id,
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
                "actor_id": actor_id,
                "request_id": request_id,
                "idempotency_key": idempotency_key,
                "occurred_at": now_iso,
                "transition_hash": t_hash,
                "schema_version": TRANSITION_SCHEMA_VERSION,
            },
        )

    return TenantTransitionRecord(
        transition_id=tid,
        tenant_id=tenant_id,
        from_state=from_state,
        to_state=to_state,
        reason=reason,
        actor_id=actor_id,
        request_id=request_id,
        idempotency_key=idempotency_key,
        occurred_at=now,
        transition_hash=t_hash,
        schema_version=TRANSITION_SCHEMA_VERSION,
    )


def get_transition_history(
    engine: Engine,
    tenant_id: str,
    *,
    limit: int = 50,
) -> list[TenantTransitionRecord]:
    """Return the most recent lifecycle transitions for a tenant, newest first."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT transition_id, tenant_id, from_state, to_state, "
                "reason, actor_id, request_id, idempotency_key, occurred_at, "
                "transition_hash, schema_version "
                "FROM tenant_lifecycle_transitions "
                "WHERE tenant_id = :tid "
                "ORDER BY occurred_at DESC "
                "LIMIT :limit"
            ),
            {"tid": tenant_id, "limit": limit},
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def compute_transition_hash(
    *,
    transition_id: str,
    tenant_id: str,
    from_state: str,
    to_state: str,
    occurred_at: str,
    request_id: Optional[str],
    actor_id: Optional[str],
) -> str:
    """Public re-export so callers can verify a stored hash without importing internals."""
    return _compute_transition_hash(
        transition_id=transition_id,
        tenant_id=tenant_id,
        from_state=from_state,
        to_state=to_state,
        occurred_at=occurred_at,
        request_id=request_id,
        actor_id=actor_id,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _compute_transition_hash(
    *,
    transition_id: str,
    tenant_id: str,
    from_state: str,
    to_state: str,
    occurred_at: str,
    request_id: Optional[str],
    actor_id: Optional[str],
) -> str:
    """SHA-256 fingerprint of the immutable transition fields.

    The hash covers transition_id so it's unique even for identical state
    changes on the same tenant at the same timestamp.  NULL fields are
    serialised as the empty string to keep the hash stable.
    """
    payload = "\n".join(
        [
            transition_id,
            tenant_id,
            from_state,
            to_state,
            occurred_at,
            request_id or "",
            actor_id or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _row_to_record(row: Sequence[Any]) -> TenantTransitionRecord:
    occurred_at = row[8]
    if isinstance(occurred_at, str):
        occurred_at = datetime.fromisoformat(occurred_at)
    # transition_hash (index 9) and schema_version (index 10) may be absent
    # on rows inserted before migration 0158.
    transition_hash = row[9] if len(row) > 9 else None
    schema_version = row[10] if len(row) > 10 else 0
    return TenantTransitionRecord(
        transition_id=row[0],
        tenant_id=row[1],
        from_state=row[2],
        to_state=row[3],
        reason=row[4],
        actor_id=row[5],
        request_id=row[6],
        idempotency_key=row[7],
        occurred_at=occurred_at,
        transition_hash=transition_hash,
        schema_version=schema_version,
    )
