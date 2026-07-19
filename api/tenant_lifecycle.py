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

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

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
        if idempotency_key:
            existing = conn.execute(
                text(
                    "SELECT transition_id, tenant_id, from_state, to_state, "
                    "reason, actor_id, request_id, idempotency_key, occurred_at "
                    "FROM tenant_lifecycle_transitions "
                    "WHERE idempotency_key = :key"
                ),
                {"key": idempotency_key},
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

        # --- apply state change ---
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        conn.execute(
            text(
                "UPDATE tenants SET lifecycle_state = :state, updated_at = :now "
                "WHERE tenant_id = :tid"
            ),
            {"state": to_state, "now": now_iso, "tid": tenant_id},
        )
        if to_state == "archived":
            conn.execute(
                text("UPDATE tenants SET archived_at = :now WHERE tenant_id = :tid"),
                {"now": now_iso, "tid": tenant_id},
            )

        # --- write transition audit record ---
        tid = transition_id or str(uuid.uuid4())
        conn.execute(
            text(
                """
                INSERT INTO tenant_lifecycle_transitions
                    (transition_id, tenant_id, from_state, to_state,
                     reason, actor_id, request_id, idempotency_key, occurred_at)
                VALUES
                    (:tid, :tenant_id, :from_state, :to_state,
                     :reason, :actor_id, :request_id, :idempotency_key, :occurred_at)
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
    )


def get_transition_history(
    engine: Engine,
    tenant_id: str,
    *,
    limit: int = 50,
) -> list[TenantTransitionRecord]:
    """Return the most recent lifecycle transitions for a tenant."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT transition_id, tenant_id, from_state, to_state, "
                "reason, actor_id, request_id, idempotency_key, occurred_at "
                "FROM tenant_lifecycle_transitions "
                "WHERE tenant_id = :tid "
                "ORDER BY occurred_at DESC "
                "LIMIT :limit"
            ),
            {"tid": tenant_id, "limit": limit},
        ).fetchall()
    return [_row_to_record(r) for r in rows]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_record(row: object) -> TenantTransitionRecord:
    occurred_at = row[8]
    if isinstance(occurred_at, str):
        occurred_at = datetime.fromisoformat(occurred_at)
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
    )
