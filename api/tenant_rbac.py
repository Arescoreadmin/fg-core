"""
api/tenant_rbac.py — Intra-tenant RBAC for FrostGate (PR 57).

Architecture:
- Roles are assigned to API keys (the identity primitive in this system).
- Built-in roles define a scope hierarchy; custom roles are future-ready.
- Role resolution happens at request time via require_role() dependency.
- All role changes are append-only audited in tenant_role_audit.

Security invariants:
- Deny-by-default: no role or unknown role → only explicit scopes; require_role denies.
- Cross-tenant: all lookups scoped to tenant_id; role assignment requires tenant_admin.
- Immutable audit: tenant_role_audit rows are never updated or deleted.
- Raw key material never appears in logs or error messages.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.deps import get_db

log = logging.getLogger("frostgate.rbac")

# ---------------------------------------------------------------------------
# Built-in role definitions
# ---------------------------------------------------------------------------

#: Ordered role hierarchy. A role implies all roles that appear after it in
#: the chain for its branch. tenant_admin implies all other roles.
#: Stored as a mapping: role → frozenset of directly implied scopes.

BUILTIN_ROLES: tuple[str, ...] = (
    "tenant_admin",
    "governance_admin",
    "analyst",
    "auditor",
    "read_only",
)

#: Scope bundles for each built-in role.
#: A key with role R gets the union of its explicit scopes_csv AND these scopes.
_ROLE_SCOPES: dict[str, frozenset[str]] = {
    "tenant_admin": frozenset(
        {
            "governance:write",
            "governance:read",
            "audit:read",
            "keys:read",
            "keys:write",
            "rag:read",
            "retrieval:read",
            "evaluation:read",
            "policy:write",
            "policy:read",
            "ingestion:write",
            "ingestion:read",
            "provider:read",
            "provider:write",
            "admin:read",
        }
    ),
    "governance_admin": frozenset(
        {
            "governance:write",
            "governance:read",
            "audit:read",
            "keys:read",
            "rag:read",
            "retrieval:read",
            "evaluation:read",
            "policy:write",
            "policy:read",
            "ingestion:write",
            "ingestion:read",
            "provider:read",
        }
    ),
    "analyst": frozenset(
        {
            "rag:read",
            "retrieval:read",
            "evaluation:read",
            "governance:read",
            "ingestion:read",
            "provider:read",
        }
    ),
    "auditor": frozenset(
        {
            "audit:read",
            "governance:read",
            "rag:read",
            "retrieval:read",
            "ingestion:read",
            "provider:read",
        }
    ),
    "read_only": frozenset(
        {
            "rag:read",
            "retrieval:read",
            "ingestion:read",
        }
    ),
}

#: Role hierarchy: a role implies these other roles (for require_role checks).
#: If a route requires "auditor", then governance_admin and tenant_admin also pass.
_ROLE_IMPLIES: dict[str, frozenset[str]] = {
    "tenant_admin": frozenset(
        {"tenant_admin", "governance_admin", "analyst", "auditor", "read_only"}
    ),
    "governance_admin": frozenset(
        {"governance_admin", "analyst", "auditor", "read_only"}
    ),
    "analyst": frozenset({"analyst", "read_only"}),
    "auditor": frozenset({"auditor", "read_only"}),
    "read_only": frozenset({"read_only"}),
}

VALID_ROLE_NAMES: frozenset[str] = frozenset(BUILTIN_ROLES)


# ---------------------------------------------------------------------------
# Role → scope expansion (public)
# ---------------------------------------------------------------------------


def get_role_scopes(role: Optional[str]) -> frozenset[str]:
    """Return the set of scopes implied by a role. Empty set for unknown/None."""
    if not role:
        return frozenset()
    return _ROLE_SCOPES.get(role, frozenset())


def role_satisfies(assigned_role: Optional[str], required_role: str) -> bool:
    """Return True if assigned_role meets or exceeds required_role in the hierarchy."""
    if not assigned_role:
        return False
    implied = _ROLE_IMPLIES.get(assigned_role, frozenset())
    return required_role in implied


def role_satisfies_any(assigned_role: Optional[str], required_roles: set[str]) -> bool:
    """Return True if assigned_role satisfies at least one of the required roles."""
    return any(role_satisfies(assigned_role, r) for r in required_roles)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _new_event_id() -> str:
    return str(uuid.uuid4())


def _table_columns(conn: Session, table: str) -> set[str]:
    """Return column names for a table (works for SQLite and PostgreSQL)."""
    try:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = :t"
            ),
            {"t": table},
        ).fetchall()
        if rows:
            return {r[0] for r in rows}
    except Exception:
        pass
    try:
        rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
        return {r[1] for r in rows}
    except Exception:
        return set()


def get_key_role(conn: Session, *, tenant_id: str, key_id: int) -> Optional[str]:
    """Return the role assigned to an API key by its DB id, or None."""
    cols = _table_columns(conn, "api_keys")
    if "role" not in cols:
        return None
    row = conn.execute(
        text("SELECT role FROM api_keys WHERE id = :id AND tenant_id = :tenant_id"),
        {"id": key_id, "tenant_id": tenant_id},
    ).fetchone()
    if row is None:
        return None
    return str(row[0]) if row[0] else None


def _get_key_role_by_prefix(
    conn: Session, *, tenant_id: str, key_prefix: str
) -> Optional[str]:
    """Fallback: look up role by prefix+tenant (used only when key_db_id unavailable)."""
    cols = _table_columns(conn, "api_keys")
    if "role" not in cols:
        return None
    row = conn.execute(
        text(
            "SELECT role FROM api_keys WHERE prefix = :prefix AND tenant_id = :tenant_id LIMIT 1"
        ),
        {"prefix": key_prefix, "tenant_id": tenant_id},
    ).fetchone()
    if row is None:
        return None
    return str(row[0]) if row[0] else None


def assign_role(
    conn: Session,
    *,
    tenant_id: str,
    actor_key_prefix: str,
    target_key_id: int,
    role_name: str,
) -> dict[str, Any]:
    """Assign a built-in role to an API key within a tenant.

    Uses api_keys.id as the unambiguous assignment target.
    Raises ValueError for invalid tenant ownership or role names.
    Appends an immutable audit record.
    """
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    if role_name not in VALID_ROLE_NAMES:
        raise ValueError(
            f"Unknown role: {role_name!r}. Valid roles: {sorted(VALID_ROLE_NAMES)}"
        )

    # Verify target key belongs to this tenant — use id for unambiguous lookup.
    target_row = conn.execute(
        text("SELECT id, name FROM api_keys WHERE id = :id AND tenant_id = :t"),
        {"id": target_key_id, "t": tenant_id},
    ).fetchone()
    if target_row is None:
        raise ValueError(
            f"key_id={target_key_id!r} not found for tenant_id={tenant_id!r}"
        )
    display_name = target_row[1] if target_row[1] else None

    # Update role column (guarded by _table_columns).
    cols = _table_columns(conn, "api_keys")
    if "role" in cols:
        conn.execute(
            text(
                "UPDATE api_keys SET role = :role WHERE id = :id AND tenant_id = :tenant_id"
            ),
            {"role": role_name, "id": target_key_id, "tenant_id": tenant_id},
        )

    now = _utc_now_iso()
    event_id = _new_event_id()
    _append_role_audit(
        conn,
        event_id=event_id,
        tenant_id=tenant_id,
        actor_key_prefix=actor_key_prefix,
        action="assign_role",
        target_key_id=str(target_key_id),
        role_name=role_name,
        timestamp=now,
        success=1,
    )
    conn.commit()

    log.info(
        "rbac.role_assigned",
        extra={
            "event": "rbac.role_assigned",
            "tenant_id": tenant_id,
            "actor_key_prefix": actor_key_prefix,
            "target_key_id": target_key_id,
            "role_name": role_name,
        },
    )
    return {
        "tenant_id": tenant_id,
        "key_id": target_key_id,
        "display_name": display_name,
        "role": role_name,
        "assigned_by": actor_key_prefix,
        "assigned_at": now,
        "event_id": event_id,
    }


def revoke_role(
    conn: Session,
    *,
    tenant_id: str,
    actor_key_prefix: str,
    target_key_id: int,
) -> dict[str, Any]:
    """Remove the role from an API key within a tenant."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")

    target_row = conn.execute(
        text("SELECT id, name FROM api_keys WHERE id = :id AND tenant_id = :t"),
        {"id": target_key_id, "t": tenant_id},
    ).fetchone()
    if target_row is None:
        raise ValueError(
            f"key_id={target_key_id!r} not found for tenant_id={tenant_id!r}"
        )
    display_name = target_row[1] if target_row[1] else None

    cols = _table_columns(conn, "api_keys")
    if "role" in cols:
        conn.execute(
            text(
                "UPDATE api_keys SET role = NULL WHERE id = :id AND tenant_id = :tenant_id"
            ),
            {"id": target_key_id, "tenant_id": tenant_id},
        )

    now = _utc_now_iso()
    event_id = _new_event_id()
    _append_role_audit(
        conn,
        event_id=event_id,
        tenant_id=tenant_id,
        actor_key_prefix=actor_key_prefix,
        action="revoke_role",
        target_key_id=str(target_key_id),
        role_name=None,
        timestamp=now,
        success=1,
    )
    conn.commit()

    log.info(
        "rbac.role_revoked",
        extra={
            "event": "rbac.role_revoked",
            "tenant_id": tenant_id,
            "actor_key_prefix": actor_key_prefix,
            "target_key_id": target_key_id,
        },
    )
    return {
        "tenant_id": tenant_id,
        "key_id": target_key_id,
        "display_name": display_name,
        "role": None,
        "revoked_by": actor_key_prefix,
        "revoked_at": now,
        "event_id": event_id,
    }


def list_role_assignments(
    conn: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return all API keys with assigned roles for a tenant."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    cols = _table_columns(conn, "api_keys")
    if "role" not in cols:
        return []
    rows = (
        conn.execute(
            text(
                "SELECT id, name, role, scopes_csv FROM api_keys "
                "WHERE tenant_id = :tenant_id AND role IS NOT NULL AND enabled = 1 "
                "ORDER BY id "
                "LIMIT :limit OFFSET :offset"
            ),
            {"tenant_id": tenant_id, "limit": limit, "offset": offset},
        )
        .mappings()
        .fetchall()
    )
    return [
        {
            "key_id": int(r["id"]),
            "display_name": r.get("name"),
            "role": str(r["role"]),
            "scopes": str(r.get("scopes_csv") or "").split(",")
            if r.get("scopes_csv")
            else [],
        }
        for r in rows
    ]


def get_role_audit_log(
    conn: Session,
    *,
    tenant_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Return the immutable role change audit log for a tenant."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    cols = _table_columns(conn, "tenant_role_audit")
    if not cols:
        return []
    rows = (
        conn.execute(
            text(
                "SELECT event_id, actor_key_prefix, action, target_key_prefix, "
                "role_name, timestamp, success "
                "FROM tenant_role_audit "
                "WHERE tenant_id = :tenant_id "
                "ORDER BY timestamp DESC "
                "LIMIT :limit OFFSET :offset"
            ),
            {"tenant_id": tenant_id, "limit": limit, "offset": offset},
        )
        .mappings()
        .fetchall()
    )
    return [
        {
            "event_id": str(r["event_id"]),
            "actor_key_prefix": r.get("actor_key_prefix"),
            "action": str(r["action"]),
            # target_key_prefix column stores the string repr of target_key_id
            "target_key_id": r.get("target_key_prefix"),
            "role_name": r.get("role_name"),
            "timestamp": str(r["timestamp"]),
            "success": bool(r.get("success", 1)),
        }
        for r in rows
    ]


def _append_role_audit(
    conn: Session,
    *,
    event_id: str,
    tenant_id: str,
    actor_key_prefix: str,
    action: str,
    target_key_id: str,
    role_name: Optional[str],
    timestamp: str,
    success: int,
) -> None:
    """Append an immutable audit event. Never updates or deletes existing rows.

    target_key_id (string repr of api_keys.id) is stored in the target_key_prefix
    column for backward-compatible schema compatibility.
    """
    cols = _table_columns(conn, "tenant_role_audit")
    if not cols:
        return
    conn.execute(
        text(
            "INSERT INTO tenant_role_audit "
            "(event_id, tenant_id, actor_key_prefix, action, target_key_prefix, "
            "role_name, timestamp, success) "
            "VALUES (:event_id, :tenant_id, :actor_key_prefix, :action, "
            ":target_key_prefix, :role_name, :timestamp, :success)"
        ),
        {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "actor_key_prefix": actor_key_prefix,
            "action": action,
            "target_key_prefix": target_key_id,
            "role_name": role_name,
            "timestamp": timestamp,
            "success": success,
        },
    )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def _get_auth_role(request: Request, conn: Session) -> Optional[str]:
    """Resolve the RBAC role for the authenticated key from the DB.

    Uses key_db_id (api_keys.id) when available for unambiguous lookup.
    Falls back to prefix-based lookup for backward compatibility with
    old-format keys or test mocks that don't carry key_db_id.
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    if auth is None:
        return None
    tenant_id = getattr(auth, "tenant_id", None)
    if not tenant_id:
        return None
    key_db_id = getattr(auth, "key_db_id", None)
    if key_db_id is not None:
        return get_key_role(conn, tenant_id=tenant_id, key_id=int(key_db_id))
    key_prefix = getattr(auth, "key_prefix", None)
    if not key_prefix:
        return None
    return _get_key_role_by_prefix(conn, tenant_id=tenant_id, key_prefix=key_prefix)


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: enforce that the authenticated key holds one of the given roles.

    Deny-by-default: a key with no role or an unknown role is rejected with 403.
    Role hierarchy is respected: tenant_admin passes any require_role check.

    Usage:
        @router.get("/sensitive")
        def endpoint(
            _: None = Depends(require_role("auditor")),
            ...
        ):
    """
    needed: set[str] = {str(r).strip() for r in allowed_roles if str(r).strip()}

    def _dep(
        request: Request,
        conn: Session = Depends(get_db),
    ) -> None:
        auth = getattr(getattr(request, "state", None), "auth", None)
        if auth is None:
            raise HTTPException(status_code=401, detail="Authentication required")

        role = _get_auth_role(request, conn)
        if not role_satisfies_any(role, needed):
            log.warning(
                "rbac.access_denied",
                extra={
                    "event": "rbac.access_denied",
                    "key_prefix": getattr(auth, "key_prefix", None),
                    "tenant_id": getattr(auth, "tenant_id", None),
                    "assigned_role": role,
                    "required_roles": sorted(needed),
                },
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "RBAC_INSUFFICIENT_ROLE",
                    "required_roles": sorted(needed),
                },
            )

    return _dep


def get_request_role(
    request: Request,
    conn: Session = Depends(get_db),
) -> Optional[str]:
    """FastAPI dependency: resolve the authenticated key's role (None if unassigned)."""
    return _get_auth_role(request, conn)
