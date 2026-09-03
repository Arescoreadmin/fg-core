"""
api/tenant_rbac.py — Intra-tenant RBAC for FrostGate.

R4.10: Roles are stored in tenant_credential_roles and bound to canonical
credential_id (UUID). All auth resolves roles via credential_id.

R4.11: Legacy _legacy_get_key_role (api_keys path) removed.

Security invariants:
- Deny-by-default: no role or unknown role → require_role denies.
- Cross-tenant: all lookups scoped to tenant_id; role assignment verifies tenant.
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

from api.deps import auth_ctx_db_session

log = logging.getLogger("frostgate.rbac")

# ---------------------------------------------------------------------------
# Built-in role definitions
# ---------------------------------------------------------------------------

BUILTIN_ROLES: tuple[str, ...] = (
    "tenant_admin",
    "governance_admin",
    "analyst",
    "auditor",
    "read_only",
)

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

# Roles that tenant_admin actors may self-service-assign via /rbac/assignments
# or credential-administration endpoints.  tenant_admin is excluded from
# self-service to prevent privilege escalation (same policy as before).
TENANT_ASSIGNABLE_ROLES: frozenset[str] = frozenset(
    {
        "governance_admin",
        "analyst",
        "auditor",
        "read_only",
    }
)

# Roles that only a platform credential authority may assign.  These are
# stored in tenant_credential_roles alongside tenant roles (same table,
# different assignment path) so the resolution chain works identically.
# P-113.6: platform_admin is the canonical platform credential role.
PLATFORM_CREDENTIAL_ROLES: frozenset[str] = frozenset(
    {
        "tenant_admin",
        "platform_admin",
    }
)

# Union of all storable roles.  assign_role() validates against this set.
# Expanding VALID_ROLE_NAMES to include platform_admin fixes Defect 1:
# assign_role() previously returned 422 for platform_admin because it was
# not in BUILTIN_ROLES.  The platform-admin bootstrap endpoint needs to
# store this role via the same assign_role() path.
VALID_ROLE_NAMES: frozenset[str] = TENANT_ASSIGNABLE_ROLES | PLATFORM_CREDENTIAL_ROLES


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


# ---------------------------------------------------------------------------
# Canonical RBAC — tenant_credential_roles
# ---------------------------------------------------------------------------


def get_credential_role(
    conn: Session, *, tenant_id: str, credential_id: str
) -> Optional[str]:
    """Return the active role for a canonical credential, or None if none assigned."""
    row = conn.execute(
        text(
            "SELECT role_name FROM tenant_credential_roles "
            "WHERE tenant_id = :tenant_id "
            "  AND credential_id = :credential_id "
            "  AND revoked_at IS NULL"
        ),
        {"tenant_id": tenant_id, "credential_id": credential_id},
    ).fetchone()
    return str(row[0]) if row and row[0] else None


def assign_role(
    conn: Session,
    *,
    tenant_id: str,
    actor_key_prefix: str,
    credential_id: str,
    role_name: str,
) -> dict[str, Any]:
    """Assign a built-in role to a canonical credential within a tenant.

    Revokes any existing active role first, then inserts the new one.
    Raises ValueError for invalid tenant ownership or role names.
    Appends an immutable audit record.
    """
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    if not credential_id or not str(credential_id).strip():
        raise ValueError("credential_id must not be blank")
    if role_name not in VALID_ROLE_NAMES:
        raise ValueError(
            f"Unknown role: {role_name!r}. Valid roles: {sorted(VALID_ROLE_NAMES)}"
        )

    # Set RLS tenant context so the credential ownership lookup is visible under
    # the tenant_credentials_tenant_isolation policy.  Mirrors the pattern used
    # in credential_authority.py.  Using is_local=true keeps the setting scoped
    # to the current transaction; callers using engine.begin() or Session with
    # autobegin get the same transaction-scoped behaviour.
    _bind = getattr(conn, "bind", None)
    if (
        _bind is not None
        and getattr(getattr(_bind, "dialect", None), "name", "") == "postgresql"
    ):
        conn.execute(
            text("SELECT set_config('app.tenant_id', :tid, true)"), {"tid": tenant_id}
        )

    # Verify credential belongs to this tenant (belt-and-suspenders; FK enforced in Postgres).
    row = conn.execute(
        text(
            "SELECT credential_id FROM tenant_credentials "
            "WHERE credential_id = :cid AND tenant_id = :tid"
        ),
        {"cid": credential_id, "tid": tenant_id},
    ).fetchone()
    if row is None:
        raise ValueError(
            f"credential_id={credential_id!r} not found for tenant_id={tenant_id!r}"
        )

    now = _utc_now_iso()

    # Revoke any existing active role before granting the new one.
    conn.execute(
        text(
            "UPDATE tenant_credential_roles "
            "SET revoked_at = :now, revoked_by = :actor "
            "WHERE tenant_id = :tenant_id "
            "  AND credential_id = :credential_id "
            "  AND revoked_at IS NULL"
        ),
        {
            "now": now,
            "actor": actor_key_prefix,
            "tenant_id": tenant_id,
            "credential_id": credential_id,
        },
    )

    conn.execute(
        text(
            "INSERT INTO tenant_credential_roles "
            "(tenant_id, credential_id, role_name, granted_at, granted_by) "
            "VALUES (:tenant_id, :credential_id, :role_name, :now, :actor)"
        ),
        {
            "tenant_id": tenant_id,
            "credential_id": credential_id,
            "role_name": role_name,
            "now": now,
            "actor": actor_key_prefix,
        },
    )

    event_id = _new_event_id()
    _append_role_audit(
        conn,
        event_id=event_id,
        tenant_id=tenant_id,
        actor_key_prefix=actor_key_prefix,
        action="assign_role",
        target_credential_id=credential_id,
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
            "rbac_target": credential_id,
            "role_name": role_name,
        },
    )
    return {
        "tenant_id": tenant_id,
        "credential_id": credential_id,
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
    credential_id: str,
) -> dict[str, Any]:
    """Remove the active role from a canonical credential within a tenant."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    if not credential_id or not str(credential_id).strip():
        raise ValueError("credential_id must not be blank")

    row = conn.execute(
        text(
            "SELECT credential_id FROM tenant_credentials "
            "WHERE credential_id = :cid AND tenant_id = :tid"
        ),
        {"cid": credential_id, "tid": tenant_id},
    ).fetchone()
    if row is None:
        raise ValueError(
            f"credential_id={credential_id!r} not found for tenant_id={tenant_id!r}"
        )

    now = _utc_now_iso()
    conn.execute(
        text(
            "UPDATE tenant_credential_roles "
            "SET revoked_at = :now, revoked_by = :actor "
            "WHERE tenant_id = :tenant_id "
            "  AND credential_id = :credential_id "
            "  AND revoked_at IS NULL"
        ),
        {
            "now": now,
            "actor": actor_key_prefix,
            "tenant_id": tenant_id,
            "credential_id": credential_id,
        },
    )

    event_id = _new_event_id()
    _append_role_audit(
        conn,
        event_id=event_id,
        tenant_id=tenant_id,
        actor_key_prefix=actor_key_prefix,
        action="revoke_role",
        target_credential_id=credential_id,
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
            "rbac_target": credential_id,
        },
    )
    return {
        "tenant_id": tenant_id,
        "credential_id": credential_id,
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
    """Return all canonical credentials with active role assignments for a tenant."""
    if not tenant_id or not str(tenant_id).strip():
        raise ValueError("tenant_id must not be blank")
    rows = (
        conn.execute(
            text(
                "SELECT credential_id, role_name, granted_at, granted_by "
                "FROM tenant_credential_roles "
                "WHERE tenant_id = :tenant_id AND revoked_at IS NULL "
                "ORDER BY granted_at "
                "LIMIT :limit OFFSET :offset"
            ),
            {"tenant_id": tenant_id, "limit": limit, "offset": offset},
        )
        .mappings()
        .fetchall()
    )
    return [
        {
            "credential_id": str(r["credential_id"]),
            "role": str(r["role_name"]),
            "granted_at": str(r["granted_at"]),
            "granted_by": r.get("granted_by"),
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
    cols = _audit_columns(conn)
    if not cols:
        return []

    select_cols = "event_id, actor_key_prefix, action, target_key_prefix, role_name, timestamp, success"
    if "target_credential_id" in cols:
        select_cols += ", target_credential_id"

    rows = (
        conn.execute(
            text(
                f"SELECT {select_cols} "
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
            "target_credential_id": r.get("target_credential_id"),
            # Preserved for historical events written before R4.10.
            "target_key_id": r.get("target_key_prefix"),
            "role_name": r.get("role_name"),
            "timestamp": str(r["timestamp"]),
            "success": bool(r.get("success", 1)),
        }
        for r in rows
    ]


def _audit_columns(conn: Session) -> set[str]:
    """Return column names for tenant_role_audit (works for SQLite and PostgreSQL)."""
    try:
        rows = conn.execute(
            text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'tenant_role_audit'"
            )
        ).fetchall()
        if rows:
            return {r[0] for r in rows}
    except Exception:
        pass
    try:
        rows = conn.execute(text("PRAGMA table_info(tenant_role_audit)")).fetchall()
        return {r[1] for r in rows}
    except Exception:
        return set()


def _append_role_audit(
    conn: Session,
    *,
    event_id: str,
    tenant_id: str,
    actor_key_prefix: str,
    action: str,
    target_credential_id: str,
    role_name: Optional[str],
    timestamp: str,
    success: int,
) -> None:
    """Append an immutable audit event. Never updates or deletes existing rows.

    target_credential_id is the canonical credential UUID (R4.10+).
    target_key_prefix is set to NULL for new events; historical rows retain their
    original string value (str repr of api_keys.id) unchanged.
    """
    cols = _audit_columns(conn)
    if not cols:
        return

    if "target_credential_id" in cols:
        conn.execute(
            text(
                "INSERT INTO tenant_role_audit "
                "(event_id, tenant_id, actor_key_prefix, action, target_key_prefix, "
                "target_credential_id, role_name, timestamp, success) "
                "VALUES (:event_id, :tenant_id, :actor_key_prefix, :action, "
                "NULL, :target_credential_id, :role_name, :timestamp, :success)"
            ),
            {
                "event_id": event_id,
                "tenant_id": tenant_id,
                "actor_key_prefix": actor_key_prefix,
                "action": action,
                "target_credential_id": target_credential_id,
                "role_name": role_name,
                "timestamp": timestamp,
                "success": success,
            },
        )
    else:
        # Fallback for DBs where migration 0177 has not yet run (e.g. test isolation).
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
                "target_key_prefix": target_credential_id,
                "role_name": role_name,
                "timestamp": timestamp,
                "success": success,
            },
        )


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------


def _get_auth_role(request: Request, conn: Session) -> Optional[str]:
    """Resolve the RBAC role for the authenticated credential from the DB.

    Canonical path: credential_id → tenant_credential_roles.
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    if auth is None:
        return None
    tenant_id = getattr(auth, "tenant_id", None)
    if not tenant_id:
        return None

    credential_id = getattr(auth, "credential_id", None)
    if credential_id is not None:
        return get_credential_role(
            conn, tenant_id=tenant_id, credential_id=str(credential_id)
        )

    return None


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: enforce that the authenticated credential holds one of the given roles.

    Deny-by-default: a credential with no role or an unknown role is rejected with 403.
    Role hierarchy is respected: tenant_admin passes any require_role check.
    """
    needed: set[str] = {str(r).strip() for r in allowed_roles if str(r).strip()}

    def _dep(
        request: Request,
        conn: Session = Depends(auth_ctx_db_session),
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
    conn: Session = Depends(auth_ctx_db_session),
) -> Optional[str]:
    """FastAPI dependency: resolve the authenticated credential's role (None if unassigned)."""
    return _get_auth_role(request, conn)
