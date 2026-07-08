"""API key identity provider — adapts the existing key infrastructure (H14).

Reads the authenticated key context from request.state.auth (populated by
the auth middleware and require_scopes()) and resolves the API key's RBAC
role via tenant_rbac.py.

Legacy role names from the original 5-role model are mapped to the new
enterprise role names so that existing key assignments continue to work.

Backward-compat fallback: keys minted before RBAC roles were introduced have
scopes (governance:write, governance:read, governance:qa_approve) but no DB role.
_permissions_from_legacy_scopes() maps those scopes to a capability set so that
existing service keys continue to function during the migration period.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from api.actor_context import ActorContext, roles_to_permissions

log = logging.getLogger("frostgate.identity.api_key")

# Maps legacy tenant_rbac.py role names → new enterprise role names.
# Existing key assignments are honoured without requiring re-assignment.
_LEGACY_ROLE_MAP: dict[str, str] = {
    "tenant_admin": "tenant_admin",
    "governance_admin": "compliance_reviewer",
    "analyst": "assessor",
    "auditor": "qa_reviewer",
    "read_only": "viewer",
}


def _permissions_from_legacy_scopes(scopes: set[str]) -> frozenset[str]:
    """Derive permissions from legacy API key scopes for backward compat.

    Keys created before RBAC role assignment was enforced have scopes but no
    tenant_rbac role. This maps the three field-assessment scopes to their
    equivalent capability sets so those keys remain functional during migration.

    Uses enterprise role names (assessor, qa_reviewer, viewer) from ROLE_PERMISSIONS,
    NOT the legacy tenant_rbac names (analyst, auditor, read_only).

    This fallback is skipped once a key has an explicit DB role.
    """
    result: set[str] = set()
    if "governance:write" in scopes:
        # Pre-RBAC write keys had full write access across FA mutations (assessor)
        # and governance decision routes (compliance_reviewer). Both are needed so
        # legacy keys retain access to POST /intelligence/... and /orchestration/...
        # mutation routes that now require governance.decision.
        result |= roles_to_permissions(["assessor", "compliance_reviewer"])
    if "governance:qa_approve" in scopes:
        result |= roles_to_permissions(["qa_reviewer"])
    if not result and "governance:read" in scopes:
        result |= roles_to_permissions(["viewer"])
    # Admin and key-management scopes used by legacy service keys and test fixtures.
    # These keys already pass require_internal_admin_gateway; the fallback ensures
    # they also satisfy the new require_permission("platform.admin"/"key.manage") gates.
    if scopes & {"admin:write", "admin:read", "keys:admin", "keys:write", "keys:read"}:
        result |= roles_to_permissions(["platform_admin"])
    return frozenset(result)


def extract_api_key_actor(request: Request, conn: Session) -> Optional[ActorContext]:
    """Build an ActorContext from an authenticated API key.

    Returns None if no valid auth context is present (unauthenticated request).
    """
    auth = getattr(getattr(request, "state", None), "auth", None)
    if not auth or not getattr(auth, "valid", False):
        return None

    tenant_id: str = getattr(auth, "tenant_id", None) or ""
    key_prefix: str = getattr(auth, "key_prefix", None) or ""
    key_db_id: Optional[int] = getattr(auth, "key_db_id", None)

    # The global service-account key (FG_API_KEY env var) carries no DB row or
    # scopes, so no fallback fires without this explicit check. Treat it as
    # platform_admin — it already bypasses scope guards in auth_gate middleware.
    if getattr(auth, "reason", None) == "global_key":
        return ActorContext(
            subject=key_prefix or "global_key",
            email="",
            name="",
            permissions=roles_to_permissions(["platform_admin"]),
            roles=["platform_admin"],
            auth_source="api_key",
            tenant_id=tenant_id or None,
        )

    raw_role: Optional[str] = None
    if key_db_id is not None and tenant_id:
        try:
            from api.tenant_rbac import get_key_role

            raw_role = get_key_role(conn, tenant_id=tenant_id, key_id=int(key_db_id))
        except Exception as exc:
            log.warning(
                "api_key_actor.role_lookup_failed",
                extra={"key_prefix": key_prefix[:8], "exc": str(exc)},
            )

    mapped_role = _LEGACY_ROLE_MAP.get(raw_role or "", raw_role)
    if mapped_role:
        roles = [mapped_role]
        permissions = roles_to_permissions(roles)
    else:
        # No DB role: derive permissions from legacy scopes for transition period.
        key_scopes: set[str] = getattr(auth, "scopes", set()) or set()
        permissions = _permissions_from_legacy_scopes(key_scopes)
        roles = []

    return ActorContext(
        subject=key_prefix,
        email="",
        name="",
        permissions=permissions,
        roles=roles,
        auth_source="api_key",
        tenant_id=tenant_id or None,
    )
