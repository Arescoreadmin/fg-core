"""API key identity provider — adapts the existing key infrastructure (H14).

Reads the authenticated key context from request.state.auth (populated by
the auth middleware and require_scopes()) and resolves the API key's RBAC
role via tenant_rbac.py.

Legacy role names from the original 5-role model are mapped to the new
enterprise role names so that existing key assignments continue to work.
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
    roles = [mapped_role] if mapped_role else []
    permissions = roles_to_permissions(roles)

    return ActorContext(
        subject=key_prefix,
        email="",
        name="",
        permissions=permissions,
        roles=roles,
        auth_source="api_key",
        tenant_id=tenant_id or None,
    )
