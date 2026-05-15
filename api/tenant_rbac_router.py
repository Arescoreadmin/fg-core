"""
api/tenant_rbac_router.py — RBAC management endpoints for FrostGate (PR 57).

Routes:
  GET  /rbac/roles            — list built-in roles and scope bundles (keys:read)
  GET  /rbac/assignments      — list role assignments for tenant (keys:read + governance_admin)
  POST /rbac/assignments      — assign role to key (keys:write + tenant_admin)
  DELETE /rbac/assignments/{key_prefix} — revoke role (keys:write + tenant_admin)
  GET  /rbac/audit            — immutable audit log (audit:read + auditor)
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import get_db
from api.tenant_rbac import (
    BUILTIN_ROLES,
    _ROLE_SCOPES,
    assign_role,
    get_role_audit_log,
    list_role_assignments,
    require_role,
    revoke_role,
)

log = logging.getLogger("frostgate.rbac")

router = APIRouter(prefix="/rbac", tags=["rbac"])


def _actor_key_prefix(request: Request) -> str:
    auth = getattr(getattr(request, "state", None), "auth", None)
    kp = getattr(auth, "key_prefix", None) if auth else None
    if not kp:
        raise HTTPException(status_code=401, detail="Authentication required")
    return str(kp)


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AssignRoleRequest(BaseModel):
    key_prefix: str = Field(..., min_length=4, max_length=64)
    role: str = Field(..., min_length=1, max_length=64)


class RoleDetail(BaseModel):
    role: str
    scopes: list[str]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/roles",
    summary="List available built-in roles and their scope bundles",
    dependencies=[Depends(require_scopes("keys:read"))],
)
def list_roles() -> list[RoleDetail]:
    return [
        RoleDetail(role=r, scopes=sorted(_ROLE_SCOPES.get(r, frozenset())))
        for r in BUILTIN_ROLES
    ]


@router.get(
    "/assignments",
    summary="List API keys with assigned roles for this tenant",
    dependencies=[
        Depends(require_scopes("keys:read")),
        Depends(require_role("governance_admin")),
    ],
)
def get_assignments(
    request: Request,
    conn: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    tenant_id = require_bound_tenant(request)
    return list_role_assignments(conn, tenant_id=tenant_id, limit=limit, offset=offset)


@router.post(
    "/assignments",
    summary="Assign a role to an API key (tenant_admin only)",
    dependencies=[
        Depends(require_scopes("keys:write")),
        Depends(require_role("tenant_admin")),
    ],
    status_code=201,
)
def assign_role_endpoint(
    body: AssignRoleRequest,
    request: Request,
    conn: Session = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor_key_prefix(request)
    try:
        return assign_role(
            conn,
            tenant_id=tenant_id,
            actor_key_prefix=actor,
            target_key_prefix=body.key_prefix,
            role_name=body.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete(
    "/assignments/{key_prefix}",
    summary="Revoke the role from an API key (tenant_admin only)",
    dependencies=[
        Depends(require_scopes("keys:write")),
        Depends(require_role("tenant_admin")),
    ],
)
def revoke_role_endpoint(
    key_prefix: str,
    request: Request,
    conn: Session = Depends(get_db),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor_key_prefix(request)
    try:
        return revoke_role(
            conn,
            tenant_id=tenant_id,
            actor_key_prefix=actor,
            target_key_prefix=key_prefix,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/audit",
    summary="Return immutable role change audit log for this tenant",
    dependencies=[
        Depends(require_scopes("audit:read")),
        Depends(require_role("auditor")),
    ],
)
def get_audit_log(
    request: Request,
    conn: Session = Depends(get_db),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    tenant_id = require_bound_tenant(request)
    return get_role_audit_log(conn, tenant_id=tenant_id, limit=limit, offset=offset)
