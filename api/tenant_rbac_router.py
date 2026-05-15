"""
api/tenant_rbac_router.py — RBAC management endpoints for FrostGate (PR 57).

Routes:
  GET  /rbac/roles            — list built-in roles and scope bundles (read_only+)
  GET  /rbac/assignments      — list role assignments for tenant (governance_admin+)
  POST /rbac/assignments      — assign role to key by id (tenant_admin only)
  DELETE /rbac/assignments/{key_id} — revoke role (tenant_admin only)
  GET  /rbac/audit            — immutable audit log (auditor+)

Authorization: require_role is the sole gate on all routes; require_scopes is not used.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import authz_scope, require_bound_tenant
from api.deps import auth_ctx_db_session
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
    key_id: int = Field(..., gt=0)
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
    dependencies=[
        Depends(authz_scope("keys:read")),
        Depends(require_role("read_only")),
    ],
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
        Depends(authz_scope("keys:read")),
        Depends(require_role("governance_admin")),
    ],
)
def get_assignments(
    request: Request,
    conn: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    tenant_id = require_bound_tenant(request)
    return list_role_assignments(conn, tenant_id=tenant_id, limit=limit, offset=offset)


@router.post(
    "/assignments",
    summary="Assign a role to an API key (tenant_admin only)",
    dependencies=[
        Depends(authz_scope("keys:write")),
        Depends(require_role("tenant_admin")),
    ],
    status_code=201,
)
def assign_role_endpoint(
    body: AssignRoleRequest,
    request: Request,
    conn: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor_key_prefix(request)
    try:
        return assign_role(
            conn,
            tenant_id=tenant_id,
            actor_key_prefix=actor,
            target_key_id=body.key_id,
            role_name=body.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.delete(
    "/assignments/{key_id}",
    summary="Revoke the role from an API key (tenant_admin only)",
    dependencies=[
        Depends(authz_scope("keys:write")),
        Depends(require_role("tenant_admin")),
    ],
)
def revoke_role_endpoint(
    key_id: int,
    request: Request,
    conn: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor_key_prefix(request)
    try:
        return revoke_role(
            conn,
            tenant_id=tenant_id,
            actor_key_prefix=actor,
            target_key_id=key_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/audit",
    summary="Return immutable role change audit log for this tenant",
    dependencies=[Depends(authz_scope("audit:read")), Depends(require_role("auditor"))],
)
def get_audit_log(
    request: Request,
    conn: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    tenant_id = require_bound_tenant(request)
    return get_role_audit_log(conn, tenant_id=tenant_id, limit=limit, offset=offset)
