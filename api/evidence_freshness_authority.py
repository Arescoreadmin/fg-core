# api/evidence_freshness_authority.py
"""Evidence Freshness Authority API — PR 14.6.7.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering note:
  Static/aggregated routes MUST appear before /{evidence_id} to prevent FastAPI
  matching them as evidence IDs.

  /freshness/dashboard, /freshness/cgin/snapshot, /freshness/exceptions
  MUST come BEFORE /freshness/{evidence_id}.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks or scope checks
  - No direct ORM access — all ops go through EvidenceFreshnessEngine
  - actor_id always from request state (key_prefix) — never from body
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.evidence_freshness_authority.engine import EvidenceFreshnessEngine
from services.evidence_freshness_authority.schemas import (
    CreateFreshnessExceptionRequest,
    CreateFreshnessPolicyRequest,
    CreateFreshnessRecordRequest,
    FreshnessCGINSnapshot,
    FreshnessDashboardResponse,
    FreshnessExceptionListResponse,
    FreshnessExceptionNotFound,
    FreshnessExceptionResponse,
    FreshnessPolicyListResponse,
    FreshnessPolicyNotFound,
    FreshnessPolicyResponse,
    FreshnessRecordConflict,
    FreshnessRecordListResponse,
    FreshnessRecordNotFound,
    FreshnessRecordResponse,
    RevokeFreshnessExceptionRequest,
    UpdateFreshnessPolicyRequest,
    UpdateFreshnessRecordRequest,
)

router = APIRouter(tags=["evidence-freshness"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _actor_type(request: Request) -> str:
    """Resolve actor type from request state. Defaults to 'human'."""
    return str(getattr(getattr(request, "state", None), "actor_type", None) or "human")


# ---------------------------------------------------------------------------
# Policy routes (static prefix /freshness-policies)
# ---------------------------------------------------------------------------


@router.post(
    "/freshness-policies",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessPolicyResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        422: {"description": "Validation error"},
    },
)
def create_policy(
    req: CreateFreshnessPolicyRequest,
    request: Request,
) -> FreshnessPolicyResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.create_policy(
            req, actor_id=_actor(request), actor_type=_actor_type(request)
        )


@router.get(
    "/freshness-policies",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessPolicyListResponse,
)
def list_policies(
    request: Request,
    evidence_type: str | None = Query(default=None),
    enabled_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FreshnessPolicyListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.list_policies(
            evidence_type=evidence_type,
            enabled_only=enabled_only,
            limit=limit,
            offset=offset,
        )


@router.get(
    "/freshness-policies/{policy_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessPolicyResponse,
)
def get_policy(
    policy_id: str,
    request: Request,
) -> FreshnessPolicyResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_policy(policy_id)
        except FreshnessPolicyNotFound:
            raise HTTPException(status_code=404, detail="Freshness policy not found")


@router.put(
    "/freshness-policies/{policy_id}",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessPolicyResponse,
)
def update_policy(
    policy_id: str,
    req: UpdateFreshnessPolicyRequest,
    request: Request,
) -> FreshnessPolicyResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.update_policy(
                policy_id,
                req,
                actor_id=_actor(request),
                actor_type=_actor_type(request),
            )
        except FreshnessPolicyNotFound:
            raise HTTPException(status_code=404, detail="Freshness policy not found")


# ---------------------------------------------------------------------------
# Static freshness routes — MUST come BEFORE /{evidence_id}
# ---------------------------------------------------------------------------


@router.get(
    "/freshness/dashboard",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessDashboardResponse,
)
def get_dashboard(
    request: Request,
) -> FreshnessDashboardResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.get_dashboard()


@router.get(
    "/freshness/cgin/snapshot",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessCGINSnapshot,
)
def get_cgin_snapshot(
    request: Request,
) -> FreshnessCGINSnapshot:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.get_cgin_snapshot()


@router.post(
    "/freshness/exceptions",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessExceptionResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Evidence not found"},
        422: {"description": "Validation error"},
    },
)
def create_exception(
    req: CreateFreshnessExceptionRequest,
    request: Request,
) -> FreshnessExceptionResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.create_exception(
            req, actor_id=_actor(request), actor_type=_actor_type(request)
        )


@router.get(
    "/freshness/exceptions",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessExceptionListResponse,
)
def list_exceptions(
    request: Request,
    evidence_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FreshnessExceptionListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.list_exceptions(
            evidence_id=evidence_id,
            status=status,
            limit=limit,
            offset=offset,
        )


@router.post(
    "/freshness/exceptions/{exception_id}/revoke",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessExceptionResponse,
)
def revoke_exception(
    exception_id: str,
    req: RevokeFreshnessExceptionRequest,
    request: Request,
) -> FreshnessExceptionResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.revoke_exception(
                exception_id,
                req,
                actor_id=_actor(request),
                actor_type=_actor_type(request),
            )
        except FreshnessExceptionNotFound:
            raise HTTPException(status_code=404, detail="Freshness exception not found")


# ---------------------------------------------------------------------------
# Per-evidence freshness routes (parameterized — MUST be last)
# ---------------------------------------------------------------------------


@router.post(
    "/freshness",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessRecordResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        409: {"description": "Freshness record already exists for this evidence"},
        422: {"description": "Validation error"},
    },
)
def create_freshness_record(
    req: CreateFreshnessRecordRequest,
    request: Request,
) -> FreshnessRecordResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.create_freshness_record(
                req, actor_id=_actor(request), actor_type=_actor_type(request)
            )
        except FreshnessRecordConflict:
            raise HTTPException(
                status_code=409,
                detail="Freshness record already exists for this evidence",
            )


@router.get(
    "/freshness",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessRecordListResponse,
)
def list_freshness_records(
    request: Request,
    freshness_state: str | None = Query(default=None),
    policy_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FreshnessRecordListResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        return svc.list_freshness_records(
            freshness_state=freshness_state,
            policy_id=policy_id,
            limit=limit,
            offset=offset,
        )


@router.get(
    "/freshness/{evidence_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=FreshnessRecordResponse,
)
def get_freshness_record(
    evidence_id: str,
    request: Request,
) -> FreshnessRecordResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_freshness_record(evidence_id)
        except FreshnessRecordNotFound:
            raise HTTPException(status_code=404, detail="Freshness record not found")


@router.put(
    "/freshness/{evidence_id}",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessRecordResponse,
)
def update_freshness_record(
    evidence_id: str,
    req: UpdateFreshnessRecordRequest,
    request: Request,
) -> FreshnessRecordResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.update_freshness_record(
                evidence_id,
                req,
                actor_id=_actor(request),
                actor_type=_actor_type(request),
            )
        except FreshnessRecordNotFound:
            raise HTTPException(status_code=404, detail="Freshness record not found")


@router.post(
    "/freshness/{evidence_id}/recompute",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=FreshnessRecordResponse,
)
def recompute_freshness(
    evidence_id: str,
    request: Request,
) -> FreshnessRecordResponse:
    tenant_id = require_bound_tenant(request)
    engine = get_engine()
    with Session(engine) as db:
        svc = EvidenceFreshnessEngine(db, tenant_id=tenant_id)
        try:
            return svc.recompute_freshness(
                evidence_id,
                actor_id=_actor(request),
                actor_type=_actor_type(request),
            )
        except FreshnessRecordNotFound:
            raise HTTPException(status_code=404, detail="Freshness record not found")
