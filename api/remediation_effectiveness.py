# api/remediation_effectiveness.py
"""Remediation Effectiveness Analytics Authority API — PR 17.5.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering note:
  Multi-segment routes (/dashboard, /patterns, /top-successes, /failures,
  /cgin/snapshot, /recalculate) are registered BEFORE /{remediation_id} to
  prevent path ambiguity.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - governance:read for all GET routes
  - governance:write for POST and PATCH routes
  - No AI, no LLMs — all outputs deterministic
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.remediation_effectiveness.engine import (
    DuplicateRemediationOutcome,
    RemediationEffectivenessEngine,
)
from services.remediation_effectiveness.schemas import (
    CGINRemediationSnapshot,
    FailuresResponse,
    OutcomeListResponse,
    PatternsResponse,
    RecalculateResponse,
    RecordOutcomeRequest,
    RemediationDashboardResponse,
    RemediationOutcomeResponse,
    TopSuccessesResponse,
    UpdateOutcomeRequest,
)
from sqlalchemy.orm import Session

router = APIRouter(tags=["remediation-effectiveness"])


# ---------------------------------------------------------------------------
# POST /remediation-effectiveness — record outcome
# ---------------------------------------------------------------------------


@router.post(
    "/remediation-effectiveness",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RemediationOutcomeResponse,
    status_code=201,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        409: {"description": "Outcome already recorded for this remediation task and control"},
    },
)
def record_outcome(
    body: RecordOutcomeRequest,
    request: Request,
) -> RemediationOutcomeResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        try:
            return RemediationEffectivenessEngine(db, tenant_id).record_outcome(body)
        except DuplicateRemediationOutcome as exc:
            raise HTTPException(
                status_code=409,
                detail=f"Outcome already recorded for this remediation task and control. Existing id: {exc.outcome_id}",
            )


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/dashboard
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/dashboard",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RemediationDashboardResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_dashboard(request: Request) -> RemediationDashboardResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).get_dashboard()


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/patterns
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/patterns",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=PatternsResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_patterns(request: Request) -> PatternsResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).get_patterns()


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/top-successes
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/top-successes",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=TopSuccessesResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_top_successes(
    request: Request,
    limit: int = Query(default=10, ge=1, le=100),
) -> TopSuccessesResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).get_top_successes(
            limit=limit
        )


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/failures
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/failures",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=FailuresResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def get_failures(request: Request) -> FailuresResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).get_failures()


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/cgin/snapshot
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/cgin/snapshot",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=CGINRemediationSnapshot,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def cgin_snapshot(request: Request) -> CGINRemediationSnapshot:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).cgin_snapshot()


# ---------------------------------------------------------------------------
# POST /remediation-effectiveness/recalculate
# ---------------------------------------------------------------------------


@router.post(
    "/remediation-effectiveness/recalculate",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RecalculateResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def recalculate(
    request: Request,
    control_id: str | None = Query(default=None),
) -> RecalculateResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).recalculate(
            control_id=control_id
        )


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness — list outcomes
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=OutcomeListResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
    },
)
def list_outcomes(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    outcome_classification: str | None = Query(default=None),
) -> OutcomeListResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        return RemediationEffectivenessEngine(db, tenant_id).list_outcomes(
            limit=limit,
            offset=offset,
            outcome_classification=outcome_classification,
        )


# ---------------------------------------------------------------------------
# GET /remediation-effectiveness/{remediation_id}
# ---------------------------------------------------------------------------


@router.get(
    "/remediation-effectiveness/{remediation_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=RemediationOutcomeResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Remediation outcome not found"},
    },
)
def get_outcome(
    remediation_id: str,
    request: Request,
) -> RemediationOutcomeResponse:
    tenant_id = require_bound_tenant(request)
    with Session(get_engine()) as db:
        result = RemediationEffectivenessEngine(db, tenant_id).get_outcome(
            remediation_id
        )
        if result is None:
            raise HTTPException(
                status_code=404, detail="Remediation outcome not found"
            )
        return result


# ---------------------------------------------------------------------------
# PATCH /remediation-effectiveness/{remediation_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/remediation-effectiveness/{remediation_id}",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=RemediationOutcomeResponse,
    responses={
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Remediation outcome not found"},
    },
)
def update_outcome_status(
    remediation_id: str,
    body: UpdateOutcomeRequest,
    request: Request,
) -> RemediationOutcomeResponse:
    tenant_id = require_bound_tenant(request)
    if body.status is None:
        # Nothing to update — fetch and return current
        with Session(get_engine()) as db:
            result = RemediationEffectivenessEngine(db, tenant_id).get_outcome(
                remediation_id
            )
            if result is None:
                raise HTTPException(
                    status_code=404, detail="Remediation outcome not found"
                )
            return result
    with Session(get_engine()) as db:
        result = RemediationEffectivenessEngine(db, tenant_id).update_outcome_status(
            remediation_id, body.status
        )
        if result is None:
            raise HTTPException(
                status_code=404, detail="Remediation outcome not found"
            )
        return result
