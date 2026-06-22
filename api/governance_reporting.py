# api/governance_reporting.py
"""Governance Reporting & Attestation API router — PR 14.5.

All routes are tenant-scoped. Tenant is resolved from auth context only.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks, scope checks, or audit generation
  - No direct ORM access — all DB ops go through GovernanceReportingEngine
  - db.commit() is called once per engine method invocation (at the end)

Route ordering:
  Literal sub-paths are defined before parametric paths to prevent FastAPI
  from matching literal segments as {report_id} path parameters.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.governance_reporting.engine import GovernanceReportingEngine
from services.governance_reporting.schemas import (
    AttestationListResponse,
    AttestationResponse,
    CreateAttestationRequest,
    GenerateReportRequest,
    GovernanceReportDetail,
    GovernanceReportListResponse,
    ManifestResponse,
    ReportNotFound,
    ReportTimelineResponse,
    VerificationResponse,
)

router = APIRouter(tags=["governance-reporting"])

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


# ---------------------------------------------------------------------------
# POST /governance-reports  — generate a new report
# ---------------------------------------------------------------------------


@router.post(
    "/governance-reports",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=GovernanceReportDetail,
    status_code=status.HTTP_201_CREATED,
)
def generate_report(
    request: Request,
    body: GenerateReportRequest,
) -> GovernanceReportDetail:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.generate_report(body, actor=_actor(request))
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-reports  — list reports
# ---------------------------------------------------------------------------


@router.get(
    "/governance-reports",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceReportListResponse,
)
def list_reports(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    risk_acceptance_id: str | None = Query(default=None),
) -> GovernanceReportListResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    with Session(engine_inst) as db:
        svc = GovernanceReportingEngine(db, tenant_id)
        result = svc.list_reports(
            risk_acceptance_id=risk_acceptance_id,
            limit=limit,
            offset=offset,
        )
        db.commit()
    return result


# ---------------------------------------------------------------------------
# GET /governance-reports/{report_id}  — get report detail
# ---------------------------------------------------------------------------


@router.get(
    "/governance-reports/{report_id}",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=GovernanceReportDetail,
)
def get_report(
    request: Request,
    report_id: str,
) -> GovernanceReportDetail:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.get_report(report_id)
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-reports/{report_id}/manifest
# ---------------------------------------------------------------------------


@router.get(
    "/governance-reports/{report_id}/manifest",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ManifestResponse,
)
def get_manifest(
    request: Request,
    report_id: str,
) -> ManifestResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.get_manifest(report_id)
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-reports/{report_id}/timeline
# ---------------------------------------------------------------------------


@router.get(
    "/governance-reports/{report_id}/timeline",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=ReportTimelineResponse,
)
def get_report_timeline(
    request: Request,
    report_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> ReportTimelineResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.get_report_timeline(report_id, limit=limit, offset=offset)
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# GET /governance-reports/{report_id}/attestations
# ---------------------------------------------------------------------------


@router.get(
    "/governance-reports/{report_id}/attestations",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=AttestationListResponse,
)
def list_attestations(
    request: Request,
    report_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> AttestationListResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.list_attestations(report_id, limit=limit, offset=offset)
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /governance-reports/{report_id}/attest
# ---------------------------------------------------------------------------


@router.post(
    "/governance-reports/{report_id}/attest",
    dependencies=[Depends(require_scopes("governance:write"))],
    response_model=AttestationResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_attestation(
    request: Request,
    report_id: str,
    body: CreateAttestationRequest,
) -> AttestationResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.create_attestation(report_id, body, actor=_actor(request))
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /governance-reports/{report_id}/verify
# ---------------------------------------------------------------------------


@router.post(
    "/governance-reports/{report_id}/verify",
    dependencies=[Depends(require_scopes("governance:read"))],
    response_model=VerificationResponse,
)
def verify_report(
    request: Request,
    report_id: str,
) -> VerificationResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            result = svc.verify_report(report_id, actor=_actor(request))
            db.commit()
        return result
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /governance-reports/{report_id}/export/pdf
# ---------------------------------------------------------------------------


@router.post(
    "/governance-reports/{report_id}/export/pdf",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def export_pdf(
    request: Request,
    report_id: str,
) -> Response:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            pdf_bytes = svc.export_pdf(report_id, actor=_actor(request))
            db.commit()
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report_id}.pdf"'
            },
        )
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# POST /governance-reports/{report_id}/export/html
# ---------------------------------------------------------------------------


@router.post(
    "/governance-reports/{report_id}/export/html",
    dependencies=[Depends(require_scopes("governance:read"))],
)
def export_html(
    request: Request,
    report_id: str,
) -> HTMLResponse:
    tenant_id = require_bound_tenant(request)
    engine_inst = get_engine()
    try:
        with Session(engine_inst) as db:
            svc = GovernanceReportingEngine(db, tenant_id)
            html_str = svc.export_html(report_id, actor=_actor(request))
            db.commit()
        return HTMLResponse(content=html_str)
    except ReportNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
