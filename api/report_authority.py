# api/report_authority.py
"""Enterprise Assessment Report Authority API — PR 18.1.

All routes are tenant-scoped. Tenant is resolved from auth context only —
never from the request body.

Route ordering note:
  Static paths (/reports/health, /reports/statistics, /reports/generate,
  /reports/compare) MUST appear before parameterized paths (/reports/{report_id}
  and its sub-paths) to prevent FastAPI matching them as report IDs.

Security invariants:
  - tenant_id always from auth context via require_bound_tenant()
  - No route bypasses tenant checks or scope checks
  - No direct ORM access — all ops go through ReportAuthorityEngine
  - audit events always written (never skipped)
  - actor_id always from request state (key_prefix) — never from body
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from services.report_authority.engine import ReportAuthorityEngine
from services.report_authority.export import build_export_bundle
from services.report_authority.manifest import build_manifest
from services.report_authority.renderer_html import render_html
from services.report_authority.renderer_json import render_json
from services.report_authority.renderer_pdf import render_pdf
from services.report_authority.schemas import (
    BundleResponse,
    CompareReportsRequest,
    GenerateReportRequest,
    HealthResponse,
    PublishReportRequest,
    ReportConflict,
    ReportGenerationError,
    ReportListResponse,
    ReportManifestResponse,
    ReportNotFound,
    ReportQualityResponse,
    ReportResponse,
    ReportStatisticsResponse,
    ReportTenantViolation,
    VersionComparisonResponse,
    VerifyReportRequest,
)

router = APIRouter(tags=["report-authority"])


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or "unknown"
    )


def _actor_type(request: Request) -> str:
    return str(getattr(getattr(request, "state", None), "actor_type", None) or "human")


def _build_report_content(
    engine: ReportAuthorityEngine,
    report_id: str,
) -> dict[str, Any]:
    """Fetch a report and build a report_data dict suitable for renderers.

    Calls engine.get_report() (raises ReportNotFound if absent) and assembles
    the top-level section map that all three renderers accept.
    """
    report: ReportResponse = engine.get_report(report_id)
    report_data: dict[str, Any] = {
        "report_id": report.id,
        "tenant_id": report.tenant_id,
        "report_ref": report.report_ref,
        "assessment_id": report.assessment_id,
        "report_type": report.report_type,
        "lifecycle_state": report.lifecycle_state,
        "title": report.title,
        "scope": report.scope,
        "objectives": report.objectives,
        "assessor_id": report.assessor_id,
        "reviewer_id": report.reviewer_id,
        "quality": {
            "quality_score": report.quality_score,
            "quality_grade": report.quality_grade,
            "evidence_coverage_score": report.evidence_coverage_score,
            "verification_coverage_score": report.verification_coverage_score,
            "freshness_score": report.freshness_score,
            "confidence_score": report.confidence_score,
        },
        "hashes": {
            "report_hash_sha256": report.report_hash_sha256,
            "report_hash_sha512": report.report_hash_sha512,
            "manifest_hash": report.manifest_hash,
            "transparency_root": report.transparency_root,
        },
        "versions": {
            "schema_version": report.schema_version,
            "manifest_schema_version": report.manifest_schema_version,
            "generator_version": report.generator_version,
        },
        "timestamps": {
            "created_at": report.created_at,
            "updated_at": report.updated_at,
            "published_at": report.published_at,
            "superseded_at": report.superseded_at,
            "archived_at": report.archived_at,
        },
    }
    return report_data


# ---------------------------------------------------------------------------
# 1. Health — no auth required (static path, must be first)
# ---------------------------------------------------------------------------


@router.get(
    "/reports/health",
    response_model=HealthResponse,
)
def report_health(request: Request) -> HealthResponse:
    """Report Authority health check — no authentication required."""
    db_engine = get_engine()
    with Session(db_engine) as db:
        # Use a minimal tenant_id sentinel for health — no tenant data accessed.
        svc = ReportAuthorityEngine(db, tenant_id="__health__")
        return svc.health()


# ---------------------------------------------------------------------------
# 2. Statistics (static path, must precede /{report_id})
# ---------------------------------------------------------------------------


@router.get(
    "/reports/statistics",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ReportStatisticsResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def report_statistics(request: Request) -> ReportStatisticsResponse:
    """Tenant-level report statistics."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        return svc.get_statistics()


# ---------------------------------------------------------------------------
# 3. List Reports (static path)
# ---------------------------------------------------------------------------


@router.get(
    "/reports",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ReportListResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def list_reports(
    request: Request,
    report_type: str | None = Query(default=None),
    lifecycle_state: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
) -> ReportListResponse:
    """List reports for the tenant with optional filters."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        return svc.list_reports(
            report_type=report_type,
            lifecycle_state=lifecycle_state,
            offset=offset,
            limit=limit,
        )


# ---------------------------------------------------------------------------
# 4. Generate Report (static path)
# ---------------------------------------------------------------------------


@router.post(
    "/reports/generate",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=ReportResponse,
    status_code=201,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def generate_report(
    req: GenerateReportRequest,
    request: Request,
) -> ReportResponse:
    """Generate a new enterprise assessment report."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.generate_report(req, actor_id=actor_id, actor_type=actor_type)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ReportConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ReportGenerationError as exc:
            raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# 15. Compare Reports (static path, must precede /{report_id})
# ---------------------------------------------------------------------------


@router.post(
    "/reports/compare",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=VersionComparisonResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def compare_reports(
    req: CompareReportsRequest,
    request: Request,
) -> VersionComparisonResponse:
    """Compare two report versions and return a structural diff."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.compare_versions(req)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))


# ---------------------------------------------------------------------------
# 5. Get Report
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ReportResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_report(report_id: str, request: Request) -> ReportResponse:
    """Get a single report by ID."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_report(report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))


# ---------------------------------------------------------------------------
# 6. Get Report Manifest
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/manifest",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ReportManifestResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_report_manifest(report_id: str, request: Request) -> ReportManifestResponse:
    """Get the cryptographic manifest for a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_manifest(report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))


# ---------------------------------------------------------------------------
# 7. Get Report Quality
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/quality",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=ReportQualityResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_report_quality(report_id: str, request: Request) -> ReportQualityResponse:
    """Get the quality breakdown for a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_quality(report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))


# ---------------------------------------------------------------------------
# 8. Download PDF
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/download/pdf",
    dependencies=[Depends(require_scopes("audit:read"))],
    responses={
        200: {"content": {"application/pdf": {}}},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
def download_report_pdf(report_id: str, request: Request) -> Response:
    """Download the PDF rendering of a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            report_data = _build_report_content(svc, report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    title = str(report_data.get("title", "FrostGate Assessment Report"))
    pdf_bytes = render_pdf(report_data, title=title)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="report-{report_id[:8]}.pdf"'
        },
    )


# ---------------------------------------------------------------------------
# 9. Download HTML
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/download/html",
    dependencies=[Depends(require_scopes("audit:read"))],
    responses={
        200: {"content": {"text/html": {}}},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
def download_report_html(report_id: str, request: Request) -> Response:
    """Download the HTML rendering of a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            report_data = _build_report_content(svc, report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    html_bytes = render_html(report_data)
    return Response(
        content=html_bytes,
        media_type="text/html",
        headers={
            "Content-Disposition": f'inline; filename="report-{report_id[:8]}.html"'
        },
    )


# ---------------------------------------------------------------------------
# 10. Download JSON
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/download/json",
    dependencies=[Depends(require_scopes("audit:read"))],
    responses={
        200: {"content": {"application/json": {}}},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
def download_report_json(report_id: str, request: Request) -> Response:
    """Download the canonical JSON rendering of a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            report_data = _build_report_content(svc, report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
    json_bytes = render_json(report_data)
    return Response(
        content=json_bytes,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="report-{report_id[:8]}.json"'
        },
    )


# ---------------------------------------------------------------------------
# 11. Get Bundle Metadata
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/bundle",
    dependencies=[Depends(require_scopes("audit:read"))],
    response_model=BundleResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def get_report_bundle(report_id: str, request: Request) -> BundleResponse:
    """Get export bundle metadata for a report (creates a PENDING bundle if none exists)."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.get_bundle(report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))


# ---------------------------------------------------------------------------
# 12. Download Bundle ZIP
# ---------------------------------------------------------------------------


@router.get(
    "/reports/{report_id}/bundle/download",
    dependencies=[Depends(require_scopes("audit:read"))],
    responses={
        200: {"content": {"application/zip": {}}},
        401: {"description": "Unauthorized"},
        403: {"description": "Forbidden"},
        404: {"description": "Not Found"},
    },
)
def download_report_bundle(report_id: str, request: Request) -> Response:
    """Download the signed ZIP export bundle for a report."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            report_data = _build_report_content(svc, report_id)
            manifest_resp = svc.get_manifest(report_id)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))

    title = str(report_data.get("title", "FrostGate Assessment Report"))
    pdf_bytes = render_pdf(report_data, title=title)
    html_bytes = render_html(report_data)
    json_bytes = render_json(report_data)

    manifest_dict = build_manifest(
        report_id=report_id,
        report_version=manifest_resp.report_version,
        schema_version=manifest_resp.schema_version,
        assessment_id=str(report_data.get("assessment_id", "")),
        report_type=str(report_data.get("report_type", "")),
        tenant_id=tenant_id,
        generation_timestamp=manifest_resp.generation_timestamp,
        assessor_id=str(report_data.get("assessor_id", "")),
        sections_included=sorted(report_data.keys()),
        authority_versions=manifest_resp.authority_versions,
        transparency_root=manifest_resp.transparency_root,
        merkle_root=manifest_resp.merkle_root,
    )

    zip_bytes = build_export_bundle(
        report_id=report_id,
        pdf_bytes=pdf_bytes,
        html_bytes=html_bytes,
        json_bytes=json_bytes,
        manifest=manifest_dict,
    )

    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="report-{report_id[:8]}-bundle.zip"'
        },
    )


# ---------------------------------------------------------------------------
# 13. Publish Report
# ---------------------------------------------------------------------------


@router.post(
    "/reports/{report_id}/publish",
    dependencies=[Depends(require_scopes("audit:write"))],
    response_model=ReportResponse,
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def publish_report(
    report_id: str,
    req: PublishReportRequest,
    request: Request,
) -> ReportResponse:
    """Publish a generated report (transitions to PUBLISHED state)."""
    tenant_id = require_bound_tenant(request)
    actor_id = _actor(request)
    actor_type = _actor_type(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.publish_report(
                report_id, req, actor_id=actor_id, actor_type=actor_type
            )
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
        except ReportConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        except ReportGenerationError as exc:
            raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# 14. Verify Report
# ---------------------------------------------------------------------------


@router.post(
    "/reports/{report_id}/verify",
    dependencies=[Depends(require_scopes("audit:read"))],
    responses={401: {"description": "Unauthorized"}, 403: {"description": "Forbidden"}},
)
def verify_report(
    report_id: str,
    req: VerifyReportRequest,
    request: Request,
) -> dict:
    """Verify a report's integrity against its stored hash and record the audit event."""
    tenant_id = require_bound_tenant(request)
    db_engine = get_engine()
    with Session(db_engine) as db:
        svc = ReportAuthorityEngine(db, tenant_id=tenant_id)
        try:
            return svc.verify_report(report_id, req)
        except ReportNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except ReportTenantViolation as exc:
            raise HTTPException(status_code=403, detail=str(exc))
