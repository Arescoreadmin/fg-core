"""MS Graph scan report API — get report and public verification endpoint.

Routes:
  GET /field-assessment/engagements/{engagement_id}/connector-runs/msgraph/reports/{report_id}
      Returns the full governance report for a completed msgraph scan.
      Requires governance:read scope.

  GET /verify/{report_hash}
      Public verification endpoint — no auth required.
      Returns report metadata and manifest validity for a given manifest_hash.
      Clients use this to confirm a delivered report was not tampered with.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant
from api.auth_scopes import require_scopes
from api.db_models_governance_report import GovernanceReportRecord
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error

router = APIRouter(tags=["connectors-msgraph-report"])


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class MsgraphReportResponse(BaseModel):
    report_id: str
    scan_result_id: str
    engagement_id: str
    tenant_id_hash: str
    scan_completed_at: str
    generated_at: str
    schema_version: str
    report_type: str
    posture_overall: int
    posture_band: str
    posture_security: int
    posture_compliance: int
    posture_ai_governance: int
    finding_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    findings: list[dict[str, Any]]
    framework_refs: list[str]
    scan_type: str
    scopes_authorized: list[str]
    endpoints_called: int
    operator_receipt_hmac: str
    manifest_hash: str
    verification_url: str
    is_finalized: bool


class VerifyReportResponse(BaseModel):
    status: str  # "verified" | "not_found"
    report_id: str | None = None
    manifest_hash: str | None = None
    report_type: str | None = None
    generated_at: str | None = None
    scan_completed_at: str | None = None
    posture_overall: int | None = None
    posture_band: str | None = None
    finding_count: int | None = None
    schema_version: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_report_record(
    db: Session,
    report_id: str,
    tenant_id: str,
) -> GovernanceReportRecord:
    record = (
        db.query(GovernanceReportRecord)
        .filter(
            GovernanceReportRecord.id == report_id,
            GovernanceReportRecord.tenant_id == tenant_id,
        )
        .first()
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_NOT_FOUND", "Governance report not found"),
        )
    return record


def _record_to_response(record: GovernanceReportRecord) -> MsgraphReportResponse:
    rj: dict[str, Any] = record.report_json or {}
    return MsgraphReportResponse(
        report_id=rj.get("report_id", record.id),
        scan_result_id=rj.get("scan_result_id", ""),
        engagement_id=rj.get("engagement_id", ""),
        tenant_id_hash=rj.get("tenant_id_hash", ""),
        scan_completed_at=rj.get("scan_completed_at", ""),
        generated_at=rj.get("generated_at", record.generated_at),
        schema_version=rj.get("schema_version", record.schema_version),
        report_type=rj.get("report_type", "msgraph_governance_v1"),
        posture_overall=rj.get("posture_overall", 0),
        posture_band=rj.get("posture_band", ""),
        posture_security=rj.get("posture_security", 0),
        posture_compliance=rj.get("posture_compliance", 0),
        posture_ai_governance=rj.get("posture_ai_governance", 0),
        finding_count=rj.get("finding_count", 0),
        critical_count=rj.get("critical_count", 0),
        high_count=rj.get("high_count", 0),
        medium_count=rj.get("medium_count", 0),
        low_count=rj.get("low_count", 0),
        informational_count=rj.get("informational_count", 0),
        findings=rj.get("findings", []),
        framework_refs=rj.get("framework_refs", []),
        scan_type=rj.get("scan_type", ""),
        scopes_authorized=rj.get("scopes_authorized", []),
        endpoints_called=rj.get("endpoints_called", 0),
        operator_receipt_hmac=rj.get("operator_receipt_hmac", ""),
        manifest_hash=record.manifest_hash,
        verification_url=rj.get("verification_url", ""),
        is_finalized=record.is_finalized,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/field-assessment/engagements/{engagement_id}/connector-runs/msgraph/reports/{report_id}",
    response_model=MsgraphReportResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_msgraph_report(
    engagement_id: str,
    report_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MsgraphReportResponse:
    """Retrieve the governance report generated from a verified MS Graph scan.

    The report includes posture score, all findings, framework coverage,
    and a verification URL clients can use to confirm report integrity.
    """
    tenant_id = _resolve_caller_tenant(request)
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="tenant context required")
    record = _load_report_record(db, report_id=report_id, tenant_id=tenant_id)

    rj: dict[str, Any] = record.report_json or {}
    if rj.get("engagement_id") and rj["engagement_id"] != engagement_id:
        raise HTTPException(
            status_code=404,
            detail=api_error("REPORT_NOT_FOUND", "Governance report not found"),
        )

    return _record_to_response(record)


@router.get("/verify/{report_hash}", response_model=VerifyReportResponse)
def verify_report(
    report_hash: str,
    db: Session = Depends(auth_ctx_db_session),
) -> VerifyReportResponse:
    """Verify a delivered MS Graph governance report by its manifest hash.

    Every report embeds a verification_url pointing here.
    Returns status='verified' with report metadata if the hash exists.
    Returns status='not_found' if the hash is unknown (tampered or fabricated).
    No authentication required — clients verify without needing API access.
    """
    record = (
        db.query(GovernanceReportRecord)
        .filter(GovernanceReportRecord.manifest_hash == report_hash)
        .first()
    )
    if record is None:
        return VerifyReportResponse(status="not_found")

    rj: dict[str, Any] = record.report_json or {}
    return VerifyReportResponse(
        status="verified",
        report_id=record.id,
        manifest_hash=record.manifest_hash,
        report_type=rj.get("report_type"),
        generated_at=record.generated_at,
        scan_completed_at=rj.get("scan_completed_at"),
        posture_overall=rj.get("posture_overall"),
        posture_band=rj.get("posture_band"),
        finding_count=rj.get("finding_count"),
        schema_version=record.schema_version,
    )
