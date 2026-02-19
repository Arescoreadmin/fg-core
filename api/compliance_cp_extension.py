from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from api.auth_scopes import require_bound_tenant, require_scopes
from services.compliance_cp_extension import ComplianceControlPlaneService
from services.compliance_cp_extension.models import ComplianceCPEvidenceIngestRequest

router = APIRouter(
    tags=["compliance-cp"],
    dependencies=[Depends(require_scopes("compliance:read"))],
)
_service: ComplianceControlPlaneService | None = None


def _get_service() -> ComplianceControlPlaneService:
    """
    Lazily initialize the control-plane service to avoid import-time DB setup.

    Contract/spec generation imports routers in environments where FG_SQLITE_PATH
    may not be set; deferring service construction prevents accidental writes to
    production-like default paths during module import.
    """
    global _service
    if _service is None:
        _service = ComplianceControlPlaneService()
    return _service


@router.get("/compliance-cp/summary")
def compliance_cp_summary(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return _get_service().summary(tenant_id)


@router.get("/compliance-cp/portfolio")
def compliance_cp_portfolio(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return _get_service().portfolio(tenant_id)


@router.get("/compliance-cp/controls")
def compliance_cp_controls(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"controls": _get_service().controls(tenant_id)}


@router.post(
    "/compliance-cp/evidence/ingest",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def compliance_cp_evidence_ingest(
    request: Request, payload: ComplianceCPEvidenceIngestRequest
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    try:
        return _get_service().ingest_evidence(tenant_id, payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": "compliance_cp_invalid_request", "reason": str(exc)},
        ) from exc
