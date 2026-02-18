from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.exception_breakglass_extension import (
    BreakglassSessionCreate,
    ExceptionApproval,
    ExceptionBreakglassService,
    ExceptionRequestCreate,
)

router = APIRouter(tags=["exceptions", "breakglass"])
service = ExceptionBreakglassService()


@router.post(
    "/exceptions/requests",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_exception_request(
    request: Request,
    payload: ExceptionRequestCreate,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.create_exception(db, tenant_id, payload)


@router.post(
    "/exceptions/requests/{request_id}/approve",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def approve_exception_request(
    request_id: str,
    request: Request,
    payload: ExceptionApproval,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    try:
        return service.approve_exception(db, tenant_id, request_id, payload)
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail={"error_code": "exception_not_found", "reason": str(exc)},
        ) from exc


@router.post(
    "/breakglass/sessions",
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_breakglass_session(
    request: Request,
    payload: BreakglassSessionCreate,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.create_breakglass(db, tenant_id, payload)
