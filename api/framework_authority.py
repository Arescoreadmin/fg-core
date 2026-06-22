from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.framework_authority import (
    ControlFrameworkMappingAuditResponse,
    ControlFrameworkMappingCreateRequest,
    ControlFrameworkMappingResponse,
    ControlFrameworkMappingTransitionRequest,
    ControlFrameworkMappingUpdateRequest,
    ControlFrameworkCoverageResponse,
    FrameworkAuthorityConflict,
    FrameworkAuthorityEngine,
    FrameworkAuthorityInvalidTransition,
    FrameworkAuthorityNotFound,
    FrameworkAuthorityPermissionDenied,
    FrameworkControlCreateRequest,
    FrameworkControlResponse,
    FrameworkControlUpdateRequest,
    FrameworkCoverageResponse,
    FrameworkCreateRequest,
    FrameworkResponse,
    FrameworkTransitionRequest,
    FrameworkUpdateRequest,
)

router = APIRouter(tags=["framework-authority"])
engine = FrameworkAuthorityEngine()


def _actor_from_request(request: Request) -> str:
    return (request.headers.get("X-Actor") or "unknown").strip() or "unknown"


def _allow_system_write(request: Request) -> bool:
    auth = getattr(getattr(request, "state", None), "auth", None)
    scopes: set[str] = getattr(auth, "scopes", set()) if auth is not None else set()
    return "admin:write" in scopes or "control-plane:admin" in scopes


def _set_system_write_context(db: Session, allow: bool) -> None:
    """Set transaction-local system-write signal for RLS on PostgreSQL."""
    bind = getattr(db, "bind", None)
    if bind is None or getattr(bind.dialect, "name", "") != "postgresql":
        return
    value = "true" if allow else "false"
    db.execute(
        text("SELECT set_config('app.allow_system_write', :v, true)"), {"v": value}
    )


def _translate_error(exc: Exception) -> HTTPException:
    if isinstance(exc, FrameworkAuthorityNotFound):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, FrameworkAuthorityInvalidTransition):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, FrameworkAuthorityConflict):
        return HTTPException(status_code=409, detail=str(exc))
    if isinstance(exc, FrameworkAuthorityPermissionDenied):
        return HTTPException(status_code=403, detail=str(exc))
    return HTTPException(status_code=500, detail="framework_authority_error")


@router.post(
    "/frameworks",
    response_model=FrameworkResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_framework(
    request: Request,
    payload: FrameworkCreateRequest,
    db: Session = Depends(tenant_db_required),
) -> FrameworkResponse:
    tenant_id = require_bound_tenant(request)
    allow_sys = _allow_system_write(request)
    try:
        _set_system_write_context(db, allow_sys)
        row = engine.create_framework(
            db,
            tenant_id=tenant_id,
            actor=_actor_from_request(request),
            allow_system_write=allow_sys,
            payload=payload,
        )
        db.flush()
        result = FrameworkResponse.model_validate(row)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.get(
    "/frameworks",
    response_model=list[FrameworkResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_frameworks(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[FrameworkResponse]:
    tenant_id = require_bound_tenant(request)
    rows = engine.list_frameworks(db, tenant_id=tenant_id)
    return [FrameworkResponse.model_validate(row) for row in rows]


@router.get(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_framework(
    framework_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> FrameworkResponse:
    tenant_id = require_bound_tenant(request)
    try:
        row = engine.get_framework(db, tenant_id=tenant_id, framework_id=framework_id)
        return FrameworkResponse.model_validate(row)
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.patch(
    "/frameworks/{framework_id}",
    response_model=FrameworkResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def update_framework(
    framework_id: str,
    request: Request,
    payload: FrameworkUpdateRequest,
    db: Session = Depends(tenant_db_required),
) -> FrameworkResponse:
    tenant_id = require_bound_tenant(request)
    allow_sys = _allow_system_write(request)
    try:
        _set_system_write_context(db, allow_sys)
        row = engine.update_framework(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_sys,
            payload=payload,
        )
        db.flush()
        result = FrameworkResponse.model_validate(row)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.post(
    "/frameworks/{framework_id}/transitions",
    response_model=FrameworkResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def transition_framework(
    framework_id: str,
    request: Request,
    payload: FrameworkTransitionRequest,
    db: Session = Depends(tenant_db_required),
) -> FrameworkResponse:
    tenant_id = require_bound_tenant(request)
    allow_sys = _allow_system_write(request)
    try:
        _set_system_write_context(db, allow_sys)
        row = engine.transition_framework(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_sys,
            payload=payload,
        )
        db.flush()
        result = FrameworkResponse.model_validate(row)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.post(
    "/frameworks/{framework_id}/controls",
    response_model=FrameworkControlResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_framework_control(
    framework_id: str,
    request: Request,
    payload: FrameworkControlCreateRequest,
    db: Session = Depends(tenant_db_required),
) -> FrameworkControlResponse:
    tenant_id = require_bound_tenant(request)
    allow_sys = _allow_system_write(request)
    try:
        _set_system_write_context(db, allow_sys)
        row = engine.create_framework_control(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            allow_system_write=allow_sys,
            payload=payload,
        )
        db.flush()
        result = FrameworkControlResponse.model_validate(row)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=list[FrameworkControlResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_framework_controls(
    framework_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[FrameworkControlResponse]:
    tenant_id = require_bound_tenant(request)
    try:
        rows = engine.list_framework_controls(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        return [FrameworkControlResponse.model_validate(row) for row in rows]
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/frameworks/{framework_id}/controls/{framework_control_id}",
    response_model=FrameworkControlResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_framework_control(
    framework_id: str,
    framework_control_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> FrameworkControlResponse:
    tenant_id = require_bound_tenant(request)
    try:
        row = engine.get_framework_control(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_control_id=framework_control_id,
        )
        return FrameworkControlResponse.model_validate(row)
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.patch(
    "/frameworks/{framework_id}/controls/{framework_control_id}",
    response_model=FrameworkControlResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def update_framework_control(
    framework_id: str,
    framework_control_id: str,
    request: Request,
    payload: FrameworkControlUpdateRequest,
    db: Session = Depends(tenant_db_required),
) -> FrameworkControlResponse:
    tenant_id = require_bound_tenant(request)
    allow_sys = _allow_system_write(request)
    try:
        _set_system_write_context(db, allow_sys)
        row = engine.update_framework_control(
            db,
            tenant_id=tenant_id,
            framework_id=framework_id,
            framework_control_id=framework_control_id,
            allow_system_write=allow_sys,
            payload=payload,
        )
        db.flush()
        result = FrameworkControlResponse.model_validate(row)
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.post(
    "/controls/{control_id}/framework-mappings",
    response_model=ControlFrameworkMappingResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def create_control_framework_mapping(
    control_id: str,
    request: Request,
    payload: ControlFrameworkMappingCreateRequest,
    db: Session = Depends(tenant_db_required),
) -> ControlFrameworkMappingResponse:
    tenant_id = require_bound_tenant(request)
    try:
        row = engine.create_mapping(
            db,
            tenant_id=tenant_id,
            control_id=control_id,
            actor=_actor_from_request(request),
            payload=payload,
        )
        db.flush()
        result = ControlFrameworkMappingResponse.model_validate(
            engine.get_mapping(db, tenant_id=tenant_id, mapping_id=row.id)
        )
        db.commit()
        return result
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.get(
    "/controls/{control_id}/framework-mappings",
    response_model=list[ControlFrameworkMappingResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_control_framework_mappings(
    control_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[ControlFrameworkMappingResponse]:
    tenant_id = require_bound_tenant(request)
    try:
        rows = engine.list_mappings_for_control(
            db, tenant_id=tenant_id, control_id=control_id
        )
        return [ControlFrameworkMappingResponse.model_validate(row) for row in rows]
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/frameworks/{framework_id}/control-mappings",
    response_model=list[ControlFrameworkMappingResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def list_framework_control_mappings(
    framework_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[ControlFrameworkMappingResponse]:
    tenant_id = require_bound_tenant(request)
    try:
        rows = engine.list_mappings_for_framework(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        return [ControlFrameworkMappingResponse.model_validate(row) for row in rows]
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/control-framework-mappings/{mapping_id}",
    response_model=ControlFrameworkMappingResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_control_framework_mapping(
    mapping_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> ControlFrameworkMappingResponse:
    tenant_id = require_bound_tenant(request)
    try:
        return ControlFrameworkMappingResponse.model_validate(
            engine.get_mapping(db, tenant_id=tenant_id, mapping_id=mapping_id)
        )
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.patch(
    "/control-framework-mappings/{mapping_id}",
    response_model=ControlFrameworkMappingResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def update_control_framework_mapping(
    mapping_id: str,
    request: Request,
    payload: ControlFrameworkMappingUpdateRequest,
    db: Session = Depends(tenant_db_required),
) -> ControlFrameworkMappingResponse:
    tenant_id = require_bound_tenant(request)
    try:
        response = engine.update_mapping(
            db,
            tenant_id=tenant_id,
            mapping_id=mapping_id,
            actor=_actor_from_request(request),
            payload=payload,
        )
        db.commit()
        return ControlFrameworkMappingResponse.model_validate(response)
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.post(
    "/control-framework-mappings/{mapping_id}/transitions",
    response_model=ControlFrameworkMappingResponse,
    dependencies=[Depends(require_scopes("governance:write"))],
)
def transition_control_framework_mapping(
    mapping_id: str,
    request: Request,
    payload: ControlFrameworkMappingTransitionRequest,
    db: Session = Depends(tenant_db_required),
) -> ControlFrameworkMappingResponse:
    tenant_id = require_bound_tenant(request)
    try:
        response = engine.transition_mapping(
            db,
            tenant_id=tenant_id,
            mapping_id=mapping_id,
            actor=_actor_from_request(request),
            payload=payload,
        )
        db.commit()
        return ControlFrameworkMappingResponse.model_validate(response)
    except Exception as exc:
        db.rollback()
        raise _translate_error(exc) from exc


@router.get(
    "/control-framework-mappings/{mapping_id}/audit",
    response_model=list[ControlFrameworkMappingAuditResponse],
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_control_framework_mapping_audit(
    mapping_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> list[ControlFrameworkMappingAuditResponse]:
    tenant_id = require_bound_tenant(request)
    try:
        rows = engine.list_mapping_audit(db, tenant_id=tenant_id, mapping_id=mapping_id)
        return [
            ControlFrameworkMappingAuditResponse.model_validate(row) for row in rows
        ]
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/frameworks/{framework_id}/coverage",
    response_model=FrameworkCoverageResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_framework_coverage(
    framework_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> FrameworkCoverageResponse:
    tenant_id = require_bound_tenant(request)
    try:
        coverage = engine.framework_coverage(
            db, tenant_id=tenant_id, framework_id=framework_id
        )
        return FrameworkCoverageResponse.model_validate(coverage)
    except Exception as exc:
        raise _translate_error(exc) from exc


@router.get(
    "/controls/{control_id}/framework-coverage",
    response_model=ControlFrameworkCoverageResponse,
    dependencies=[Depends(require_scopes("governance:read"))],
)
def get_control_framework_coverage(
    control_id: str,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> ControlFrameworkCoverageResponse:
    tenant_id = require_bound_tenant(request)
    try:
        coverage = engine.control_coverage(
            db, tenant_id=tenant_id, control_id=control_id
        )
        return ControlFrameworkCoverageResponse.model_validate(coverage)
    except Exception as exc:
        raise _translate_error(exc) from exc
