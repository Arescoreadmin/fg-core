from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.enterprise_controls_extension import (
    EnterpriseControlsService,
    TenantControlStateUpsert,
)

router = APIRouter(
    tags=["enterprise-controls"],
    dependencies=[Depends(require_scopes("compliance:read"))],
)
service = EnterpriseControlsService()


@router.get("/enterprise-controls/frameworks")
def list_frameworks(db: Session = Depends(tenant_db_required)) -> dict[str, object]:
    service.seed_minimal(db)
    return {"frameworks": service.frameworks(db)}


@router.get("/enterprise-controls/catalog")
def list_catalog(db: Session = Depends(tenant_db_required)) -> dict[str, object]:
    service.seed_minimal(db)
    return {"catalog": service.catalog(db)}


@router.get("/enterprise-controls/crosswalk")
def list_crosswalk(db: Session = Depends(tenant_db_required)) -> dict[str, object]:
    service.seed_minimal(db)
    return {"crosswalk": service.crosswalk(db)}


@router.post(
    "/enterprise-controls/tenant-state",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def upsert_tenant_control_state(
    request: Request,
    payload: TenantControlStateUpsert,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.upsert_tenant_state(db, tenant_id, payload)
