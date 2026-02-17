from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from api.auth_scopes import require_bound_tenant, require_scopes
from services.compliance_registry import (
    ComplianceRegistry,
    FindingCreateItem,
    RequirementImportItem,
    RequirementPackageMeta,
)

router = APIRouter(tags=["compliance"])


class RequirementImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: RequirementPackageMeta
    requirements: list[RequirementImportItem]
    update_id: str | None = None


class FindingCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[FindingCreateItem]


class RequirementUpdateAvailableRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    package: RequirementPackageMeta
    diff: dict[str, object]


@router.post(
    "/compliance/requirements/import",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def import_requirements(
    request: Request, body: RequirementImportRequest
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    actor = request.headers.get("X-Actor", "unknown")
    created = ComplianceRegistry().import_requirements(
        tenant_id,
        body.requirements,
        actor,
        body.package,
        update_id=body.update_id,
    )
    return {"created": created, "count": len(created)}


@router.post(
    "/compliance/requirements/updates/available",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def update_available(
    request: Request, body: RequirementUpdateAvailableRequest
) -> dict[str, str]:
    tenant_id = require_bound_tenant(request)
    update_id = ComplianceRegistry().record_update_available(
        tenant_id, body.package, body.diff
    )
    return {"update_id": update_id}


@router.get(
    "/compliance/requirements/updates",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def list_updates(request: Request) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"updates": ComplianceRegistry().list_updates(tenant_id)}


@router.post(
    "/compliance/requirements/updates/{update_id}/apply",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def apply_update(update_id: str, request: Request) -> dict[str, str]:
    tenant_id = require_bound_tenant(request)
    registry = ComplianceRegistry()
    updates = registry.list_updates(tenant_id)
    selected = next((u for u in updates if u["update_id"] == update_id), None)
    if selected is None:
        raise HTTPException(status_code=404, detail="update_not_found")
    return {"update_id": update_id, "status": "ready_to_apply_via_import"}


@router.get(
    "/compliance/requirements/diff",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def requirements_diff(request: Request, since: str) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    rows = ComplianceRegistry().requirements_diff(tenant_id, since)
    return {"changes": rows}


@router.post(
    "/compliance/findings/import",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def import_findings(request: Request, body: FindingCreateRequest) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    created = ComplianceRegistry().add_findings(tenant_id, body.findings)
    return {"created": created, "count": len(created)}
