from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.evidence_index import EvidenceIndexService

router = APIRouter(tags=["evidence-index"])
service = EvidenceIndexService()


class EvidenceRunRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plane_id: str
    artifact_type: str
    artifact_path: str
    schema_version: str
    git_sha: str
    status: str
    summary_json: dict[str, object]
    retention_class: str = "hot"
    anchor_status: str = "none"


@router.get("/evidence/runs", dependencies=[Depends(require_scopes("compliance:read"))])
def list_evidence_runs(request: Request, db: Session = Depends(tenant_db_required)) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"runs": service.list_runs(db, tenant_id)}


@router.get("/evidence/runs/{run_id}", dependencies=[Depends(require_scopes("compliance:read"))])
def get_evidence_run(run_id: str, request: Request, db: Session = Depends(tenant_db_required)) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    row = service.get_run(db, tenant_id, run_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error_code": "EVIDENCE_RUN_NOT_FOUND"})
    return row


@router.post("/evidence/runs/register", dependencies=[Depends(require_scopes("admin:write"))])
def register_evidence_run(
    request: Request,
    payload: EvidenceRunRegisterRequest,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return service.register_run(
        db,
        tenant_id=tenant_id,
        plane_id=payload.plane_id,
        artifact_type=payload.artifact_type,
        artifact_path=payload.artifact_path,
        schema_version=payload.schema_version,
        git_sha=payload.git_sha,
        status=payload.status,
        summary_json=payload.summary_json,
        retention_class=payload.retention_class,
        anchor_status=payload.anchor_status,
    )
