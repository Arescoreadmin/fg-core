from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.deps import tenant_db_required
from services.artifact_paths import ArtifactIntegrityError, ArtifactNotAuthorized
from services.evidence_anchor_extension import (
    EvidenceAnchorCreate,
    EvidenceAnchorService,
)

router = APIRouter(tags=["evidence-anchors"])
service = EvidenceAnchorService()


@router.post(
    "/evidence/anchors",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def create_anchor(
    request: Request,
    payload: EvidenceAnchorCreate,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    try:
        return service.create_anchor(db, tenant_id, payload)
    except ArtifactNotAuthorized as exc:
        # Foreign, unknown and missing artifacts share this one response, and
        # it no longer echoes the requested path.
        raise HTTPException(
            status_code=404,
            detail={"error_code": "evidence_anchor_artifact_not_found"},
        ) from exc
    except ArtifactIntegrityError as exc:
        raise HTTPException(status_code=409, detail={"error_code": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={"error_code": str(exc)},
        ) from exc


@router.get(
    "/evidence/anchors",
    dependencies=[Depends(require_scopes("compliance:read"))],
)
def list_anchors(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, object]:
    tenant_id = require_bound_tenant(request)
    return {"anchors": service.list_anchors(db, tenant_id)}
