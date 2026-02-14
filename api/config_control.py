from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.config_versioning import LEGACY_CONFIG_HASH, create_config_version
from api.deps import tenant_db_required
from api.security_audit import AuditEvent, EventType, get_auditor

router = APIRouter(prefix="/config", tags=["config"])


class ConfigWriteRequest(BaseModel):
    tenant_id: Optional[str] = None
    config_payload: dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = None
    parent_hash: Optional[str] = None
    set_active: bool = True


@router.post(
    "/versions",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def write_config_version(
    req: ConfigWriteRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = bind_tenant_id(
        request, req.tenant_id, require_explicit_for_unscoped=True
    )
    if tenant_id == "unknown":
        raise HTTPException(status_code=400, detail="tenant_id must be known")

    if req.config_payload.get("_legacy") is True:
        raise HTTPException(status_code=400, detail="_legacy marker is reserved")

    version = create_config_version(
        db,
        tenant_id=tenant_id,
        config_payload=req.config_payload,
        created_by=req.created_by,
        parent_hash=req.parent_hash,
        set_active=req.set_active,
    )
    if version.config_hash == LEGACY_CONFIG_HASH:
        raise HTTPException(status_code=400, detail="legacy hash is reserved")

    db.commit()

    get_auditor().log_event(
        AuditEvent(
            event_type=EventType.ADMIN_ACTION,
            tenant_id=tenant_id,
            request_path="/config/versions",
            request_method="POST",
            details={
                "config_hash": version.config_hash,
                "set_active": bool(req.set_active),
            },
        )
    )

    return {
        "tenant_id": tenant_id,
        "config_hash": version.config_hash,
        "created_at": version.created_at.isoformat() if version.created_at else None,
        "created_by": version.created_by,
        "parent_hash": version.parent_hash,
        "set_active": bool(req.set_active),
    }
