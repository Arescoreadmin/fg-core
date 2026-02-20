# /home/jcosat/Projects/fg-core/api/connectors_internal.py
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db_models import ConnectorTenantState
from api.deps import tenant_db_required

router = APIRouter(prefix="/internal/connectors", tags=["connectors-internal"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IngestPayload(_StrictModel):
    cursor: Optional[str] = None
    since_ts: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=500)
    resource_ids: list[str] = Field(default_factory=list)


class IngestRequest(_StrictModel):
    # NOTE: intentionally NO tenant_id field.
    # Any tenant_id in input becomes a 422 via extra="forbid" (as required by tests).
    collection_id: str = Field(min_length=1)
    payload: IngestPayload = Field(default_factory=IngestPayload)


def _is_connector_enabled(db: Session, *, tenant_id: str, connector_id: str) -> bool:
    """
    Fail-closed enablement gate.

    Contract:
      - Missing row => disabled
      - enabled must be truthy
    """
    enabled = db.execute(
        select(ConnectorTenantState.enabled).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id == connector_id,
        )
    ).scalar_one_or_none()

    return bool(enabled) if enabled is not None else False


@router.post(
    "/{connector_id}/ingest",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def connector_ingest(
    connector_id: str,
    body: IngestRequest,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> dict:
    tenant_id = require_bound_tenant(request)

    # Gate 1: Connector must be enabled for the tenant.
    # Test requires: 403 + {"detail": "CONNECTOR_DISABLED"} for disabled connectors.
    if not _is_connector_enabled(db, tenant_id=tenant_id, connector_id=connector_id):
        raise HTTPException(status_code=403, detail="CONNECTOR_DISABLED")

    # Gate 2: Dispatch is not wired yet.
    # Keep fail-closed. If later you wire dispatch, replace this block with:
    #   services.connectors.dispatch_ingest(db, tenant_id=tenant_id, connector_id=connector_id, ...)
    #
    # We intentionally do NOT leak tenant_id/connector_id in the response.
    raise HTTPException(status_code=403, detail="CONNECTOR_INGEST_DENIED")
