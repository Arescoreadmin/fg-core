from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes, require_bound_tenant
from api.db_models import ConnectorTenantState
from api.deps import tenant_db_required

router = APIRouter(prefix="/admin/connectors", tags=["connectors-status"])


@router.get(
    "/status",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def connectors_status(
    request: Request, db: Session = Depends(tenant_db_required)
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)

    rows = db.execute(
        select(
            ConnectorTenantState.connector_id,
            ConnectorTenantState.enabled,
            ConnectorTenantState.last_success_at,
            ConnectorTenantState.last_error_code,
        ).where(ConnectorTenantState.tenant_id == tenant_id)
    ).all()

    connectors: list[dict[str, Any]] = []
    for connector_id, enabled, last_success_at, last_error_code in rows:
        if connector_id == "__policy__":
            # policy is an internal sentinel, not a real connector surface
            continue

        enabled_b = bool(enabled)
        connected = bool(last_success_at) and last_error_code is None

        connectors.append(
            {
                "connector_id": connector_id,
                "connected": connected,
                "enabled": enabled_b,
                "last_success_at": last_success_at,
                "last_error_code": last_error_code,
                # Keep it boring and deterministic. Don’t leak. Don’t get clever.
                "health": "ok"
                if (enabled_b and connected)
                else ("disabled" if not enabled_b else "degraded"),
            }
        )

    return {"tenant_id": tenant_id, "connectors": connectors}
