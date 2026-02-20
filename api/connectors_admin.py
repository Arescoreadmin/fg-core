from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes, require_bound_tenant
from api.db_models import ConnectorAuditLedger, ConnectorCredential
from api.deps import tenant_db_required

router = APIRouter(prefix="/admin/connectors", tags=["connectors-admin"])


def _actor(request: Request) -> str:
    # Match the rest of your codebase style: key prefix is the “actor”
    return str(getattr(getattr(request.state, "auth", None), "key_prefix", "unknown"))


@router.post(
    "/{connector_id}/revoke",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_connector(
    connector_id: str,
    request: Request,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)

    # Revoke semantics for MVP/security tests:
    # - delete credentials for this tenant+connector
    # - emit connectors_audit_ledger action='credential_revoke'
    #
    # If you later want soft-revocation, add status flags on credentials instead.

    creds = (
        db.execute(
            select(ConnectorCredential).where(
                ConnectorCredential.tenant_id == tenant_id,
                ConnectorCredential.connector_id == connector_id,
            )
        )
        .scalars()
        .all()
    )

    for c in creds:
        db.delete(c)

    db.add(
        ConnectorAuditLedger(
            tenant_id=tenant_id,
            connector_id=connector_id,
            action="credential_revoke",
            params_hash="",  # keep minimal; don’t leak request contents
            actor=actor,
            request_id=(idempotency_key or ""),
        )
    )
    db.commit()

    return {"ok": True}
