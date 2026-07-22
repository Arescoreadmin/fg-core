from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

import api.credential_authority as ca
from api.auth_scopes import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models import ConnectorAuditLedger, ConnectorCredential
from api.deps import tenant_db_required

log = logging.getLogger("frostgate.connectors_admin")
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

    engine = get_engine()

    # Find canonical credentials for this connector in tenant_credentials.
    # Revoke canonical records first (fail-safe: any exception is swallowed so
    # the soft-revocation of connectors_credentials still proceeds).
    # Exception is swallowed for pre-migration databases where tenant_credentials
    # may not yet exist (migration 0162 has not run).
    try:
        with engine.begin() as conn:
            canonical_rows = conn.execute(
                text(
                    "SELECT credential_id FROM tenant_credentials "
                    "WHERE tenant_id = :tid AND credential_type = ‘connector’ "
                    "  AND credential_slot LIKE :slot_suffix "
                    "  AND status NOT IN (‘revoked’, ‘rotated’, ‘expired’)"
                ),
                {"tid": tenant_id, "slot_suffix": f"%:{connector_id}"},
            ).fetchall()

        for row in canonical_rows:
            try:
                ca.revoke_credential(
                    engine,
                    credential_id=row[0],
                    tenant_id=tenant_id,
                    actor_id=actor,
                    reason="admin_connector_revoke",
                    request_id=idempotency_key,
                )
            except Exception:
                log.warning(
                    "canonical_revoke_failed cred=%s tenant=%s connector=%s",
                    row[0],
                    tenant_id,
                    connector_id,
                    exc_info=True,
                )
    except Exception:
        # tenant_credentials table may not exist yet (migration 0162 pending).
        log.warning(
            "canonical_revoke_skipped tenant=%s connector=%s reason=table_unavailable",
            tenant_id,
            connector_id,
            exc_info=True,
        )

    # Soft-revoke connectors_credentials rows (replaces hard DELETE).
    creds = (
        db.execute(
            select(ConnectorCredential).where(
                ConnectorCredential.tenant_id == tenant_id,
                ConnectorCredential.connector_id == connector_id,
                ConnectorCredential.revoked_at.is_(None),
            )
        )
        .scalars()
        .all()
    )

    now = datetime.now(UTC)
    for c in creds:
        c.revoked_at = now

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
