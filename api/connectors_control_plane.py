from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.auth_scopes import require_bound_tenant, require_scopes
from api.db_models import ConnectorAuditLedger, ConnectorCredential, ConnectorTenantState
from api.deps import tenant_db_required
from api.security_audit import get_auditor
from services.canonical import canonical_json_bytes
from services.connectors import (
    audit_connector_action,
    dispatch_ingest,
    list_connector_manifests,
    load_policy,
    load_tenant_policy,
    policy_changed_fields,
    policy_hash,
    revoke_connector_credentials,
    set_tenant_policy_version,
    upsert_credential,
)

router = APIRouter(tags=["connectors-control-plane"])


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PolicySetRequest(_StrictModel):
    version: str = Field(min_length=1)


class IngestPayload(_StrictModel):
    cursor: str | None = None
    since_ts: str | None = None
    limit: int | None = Field(default=100, ge=1, le=500)
    resource_ids: list[str] = Field(default_factory=list)


class IngestRequest(_StrictModel):
    collection_id: str = Field(min_length=1)
    payload: IngestPayload = Field(default_factory=IngestPayload)


class CredentialConnectRequest(_StrictModel):
    principal_id: str = Field(min_length=1)
    auth_mode: str = Field(min_length=1)
    credential_id: str = Field(default="primary", min_length=1)
    secret_payload: dict[str, Any] = Field(default_factory=dict)


class ConnectorStateRequest(_StrictModel):
    enabled: bool


def _safe_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _actor(request: Request) -> str:
    return str(getattr(getattr(request.state, "auth", None), "key_prefix", "unknown"))


def _prune_idempotency_records(db: Session, *, tenant_id: str, connector_id: str) -> None:
    max_rows = int((os.getenv("FG_CONNECTOR_IDEMPOTENCY_MAX_ROWS") or "2000").strip())
    ttl_hours = int((os.getenv("FG_CONNECTOR_IDEMPOTENCY_TTL_HOURS") or "168").strip())
    cutoff = datetime.now(UTC) - timedelta(hours=ttl_hours)

    stale = db.execute(
        select(ConnectorAuditLedger)
        .where(
            ConnectorAuditLedger.tenant_id == tenant_id,
            ConnectorAuditLedger.connector_id == connector_id,
            ConnectorAuditLedger.request_id != "",
            ConnectorAuditLedger.created_at < cutoff,
        )
    ).scalars().all()
    for row in stale:
        db.delete(row)

    rows = db.execute(
        select(ConnectorAuditLedger.id)
        .where(
            ConnectorAuditLedger.tenant_id == tenant_id,
            ConnectorAuditLedger.connector_id == connector_id,
            ConnectorAuditLedger.request_id != "",
        )
        .order_by(ConnectorAuditLedger.created_at.desc(), ConnectorAuditLedger.id.desc())
    ).scalars().all()
    if len(rows) > max_rows:
        for rid in rows[max_rows:]:
            doomed = db.get(ConnectorAuditLedger, rid)
            if doomed is not None:
                db.delete(doomed)
    db.flush()


def _idempotent_seen(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    idempotency_key: str | None,
) -> bool:
    if not idempotency_key:
        return False
    row = db.execute(
        select(ConnectorAuditLedger.id)
        .where(
            ConnectorAuditLedger.tenant_id == tenant_id,
            ConnectorAuditLedger.connector_id == connector_id,
            ConnectorAuditLedger.action == action,
            ConnectorAuditLedger.request_id == idempotency_key,
        )
        .limit(1)
    ).first()
    return row is not None


@router.post(
    "/admin/connectors/{connector_id}/state",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def set_connector_state(
    connector_id: str,
    request: Request,
    body: ConnectorStateRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    _prune_idempotency_records(db, tenant_id=tenant_id, connector_id=connector_id)

    if _idempotent_seen(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="state_set",
        idempotency_key=idempotency_key,
    ):
        return {"ok": True, "connector_id": connector_id, "enabled": body.enabled, "idempotent_replay": True}

    row = db.execute(
        select(ConnectorTenantState).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id == connector_id,
        )
    ).scalar_one_or_none()
    cfg_hash = _safe_hash({"enabled": body.enabled, "connector_id": connector_id})
    if row is None:
        row = ConnectorTenantState(
            tenant_id=tenant_id,
            connector_id=connector_id,
            enabled=body.enabled,
            config_hash=cfg_hash,
            updated_by=actor,
        )
        db.add(row)
    else:
        row.enabled = body.enabled
        row.config_hash = cfg_hash
        row.updated_by = actor

    audit_connector_action(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="state_set",
        params={"enabled": body.enabled},
        actor=actor,
        request_id=idempotency_key,
    )
    get_auditor().log_admin_action(
        action="connector_state_set",
        tenant_id=tenant_id,
        request=request,
        details={"connector_id": connector_id, "enabled": body.enabled},
    )
    db.commit()
    return {"ok": True, "connector_id": connector_id, "enabled": body.enabled}


@router.get(
    "/admin/connectors/policy",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def get_connectors_policy(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    version, policy = load_tenant_policy(db, tenant_id)
    return {
        "tenant_id": tenant_id,
        "version": version,
        "policy_hash": policy_hash(policy),
        "policy": policy,
    }


@router.post(
    "/admin/connectors/policy",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def set_connectors_policy(
    request: Request,
    body: PolicySetRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    _prune_idempotency_records(db, tenant_id=tenant_id, connector_id="__policy__")

    if _idempotent_seen(
        db,
        tenant_id=tenant_id,
        connector_id="__policy__",
        action="policy_set",
        idempotency_key=idempotency_key,
    ):
        return {"ok": True, "version": body.version, "idempotent_replay": True}

    try:
        old_version, old_policy = load_tenant_policy(db, tenant_id)
        old_hash = policy_hash(old_policy)
    except Exception:
        old_version, old_policy = "unknown", {}
        old_hash = "none"
    try:
        version, new_hash = set_tenant_policy_version(
            db, tenant_id, version=body.version, actor=actor
        )
        new_policy = load_policy(version)
    except Exception as exc:
        raise HTTPException(status_code=403, detail="CONNECTOR_POLICY_DENY") from exc

    changed = policy_changed_fields(old_policy, new_policy)
    audit_connector_action(
        db,
        tenant_id=tenant_id,
        connector_id="__policy__",
        action="policy_set",
        params={
            "old_hash": old_hash,
            "new_hash": new_hash,
            "changed_fields": changed,
            "governance_hook": "advisory",
            "old_version": old_version,
            "new_version": version,
        },
        actor=actor,
        request_id=idempotency_key,
    )

    get_auditor().log_admin_action(
        action="connectors_policy_set",
        tenant_id=tenant_id,
        request=request,
        details={
            "old_hash": old_hash,
            "new_hash": new_hash,
            "changed_fields": changed,
            "governance_hook": "advisory",
        },
    )
    db.commit()
    return {"ok": True, "version": version, "changed_fields": changed}


@router.post(
    "/admin/connectors/{connector_id}/connect",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def connect_connector_credentials(
    connector_id: str,
    request: Request,
    body: CredentialConnectRequest,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    _prune_idempotency_records(db, tenant_id=tenant_id, connector_id=connector_id)

    if _idempotent_seen(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="credential_connect",
        idempotency_key=idempotency_key,
    ):
        return {"ok": True, "connector_id": connector_id, "idempotent_replay": True}

    upsert_credential(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        principal_id=body.principal_id,
        auth_mode=body.auth_mode,
        secret_payload=body.secret_payload,
        credential_id=body.credential_id,
    )
    audit_connector_action(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="credential_connect",
        params={
            "principal_hash": _safe_hash({"principal_id": body.principal_id}),
            "credential_id": body.credential_id,
        },
        actor=actor,
        request_id=idempotency_key,
    )
    get_auditor().log_admin_action(
        action="connector_credential_connect",
        tenant_id=tenant_id,
        request=request,
        details={
            "connector_id": connector_id,
            "principal_hash": _safe_hash({"principal_id": body.principal_id}),
        },
    )
    db.commit()
    return {"ok": True, "connector_id": connector_id}


@router.post(
    "/admin/connectors/{connector_id}/revoke",
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
    _prune_idempotency_records(db, tenant_id=tenant_id, connector_id=connector_id)

    if _idempotent_seen(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="credential_revoke",
        idempotency_key=idempotency_key,
    ):
        return {"ok": True, "revoked_count": 0, "idempotent_replay": True}

    revoked_count = revoke_connector_credentials(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
    )
    audit_connector_action(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        action="credential_revoke",
        params={"revoked_count": revoked_count},
        actor=actor,
        request_id=idempotency_key,
    )
    get_auditor().log_admin_action(
        action="connector_credential_revoke",
        tenant_id=tenant_id,
        request=request,
        details={"connector_id": connector_id, "revoked_count": revoked_count},
    )
    db.commit()
    return {"ok": True, "revoked_count": revoked_count}


@router.get(
    "/admin/connectors/status",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def connector_status(
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    manifests = list_connector_manifests()
    states = db.execute(
        select(ConnectorTenantState).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id != "__policy__",
        )
    ).scalars().all()
    by_id = {row.connector_id: row for row in states}

    creds = db.execute(
        select(ConnectorCredential.connector_id).where(
            ConnectorCredential.tenant_id == tenant_id,
            ConnectorCredential.revoked_at.is_(None),
        )
    ).all()
    has_creds = {r[0] for r in creds}

    connectors: list[dict[str, Any]] = []
    for item in manifests:
        cid = str(item["id"])
        state = by_id.get(cid)
        connected = cid in has_creds
        enabled = bool(getattr(state, "enabled", False))
        last_error_code = getattr(state, "last_error_code", None)
        health = "ok"
        if not enabled:
            health = "blocked"
        elif last_error_code:
            health = "degraded"
        last_success_at = getattr(state, "last_success_at", None)
        last_success_s = None
        if isinstance(last_success_at, datetime):
            if last_success_at.tzinfo is None:
                last_success_at = last_success_at.replace(tzinfo=UTC)
            last_success_s = last_success_at.isoformat()

        connectors.append(
            {
                "connector_id": cid,
                "connected": connected,
                "enabled": enabled,
                "last_success_at": last_success_s,
                "last_error_code": last_error_code,
                "health": health,
            }
        )

    return {"tenant_id": tenant_id, "connectors": connectors}


@router.post(
    "/internal/connectors/{connector_id}/ingest",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def ingest_connector(
    connector_id: str,
    body: IngestRequest,
    request: Request,
    db: Session = Depends(tenant_db_required),
) -> dict[str, Any]:
    tenant_id = require_bound_tenant(request)
    actor = _actor(request)
    result = dispatch_ingest(
        db,
        tenant_id=tenant_id,
        connector_id=connector_id,
        actor=actor,
        request_id=getattr(request.state, "request_id", None),
        collection_id=body.collection_id,
        payload=body.payload.model_dump(mode="json"),
    )
    db.commit()
    return result
