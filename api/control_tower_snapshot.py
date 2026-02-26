from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.auth_scopes.mapping import list_api_keys
from api.db_models import AgentDeviceRegistry, AuditLedgerRecord, ConnectorTenantState, DecisionRecord
from api.deps import tenant_db_required
from api.evidence_chain import verify_chain_for_tenant
from services.locker_command_bus import LockerCommandBus

router = APIRouter(prefix="/control-tower", tags=["control-tower"])


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()
    return str(value)


def _canonical_payload(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@router.get("/snapshot", dependencies=[Depends(require_scopes("admin:read"))])
def control_tower_snapshot_v1(request: Request, db: Session = Depends(tenant_db_required)) -> Response:
    tenant_id = str(getattr(request.state, "tenant_id", "unknown"))
    request_id = request.headers.get("x-request-id") or ""
    requested_tenant = request.query_params.get("tenant_id")

    decision = (
        db.query(DecisionRecord)
        .filter(DecisionRecord.tenant_id == tenant_id)
        .order_by(DecisionRecord.id.desc())
        .first()
    )

    chain_result = verify_chain_for_tenant(db, tenant_id=tenant_id, limit=25)
    keys = list_api_keys(tenant_id=tenant_id, include_disabled=True)
    active_keys = [k for k in keys if bool(k.get("enabled", False))]

    connector_rows = (
        db.query(ConnectorTenantState)
        .filter(ConnectorTenantState.tenant_id == tenant_id)
        .order_by(ConnectorTenantState.connector_id.asc())
        .all()
    )

    agent_total = db.query(func.count(AgentDeviceRegistry.id)).filter(AgentDeviceRegistry.tenant_id == tenant_id).scalar() or 0
    agent_quarantine = (
        db.query(func.count(AgentDeviceRegistry.id))
        .filter(AgentDeviceRegistry.tenant_id == tenant_id, AgentDeviceRegistry.status == "quarantined")
        .scalar()
        or 0
    )

    recent_audit = (
        db.query(AuditLedgerRecord)
        .filter(AuditLedgerRecord.tenant_id == tenant_id)
        .order_by(AuditLedgerRecord.id.desc())
        .limit(10)
        .all()
    )

    lockers = LockerCommandBus().list_lockers(tenant_id=tenant_id)

    payload: dict[str, Any] = {
        "version": "ControlTowerSnapshotV1",
        "tenant": {
            "tenant_id": tenant_id,
            "clamp": {
                "requested_tenant_id": requested_tenant,
                "effective_tenant_id": tenant_id,
                "clamped": bool(requested_tenant and requested_tenant != tenant_id),
            },
        },
        "planes": {
            "agent": "ok" if agent_quarantine == 0 else "degraded",
            "ai": "unknown",
            "connector": "ok" if all(bool(c.enabled) for c in connector_rows) else "degraded",
            "control": "ok",
            "data": "ok",
            "evidence": "ok" if chain_result.get("ok", False) else "degraded",
            "security": "ok",
            "ui": "ok",
        },
        "last_replay": {
            "event_id": getattr(decision, "event_id", None),
            "timestamp": _iso(getattr(decision, "created_at", None)),
            "result": "pass" if chain_result.get("ok", False) else "fail",
            "request_id": request_id or None,
        },
        "chain_integrity": {
            "status": "pass" if chain_result.get("ok", False) else "fail",
            "first_bad": chain_result.get("first_bad") if isinstance(chain_result, dict) else None,
            "chain_head_hash": chain_result.get("head_hash") if isinstance(chain_result, dict) else None,
        },
        "key_lifecycle": {
            "active_key_count": len(active_keys),
            "last_rotation": max((_iso(k.get("created_at")) for k in active_keys if k.get("created_at")), default=None),
            "grace_window_seconds": None,
            "recent_actions": [{"prefix": k.get("prefix"), "enabled": bool(k.get("enabled", False))} for k in sorted(keys, key=lambda x: str(x.get("prefix", "")))[:10]],
        },
        "connectors": {
            "enabled": sum(1 for c in connector_rows if bool(c.enabled)),
            "last_sync": max((_iso(c.last_success_at) for c in connector_rows if c.last_success_at), default=None),
            "errors": [
                {"connector_id": c.connector_id, "error": c.last_error_code}
                for c in connector_rows
                if c.last_error_code
            ],
        },
        "agents": {
            "total": agent_total,
            "quarantine_count": agent_quarantine,
            "update_channel_status": "managed",
        },
        "lockers": {
            "status": "running" if lockers else "stopped",
            "last_restart": None,
            "count": len(lockers),
        },
        "audit_incidents": {
            "recent_events": [
                {
                    "session_id": a.session_id,
                    "timestamp": a.timestamp_utc,
                    "decision": a.decision,
                    "invariant_id": a.invariant_id,
                }
                for a in recent_audit
            ],
            "facets": {
                "decision": sorted({a.decision for a in recent_audit}),
                "invariant_id": sorted({a.invariant_id for a in recent_audit}),
            },
        },
        "links": {
            "audit": "/audit/sessions",
            "chain_verify": "/forensics/chain/verify",
            "connectors": "/admin/connectors/status",
            "keys": "/keys",
            "lockers": "/control-plane/lockers",
        },
    }

    body = _canonical_payload(payload)
    return Response(content=body, media_type="application/json", headers={"Cache-Control": "no-store", "x-request-id": request_id or "snapshot-local"})
