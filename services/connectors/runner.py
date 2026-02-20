from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.db_models import ConnectorAuditLedger, ConnectorTenantState
from services.canonical import canonical_json_bytes
from services.connectors.policy import enforce_connector_allowed


def params_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def audit_connector_action(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    action: str,
    params: dict[str, Any],
    actor: str,
    request_id: str | None,
) -> None:
    db.add(
        ConnectorAuditLedger(
            tenant_id=tenant_id,
            connector_id=connector_id,
            action=action,
            params_hash=params_hash(params),
            actor=actor,
            request_id=request_id or "",
        )
    )
    db.flush()


def _load_state(db: Session, tenant_id: str, connector_id: str) -> ConnectorTenantState | None:
    return db.execute(
        select(ConnectorTenantState).where(
            ConnectorTenantState.tenant_id == tenant_id,
            ConnectorTenantState.connector_id == connector_id,
        )
    ).scalar_one_or_none()


def _enforce_rate_budget(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    policy: dict[str, Any],
) -> None:
    limits = policy.get("rate_limits") if isinstance(policy.get("rate_limits"), dict) else {}
    tenant_budget = int(limits.get("tenant_dispatch_per_minute", 60))
    connector_budget = int(limits.get("connector_dispatch_per_minute", 30))
    cutoff = datetime.now(UTC) - timedelta(minutes=1)

    tenant_count = (
        db.execute(
            select(func.count(ConnectorAuditLedger.id)).where(
                ConnectorAuditLedger.tenant_id == tenant_id,
                ConnectorAuditLedger.action == "dispatch_attempt_allow",
                ConnectorAuditLedger.created_at >= cutoff,
            )
        ).scalar_one()
        or 0
    )
    if tenant_count >= tenant_budget:
        raise HTTPException(status_code=429, detail="CONNECTOR_RATE_BUDGET_EXCEEDED")

    connector_count = (
        db.execute(
            select(func.count(ConnectorAuditLedger.id)).where(
                ConnectorAuditLedger.tenant_id == tenant_id,
                ConnectorAuditLedger.connector_id == connector_id,
                ConnectorAuditLedger.action == "dispatch_attempt_allow",
                ConnectorAuditLedger.created_at >= cutoff,
            )
        ).scalar_one()
        or 0
    )
    if connector_count >= connector_budget:
        raise HTTPException(status_code=429, detail="CONNECTOR_RATE_BUDGET_EXCEEDED")


def _enforce_cooldown(db: Session, *, tenant_id: str, connector_id: str, policy: dict[str, Any]) -> None:
    limits = policy.get("rate_limits") if isinstance(policy.get("rate_limits"), dict) else {}
    max_failures = int(limits.get("failure_cooldown_threshold", 3))
    cooldown_seconds = int(limits.get("failure_cooldown_seconds", 120))
    state = _load_state(db, tenant_id, connector_id)
    if state is None:
        return
    if int(state.failure_count or 0) < max_failures:
        return
    updated_at = state.updated_at
    if not updated_at:
        return
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    until = updated_at + timedelta(seconds=cooldown_seconds)
    if datetime.now(UTC) < until:
        raise HTTPException(status_code=429, detail="CONNECTOR_COOLDOWN_ACTIVE")


def dispatch_ingest(
    db: Session,
    *,
    tenant_id: str,
    connector_id: str,
    actor: str,
    request_id: str | None,
    collection_id: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    try:
        policy = enforce_connector_allowed(db, tenant_id, connector_id)
        _enforce_rate_budget(db, tenant_id=tenant_id, connector_id=connector_id, policy=policy)
        _enforce_cooldown(db, tenant_id=tenant_id, connector_id=connector_id, policy=policy)
        allowed_collections = set(policy.get("allowed_collections") or [])
        if collection_id not in allowed_collections:
            raise HTTPException(status_code=403, detail="CONNECTOR_COLLECTION_DENY")

        allowed_resources = set((policy.get("allowed_resources") or {}).get(connector_id, []))
        requested_resources = set(payload.get("resource_ids") or [])
        if requested_resources and not requested_resources.issubset(allowed_resources):
            raise HTTPException(status_code=403, detail="CONNECTOR_RESOURCE_DENY")

        audit_connector_action(
            db,
            tenant_id=tenant_id,
            connector_id=connector_id,
            action="dispatch_attempt_allow",
            params={"collection_id": collection_id, "payload": payload},
            actor=actor,
            request_id=request_id,
        )

        state = _load_state(db, tenant_id, connector_id)
        if state is not None:
            state.last_success_at = datetime.now(UTC)
            state.last_error_code = None
            state.failure_count = 0

        return {
            "status": "accepted",
            "connector_id": connector_id,
            "collection_id": collection_id,
            "mode": "read-only-v1",
            "hooks": {
                "polling": "stub",
                "subscription": "stub",
            },
        }
    except HTTPException as exc:
        audit_connector_action(
            db,
            tenant_id=tenant_id,
            connector_id=connector_id,
            action="dispatch_attempt_deny",
            params={"error_code": str(exc.detail), "collection_id": collection_id},
            actor=actor,
            request_id=request_id,
        )
        state = _load_state(db, tenant_id, connector_id)
        if state is not None:
            state.last_error_code = str(exc.detail)
            state.failure_count = int(state.failure_count or 0) + 1
        raise
