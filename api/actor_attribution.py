from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from prometheus_client import Counter
from sqlalchemy.orm import Session

from api.auth_scopes.resolution import require_bound_tenant, require_scopes
from api.db import get_engine
from api.db_models_actor_attribution import (
    ActorAuditEvent,
    ActorAttributionRecord,
    ActorIdentity,
    ActorIdentitySnapshot as ActorIdentitySnapshotOrm,  # noqa: F401
)

router = APIRouter(tags=["actor-attribution"])

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

ACTOR_GET_TOTAL = Counter("frostgate_actor_get_total", "GET actor requests")
ACTOR_HISTORY_GET_TOTAL = Counter(
    "frostgate_actor_history_get_total", "GET actor history requests"
)
ACTOR_ATTRIBUTION_GET_TOTAL = Counter(
    "frostgate_actor_attribution_get_total", "GET actor attribution requests"
)
REPORT_CHAIN_GET_TOTAL = Counter(
    "frostgate_report_actor_chain_get_total", "GET report actor chain requests"
)
EVIDENCE_CHAIN_GET_TOTAL = Counter(
    "frostgate_evidence_actor_chain_get_total", "GET evidence actor chain requests"
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ACTOR_UNKNOWN = "unknown"


def _actor(request: Request) -> str:
    return str(
        getattr(getattr(request, "state", None), "key_prefix", None) or _ACTOR_UNKNOWN
    )


def _attribution_record_dict(row: ActorAttributionRecord) -> dict:
    return {
        "attribution_id": row.id,
        "event_type": row.event_type,
        "event_ref": row.event_ref,
        "event_ref_type": row.event_ref_type,
        "actor_type": row.actor_type,
        "authentication_method": row.authentication_method,
        "governance_role": row.governance_role,
        "trust_level": row.trust_level,
        "actor_fingerprint": row.actor_fingerprint,
        "attribution_hash": row.attribution_hash,
        "event_hash": row.event_hash,
        "previous_hash": row.previous_hash,
        "request_id": row.request_id,
        "created_at": row.created_at,
        "schema_version": row.schema_version,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get(
    "/actor-attribution/actor/{actor_id}",
    dependencies=[Depends(require_scopes("actor:read"))],
)
def get_actor(actor_id: str, request: Request) -> dict:
    """Return the canonical actor identity record."""
    tenant_id = require_bound_tenant(request)
    ACTOR_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        row = (
            db.query(ActorIdentity)
            .filter(
                ActorIdentity.id == actor_id,
                ActorIdentity.tenant_id == tenant_id,
            )
            .first()
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "ACTOR_NOT_FOUND", "message": "actor not found"},
        )
    return {
        "actor_id": row.id,
        "actor_type": row.actor_type,
        "actor_subject": row.actor_subject,
        "actor_display_name": row.actor_display_name,
        "authentication_method": row.authentication_method,
        "identity_provider": row.identity_provider,
        "governance_role": row.governance_role,
        "trust_level": row.trust_level,
        "status": row.status,
        "is_service_account": bool(row.is_service_account),
        "is_robot": bool(row.is_robot),
        "service_account_id": row.service_account_id,
        "robot_identity": row.robot_identity,
        "delegated_by": row.delegated_by,
        "organization_id": row.organization_id,
        "tenant_id": row.tenant_id,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "last_seen_at": row.last_seen_at,
        "schema_version": row.schema_version,
    }


@router.get(
    "/actor-attribution/actor/{actor_id}/history",
    dependencies=[Depends(require_scopes("actor:read"))],
)
def get_actor_history(
    actor_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Return the audit event history for an actor identity."""
    tenant_id = require_bound_tenant(request)
    ACTOR_HISTORY_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        actor = (
            db.query(ActorIdentity)
            .filter(
                ActorIdentity.id == actor_id,
                ActorIdentity.tenant_id == tenant_id,
            )
            .first()
        )
        if actor is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "ACTOR_NOT_FOUND", "message": "actor not found"},
            )
        base_q = db.query(ActorAuditEvent).filter(
            ActorAuditEvent.actor_id == actor_id,
            ActorAuditEvent.tenant_id == tenant_id,
        )
        total = base_q.count()
        rows = (
            base_q.order_by(ActorAuditEvent.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    return {
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "events": [
            {
                "event_id": row.id,
                "event_type": row.event_type,
                "actor_type_snapshot": row.actor_type_snapshot,
                "changed_by_actor_id": row.changed_by_actor_id,
                "old_value": row.old_value,
                "new_value": row.new_value,
                "reason": row.reason,
                "created_at": row.created_at,
                "schema_version": row.schema_version,
            }
            for row in rows
        ],
    }


@router.get(
    "/actor-attribution/actor/{actor_id}/attribution",
    dependencies=[Depends(require_scopes("actor:read"))],
)
def get_actor_attribution(
    actor_id: str,
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    event_type: Optional[str] = Query(default=None),
) -> dict:
    """Return attribution records for an actor, optionally filtered by event_type."""
    tenant_id = require_bound_tenant(request)
    ACTOR_ATTRIBUTION_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        actor = (
            db.query(ActorIdentity)
            .filter(
                ActorIdentity.id == actor_id,
                ActorIdentity.tenant_id == tenant_id,
            )
            .first()
        )
        if actor is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "ACTOR_NOT_FOUND", "message": "actor not found"},
            )
        base_q = db.query(ActorAttributionRecord).filter(
            ActorAttributionRecord.actor_id == actor_id,
            ActorAttributionRecord.tenant_id == tenant_id,
        )
        if event_type is not None:
            base_q = base_q.filter(ActorAttributionRecord.event_type == event_type)
        total = base_q.count()
        rows = (
            base_q.order_by(ActorAttributionRecord.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
    return {
        "actor_id": actor_id,
        "tenant_id": tenant_id,
        "total": total,
        "offset": offset,
        "limit": limit,
        "attribution_records": [_attribution_record_dict(row) for row in rows],
    }


@router.get(
    "/actor-attribution/report/{report_id}/actor-chain",
    dependencies=[Depends(require_scopes("actor:read"))],
)
def get_report_actor_chain(report_id: str, request: Request) -> dict:
    """Return all attribution records linked to a specific report."""
    tenant_id = require_bound_tenant(request)
    REPORT_CHAIN_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        _REPORT_EVENT_TYPES = [
            "report_generation",
            "report_approval",
            "report_supersede",
            "report_delivery",
            "manifest_generation",
        ]
        rows = (
            db.query(ActorAttributionRecord)
            .filter(
                ActorAttributionRecord.event_ref == report_id,
                ActorAttributionRecord.tenant_id == tenant_id,
                ActorAttributionRecord.event_type.in_(_REPORT_EVENT_TYPES),
            )
            .order_by(ActorAttributionRecord.created_at.asc())
            .all()
        )
    return {
        "report_id": report_id,
        "tenant_id": tenant_id,
        "chain_length": len(rows),
        "chain": [_attribution_record_dict(row) for row in rows],
    }


@router.get(
    "/actor-attribution/evidence/{evidence_id}/actor-chain",
    dependencies=[Depends(require_scopes("actor:read"))],
)
def get_evidence_actor_chain(evidence_id: str, request: Request) -> dict:
    """Return all attribution records linked to a specific evidence item."""
    tenant_id = require_bound_tenant(request)
    EVIDENCE_CHAIN_GET_TOTAL.inc()
    with Session(get_engine()) as db:
        rows = (
            db.query(ActorAttributionRecord)
            .filter(
                ActorAttributionRecord.event_ref == evidence_id,
                ActorAttributionRecord.tenant_id == tenant_id,
                ActorAttributionRecord.event_ref_type.in_(
                    ["evidence", "evidence_link", "evidence_provenance"]
                ),
            )
            .order_by(ActorAttributionRecord.created_at.asc())
            .all()
        )
    return {
        "evidence_id": evidence_id,
        "tenant_id": tenant_id,
        "chain_length": len(rows),
        "chain": [_attribution_record_dict(row) for row in rows],
    }
