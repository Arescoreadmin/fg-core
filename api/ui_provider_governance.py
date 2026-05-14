from __future__ import annotations

from datetime import timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_scopes
from api.db import get_engine
from api.db_models import ProviderBaaRecord, ProviderGovernanceRecord

router = APIRouter(
    tags=["ui-provider-governance"], dependencies=[Depends(require_scopes("ui:read"))]
)

_KNOWN_STATES = frozenset(
    {"healthy", "degraded", "unavailable", "blocked", "restricted", "maintenance"}
)
_KNOWN_GOVERNANCE_STATES = frozenset(
    {"approved", "restricted", "blocked", "pending_review"}
)
_KNOWN_TRUST = frozenset({"trusted", "regulated", "untrusted", "unknown"})


def _safe_governance_record(row: ProviderGovernanceRecord) -> dict[str, Any]:
    blocked_at = row.blocked_at
    if blocked_at is not None and blocked_at.tzinfo is None:
        blocked_at = blocked_at.replace(tzinfo=timezone.utc)
    created_at = row.created_at
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    updated_at = row.updated_at
    if updated_at is not None and updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    return {
        "provider_id": row.provider_id,
        "operational_state": row.operational_state,
        "governance_state": row.governance_state,
        "trust_classification": row.trust_classification,
        "routing_eligible": row.routing_eligible,
        "failover_eligible": row.failover_eligible,
        "restrictions": row.restrictions_json or [],
        "blocked_at": blocked_at.isoformat() if blocked_at else None,
        "block_reason": row.block_reason,
        "policy_version": row.policy_version,
        "created_at": created_at.isoformat() if created_at else None,
        "updated_at": updated_at.isoformat() if updated_at else None,
    }


def _safe_baa_record(row: ProviderBaaRecord) -> dict[str, Any]:
    expiry_date = row.expiry_date
    signed_at = row.signed_at
    if signed_at is not None and signed_at.tzinfo is None:
        signed_at = signed_at.replace(tzinfo=timezone.utc)
    created_at = row.created_at
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return {
        "provider_id": row.provider_id,
        "baa_status": row.baa_status,
        "expiry_date": expiry_date.isoformat() if expiry_date else None,
        "signed_at": signed_at.isoformat() if signed_at else None,
        "created_at": created_at.isoformat() if created_at else None,
    }


@router.get("/ui/provider/governance")
def ui_provider_governance_list(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    operational_state: Optional[str] = Query(default=None, max_length=32),
    governance_state: Optional[str] = Query(default=None, max_length=32),
) -> dict[str, Any]:
    """List provider governance records for the authenticated tenant.

    Returns deterministic governance state — no fabricated telemetry.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        q = session.query(ProviderGovernanceRecord).filter(
            ProviderGovernanceRecord.tenant_id == tenant_id
        )
        if operational_state:
            q = q.filter(
                ProviderGovernanceRecord.operational_state == operational_state
            )
        if governance_state:
            q = q.filter(ProviderGovernanceRecord.governance_state == governance_state)
        total = q.count()
        rows = (
            q.order_by(
                desc(ProviderGovernanceRecord.updated_at),
                desc(ProviderGovernanceRecord.id),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

    return {
        "providers": [_safe_governance_record(r) for r in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
        "note": "Governance state reflects backend truth only. No fabricated telemetry.",
    }


@router.get("/ui/provider/governance/{provider_id}")
def ui_provider_governance_detail(
    request: Request,
    provider_id: str,
) -> dict[str, Any]:
    """Return full governance detail for a single provider.

    Combines governance record with BAA state. Never exposes API keys or
    raw provider credentials.
    """
    if not provider_id or len(provider_id) > 64:
        raise HTTPException(
            status_code=422,
            detail="provider_id must be non-empty and at most 64 characters",
        )
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        gov_row = (
            session.query(ProviderGovernanceRecord)
            .filter(
                ProviderGovernanceRecord.tenant_id == tenant_id,
                ProviderGovernanceRecord.provider_id == provider_id,
            )
            .first()
        )
        baa_row = (
            session.query(ProviderBaaRecord)
            .filter(
                ProviderBaaRecord.tenant_id == tenant_id,
                ProviderBaaRecord.provider_id == provider_id,
            )
            .first()
        )

    governance = _safe_governance_record(gov_row) if gov_row else None
    baa = _safe_baa_record(baa_row) if baa_row else None

    return {
        "provider_id": provider_id,
        "governance": governance,
        "baa": baa,
        "governance_available": governance is not None,
        "baa_available": baa is not None,
    }


@router.get("/ui/provider/routing")
def ui_provider_routing(
    request: Request,
) -> dict[str, Any]:
    """Return tenant routing policy visibility.

    Exposes allowed/blocked/failover provider chains derived from governance
    records and BAA state. Tenant-scoped. No raw provider config or secrets.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        gov_rows = (
            session.query(ProviderGovernanceRecord)
            .filter(ProviderGovernanceRecord.tenant_id == tenant_id)
            .order_by(ProviderGovernanceRecord.provider_id)
            .all()
        )
        baa_rows = (
            session.query(ProviderBaaRecord)
            .filter(ProviderBaaRecord.tenant_id == tenant_id)
            .all()
        )

    baa_by_provider = {r.provider_id: r for r in baa_rows}

    allowed: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    failover: list[dict[str, Any]] = []
    restricted: list[dict[str, Any]] = []

    for row in gov_rows:
        baa = baa_by_provider.get(row.provider_id)
        entry: dict[str, Any] = {
            "provider_id": row.provider_id,
            "operational_state": row.operational_state,
            "governance_state": row.governance_state,
            "routing_eligible": row.routing_eligible,
            "failover_eligible": row.failover_eligible,
            "baa_status": baa.baa_status if baa else "missing",
            "trust_classification": row.trust_classification,
            "restrictions": row.restrictions_json or [],
        }
        if row.governance_state == "blocked" or not row.routing_eligible:
            blocked.append(entry)
        elif row.governance_state == "restricted":
            restricted.append(entry)
        elif row.failover_eligible:
            failover.append(entry)
        else:
            allowed.append(entry)

    return {
        "tenant_id": tenant_id,
        "allowed_providers": allowed,
        "blocked_providers": blocked,
        "restricted_providers": restricted,
        "failover_providers": failover,
        "routing_policy_note": "Routing eligibility is derived from governance and BAA state. No raw provider configuration is exposed.",
    }


@router.get("/ui/provider/failover")
def ui_provider_failover(
    request: Request,
) -> dict[str, Any]:
    """Return failover chain visibility for the tenant.

    Shows degraded/unavailable providers and their failover-eligible
    alternates. State is derived from governance records only — no fabricated
    uptime or availability metrics.
    """
    tenant_id = bind_tenant_id(request, None, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as session:
        rows = (
            session.query(ProviderGovernanceRecord)
            .filter(ProviderGovernanceRecord.tenant_id == tenant_id)
            .order_by(ProviderGovernanceRecord.provider_id)
            .all()
        )

    degraded = [
        {
            "provider_id": r.provider_id,
            "operational_state": r.operational_state,
            "governance_state": r.governance_state,
            "routing_eligible": r.routing_eligible,
            "failover_eligible": r.failover_eligible,
        }
        for r in rows
        if r.operational_state in ("degraded", "unavailable", "maintenance")
    ]
    failover_ready = [
        {
            "provider_id": r.provider_id,
            "operational_state": r.operational_state,
            "governance_state": r.governance_state,
            "routing_eligible": r.routing_eligible,
        }
        for r in rows
        if r.failover_eligible
        and r.operational_state not in ("blocked", "unavailable")
        and r.governance_state not in ("blocked",)
    ]

    return {
        "degraded_providers": degraded,
        "failover_ready_providers": failover_ready,
        "failover_note": "Failover state is derived from governance records. No fabricated uptime or availability percentages.",
        "telemetry_available": False,
    }
