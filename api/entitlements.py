"""api/entitlements.py — Commercial Capability Authority (P0-5).

FrostGate enforces entitlements. External systems grant them.

Design principles:
  - Capabilities are the atomic unit of access control.
  - Products are packaging; they map to capabilities, not vice versa.
  - Explicit DB grants take precedence over tier defaults.
  - Tier defaults provide backward-compatible fallback for unprovisioned tenants.
  - Every entitlement decision generates an audit event.
  - Fail-closed: unknown capabilities are always denied.
  - FG_ENTITLEMENT_ENFORCEMENT controls whether denials are enforced (default: audit-only).

Capability namespace:
  report.*         — assessment report artifacts
  verification.*   — evidence bundles and signed artifacts
  trust.*          — trust intelligence, memory, certification, replay
  continuous.*     — continuous monitoring (posture, governance, drift)
  governance.*     — governance timeline and workflow surfaces
  agent.*          — agent governance
  workflow.*       — workflow governance
  autonomous_systems.* — autonomous systems governance
  agi.*            — AGI governance (future)
  audit.*          — audit exports and forensics
"""

from __future__ import annotations

import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from api.auth_scopes import bind_tenant_id, require_bound_tenant, require_scopes
from api.db import get_engine, set_tenant_context
from api.db_models import TenantEntitlement
from api.deps import get_db
from api.security_audit import AuditEvent, EventType, Severity, get_auditor

log = logging.getLogger("frostgate.entitlements")

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


# When True, require_capability() raises 403 on denial.
# When False (default), it audits and logs but allows through — permissive
# deployment mode until entitlements are provisioned in production.
ENFORCEMENT_STRICT = _env_bool("FG_ENTITLEMENT_ENFORCEMENT", False)

# ---------------------------------------------------------------------------
# Capability registry — explicit enumeration, no wildcards
# ---------------------------------------------------------------------------

CAPABILITY_REGISTRY: frozenset[str] = frozenset(
    {
        # Assessment report artifacts
        "report.view",
        "report.export",  # PDF / HTML bytes
        "report.manifest",  # manifest + SHA-256 hash
        "report.replay",  # replay-verify contract
        # Signed evidence bundles
        "verification.view",
        "verification.download",
        # Trust intelligence and memory
        "trust.replay",
        "trust.timeline",
        "trust.intelligence",
        "trust.memory",
        "trust.certification",
        "trust.proof_package",
        "trust.chain_of_custody",
        "trust.decision_reconstruction",
        # Continuous monitoring
        "continuous.monitoring",
        "continuous.governance_monitoring",
        "continuous.trust_drift",
        "continuous.inventory_drift",
        "continuous.agent_drift",
        # Governance surfaces
        "governance.timeline",
        "governance.workflow",
        # Agent and autonomous governance
        "agent.governance",
        "workflow.governance",
        "autonomous_systems.governance",
        "agi.governance",
        # Audit and forensics exports
        "audit.view",
        "audit.export",
        "audit.forensics",
    }
)

# ---------------------------------------------------------------------------
# Tier-capability mapping (backward-compatible default)
# ---------------------------------------------------------------------------


# Imported lazily to avoid circular import; SubscriptionTier is string-based.
def _tier_capabilities() -> dict[str, frozenset[str]]:
    from api.tenant_usage import SubscriptionTier

    _base = frozenset(
        {
            "report.view",
            "report.export",
            "report.manifest",
            "report.replay",
            "verification.view",
            "verification.download",
            "trust.replay",
            "trust.timeline",
            "audit.view",
            "audit.export",
            "governance.timeline",
            "governance.workflow",
        }
    )
    _enterprise_extras = frozenset(
        {
            "trust.intelligence",
            "trust.memory",
            "trust.certification",
            "trust.proof_package",
            "trust.chain_of_custody",
            "trust.decision_reconstruction",
            "continuous.monitoring",
            "continuous.governance_monitoring",
            "continuous.trust_drift",
            "continuous.inventory_drift",
            "audit.forensics",
            "agent.governance",
            "workflow.governance",
        }
    )
    return {
        SubscriptionTier.FREE.value: frozenset({"report.view", "audit.view"}),
        SubscriptionTier.STARTER.value: frozenset(
            {"report.view", "report.export", "audit.view"}
        ),
        SubscriptionTier.PRO.value: _base,
        SubscriptionTier.ENTERPRISE.value: _base | _enterprise_extras,
        SubscriptionTier.INTERNAL.value: CAPABILITY_REGISTRY,
    }


def _get_tenant_tier(tenant_id: str) -> str:
    try:
        from api.tenant_usage import SubscriptionTier, get_usage_tracker

        tracker = get_usage_tracker()
        return tracker._tenant_tiers.get(tenant_id, SubscriptionTier.FREE).value
    except Exception:
        log.warning("entitlements.tier_lookup_error tenant_id=%s", tenant_id)
        return "free"


# ---------------------------------------------------------------------------
# Entitlement result
# ---------------------------------------------------------------------------


@dataclass
class EntitlementResult:
    allowed: bool
    capability: str
    tenant_id: str
    source: str  # "explicit" | "tier" | "tier_default" | "registry_miss" | "no_tenant" | "error"
    tier: str
    reason: str  # human-readable; included in audit details and 403 body


# ---------------------------------------------------------------------------
# Core capability check (pure function — no HTTP coupling)
# ---------------------------------------------------------------------------


def check_capability(
    db: Session,
    tenant_id: str | None,
    capability: str,
) -> EntitlementResult:
    """Return an EntitlementResult for (tenant, capability).

    Resolution order:
      1. Capability must exist in CAPABILITY_REGISTRY — else deny.
      2. Explicit grant in tenant_entitlements DB table (honours expiry).
      3. Tier-based default from TIER_CAPABILITIES.
    """
    if capability not in CAPABILITY_REGISTRY:
        return EntitlementResult(
            allowed=False,
            capability=capability,
            tenant_id=tenant_id or "",
            source="registry_miss",
            tier="unknown",
            reason=f"unknown_capability:{capability}",
        )

    if not tenant_id:
        return EntitlementResult(
            allowed=False,
            capability=capability,
            tenant_id="",
            source="no_tenant",
            tier="unknown",
            reason="no_tenant_context",
        )

    # --- explicit DB grant ---
    try:
        set_tenant_context(db, tenant_id)
        now = datetime.now(timezone.utc)
        record = (
            db.query(TenantEntitlement)
            .filter(
                TenantEntitlement.tenant_id == tenant_id,
                TenantEntitlement.capability == capability,
                or_(
                    TenantEntitlement.expires_at.is_(None),
                    TenantEntitlement.expires_at > now,
                ),
            )
            .first()
        )
        if record is not None:
            return EntitlementResult(
                allowed=True,
                capability=capability,
                tenant_id=tenant_id,
                source="explicit",
                tier=_get_tenant_tier(tenant_id),
                reason="explicit_grant",
            )
    except Exception:
        log.exception(
            "entitlements.db_error tenant_id=%s capability=%s", tenant_id, capability
        )
        return EntitlementResult(
            allowed=False,
            capability=capability,
            tenant_id=tenant_id,
            source="error",
            tier="unknown",
            reason="entitlement_db_error",
        )

    # --- tier fallback ---
    tier = _get_tenant_tier(tenant_id)
    tier_caps = _tier_capabilities().get(tier, frozenset())
    allowed = capability in tier_caps
    return EntitlementResult(
        allowed=allowed,
        capability=capability,
        tenant_id=tenant_id,
        source="tier",
        tier=tier,
        reason=f"tier_{tier}_{'granted' if allowed else 'denied'}",
    )


# ---------------------------------------------------------------------------
# Audit helper
# ---------------------------------------------------------------------------


def _audit_entitlement_decision(
    request: Request | None,
    result: EntitlementResult,
) -> None:
    try:
        tenant_id = result.tenant_id or None
        path = getattr(request, "url", None)
        path_str = str(path) if path else None
        method = getattr(request, "method", None)

        get_auditor().log_event(
            AuditEvent(
                event_type=EventType.ADMIN_ACTION,
                success=result.allowed,
                severity=Severity.INFO if result.allowed else Severity.WARNING,
                tenant_id=tenant_id,
                request_path=path_str,
                request_method=method,
                reason="entitlement_check",
                details={
                    "action": "entitlement_check",
                    "capability": result.capability,
                    "decision": "granted" if result.allowed else "denied",
                    "source": result.source,
                    "tier": result.tier,
                    "denial_reason": result.reason if not result.allowed else None,
                },
            )
        )
    except Exception:
        log.exception("entitlements.audit_error capability=%s", result.capability)


# ---------------------------------------------------------------------------
# FastAPI dependency — require_capability()
# ---------------------------------------------------------------------------


def require_capability(capability: str):
    """FastAPI dependency that enforces a capability entitlement.

    When FG_ENTITLEMENT_ENFORCEMENT=true: raises HTTP 403 if denied.
    When FG_ENTITLEMENT_ENFORCEMENT=false (default): audits and logs only.

    Usage:
        @router.get("/...", dependencies=[Depends(require_capability("report.export"))])
    """

    def _dep(
        request: Request,
        db: Session = Depends(get_db),
    ) -> None:
        tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
        if not tenant_id:
            auth = getattr(getattr(request, "state", None), "auth", None)
            tenant_id = getattr(auth, "tenant_id", None)

        result = check_capability(db, tenant_id, capability)
        _audit_entitlement_decision(request, result)

        if not result.allowed and ENFORCEMENT_STRICT:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "CAPABILITY_DENIED",
                    "capability": capability,
                    "reason": result.reason,
                    "upgrade_required": result.source == "tier",
                },
            )

        if not result.allowed:
            log.warning(
                "entitlements.denied_audit_only tenant_id=%s capability=%s reason=%s",
                tenant_id,
                capability,
                result.reason,
            )

    return _dep


# ---------------------------------------------------------------------------
# Admin CRUD operations (called by admin routes)
# ---------------------------------------------------------------------------


def _list_entitlements_for_tenant(
    db: Session, tenant_id: str, *, active_only: bool = False
) -> list[dict[str, Any]]:
    set_tenant_context(db, tenant_id)
    q = db.query(TenantEntitlement).filter(TenantEntitlement.tenant_id == tenant_id)
    if active_only:
        now = datetime.now(timezone.utc)
        q = q.filter(
            or_(
                TenantEntitlement.expires_at.is_(None),
                TenantEntitlement.expires_at > now,
            )
        )
    records = q.order_by(TenantEntitlement.capability).all()
    return [
        {
            "id": r.id,
            "capability": r.capability,
            "granted_by": r.granted_by,
            "granted_at": r.granted_at.isoformat() if r.granted_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "reason": r.reason,
        }
        for r in records
    ]


def _grant_entitlement(
    db: Session,
    tenant_id: str,
    capability: str,
    granted_by: str,
    reason: str | None,
    expires_at: datetime | None,
) -> dict[str, Any]:
    if capability not in CAPABILITY_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "UNKNOWN_CAPABILITY",
                "capability": capability,
                "valid_capabilities": sorted(CAPABILITY_REGISTRY),
            },
        )
    set_tenant_context(db, tenant_id)
    existing = (
        db.query(TenantEntitlement)
        .filter(
            TenantEntitlement.tenant_id == tenant_id,
            TenantEntitlement.capability == capability,
        )
        .first()
    )
    if existing is not None:
        existing.granted_by = granted_by
        existing.granted_at = datetime.now(timezone.utc)
        existing.expires_at = expires_at
        existing.reason = reason
        db.commit()
        return {"updated": True, "id": existing.id, "capability": capability}

    record = TenantEntitlement(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        capability=capability,
        granted_by=granted_by,
        granted_at=datetime.now(timezone.utc),
        expires_at=expires_at,
        reason=reason,
    )
    db.add(record)
    db.commit()
    return {"created": True, "id": record.id, "capability": capability}


def _revoke_entitlement(db: Session, tenant_id: str, capability: str) -> dict[str, Any]:
    set_tenant_context(db, tenant_id)
    record = (
        db.query(TenantEntitlement)
        .filter(
            TenantEntitlement.tenant_id == tenant_id,
            TenantEntitlement.capability == capability,
        )
        .first()
    )
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ENTITLEMENT_NOT_FOUND",
                "tenant_id": tenant_id,
                "capability": capability,
            },
        )
    db.delete(record)
    db.commit()
    return {"revoked": True, "capability": capability}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class GrantEntitlementRequest(BaseModel):
    capability: str
    granted_by: str = "admin"
    reason: str | None = None
    expires_at: datetime | None = None


# ---------------------------------------------------------------------------
# Router — admin routes + tenant self-service
# ---------------------------------------------------------------------------

router = APIRouter()


@router.get(
    "/admin/tenants/{tenant_id}/entitlements",
    dependencies=[Depends(require_scopes("admin:read"))],
    tags=["admin", "entitlements"],
)
def list_tenant_entitlements(
    tenant_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """List all explicit capability grants for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    all_records = _list_entitlements_for_tenant(db, tenant_id)
    active_records = _list_entitlements_for_tenant(db, tenant_id, active_only=True)
    tier = _get_tenant_tier(tenant_id)
    tier_caps = sorted(_tier_capabilities().get(tier, frozenset()))
    return {
        "tenant_id": tenant_id,
        "tier": tier,
        "tier_capabilities": tier_caps,
        "explicit_grants": all_records,
        "effective_capabilities": sorted(
            {r["capability"] for r in active_records} | set(tier_caps)
        ),
        "enforcement_strict": ENFORCEMENT_STRICT,
    }


@router.post(
    "/admin/tenants/{tenant_id}/entitlements",
    dependencies=[Depends(require_scopes("admin:write"))],
    tags=["admin", "entitlements"],
)
def grant_tenant_entitlement(
    tenant_id: str,
    body: GrantEntitlementRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Grant an explicit capability to a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    result = _grant_entitlement(
        db,
        tenant_id=tenant_id,
        capability=body.capability,
        granted_by=body.granted_by,
        reason=body.reason,
        expires_at=body.expires_at,
    )
    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="entitlement_granted",
        tenant_id=tenant_id,
        request=request,
        details={
            "capability": body.capability,
            "granted_by": body.granted_by,
            "reason": body.reason,
            "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        },
    )
    return {"tenant_id": tenant_id, **result}


@router.delete(
    "/admin/tenants/{tenant_id}/entitlements/{capability}",
    dependencies=[Depends(require_scopes("admin:write"))],
    tags=["admin", "entitlements"],
)
def revoke_tenant_entitlement(
    tenant_id: str,
    capability: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Revoke an explicit capability grant from a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    result = _revoke_entitlement(db, tenant_id=tenant_id, capability=capability)
    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="entitlement_revoked",
        tenant_id=tenant_id,
        request=request,
        details={"capability": capability},
    )
    return {"tenant_id": tenant_id, **result}


@router.get(
    "/ui/entitlements",
    dependencies=[Depends(require_scopes("ui:read")), Depends(require_bound_tenant)],
    tags=["ui", "entitlements"],
)
def get_own_entitlements(
    request: Request,
) -> dict[str, Any]:
    """Return the calling tenant's effective capability set.

    Used by the portal to display enabled / disabled features and upgrade prompts.
    """
    tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Missing tenant context")

    engine = get_engine()
    with Session(engine) as db:
        active_records = _list_entitlements_for_tenant(db, tenant_id, active_only=True)

    tier = _get_tenant_tier(tenant_id)
    tier_caps = sorted(_tier_capabilities().get(tier, frozenset()))
    explicit_caps = {r["capability"] for r in active_records}
    effective = sorted(explicit_caps | set(tier_caps))

    all_caps = sorted(CAPABILITY_REGISTRY)
    return {
        "tenant_id": tenant_id,
        "tier": tier,
        "enforcement_strict": ENFORCEMENT_STRICT,
        "capabilities": {
            "enabled": effective,
            "disabled": [c for c in all_caps if c not in effective],
            "explicit_grants": sorted(explicit_caps),
            "tier_grants": tier_caps,
        },
    }


@router.get(
    "/ui/entitlements/registry",
    tags=["ui", "entitlements"],
)
def get_capability_registry() -> dict[str, Any]:
    """Return the full capability registry. Public — no auth required.

    Allows portal to show upgrade states without a live API call per capability.
    """
    return {
        "capabilities": sorted(CAPABILITY_REGISTRY),
        "namespaces": sorted({c.split(".")[0] for c in CAPABILITY_REGISTRY}),
    }
