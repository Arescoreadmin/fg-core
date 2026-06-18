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
from api.db_models import (
    PolicyBundle,
    TenantBundleAssignment,
    TenantEntitlement,
)
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


# P1.3: enforcement is strict (fail-closed) by default.
# Set FG_ENTITLEMENT_ENFORCEMENT=false only in local dev / migration windows.
ENFORCEMENT_STRICT = _env_bool("FG_ENTITLEMENT_ENFORCEMENT", True)

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
        # Executive Trust Command Center (P0-8)
        "trust.executive.dashboard",
        "trust.executive.drilldown",
        "trust.risk",
        "trust.reporting",
        "trust.executive.export",
        # Quarterly Trust Briefs (P0-9)
        "trust.quarterly.briefs",
        "trust.board.reporting",
        "trust.report.export",
        "trust.report.review",
        "trust.report.delivery",
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
        # Certification Lifecycle Management (P0-10)
        "certification.read",
        "certification.review",
        "certification.attest",
        "certification.approve",
        "certification.renew",
        "certification.revoke",
        "certification.admin",
        "certification.executive.view",
        "certification.drilldown",
        # Continuous Governance Control Tower (P0-11)
        "controltower.read",
        "controltower.executive",
        "controltower.risk",
        "controltower.certification",
        "controltower.evidence",
        "controltower.timeline",
        "controltower.decisions",
        "controltower.drift",
        "controltower.operations",
        "controltower.admin",
        # P1.2: Portal capabilities
        "portal.access",
        "portal.remediation",
        "portal.ai",
        "portal.rag",
        # P1.2: AI capabilities
        "ai.workspace",
        "ai.chat",
        "ai.rag",
        "ai.document_ingestion",
        "ai.agent_builder",
        "ai.multi_agent",
        "ai.private_models",
        "ai.fine_tuning",
        "ai.governance",
        "ai.compliance_assistant",
        "ai.executive_advisor",
        # P1.2: API access
        "api.access",
        # P1.2: Identity capabilities
        "identity.sso",
        "identity.scim",
        # P1.2: Report bundles
        "reports.executive",
        "reports.regulatory",
        # P1.2: Tenant capabilities
        "tenant.multi_region",
        # P1.2: MSP capabilities
        "msp.multi_tenant",
        "msp.white_label",
        "msp.cross_tenant_reporting",
        "msp.tenant_switching",
        # P1.2: Government capabilities
        "government.fedramp",
        "government.cjis",
        "government.itar",
        "government.airgap",
        "government.private_llm",
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
            # Executive Trust Command Center (P0-8)
            "trust.executive.dashboard",
            "trust.executive.drilldown",
            "trust.risk",
            "trust.reporting",
            "trust.executive.export",
            # Quarterly Trust Briefs (P0-9)
            "trust.quarterly.briefs",
            "trust.board.reporting",
            "trust.report.export",
            "trust.report.review",
            "trust.report.delivery",
            # Certification Lifecycle Management (P0-10)
            "certification.read",
            "certification.review",
            "certification.attest",
            "certification.approve",
            "certification.renew",
            "certification.revoke",
            "certification.admin",
            "certification.executive.view",
            "certification.drilldown",
            # Continuous Governance Control Tower (P0-11)
            "controltower.read",
            "controltower.executive",
            "controltower.risk",
            "controltower.certification",
            "controltower.evidence",
            "controltower.timeline",
            "controltower.decisions",
            "controltower.drift",
            "controltower.operations",
            "controltower.admin",
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
      3. Bundle/capability assignment via resolve_tenant_capabilities() (P1.2).
      4. Tier-based default from TIER_CAPABILITIES (backward compat).
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

    # --- bundle/capability assignment (P1.2) ---
    try:
        from services.capability_bundles.resolver import resolve_tenant_capabilities

        bundle_caps = resolve_tenant_capabilities(db, tenant_id)
        if capability in bundle_caps:
            return EntitlementResult(
                allowed=True,
                capability=capability,
                tenant_id=tenant_id,
                source="bundle",
                tier=_get_tenant_tier(tenant_id),
                reason="bundle_grant",
            )
    except Exception:
        log.exception(
            "entitlements.bundle_error tenant_id=%s capability=%s",
            tenant_id,
            capability,
        )
        # Non-fatal: fall through to tier default

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
    *,
    dep_failure: str | None = None,
) -> None:
    try:
        tenant_id = result.tenant_id or None
        path = getattr(request, "url", None)
        path_str = str(path) if path else None
        method = getattr(request, "method", None)

        if result.source == "registry_miss":
            event_type = EventType.CAPABILITY_UNKNOWN
        elif dep_failure is not None:
            event_type = EventType.CAPABILITY_DEPENDENCY_FAILURE
        elif result.allowed:
            event_type = EventType.CAPABILITY_GRANTED
        else:
            event_type = EventType.CAPABILITY_DENIED

        get_auditor().log_event(
            AuditEvent(
                event_type=event_type,
                success=result.allowed,
                severity=Severity.INFO if result.allowed else Severity.WARNING,
                tenant_id=tenant_id,
                request_path=path_str,
                request_method=method,
                reason="capability_check",
                details={
                    "capability": result.capability,
                    "decision": "granted" if result.allowed else "denied",
                    "source": result.source,
                    "tier": result.tier,
                    "denial_reason": result.reason if not result.allowed else None,
                    "missing_dependency": dep_failure,
                },
            )
        )
    except Exception:
        log.exception("entitlements.audit_error capability=%s", result.capability)

    # Record Prometheus metrics (non-fatal)
    try:
        from api.observability.metrics import (
            CAPABILITY_CHECKS_TOTAL,
            CAPABILITY_DENIALS_TOTAL,
            CAPABILITY_DEPENDENCY_FAILURES_TOTAL,
            CAPABILITY_GRANTS_TOTAL,
        )

        if dep_failure is not None:
            CAPABILITY_CHECKS_TOTAL.labels(
                capability=result.capability, result="dep_failure"
            ).inc()
            CAPABILITY_DENIALS_TOTAL.labels(
                capability=result.capability, reason="dep_failure"
            ).inc()
            CAPABILITY_DEPENDENCY_FAILURES_TOTAL.labels(
                capability=result.capability, missing_dep=dep_failure
            ).inc()
        elif result.source == "registry_miss":
            CAPABILITY_CHECKS_TOTAL.labels(
                capability=result.capability, result="unknown"
            ).inc()
            CAPABILITY_DENIALS_TOTAL.labels(
                capability=result.capability, reason="unknown"
            ).inc()
        elif result.allowed:
            CAPABILITY_CHECKS_TOTAL.labels(
                capability=result.capability, result="granted"
            ).inc()
            CAPABILITY_GRANTS_TOTAL.labels(
                capability=result.capability, source=result.source
            ).inc()
        else:
            reason = "no_tenant" if result.source == "no_tenant" else "missing"
            CAPABILITY_CHECKS_TOTAL.labels(
                capability=result.capability, result="denied"
            ).inc()
            CAPABILITY_DENIALS_TOTAL.labels(
                capability=result.capability, reason=reason
            ).inc()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# FastAPI dependency — require_capability()
# ---------------------------------------------------------------------------


def require_capability(capability: str):
    """FastAPI dependency that enforces a capability entitlement.

    Enforcement is fail-closed by default (P1.3). Set FG_ENTITLEMENT_ENFORCEMENT=false
    for audit-only mode during dev or migration windows.

    Also enforces the transitive dependency chain — e.g. requiring ai.rag will also
    verify ai.workspace is present.

    Usage:
        @router.get("/...", dependencies=[Depends(require_capability("ai.chat"))])
    """

    def _dep(request: Request) -> None:
        tenant_id = getattr(getattr(request, "state", None), "tenant_id", None)
        if not tenant_id:
            auth = getattr(getattr(request, "state", None), "auth", None)
            tenant_id = getattr(auth, "tenant_id", None)

        engine = get_engine()
        with Session(engine) as db:
            result = check_capability(db, tenant_id, capability)

        # --- dependency chain check ---
        dep_failure: str | None = None
        if result.allowed:
            try:
                from services.capability_enforcement.graph import (
                    get_required_capabilities,
                )

                required_deps = get_required_capabilities(capability)
                if required_deps and tenant_id:
                    with Session(engine) as db_dep:
                        for dep in required_deps:
                            dep_result = check_capability(db_dep, tenant_id, dep)
                            if not dep_result.allowed:
                                result = EntitlementResult(
                                    allowed=False,
                                    capability=capability,
                                    tenant_id=tenant_id,
                                    source="dep_failure",
                                    tier=result.tier,
                                    reason=f"missing_dependency:{dep}",
                                )
                                dep_failure = dep
                                break
            except Exception:
                log.exception(
                    "entitlements.dep_check_error tenant_id=%s capability=%s",
                    tenant_id,
                    capability,
                )
                # Fail closed on dep-check errors
                result = EntitlementResult(
                    allowed=False,
                    capability=capability,
                    tenant_id=tenant_id or "",
                    source="error",
                    tier="unknown",
                    reason="dep_check_error",
                )

        _audit_entitlement_decision(request, result, dep_failure=dep_failure)

        # Read enforcement flag at call time. Falls back to module-level constant
        # (which tests can patch directly) so both patch() and monkeypatch.setenv work.
        strict = _env_bool("FG_ENTITLEMENT_ENFORCEMENT", ENFORCEMENT_STRICT)
        if not result.allowed and strict:
            raise HTTPException(
                status_code=403,
                detail={
                    "code": "CAPABILITY_DENIED",
                    "capability": capability,
                    "reason": result.reason,
                    "missing_dependency": dep_failure,
                    "upgrade_required": result.source in ("tier", "dep_failure"),
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
# Routers — admin routes (always mounted) + UI routes (dev/self-hosted only)
# ---------------------------------------------------------------------------

router = APIRouter()
ui_router = APIRouter()


@router.get(
    "/admin/tenants/{tenant_id}/entitlements",
    dependencies=[Depends(require_scopes("admin:read"))],
    tags=["admin", "entitlements"],
)
def list_tenant_entitlements(
    tenant_id: str,
    request: Request,
) -> dict[str, Any]:
    """List all explicit capability grants for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
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
) -> dict[str, Any]:
    """Grant an explicit capability to a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
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
) -> dict[str, Any]:
    """Revoke an explicit capability grant from a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
        result = _revoke_entitlement(db, tenant_id=tenant_id, capability=capability)
    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="entitlement_revoked",
        tenant_id=tenant_id,
        request=request,
        details={"capability": capability},
    )
    return {"tenant_id": tenant_id, **result}


@ui_router.get(
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


@ui_router.get(
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


# ---------------------------------------------------------------------------
# P1.2: Bundle management admin routes
# ---------------------------------------------------------------------------


class AssignBundleRequest(BaseModel):
    bundle_key: str
    assigned_by: str = "admin"
    expires_at: datetime | None = None
    subscription_id: str | None = None


class CreateSubscriptionRequest(BaseModel):
    subscription_type: str
    status: str = "active"
    expires_at: datetime | None = None


def _list_all_bundles(db: Session) -> list[dict[str, Any]]:
    """Return all active policy bundles with their capability keys."""
    from api.db_models import Capability, PolicyBundleCapability

    bundles = db.query(PolicyBundle).filter(PolicyBundle.active.is_(True)).all()
    result = []
    for b in bundles:
        cap_ids = [
            r.capability_id
            for r in db.query(PolicyBundleCapability)
            .filter(PolicyBundleCapability.bundle_id == b.id)
            .all()
        ]
        caps = (
            db.query(Capability.capability_key).filter(Capability.id.in_(cap_ids)).all()
        )
        result.append(
            {
                "id": b.id,
                "bundle_key": b.bundle_key,
                "bundle_name": b.bundle_name,
                "bundle_version": b.bundle_version,
                "capabilities": sorted(c[0] for c in caps),
            }
        )
    return result


def _list_tenant_bundles(db: Session, tenant_id: str) -> list[dict[str, Any]]:
    """Return bundles assigned to a specific tenant."""
    assignments = (
        db.query(TenantBundleAssignment)
        .filter(TenantBundleAssignment.tenant_id == tenant_id)
        .all()
    )
    result = []
    for a in assignments:
        bundle = db.query(PolicyBundle).filter(PolicyBundle.id == a.bundle_id).first()
        result.append(
            {
                "id": a.id,
                "bundle_key": bundle.bundle_key if bundle else None,
                "bundle_name": bundle.bundle_name if bundle else None,
                "assigned_at": a.assigned_at.isoformat() if a.assigned_at else None,
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "assigned_by": a.assigned_by,
                "subscription_id": a.subscription_id,
            }
        )
    return result


@router.get(
    "/admin/bundles",
    dependencies=[Depends(require_scopes("admin:read"))],
    tags=["admin", "bundles"],
)
def list_all_bundles(request: Request) -> dict[str, Any]:
    """List all available policy bundles with their capabilities."""
    engine = get_engine()
    with Session(engine) as db:
        bundles = _list_all_bundles(db)
    return {"bundles": bundles, "count": len(bundles)}


@router.get(
    "/admin/tenants/{tenant_id}/bundles",
    dependencies=[Depends(require_scopes("admin:read"))],
    tags=["admin", "bundles"],
)
def list_tenant_bundles(tenant_id: str, request: Request) -> dict[str, Any]:
    """List all bundle assignments for a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
        assignments = _list_tenant_bundles(db, tenant_id)
    return {"tenant_id": tenant_id, "bundles": assignments, "count": len(assignments)}


@router.post(
    "/admin/tenants/{tenant_id}/bundles",
    dependencies=[Depends(require_scopes("admin:write"))],
    tags=["admin", "bundles"],
)
def assign_bundle_to_tenant(
    tenant_id: str,
    body: AssignBundleRequest,
    request: Request,
) -> dict[str, Any]:
    """Assign a policy bundle to a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
        bundle = (
            db.query(PolicyBundle)
            .filter(PolicyBundle.bundle_key == body.bundle_key)
            .first()
        )
        if bundle is None:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "UNKNOWN_BUNDLE",
                    "bundle_key": body.bundle_key,
                },
            )
        existing = (
            db.query(TenantBundleAssignment)
            .filter(
                TenantBundleAssignment.tenant_id == tenant_id,
                TenantBundleAssignment.bundle_id == bundle.id,
            )
            .first()
        )
        if existing is not None:
            existing.assigned_by = body.assigned_by
            existing.expires_at = body.expires_at
            existing.subscription_id = body.subscription_id
            db.commit()
            assignment_id = existing.id
            created = False
        else:
            assignment = TenantBundleAssignment(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                bundle_id=bundle.id,
                assigned_by=body.assigned_by,
                expires_at=body.expires_at,
                subscription_id=body.subscription_id,
            )
            db.add(assignment)
            db.commit()
            assignment_id = assignment.id
            created = True

    # Invalidate cache for this tenant
    try:
        from services.capability_bundles.resolver import invalidate_cache

        invalidate_cache(tenant_id)
    except Exception:
        pass

    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="bundle_assigned",
        tenant_id=tenant_id,
        request=request,
        details={
            "bundle_key": body.bundle_key,
            "assigned_by": body.assigned_by,
            "expires_at": body.expires_at.isoformat() if body.expires_at else None,
        },
    )
    return {
        "tenant_id": tenant_id,
        "bundle_key": body.bundle_key,
        "assignment_id": assignment_id,
        "created": created,
    }


@router.delete(
    "/admin/tenants/{tenant_id}/bundles/{bundle_key}",
    dependencies=[Depends(require_scopes("admin:write"))],
    tags=["admin", "bundles"],
)
def remove_bundle_from_tenant(
    tenant_id: str,
    bundle_key: str,
    request: Request,
) -> dict[str, Any]:
    """Remove a policy bundle assignment from a tenant."""
    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
        bundle = (
            db.query(PolicyBundle).filter(PolicyBundle.bundle_key == bundle_key).first()
        )
        if bundle is None:
            raise HTTPException(
                status_code=404,
                detail={"code": "UNKNOWN_BUNDLE", "bundle_key": bundle_key},
            )
        assignment = (
            db.query(TenantBundleAssignment)
            .filter(
                TenantBundleAssignment.tenant_id == tenant_id,
                TenantBundleAssignment.bundle_id == bundle.id,
            )
            .first()
        )
        if assignment is None:
            raise HTTPException(
                status_code=404,
                detail={
                    "code": "BUNDLE_NOT_ASSIGNED",
                    "tenant_id": tenant_id,
                    "bundle_key": bundle_key,
                },
            )
        db.delete(assignment)
        db.commit()

    # Invalidate cache
    try:
        from services.capability_bundles.resolver import invalidate_cache

        invalidate_cache(tenant_id)
    except Exception:
        pass

    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="bundle_removed",
        tenant_id=tenant_id,
        request=request,
        details={"bundle_key": bundle_key},
    )
    return {"tenant_id": tenant_id, "bundle_key": bundle_key, "removed": True}


@router.post(
    "/admin/tenants/{tenant_id}/subscriptions",
    dependencies=[Depends(require_scopes("admin:write"))],
    tags=["admin", "subscriptions"],
)
def create_tenant_subscription(
    tenant_id: str,
    body: CreateSubscriptionRequest,
    request: Request,
) -> dict[str, Any]:
    """Create a subscription record for a tenant."""
    from api.db_models import TenantSubscription

    bind_tenant_id(request, tenant_id, require_explicit_for_unscoped=True)
    engine = get_engine()
    with Session(engine) as db:
        sub = TenantSubscription(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            subscription_type=body.subscription_type,
            status=body.status,
            expires_at=body.expires_at,
        )
        db.add(sub)
        db.commit()
        sub_id = sub.id

    from api.security_audit import audit_admin_action

    audit_admin_action(
        action="subscription_changed",
        tenant_id=tenant_id,
        request=request,
        details={
            "subscription_type": body.subscription_type,
            "status": body.status,
        },
    )
    return {
        "tenant_id": tenant_id,
        "subscription_id": sub_id,
        "subscription_type": body.subscription_type,
        "status": body.status,
    }
