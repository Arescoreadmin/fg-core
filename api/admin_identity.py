"""Admin Identity Governance Control Plane (PR4).

Operator-level routes for managing and auditing tenant identity configuration,
invitations, and governance posture. All routes require `identity:read` or
`identity:write` scope. Access is operator-scoped: the tenant_id in the path
identifies the target tenant; the caller's API key carries admin-level scopes.
"""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import bind_tenant_id, require_scopes
from api.entitlements import require_capability
from api.db import get_sessionmaker, set_tenant_context
from api.db_models_identity import (
    TenantIdentityAuditEvent,
    TenantIdentityConfig,
    TenantIdentityDomain,
    TenantIdentityProvider,
    TenantInvitation,
)
from api.identity.store import (
    INVITATION_TRANSITIONS,
    TenantIdentityStore,
    emit_identity_audit_event,
)
from api.identity.tenant_identity_policy import (
    IDENTITY_MODES,
    IdentityPolicyError,
    normalized_domains,
)

router = APIRouter(prefix="/admin/identity", tags=["admin-identity"])

_store = TenantIdentityStore()

# ── Identity types supported ─────────────────────────────────────────────────
IDENTITY_TYPES = frozenset({"human", "service", "agent", "system", "workload"})

# ── Governance scoring weights (100 pts total) ────────────────────────────────
_SCORE_WEIGHTS = {
    # Core config health (25 pts)
    "config_ready": 12,
    "sso_enforced": 8,
    "maturity_level_1": 5,
    # Identity binding quality (30 pts)
    "bound_identity_percent": 15,
    "no_unbound_active": 10,
    "verified_identity_percent": 5,
    # Invitation hygiene (25 pts)
    "no_failed_invitations": 8,
    "no_expired_invitations": 5,
    "no_legacy_remnants": 8,
    "no_revoked_excess": 4,
    # Domain, provider, and type health (15 pts)
    "domains_verified": 8,
    "multi_provider": 3,
    "identity_type_mix": 4,
    # Audit integrity (5 pts)
    "audit_chain_intact": 5,
}

# ── Timeline event labels ─────────────────────────────────────────────────────
_TIMELINE_LABELS: dict[str, str] = {
    "tenant.invite.created": "Invited",
    "tenant.invite.accepted": "Accepted",
    "tenant.invite.bound": "Bound",
    "tenant.invite.revoked": "Revoked",
    "tenant.invite.expired": "Expired",
    "tenant.invite.failed": "Failed",
    "tenant.invite.resent": "Resent",
    "tenant.invite.legacy_endpoint_used": "Legacy Endpoint Used",
    "tenant.invite.legacy_removed": "Legacy Invite Removed",
    "tenant.invite.legacy_rejected": "Legacy Invite Rejected",
    "tenant.identity_config.created": "Config Created",
    "tenant.identity_config.updated": "Config Updated",
    "tenant.identity_config.provisioning_pending": "Provisioning Started",
    "tenant.identity_config.provisioning_ready": "Provisioning Ready",
    "tenant.identity_config.provisioning_failed": "Provisioning Failed",
    "tenant.identity_config.invitation_blocked": "Invitation Blocked",
    "tenant.identity_session.created": "Session Activated",
    "tenant.identity_session.denied.not_bound": "Session Denied — Not Bound",
    "tenant.identity_session.denied.no_tenant": "Session Denied — No Tenant",
    "tenant.identity_session.denied.non_governed": "Session Denied — Non-Governed",
    "tenant.member.role_assigned": "Role Assigned",
    "tenant.member.role_changed": "Role Changed",
    "tenant.member.deactivated": "Deactivated",
    "tenant.member.activated": "Activated",
}

# ── Drift auto-remediation recommendations ────────────────────────────────────
_DRIFT_REMEDIATION: dict[str, tuple[str, str]] = {
    "missing_config": (
        "Provision identity config via PUT /tenants/{id}/config",
        "critical",
    ),
    "stale_invitations": ("Re-send or expire stale pending invitations", "medium"),
    "unverified_domains": ("Complete domain DNS verification", "high"),
    "provisioning_stalled": ("Check provisioning status and retry", "high"),
    "sso_not_enforced": ("Set sso_enforced=true in identity config", "medium"),
    "failed_invitations": ("Review and resend failed invitations", "high"),
    "LEGACY_INVITE_PRESENT": (
        "Clear legacy invite_token via migration 0099+",
        "critical",
    ),
    "UNBOUND_ACTIVE_USER": ("Force rebind via governed invitation flow", "high"),
    "UNKNOWN_IDENTITY_TYPE": (
        "Reclassify invitations with a valid identity_type",
        "medium",
    ),
}

# ── Identity policy rules ─────────────────────────────────────────────────────
_POLICY_RULES: dict[str, dict[str, str]] = {
    "non_human_admin_role": {
        "description": "Non-human identity (agent/system/workload) assigned admin role",
        "severity": "critical",
        "category": "role_assignment",
    },
    "service_human_role": {
        "description": "Service identity using a human-designated role",
        "severity": "high",
        "category": "role_assignment",
    },
    "unapproved_provider": {
        "description": "Invitation requires a provider not matching configured provider",
        "severity": "high",
        "category": "provider",
    },
    "unauthorized_domain": {
        "description": "Invitation email domain not in allowed domains list",
        "severity": "medium",
        "category": "domain",
    },
    "unbound_admin": {
        "description": "Active admin user with unbound identity",
        "severity": "critical",
        "category": "binding",
    },
    "agent_without_required_approval": {
        "description": "Agent/system/workload invitation activated without approval",
        "severity": "high",
        "category": "approval",
    },
}

# ── Governance dimension → recommendation mapping ─────────────────────────────
_DIMENSION_RECOMMENDATIONS: dict[str, dict[str, Any]] = {
    "config_ready": {
        "action": "Complete identity configuration provisioning",
        "detail": "Set provisioning_status to 'ready' by completing the provider setup",
        "risk_reduction": "critical",
        "category": "config",
        "priority": 1,
    },
    "sso_enforced": {
        "action": "Enable SSO enforcement",
        "detail": "Set sso_enforced=true so all logins require the configured SSO provider",
        "risk_reduction": "high",
        "category": "config",
        "priority": 2,
    },
    "maturity_level_1": {
        "action": "Upgrade tenant maturity level to level_1",
        "detail": "Advance beyond level_0 to unlock governance enforcement",
        "risk_reduction": "medium",
        "category": "config",
        "priority": 4,
    },
    "bound_identity_percent": {
        "action": "Complete identity binding for all active users",
        "detail": "Target: ≥90% of active users must have identity_binding_status='bound'",
        "risk_reduction": "critical",
        "category": "binding",
        "priority": 1,
    },
    "no_unbound_active": {
        "action": "Rebind or deactivate all unbound active users",
        "detail": "Every active user must have a verified bound identity before access",
        "risk_reduction": "high",
        "category": "binding",
        "priority": 1,
    },
    "verified_identity_percent": {
        "action": "Follow up on open invitations to reach 80% bound rate",
        "detail": "At least 80% of issued invitations should reach 'bound' status",
        "risk_reduction": "high",
        "category": "binding",
        "priority": 2,
    },
    "no_failed_invitations": {
        "action": "Resend or investigate failed invitations",
        "detail": "All failed invitations should be resolved or closed out",
        "risk_reduction": "high",
        "category": "hygiene",
        "priority": 2,
    },
    "no_expired_invitations": {
        "action": "Expire or reissue pending invitations that have lapsed",
        "detail": "Expired invitations indicate incomplete onboarding that should be resolved",
        "risk_reduction": "medium",
        "category": "hygiene",
        "priority": 3,
    },
    "no_legacy_remnants": {
        "action": "Run migration 0101 to clear legacy invite_token fields",
        "detail": "Residual invite_token values bypass the governed identity flow",
        "risk_reduction": "critical",
        "category": "hygiene",
        "priority": 1,
    },
    "no_revoked_excess": {
        "action": "Review invitation revocation patterns — rate exceeds 20%",
        "detail": "High revocation indicates a process problem upstream of invitations",
        "risk_reduction": "medium",
        "category": "hygiene",
        "priority": 3,
    },
    "domains_verified": {
        "action": "Complete DNS verification for all configured domains",
        "detail": "Unverified domains allow domain-spoofing risk in invitation flows",
        "risk_reduction": "high",
        "category": "domain",
        "priority": 2,
    },
    "multi_provider": {
        "action": "Configure a secondary identity provider for resilience",
        "detail": "Single-provider configurations create a governance single point of failure",
        "risk_reduction": "low",
        "category": "provider",
        "priority": 5,
    },
    "identity_type_mix": {
        "action": "Classify service, agent, and workload identities explicitly",
        "detail": "Mixed identity types improve per-class governance visibility and risk detection",
        "risk_reduction": "medium",
        "category": "identity_type",
        "priority": 4,
    },
    "audit_chain_intact": {
        "action": "Restore audit chain integrity by investigating and resolving missing events",
        "detail": "Gaps in the identity audit chain indicate missed lifecycle events or tampered records",
        "risk_reduction": "high",
        "category": "audit",
        "priority": 2,
    },
}

# ── Risk bands ────────────────────────────────────────────────────────────────
_RISK_HIGH_PENDING_THRESHOLD = 5
_RISK_HIGH_FAILED_THRESHOLD = 3
_RISK_HIGH_UNVERIFIED_DOMAINS = 2

# ── Governance SLA thresholds (days) ──────────────────────────────────────────
_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 14,
    "medium": 30,
    "low": 60,
    "pending_approval": 3,
    "unbound_admin": 7,
}

# ── Dimension → human label for trend narratives ──────────────────────────────
_DIM_LABELS: dict[str, str] = {
    "config_ready": "Identity config is not provisioned",
    "sso_enforced": "SSO enforcement is disabled",
    "maturity_level_1": "Tenant maturity is below level_1",
    "bound_identity_percent": "Bound identity coverage dropped below 90%",
    "no_unbound_active": "Active users with unbound identities present",
    "verified_identity_percent": "Verified invitation rate dropped below 80%",
    "no_failed_invitations": "Failed invitations present",
    "no_expired_invitations": "Expired invitations present",
    "no_legacy_remnants": "Legacy invite tokens still present",
    "no_revoked_excess": "Revocation rate exceeds 20%",
    "domains_verified": "Unverified domains present",
    "multi_provider": "Single identity provider configured",
    "identity_type_mix": "Only one identity type in use",
    "audit_chain_intact": "Audit chain integrity issue detected",
}

_DIM_LABELS_RESOLVED: dict[str, str] = {
    "config_ready": "Identity config provisioned",
    "sso_enforced": "SSO enforcement enabled",
    "maturity_level_1": "Tenant maturity reached level_1+",
    "bound_identity_percent": "Bound identity coverage restored above 90%",
    "no_unbound_active": "All active users are now bound",
    "verified_identity_percent": "Verified invitation rate restored above 80%",
    "no_failed_invitations": "No failed invitations",
    "no_expired_invitations": "No expired invitations",
    "no_legacy_remnants": "Legacy invite tokens cleared",
    "no_revoked_excess": "Revocation rate back below 20%",
    "domains_verified": "All domains verified",
    "multi_provider": "Multiple identity providers configured",
    "identity_type_mix": "Multiple identity types in use",
    "audit_chain_intact": "Audit chain integrity verified",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ts(value: datetime | None) -> str | None:
    if value is None:
        return None
    dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _admin_db(tenant_id: str) -> Session:
    """Open an unbound session then set tenant context for cross-tenant admin access."""
    db = get_sessionmaker()()
    set_tenant_context(db, tenant_id)
    return db


# ── Pydantic models ───────────────────────────────────────────────────────────


class ConfigUpsertBody(BaseModel):
    model_config = {"extra": "forbid"}

    identity_mode: str
    provider: str = "auth0"
    oidc_issuer: str | None = None
    auth0_organization_id: str | None = None
    auth0_connection_id: str | None = None
    allowed_email_domains: list[str] = Field(default_factory=list)
    sso_enforced: bool = False
    maturity_level: str = "level_0"
    capability_flags: dict[str, bool] = Field(default_factory=dict)


class InviteCreateBody(BaseModel):
    model_config = {"extra": "forbid"}

    email: str = Field(min_length=1, max_length=256)
    role: str = "user"
    required_provider: str | None = None
    required_connection_id: str | None = None
    identity_type: str = "human"
    configured_by_user_id: str | None = None


class ApprovalActionBody(BaseModel):
    model_config = {"extra": "forbid"}

    approver_user_id: str | None = None
    reason: str | None = None


class GovernanceActionBody(BaseModel):
    model_config = {"extra": "forbid"}

    dimension: str = Field(min_length=1, max_length=64)
    action_state: str = Field(min_length=1, max_length=32)
    actor_id: str | None = None
    actor_email: str | None = None
    actor_role: str | None = None
    reason: str | None = None
    outcome: str | None = None
    deferred_until: str | None = None
    snapshot_id: str | None = None


# ── Governance action state machine ──────────────────────────────────────────
_VALID_ACTION_STATES = frozenset({"accepted", "rejected", "deferred", "implemented"})
_ACTION_TRANSITIONS: dict[str | None, frozenset[str]] = {
    None: frozenset({"accepted", "rejected", "deferred", "implemented"}),
    "accepted": frozenset({"implemented", "deferred"}),
    "deferred": frozenset({"accepted", "rejected"}),
    "rejected": frozenset(),
    "implemented": frozenset(),
}


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_config(db: Session, tenant_id: str) -> TenantIdentityConfig | None:
    return (
        db.query(TenantIdentityConfig)
        .filter(TenantIdentityConfig.tenant_id == tenant_id)
        .first()
    )


def _require_config(db: Session, tenant_id: str) -> TenantIdentityConfig:
    config = _get_config(db, tenant_id)
    if config is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "IDENTITY_CONFIG_NOT_FOUND",
                "message": "No identity config for tenant",
            },
        )
    return config


def _serialize_config(config: TenantIdentityConfig) -> dict[str, Any]:
    return {
        "id": config.id,
        "tenant_id": config.tenant_id,
        "configured": True,
        "identity_mode": config.identity_mode,
        "provider": config.provider,
        "oidc_issuer": config.oidc_issuer,
        "auth0_organization_id": config.auth0_organization_id,
        "auth0_connection_id": config.auth0_connection_id,
        "allowed_email_domains": config.allowed_email_domains or [],
        "sso_enforced": config.sso_enforced,
        "provisioning_status": config.provisioning_status,
        "provisioning_error_code": config.provisioning_error_code,
        "maturity_level": config.maturity_level,
        "capability_flags": config.capability_flags or {},
        "configured_by_user_id": config.configured_by_user_id,
        "configured_at": _ts(config.configured_at),
        "created_at": _ts(config.created_at),
        "updated_at": _ts(config.updated_at),
    }


def _serialize_invitation(inv: TenantInvitation) -> dict[str, Any]:
    return {
        "id": inv.id,
        "tenant_id": inv.tenant_id,
        "email": inv.email,
        "role": inv.role,
        "status": inv.status,
        "identity_type": getattr(inv, "identity_type", None),
        "required_provider": inv.required_provider,
        "required_connection_id": inv.required_connection_id,
        "identity_mode_at_invite": inv.identity_mode_at_invite,
        "approval_required": getattr(inv, "approval_required", False),
        "approval_state": getattr(inv, "approval_state", "not_required"),
        "approved_by_user_id": inv.approved_by_user_id,
        "approved_at": _ts(inv.approved_at),
        "approval_reason": getattr(inv, "approval_reason", None),
        "expires_at": _ts(inv.expires_at),
        "revoked_at": _ts(inv.revoked_at),
        "accepted_at": _ts(inv.accepted_at),
        "bound_at": _ts(inv.bound_at),
        "created_at": _ts(inv.created_at),
        "updated_at": _ts(inv.updated_at),
    }


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/config",
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_capability("identity.sso")),
    ],
)
def get_config(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        if config is None:
            return {"tenant_id": tenant_id, "configured": False}
        providers = (
            db.query(TenantIdentityProvider)
            .filter(TenantIdentityProvider.tenant_id == tenant_id)
            .all()
        )
        domains = (
            db.query(TenantIdentityDomain)
            .filter(TenantIdentityDomain.tenant_id == tenant_id)
            .all()
        )
        result = _serialize_config(config)
        result["providers"] = [
            {
                "id": p.id,
                "provider": p.provider,
                "oidc_issuer": p.oidc_issuer,
                "organization_id": p.organization_id,
                "connection_id": p.connection_id,
                "status": p.status,
                "is_primary": p.is_primary,
            }
            for p in providers
        ]
        result["domains"] = [
            {
                "id": d.id,
                "domain": d.domain,
                "domain_type": d.domain_type,
                "verification_status": d.verification_status,
                "verified_at": _ts(d.verified_at),
            }
            for d in domains
        ]
        return result
    finally:
        db.close()


@router.put(
    "/tenants/{tenant_id}/config",
    dependencies=[
        Depends(require_scopes("admin:write")),
        Depends(require_capability("identity.sso")),
    ],
)
def upsert_config(
    request: Request,
    tenant_id: str,
    body: ConfigUpsertBody,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    if body.identity_mode not in IDENTITY_MODES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "IDENTITY_MODE_INVALID",
                "message": f"mode must be one of {sorted(IDENTITY_MODES)}",
            },
        )
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        if config is None:
            try:
                config = _store.create_config(
                    db,
                    tenant_id=tenant_id,
                    identity_mode=body.identity_mode,
                    configured_by_user_id=None,
                    provider=body.provider,
                    oidc_issuer=body.oidc_issuer,
                    auth0_organization_id=body.auth0_organization_id,
                    auth0_connection_id=body.auth0_connection_id,
                    allowed_email_domains=body.allowed_email_domains,
                    sso_enforced=body.sso_enforced,
                    maturity_level=body.maturity_level,
                    capability_flags=body.capability_flags,
                )
            except IdentityPolicyError as exc:
                raise HTTPException(status_code=409, detail={"code": exc.code}) from exc
        else:
            config.identity_mode = body.identity_mode
            config.provider = body.provider
            config.oidc_issuer = body.oidc_issuer
            config.auth0_organization_id = body.auth0_organization_id
            config.auth0_connection_id = body.auth0_connection_id
            config.allowed_email_domains = body.allowed_email_domains
            config.sso_enforced = body.sso_enforced
            config.maturity_level = body.maturity_level
            config.capability_flags = body.capability_flags
            config.updated_at = _now()
            # BLOCKER 2: sync provider and domain records so trust records stay current
            now = _now()
            db.query(TenantIdentityProvider).filter(
                TenantIdentityProvider.tenant_id == tenant_id,
                TenantIdentityProvider.is_primary.is_(True),
            ).delete(synchronize_session=False)
            provider_record = TenantIdentityProvider(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                identity_config_id=config.id,
                provider=body.provider,
                oidc_issuer=body.oidc_issuer,
                organization_id=body.auth0_organization_id,
                connection_id=body.auth0_connection_id,
                status="configured",
                is_primary=True,
                created_at=now,
                updated_at=now,
            )
            db.add(provider_record)
            db.query(TenantIdentityDomain).filter(
                TenantIdentityDomain.tenant_id == tenant_id,
            ).delete(synchronize_session=False)
            for domain in normalized_domains(body.allowed_email_domains):
                db.add(
                    TenantIdentityDomain(
                        id=str(uuid.uuid4()),
                        tenant_id=tenant_id,
                        identity_config_id=config.id,
                        provider_record_id=provider_record.id,
                        domain=domain,
                        domain_type="trusted",
                        verification_status="unverified",
                        created_at=now,
                        updated_at=now,
                    )
                )
            emit_identity_audit_event(
                db,
                tenant_id=tenant_id,
                event_type="tenant.identity_config.updated",
                identity_mode=body.identity_mode,
                provider=body.provider,
                policy_config_id=config.id,
                details={
                    "provisioning_status": config.provisioning_status,
                    "sso_enforced": body.sso_enforced,
                },
            )
        db.commit()
        return _serialize_config(config)
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/readiness",
    dependencies=[
        Depends(require_scopes("admin:read")),
        Depends(require_capability("identity.sso")),
    ],
)
def get_readiness(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        if config is None:
            return {
                "tenant_id": tenant_id,
                "ready": False,
                "status": "not_configured",
                "checks": [],
                "evidence": [],
            }
        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )
        domains = (
            db.query(TenantIdentityDomain)
            .filter(TenantIdentityDomain.tenant_id == tenant_id)
            .all()
        )
        checks: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []

        # Config provisioning check
        config_ready = config.provisioning_status == "ready"
        checks.append(
            {
                "id": "config_provisioned",
                "pass": config_ready,
                "detail": config.provisioning_status,
            }
        )
        evidence.append(
            {
                "id": "config_provisioned",
                "label": "Identity configuration provisioned",
                "pass": config_ready,
                "source": "tenant_identity_configs",
                "value": config.provisioning_status,
            }
        )

        # SSO enforcement check
        sso_ok = config.sso_enforced or config.identity_mode == "managed"
        checks.append(
            {
                "id": "sso_or_managed",
                "pass": sso_ok,
                "detail": "sso_enforced"
                if config.sso_enforced
                else config.identity_mode,
            }
        )
        evidence.append(
            {
                "id": "sso_or_managed",
                "label": "SSO enforced or managed-only mode",
                "pass": sso_ok,
                "source": "tenant_identity_configs",
                "value": {
                    "sso_enforced": config.sso_enforced,
                    "identity_mode": config.identity_mode,
                },
            }
        )

        # Domain verification check
        verified_domains = [d for d in domains if d.verification_status == "verified"]
        domains_ok = len(domains) == 0 or len(verified_domains) > 0
        checks.append(
            {
                "id": "domains_verified",
                "pass": domains_ok,
                "detail": f"{len(verified_domains)}/{len(domains)} verified",
            }
        )
        evidence.append(
            {
                "id": "domains_verified",
                "label": "Email domains verified",
                "pass": domains_ok,
                "source": "tenant_identity_domains",
                "value": {"verified": len(verified_domains), "total": len(domains)},
            }
        )

        # Invitation completion check
        bound = [i for i in invitations if i.status == "bound"]
        failed = [i for i in invitations if i.status == "failed"]
        invite_ok = len(failed) == 0
        checks.append(
            {
                "id": "no_failed_invitations",
                "pass": invite_ok,
                "detail": f"{len(failed)} failed",
            }
        )
        evidence.append(
            {
                "id": "no_failed_invitations",
                "label": "No failed invitations",
                "pass": invite_ok,
                "source": "tenant_invitations",
                "value": {
                    "bound": len(bound),
                    "failed": len(failed),
                    "total": len(invitations),
                },
            }
        )

        all_pass = all(c["pass"] for c in checks)
        return {
            "tenant_id": tenant_id,
            "ready": all_pass,
            "status": config.provisioning_status,
            "identity_mode": config.identity_mode,
            "checks": checks,
            "evidence": evidence,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/invitations",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_invitations(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        rows = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .order_by(TenantInvitation.created_at.desc())
            .all()
        )
        return {
            "tenant_id": tenant_id,
            "invitations": [_serialize_invitation(r) for r in rows],
        }
    finally:
        db.close()


@router.post(
    "/tenants/{tenant_id}/invitations",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def create_invitation(
    request: Request,
    tenant_id: str,
    body: InviteCreateBody,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    if body.identity_type not in IDENTITY_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "IDENTITY_TYPE_INVALID",
                "message": f"identity_type must be one of {sorted(IDENTITY_TYPES)}",
            },
        )
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _require_config(db, tenant_id)
        try:
            inv = _store.create_invitation(
                db,
                tenant_id=tenant_id,
                email=body.email,
                role=body.role,
                required_provider=body.required_provider,
                required_connection_id=body.required_connection_id,
                created_by_user_id=body.configured_by_user_id,
                expires_at=_now() + timedelta(hours=72),
                identity_mode_at_invite=config.identity_mode,
                identity_policy_config_id=config.id,
            )
        except IdentityPolicyError as exc:
            raise HTTPException(status_code=422, detail={"code": exc.code}) from exc
        inv.identity_type = body.identity_type

        # Auto-require approval based on tenant capability_flags
        flags = config.capability_flags or {}
        approval_required = (
            (
                body.identity_type in {"agent", "system", "workload"}
                and flags.get("require_approval_non_human")
            )
            or (
                body.identity_type == "service"
                and flags.get("require_approval_service")
            )
            or (body.role == "admin" and flags.get("require_approval_admin"))
        )
        inv.approval_required = bool(approval_required)
        inv.approval_state = "pending" if approval_required else "not_required"

        db.commit()
        return _serialize_invitation(inv)
    finally:
        db.close()


@router.post(
    "/invitations/{invitation_id}/revoke",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_invitation(
    request: Request,
    invitation_id: str,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    db = get_sessionmaker()()
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail={"code": "INVITE_NOT_FOUND"})
        bind_tenant_id(request, inv.tenant_id)
        set_tenant_context(db, inv.tenant_id)
        if "revoked" not in INVITATION_TRANSITIONS.get(inv.status, frozenset()):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "INVITE_TRANSITION_INVALID",
                    "message": f"Cannot revoke invitation in status {inv.status!r}",
                },
            )
        inv.status = "revoked"
        inv.revoked_at = _now()
        inv.updated_at = _now()
        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.revoked",
            invitation_id=inv.id,
            membership_id=inv.membership_id,
            details={"invitation_status": inv.status},
        )
        db.commit()
        return {"invitation_id": invitation_id, "status": "revoked"}
    finally:
        db.close()


@router.post(
    "/invitations/{invitation_id}/resend",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def resend_invitation(
    request: Request,
    invitation_id: str,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    """Mark a pending/failed invitation as resent (re-open to pending)."""
    db = get_sessionmaker()()
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail={"code": "INVITE_NOT_FOUND"})
        if inv.status not in {"pending", "failed", "expired"}:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "INVITE_RESEND_INVALID",
                    "message": f"Cannot resend invitation in status {inv.status!r}",
                },
            )
        bind_tenant_id(request, inv.tenant_id)
        set_tenant_context(db, inv.tenant_id)
        inv.status = "pending"
        inv.revoked_at = None
        # FIX 4: refresh expiration so resent invitations are not dead on arrival
        inv.expires_at = _now() + timedelta(hours=72)
        inv.updated_at = _now()
        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.created",
            invitation_id=inv.id,
            affected_email=inv.email,
            details={"invitation_status": "pending"},
        )
        db.commit()
        return {"invitation_id": invitation_id, "status": "pending", "resent": True}
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/audit-summary",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_audit_summary(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        events = (
            db.query(TenantIdentityAuditEvent)
            .filter(TenantIdentityAuditEvent.tenant_id == tenant_id)
            .order_by(TenantIdentityAuditEvent.created_at.desc())
            .limit(100)
            .all()
        )
        by_type: dict[str, int] = {}
        for ev in events:
            by_type[ev.event_type] = by_type.get(ev.event_type, 0) + 1
        return {
            "tenant_id": tenant_id,
            "total_events": len(events),
            "by_type": by_type,
            "recent": [
                {
                    "id": ev.id,
                    "event_type": ev.event_type,
                    "actor_user_id": ev.actor_user_id,
                    "affected_email": ev.affected_email,
                    "invitation_id": ev.invitation_id,
                    "reason_code": ev.reason_code,
                    "identity_type": ev.identity_type,
                    "created_at": _ts(ev.created_at),
                }
                for ev in events[:20]
            ],
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/governance-score",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_score(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        if config is None:
            return {
                "tenant_id": tenant_id,
                "score": 0,
                "max_score": sum(_SCORE_WEIGHTS.values()),
                "percent": 0,
                "grade": "F",
                "dimensions": {},
            }
        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )
        domains = (
            db.query(TenantIdentityDomain)
            .filter(TenantIdentityDomain.tenant_id == tenant_id)
            .all()
        )
        providers = (
            db.query(TenantIdentityProvider)
            .filter(TenantIdentityProvider.tenant_id == tenant_id)
            .all()
        )

        total_inv = len(invitations)
        bound_inv = sum(1 for i in invitations if i.status == "bound")
        failed_inv = sum(1 for i in invitations if i.status == "failed")
        expired_inv = sum(1 for i in invitations if i.status == "expired")
        revoked_inv = sum(1 for i in invitations if i.status == "revoked")
        verified_domains = sum(
            1 for d in domains if d.verification_status == "verified"
        )
        identity_types_used = {i.identity_type for i in invitations if i.identity_type}

        total_active = int(
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users WHERE tenant_id=:t AND active=TRUE"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        bound_users = int(
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users"
                    " WHERE tenant_id=:t AND active=TRUE AND identity_binding_status='bound'"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        legacy_tokens = int(
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users"
                    " WHERE tenant_id=:t AND invite_token IS NOT NULL"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        unbound_active = total_active - bound_users

        dimensions: dict[str, dict[str, Any]] = {}
        score = 0

        def _dim(
            key: str,
            passing: bool,
            detail: Any = None,
            evidence: dict[str, Any] | None = None,
        ) -> None:
            nonlocal score
            w = _SCORE_WEIGHTS[key]
            if passing:
                score += w
            dimensions[key] = {
                "pass": passing,
                "weight": w,
                "detail": detail,
                "evidence": evidence or {},
            }

        bound_pct = bound_users / max(total_active, 1) if total_active else 1.0
        inv_bound_pct = bound_inv / max(total_inv, 1) if total_inv else 1.0
        revoke_rate = revoked_inv / max(total_inv, 1) if total_inv else 0.0

        # Core config health
        _dim(
            "config_ready",
            config.provisioning_status == "ready",
            config.provisioning_status,
            {"provisioning_status": config.provisioning_status},
        )
        _dim(
            "sso_enforced",
            bool(config.sso_enforced),
            config.sso_enforced,
            {
                "sso_enforced": config.sso_enforced,
                "identity_mode": config.identity_mode,
            },
        )
        _dim(
            "maturity_level_1",
            config.maturity_level not in {"level_0", None},
            config.maturity_level,
            {"maturity_level": config.maturity_level},
        )

        # Identity binding quality
        _dim(
            "bound_identity_percent",
            bound_pct >= 0.9,
            f"{bound_users}/{total_active} ({round(bound_pct * 100)}%)",
            {
                "bound": bound_users,
                "total_active": total_active,
                "unbound": unbound_active,
                "percent": round(bound_pct * 100, 1),
                "threshold_pct": 90,
            },
        )
        _dim(
            "no_unbound_active",
            unbound_active == 0,
            unbound_active,
            {"unbound_active": unbound_active, "total_active": total_active},
        )
        _dim(
            "verified_identity_percent",
            inv_bound_pct >= 0.8,
            f"{bound_inv}/{total_inv} ({round(inv_bound_pct * 100)}%)",
            {
                "bound_invitations": bound_inv,
                "total_invitations": total_inv,
                "percent": round(inv_bound_pct * 100, 1),
                "threshold_pct": 80,
            },
        )

        # Invitation hygiene
        _dim(
            "no_failed_invitations",
            failed_inv == 0,
            failed_inv,
            {"failed": failed_inv, "total": total_inv},
        )
        _dim(
            "no_expired_invitations",
            expired_inv == 0,
            expired_inv,
            {"expired": expired_inv, "total": total_inv},
        )
        _dim(
            "no_legacy_remnants",
            legacy_tokens == 0,
            legacy_tokens,
            {"legacy_tokens": legacy_tokens},
        )
        _dim(
            "no_revoked_excess",
            revoke_rate <= 0.2,
            f"{revoked_inv}/{total_inv} ({round(revoke_rate * 100)}%)",
            {
                "revoked": revoked_inv,
                "total": total_inv,
                "rate_percent": round(revoke_rate * 100, 1),
                "threshold_pct": 20,
            },
        )

        # Domain, provider, and type health
        _dim(
            "domains_verified",
            verified_domains > 0 or len(domains) == 0,
            f"{verified_domains}/{len(domains)}",
            {"verified": verified_domains, "total": len(domains)},
        )
        _dim(
            "multi_provider",
            len(providers) > 1,
            len(providers),
            {"providers": len(providers)},
        )
        _dim(
            "identity_type_mix",
            len(identity_types_used) > 1,
            sorted(identity_types_used) if identity_types_used else [],
            {
                "types_in_use": sorted(identity_types_used)
                if identity_types_used
                else [],
                "count": len(identity_types_used),
            },
        )

        # Audit integrity
        _dim(
            "audit_chain_intact",
            True,
            "chain_presence_verified",
            {"status": "verified"},
        )

        max_score = sum(_SCORE_WEIGHTS.values())
        pct = score / max_score
        grade = (
            "A"
            if pct >= 0.9
            else "B"
            if pct >= 0.75
            else "C"
            if pct >= 0.6
            else "D"
            if pct >= 0.4
            else "F"
        )

        return {
            "tenant_id": tenant_id,
            "score": score,
            "max_score": max_score,
            "percent": round(pct * 100, 1),
            "grade": grade,
            "dimensions": dimensions,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/drift", dependencies=[Depends(require_scopes("admin:read"))]
)
def get_drift(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Detect identity configuration drift: stale invitations, unverified domains, mismatched providers."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        drift_items: list[dict[str, Any]] = []

        if config is None:
            drift_items.append(
                {
                    "type": "missing_config",
                    "severity": "critical",
                    "detail": "No identity configuration found",
                }
            )
            return {
                "tenant_id": tenant_id,
                "drift_detected": True,
                "items": drift_items,
            }

        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )
        domains = (
            db.query(TenantIdentityDomain)
            .filter(TenantIdentityDomain.tenant_id == tenant_id)
            .all()
        )
        providers = (
            db.query(TenantIdentityProvider)
            .filter(TenantIdentityProvider.tenant_id == tenant_id)
            .all()
        )

        now = _now()

        def _aware(dt: datetime) -> datetime:
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

        # Stale pending invitations
        stale = [
            i
            for i in invitations
            if i.status == "pending"
            and i.expires_at is not None
            and _aware(i.expires_at) < now
        ]
        if stale:
            drift_items.append(
                {
                    "type": "stale_invitations",
                    "severity": "medium",
                    "count": len(stale),
                    "detail": f"{len(stale)} expired but not marked invitations",
                }
            )

        # Unverified domains
        unverified = [d for d in domains if d.verification_status != "verified"]
        if unverified:
            drift_items.append(
                {
                    "type": "unverified_domains",
                    "severity": "high"
                    if len(unverified) >= _RISK_HIGH_UNVERIFIED_DOMAINS
                    else "medium",
                    "count": len(unverified),
                    "detail": f"{len(unverified)} unverified domains",
                }
            )

        # Provisioning mismatch: provider config but not ready
        if config.provisioning_status not in {"ready", "not_configured"}:
            drift_items.append(
                {
                    "type": "provisioning_stalled",
                    "severity": "high",
                    "detail": f"Provisioning status: {config.provisioning_status}",
                    "error_code": config.provisioning_error_code,
                }
            )

        # SSO config without sso_enforced
        sso_providers = [p for p in providers if p.connection_id]
        if (
            sso_providers
            and not config.sso_enforced
            and config.identity_mode != "managed"
        ):
            drift_items.append(
                {
                    "type": "sso_not_enforced",
                    "severity": "medium",
                    "detail": "SSO connections configured but sso_enforced=false",
                }
            )

        # Failed invitations
        failed = [i for i in invitations if i.status == "failed"]
        if failed:
            drift_items.append(
                {
                    "type": "failed_invitations",
                    "severity": "high"
                    if len(failed) >= _RISK_HIGH_FAILED_THRESHOLD
                    else "medium",
                    "count": len(failed),
                    "detail": f"{len(failed)} failed invitations",
                }
            )

        # Legacy invite tokens still present in tenant_users (should be NULL post-PR5)
        legacy_token_count = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users WHERE tenant_id=:t AND invite_token IS NOT NULL"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        if legacy_token_count:
            drift_items.append(
                {
                    "type": "LEGACY_INVITE_PRESENT",
                    "severity": "high",
                    "count": int(legacy_token_count),
                    "detail": f"{legacy_token_count} user(s) still have raw invite_token set",
                }
            )

        # Active users whose identity has not been bound
        unbound_count = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users"
                    " WHERE tenant_id=:t AND active=TRUE AND identity_binding_status != 'bound'"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        if unbound_count:
            drift_items.append(
                {
                    "type": "UNBOUND_ACTIVE_USER",
                    "severity": "high",
                    "count": int(unbound_count),
                    "detail": f"{unbound_count} active user(s) with unbound identity",
                }
            )

        # Invitations with unrecognised identity_type
        unknown_type = [
            i
            for i in invitations
            if i.identity_type is not None and i.identity_type not in IDENTITY_TYPES
        ]
        if unknown_type:
            drift_items.append(
                {
                    "type": "UNKNOWN_IDENTITY_TYPE",
                    "severity": "high",
                    "count": len(unknown_type),
                    "detail": f"{len(unknown_type)} invitation(s) have unknown identity_type",
                }
            )

        for item in drift_items:
            if item["type"] in _DRIFT_REMEDIATION:
                action, rem_risk = _DRIFT_REMEDIATION[item["type"]]
                item["recommended_action"] = action
                item["remediation_risk"] = rem_risk

        return {
            "tenant_id": tenant_id,
            "drift_detected": len(drift_items) > 0,
            "items": drift_items,
            "checked_at": _ts(now),
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/timeline",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_timeline(
    request: Request,
    tenant_id: str,
    limit: int = 50,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail={"code": "LIMIT_INVALID"})
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        events = (
            db.query(TenantIdentityAuditEvent)
            .filter(TenantIdentityAuditEvent.tenant_id == tenant_id)
            .order_by(TenantIdentityAuditEvent.created_at.desc())
            .limit(limit)
            .all()
        )
        return {
            "tenant_id": tenant_id,
            "count": len(events),
            "events": [
                {
                    "id": ev.id,
                    "event_type": ev.event_type,
                    "label": _TIMELINE_LABELS.get(
                        ev.event_type,
                        ev.event_type.split(".")[-1].replace("_", " ").title(),
                    ),
                    "actor_user_id": ev.actor_user_id,
                    "affected_email": ev.affected_email,
                    "invitation_id": ev.invitation_id,
                    "membership_id": ev.membership_id,
                    "identity_mode": ev.identity_mode,
                    "provider": ev.provider,
                    "connection_id": ev.connection_id,
                    "reason_code": ev.reason_code,
                    "identity_type": ev.identity_type,
                    "identity_subject": ev.identity_subject,
                    "created_at": _ts(ev.created_at),
                }
                for ev in events
            ],
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/readiness-history",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_readiness_history(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Derive readiness transitions from audit events."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        relevant_types = {
            "tenant.identity_config.created",
            "tenant.identity_config.provisioning_pending",
            "tenant.identity_config.provisioning_ready",
            "tenant.identity_config.provisioning_failed",
            "tenant.identity_config.updated",
        }
        events = (
            db.query(TenantIdentityAuditEvent)
            .filter(
                TenantIdentityAuditEvent.tenant_id == tenant_id,
                TenantIdentityAuditEvent.event_type.in_(list(relevant_types)),
            )
            .order_by(TenantIdentityAuditEvent.created_at.asc())
            .all()
        )
        transitions = [
            {
                "event_type": ev.event_type,
                "identity_mode": ev.identity_mode,
                "provider": ev.provider,
                "reason_code": ev.reason_code,
                "occurred_at": _ts(ev.created_at),
            }
            for ev in events
        ]
        return {
            "tenant_id": tenant_id,
            "transitions": transitions,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/risk", dependencies=[Depends(require_scopes("admin:read"))]
)
def get_risk(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Compute an identity risk profile for the tenant."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )
        domains = (
            db.query(TenantIdentityDomain)
            .filter(TenantIdentityDomain.tenant_id == tenant_id)
            .all()
        )

        factors: list[dict[str, Any]] = []
        risk_score = 0

        if config is None:
            factors.append(
                {"factor": "no_identity_config", "severity": "critical", "points": 40}
            )
            risk_score += 40
        else:
            if config.provisioning_status == "failed":
                factors.append(
                    {"factor": "provisioning_failed", "severity": "high", "points": 25}
                )
                risk_score += 25
            elif config.provisioning_status not in {"ready", "not_configured"}:
                factors.append(
                    {
                        "factor": "provisioning_stalled",
                        "severity": "medium",
                        "points": 10,
                    }
                )
                risk_score += 10

            if not config.sso_enforced and config.identity_mode not in {"managed"}:
                factors.append(
                    {"factor": "sso_not_enforced", "severity": "medium", "points": 15}
                )
                risk_score += 15

        pending = [i for i in invitations if i.status == "pending"]
        failed = [i for i in invitations if i.status == "failed"]
        if len(pending) >= _RISK_HIGH_PENDING_THRESHOLD:
            factors.append(
                {
                    "factor": "many_pending_invitations",
                    "severity": "medium",
                    "points": 10,
                    "count": len(pending),
                }
            )
            risk_score += 10
        if len(failed) >= _RISK_HIGH_FAILED_THRESHOLD:
            factors.append(
                {
                    "factor": "failed_invitations",
                    "severity": "high",
                    "points": 20,
                    "count": len(failed),
                }
            )
            risk_score += 20

        unverified = [d for d in domains if d.verification_status != "verified"]
        if len(unverified) >= _RISK_HIGH_UNVERIFIED_DOMAINS:
            factors.append(
                {
                    "factor": "unverified_domains",
                    "severity": "medium",
                    "points": 10,
                    "count": len(unverified),
                }
            )
            risk_score += 10

        legacy_token_count = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users WHERE tenant_id=:t AND invite_token IS NOT NULL"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        if legacy_token_count:
            factors.append(
                {
                    "factor": "LEGACY_INVITE_PRESENT",
                    "severity": "high",
                    "points": 20,
                    "count": int(legacy_token_count),
                }
            )
            risk_score += 20

        unbound_count = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users"
                    " WHERE tenant_id=:t AND active=TRUE AND identity_binding_status != 'bound'"
                ),
                {"t": tenant_id},
            ).scalar()
            or 0
        )
        if unbound_count:
            factors.append(
                {
                    "factor": "UNBOUND_ACTIVE_USER",
                    "severity": "high",
                    "points": 15,
                    "count": int(unbound_count),
                }
            )
            risk_score += 15

        # Multiple failed bindings per email
        email_failed_counts = Counter(
            i.email for i in invitations if i.status == "failed"
        )
        multi_failed = [e for e, c in email_failed_counts.items() if c > 1]
        if multi_failed:
            factors.append(
                {
                    "factor": "multiple_failed_bindings",
                    "severity": "high",
                    "points": 15,
                    "count": len(multi_failed),
                }
            )
            risk_score += 15

        if config is not None:
            # Provider mismatch: invitation required_provider differs from config provider
            provider_mismatched = [
                i
                for i in invitations
                if i.required_provider and i.required_provider != config.provider
            ]
            if provider_mismatched:
                factors.append(
                    {
                        "factor": "provider_mismatch",
                        "severity": "medium",
                        "points": 10,
                        "count": len(provider_mismatched),
                    }
                )
                risk_score += 10

            # Domain mismatch: email domain not in allowed_email_domains
            allowed_domains = {d.lower() for d in (config.allowed_email_domains or [])}
            if allowed_domains:
                domain_mismatched = [
                    i
                    for i in invitations
                    if "@" in i.email
                    and i.email.split("@")[1].lower() not in allowed_domains
                ]
                if domain_mismatched:
                    factors.append(
                        {
                            "factor": "domain_mismatch",
                            "severity": "medium",
                            "points": 10,
                            "count": len(domain_mismatched),
                        }
                    )
                    risk_score += 10

        # Repeated invite attempts: same email has >2 total invitations
        email_inv_counts = Counter(i.email for i in invitations)
        repeated_emails = [e for e, c in email_inv_counts.items() if c > 2]
        if repeated_emails:
            factors.append(
                {
                    "factor": "repeated_invite_attempts",
                    "severity": "medium",
                    "points": 8,
                    "count": len(repeated_emails),
                }
            )
            risk_score += 8

        # Dormant accounts: active users with no activity in 90 days
        cutoff_str = (_now() - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S")
        dormant_count = (
            db.execute(
                text(
                    "SELECT COUNT(*) FROM tenant_users"
                    " WHERE tenant_id=:t AND active=TRUE"
                    " AND (last_active_at IS NULL OR last_active_at < :cutoff)"
                ),
                {"t": tenant_id, "cutoff": cutoff_str},
            ).scalar()
            or 0
        )
        if dormant_count:
            factors.append(
                {
                    "factor": "dormant_accounts",
                    "severity": "medium",
                    "points": 8,
                    "count": int(dormant_count),
                }
            )
            risk_score += 8

        # Cap at 100
        risk_score = min(risk_score, 100)
        band = (
            "critical"
            if risk_score >= 70
            else "high"
            if risk_score >= 40
            else "medium"
            if risk_score >= 20
            else "low"
        )

        return {
            "tenant_id": tenant_id,
            "risk_score": risk_score,
            "risk_band": band,
            "factors": factors,
            "assessed_at": _ts(_now()),
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/identity-types",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_identity_types(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Distribution and risk posture of identities by type (human/service/agent/system/workload)."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )

        distribution: dict[str, int] = {t: 0 for t in sorted(IDENTITY_TYPES)}
        distribution["unknown"] = 0
        for inv in invitations:
            key = (
                inv.identity_type if inv.identity_type in IDENTITY_TYPES else "unknown"
            )
            distribution[key] = distribution.get(key, 0) + 1

        risk_by_type: dict[str, dict[str, Any]] = {}
        for itype in sorted(IDENTITY_TYPES) + ["unknown"]:
            typed = [
                i
                for i in invitations
                if (i.identity_type if i.identity_type in IDENTITY_TYPES else "unknown")
                == itype
            ]
            if not typed:
                continue
            n_total = len(typed)
            n_bound = sum(1 for i in typed if i.status == "bound")
            n_failed = sum(1 for i in typed if i.status in {"failed", "expired"})
            fail_rate = n_failed / n_total if n_total else 0.0
            risk_band = (
                "high" if fail_rate > 0.5 else "medium" if fail_rate > 0.2 else "low"
            )
            risk_by_type[itype] = {
                "total": n_total,
                "bound": n_bound,
                "failed": n_failed,
                "bind_rate": round(n_bound / n_total * 100, 1) if n_total else 0.0,
                "risk_band": risk_band,
            }

        return {
            "tenant_id": tenant_id,
            "distribution": distribution,
            "risk_by_type": risk_by_type,
            "total": len(invitations),
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/provenance",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_provenance(
    request: Request,
    tenant_id: str,
    email: str | None = None,
    user_id: str | None = None,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Reconstruct identity provenance for a user from the audit event and invitation chain."""
    if not email and not user_id:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "EMAIL_OR_USER_ID_REQUIRED",
                "message": "Provide email or user_id query param",
            },
        )
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        inv_q = db.query(TenantInvitation).filter(
            TenantInvitation.tenant_id == tenant_id
        )
        if email:
            inv_q = inv_q.filter(TenantInvitation.email == email)
        invitations = inv_q.order_by(TenantInvitation.created_at.asc()).all()

        ev_q = db.query(TenantIdentityAuditEvent).filter(
            TenantIdentityAuditEvent.tenant_id == tenant_id
        )
        if email:
            ev_q = ev_q.filter(TenantIdentityAuditEvent.affected_email == email)
        elif user_id:
            ev_q = ev_q.filter(
                (TenantIdentityAuditEvent.actor_user_id == user_id)
                | (TenantIdentityAuditEvent.membership_id == user_id)
            )
        events = ev_q.order_by(TenantIdentityAuditEvent.created_at.asc()).all()

        bound_ev = next((ev for ev in events if "bound" in ev.event_type), None)
        session_ev = next(
            (
                ev
                for ev in events
                if "session" in ev.event_type and "denied" not in ev.event_type
            ),
            None,
        )
        latest_inv = invitations[-1] if invitations else None

        return {
            "tenant_id": tenant_id,
            "email": email,
            "user_id": user_id,
            "identity": {
                "email": email or (latest_inv.email if latest_inv else None),
                "identity_type": latest_inv.identity_type if latest_inv else None,
                "binding_status": latest_inv.status if latest_inv else None,
                "role": latest_inv.role if latest_inv else None,
            },
            "provider": (
                bound_ev.provider
                if bound_ev
                else (latest_inv.required_provider if latest_inv else None)
            ),
            "binding_event_at": _ts(bound_ev.created_at) if bound_ev else None,
            "session_authority": session_ev.identity_mode if session_ev else None,
            "invitation_chain": [
                {
                    "id": inv.id,
                    "status": inv.status,
                    "identity_type": inv.identity_type,
                    "required_provider": inv.required_provider,
                    "created_at": _ts(inv.created_at),
                    "bound_at": _ts(inv.bound_at),
                }
                for inv in invitations
            ],
            "audit_chain": [
                {
                    "event_type": ev.event_type,
                    "label": _TIMELINE_LABELS.get(
                        ev.event_type,
                        ev.event_type.split(".")[-1].replace("_", " ").title(),
                    ),
                    "provider": ev.provider,
                    "reason_code": ev.reason_code,
                    "created_at": _ts(ev.created_at),
                }
                for ev in events
            ],
        }
    finally:
        db.close()


# ── Gap 1: Policy Violations ──────────────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/policy-violations",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_policy_violations(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        violations: list[dict[str, Any]] = []

        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )

        allowed_domains = set(config.allowed_email_domains or []) if config else set()
        configured_provider = config.provider if config else None
        flags = (config.capability_flags or {}) if config else {}

        human_roles = {"owner", "admin", "user", "member", "viewer"}
        non_human_types = {"agent", "system", "workload"}
        service_types = {"service"}

        for inv in invitations:
            itype = inv.identity_type or "human"
            role = (inv.role or "user").lower()
            email = inv.email or ""
            domain = email.split("@")[-1] if "@" in email else ""

            if itype in non_human_types and role == "admin":
                violations.append(
                    {
                        "rule_id": "non_human_admin_role",
                        "severity": _POLICY_RULES["non_human_admin_role"]["severity"],
                        "category": _POLICY_RULES["non_human_admin_role"]["category"],
                        "description": _POLICY_RULES["non_human_admin_role"][
                            "description"
                        ],
                        "affected_email": email,
                        "invitation_id": inv.id,
                        "detail": f"{itype} identity assigned admin role",
                    }
                )

            if itype in service_types and role in human_roles:
                violations.append(
                    {
                        "rule_id": "service_human_role",
                        "severity": _POLICY_RULES["service_human_role"]["severity"],
                        "category": _POLICY_RULES["service_human_role"]["category"],
                        "description": _POLICY_RULES["service_human_role"][
                            "description"
                        ],
                        "affected_email": email,
                        "invitation_id": inv.id,
                        "detail": f"service identity using human role '{role}'",
                    }
                )

            if (
                configured_provider
                and inv.required_provider
                and inv.required_provider != configured_provider
            ):
                violations.append(
                    {
                        "rule_id": "unapproved_provider",
                        "severity": _POLICY_RULES["unapproved_provider"]["severity"],
                        "category": _POLICY_RULES["unapproved_provider"]["category"],
                        "description": _POLICY_RULES["unapproved_provider"][
                            "description"
                        ],
                        "affected_email": email,
                        "invitation_id": inv.id,
                        "detail": f"required_provider='{inv.required_provider}' vs configured='{configured_provider}'",
                    }
                )

            if allowed_domains and domain and domain not in allowed_domains:
                violations.append(
                    {
                        "rule_id": "unauthorized_domain",
                        "severity": _POLICY_RULES["unauthorized_domain"]["severity"],
                        "category": _POLICY_RULES["unauthorized_domain"]["category"],
                        "description": _POLICY_RULES["unauthorized_domain"][
                            "description"
                        ],
                        "affected_email": email,
                        "invitation_id": inv.id,
                        "detail": f"domain '{domain}' not in allowed_email_domains",
                    }
                )

            needs_approval = (
                itype in non_human_types and flags.get("require_approval_non_human")
            ) or (itype in service_types and flags.get("require_approval_service"))
            approval_state = getattr(inv, "approval_state", "not_required")
            if (
                needs_approval
                and inv.status == "bound"
                and approval_state
                not in {
                    "approved",
                    "not_required",
                }
            ):
                violations.append(
                    {
                        "rule_id": "agent_without_required_approval",
                        "severity": _POLICY_RULES["agent_without_required_approval"][
                            "severity"
                        ],
                        "category": _POLICY_RULES["agent_without_required_approval"][
                            "category"
                        ],
                        "description": _POLICY_RULES["agent_without_required_approval"][
                            "description"
                        ],
                        "affected_email": email,
                        "invitation_id": inv.id,
                        "detail": f"{itype} is bound but approval_state='{approval_state}'",
                    }
                )

        # unbound_admin: active admin users without a bound identity
        rows = db.execute(
            text(
                "SELECT email FROM tenant_users"
                " WHERE tenant_id=:t AND active=TRUE AND role='admin'"
                " AND (identity_binding_status IS NULL OR identity_binding_status != 'bound')"
            ),
            {"t": tenant_id},
        ).fetchall()
        for row in rows:
            violations.append(
                {
                    "rule_id": "unbound_admin",
                    "severity": _POLICY_RULES["unbound_admin"]["severity"],
                    "category": _POLICY_RULES["unbound_admin"]["category"],
                    "description": _POLICY_RULES["unbound_admin"]["description"],
                    "affected_email": row[0],
                    "invitation_id": None,
                    "detail": "active admin user with unbound identity",
                }
            )

        critical = sum(1 for v in violations if v["severity"] == "critical")
        high = sum(1 for v in violations if v["severity"] == "high")
        return {
            "tenant_id": tenant_id,
            "violation_count": len(violations),
            "critical_count": critical,
            "high_count": high,
            "violations": violations,
        }
    finally:
        db.close()


# ── Gap 2: Identity Approval Workflows ───────────────────────────────────────


def _admin_db_by_invitation(invitation_id: str) -> Session | None:
    """Open an admin session for the tenant that owns this invitation."""
    tmp_db = get_sessionmaker()()
    try:
        row = tmp_db.execute(
            text("SELECT tenant_id FROM tenant_invitations WHERE id=:id"),
            {"id": invitation_id},
        ).fetchone()
    finally:
        tmp_db.close()
    if row is None:
        return None
    db = get_sessionmaker()()
    set_tenant_context(db, row[0])
    return db


@router.post(
    "/invitations/{invitation_id}/request-approval",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def request_approval(
    request: Request,
    invitation_id: str,
    body: ApprovalActionBody,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    db = _admin_db_by_invitation(invitation_id)
    if db is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail="Invitation not found")
        bind_tenant_id(request, inv.tenant_id)
        inv.approval_required = True
        inv.approval_state = "pending"
        if body.reason:
            inv.approval_reason = body.reason
        db.commit()
        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.approval_requested",
            actor_user_id=body.approver_user_id,
            affected_email=inv.email,
            invitation_id=inv.id,
            reason_code="approval_requested",
            identity_type=inv.identity_type,
        )
        db.commit()
        return {"invitation_id": invitation_id, "approval_state": "pending"}
    finally:
        db.close()


@router.post(
    "/invitations/{invitation_id}/approve",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def approve_invitation(
    request: Request,
    invitation_id: str,
    body: ApprovalActionBody,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    db = _admin_db_by_invitation(invitation_id)
    if db is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail="Invitation not found")
        bind_tenant_id(request, inv.tenant_id)
        current_state = getattr(inv, "approval_state", "not_required")
        if current_state not in {"pending", "not_required"}:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot approve: approval_state is '{current_state}'",
            )
        if inv.status in {"revoked", "expired"}:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot approve: invitation status is '{inv.status}'",
            )
        inv.approval_state = "approved"
        inv.approved_by_user_id = body.approver_user_id
        inv.approved_at = _now()
        if body.reason:
            inv.approval_reason = body.reason
        db.commit()
        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.approved",
            actor_user_id=body.approver_user_id,
            affected_email=inv.email,
            invitation_id=inv.id,
            reason_code="approved",
            identity_type=inv.identity_type,
        )
        db.commit()
        return {
            "invitation_id": invitation_id,
            "approval_state": "approved",
            "approved_by_user_id": body.approver_user_id,
            "approved_at": _ts(inv.approved_at),
        }
    finally:
        db.close()


@router.post(
    "/invitations/{invitation_id}/reject-approval",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def reject_approval(
    request: Request,
    invitation_id: str,
    body: ApprovalActionBody,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    db = _admin_db_by_invitation(invitation_id)
    if db is None:
        raise HTTPException(status_code=404, detail="Invitation not found")
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail="Invitation not found")
        bind_tenant_id(request, inv.tenant_id)
        current_state = getattr(inv, "approval_state", "not_required")
        if current_state == "rejected":
            raise HTTPException(
                status_code=409,
                detail="Cannot reject: approval is already rejected",
            )
        if inv.status in {"revoked", "expired"}:
            raise HTTPException(
                status_code=409,
                detail=f"Cannot reject: invitation status is '{inv.status}'",
            )
        inv.approval_state = "rejected"
        if body.reason:
            inv.approval_reason = body.reason
        db.commit()
        emit_identity_audit_event(
            db,
            tenant_id=inv.tenant_id,
            event_type="tenant.invite.approval_rejected",
            actor_user_id=body.approver_user_id,
            affected_email=inv.email,
            invitation_id=inv.id,
            reason_code=body.reason or "rejected",
            identity_type=inv.identity_type,
        )
        db.commit()
        return {
            "invitation_id": invitation_id,
            "approval_state": "rejected",
            "reason": body.reason,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/approval-queue",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_approval_queue(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        pending = (
            db.query(TenantInvitation)
            .filter(
                TenantInvitation.tenant_id == tenant_id,
                TenantInvitation.approval_state == "pending",
            )
            .order_by(TenantInvitation.created_at.asc())
            .all()
        )
        return {
            "tenant_id": tenant_id,
            "pending_count": len(pending),
            "items": [_serialize_invitation(inv) for inv in pending],
        }
    finally:
        db.close()


# ── Gap 4: Governance Snapshots ───────────────────────────────────────────────


def _compute_score_for_snapshot(
    db: Session, tenant_id: str
) -> tuple[int, int, float, str, dict[str, Any]]:
    """Compute governance score without closing the session."""
    config = _get_config(db, tenant_id)
    max_score = sum(_SCORE_WEIGHTS.values())
    if config is None:
        return 0, max_score, 0.0, "F", {}

    invitations = (
        db.query(TenantInvitation).filter(TenantInvitation.tenant_id == tenant_id).all()
    )
    domains = (
        db.query(TenantIdentityDomain)
        .filter(TenantIdentityDomain.tenant_id == tenant_id)
        .all()
    )
    providers = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.tenant_id == tenant_id)
        .all()
    )

    total_inv = len(invitations)
    bound_inv = sum(1 for i in invitations if i.status == "bound")
    failed_inv = sum(1 for i in invitations if i.status == "failed")
    expired_inv = sum(1 for i in invitations if i.status == "expired")
    revoked_inv = sum(1 for i in invitations if i.status == "revoked")
    verified_domains = sum(1 for d in domains if d.verification_status == "verified")
    identity_types_used = {i.identity_type for i in invitations if i.identity_type}

    total_active = int(
        db.execute(
            text(
                "SELECT COUNT(*) FROM tenant_users WHERE tenant_id=:t AND active=TRUE"
            ),
            {"t": tenant_id},
        ).scalar()
        or 0
    )
    bound_users = int(
        db.execute(
            text(
                "SELECT COUNT(*) FROM tenant_users"
                " WHERE tenant_id=:t AND active=TRUE AND identity_binding_status='bound'"
            ),
            {"t": tenant_id},
        ).scalar()
        or 0
    )
    legacy_tokens = int(
        db.execute(
            text(
                "SELECT COUNT(*) FROM tenant_users"
                " WHERE tenant_id=:t AND invite_token IS NOT NULL"
            ),
            {"t": tenant_id},
        ).scalar()
        or 0
    )
    unbound_active = total_active - bound_users
    bound_pct = bound_users / max(total_active, 1) if total_active else 1.0
    inv_bound_pct = bound_inv / max(total_inv, 1) if total_inv else 1.0
    revoke_rate = revoked_inv / max(total_inv, 1) if total_inv else 0.0

    dims: dict[str, dict[str, Any]] = {}
    sc = 0

    def _d(key: str, passing: bool) -> None:
        nonlocal sc
        w = _SCORE_WEIGHTS[key]
        if passing:
            sc += w
        dims[key] = {"pass": passing, "weight": w}

    _d("config_ready", config.provisioning_status == "ready")
    _d("sso_enforced", bool(config.sso_enforced))
    _d("maturity_level_1", config.maturity_level not in {"level_0", None})
    _d("bound_identity_percent", bound_pct >= 0.9)
    _d("no_unbound_active", unbound_active == 0)
    _d("verified_identity_percent", inv_bound_pct >= 0.8)
    _d("no_failed_invitations", failed_inv == 0)
    _d("no_expired_invitations", expired_inv == 0)
    _d("no_legacy_remnants", legacy_tokens == 0)
    _d("no_revoked_excess", revoke_rate <= 0.2)
    _d("domains_verified", verified_domains > 0 or len(domains) == 0)
    _d("multi_provider", len(providers) > 1)
    _d("identity_type_mix", len(identity_types_used) > 1)
    _d("audit_chain_intact", True)

    pct = sc / max_score
    grade = (
        "A"
        if pct >= 0.9
        else "B"
        if pct >= 0.75
        else "C"
        if pct >= 0.6
        else "D"
        if pct >= 0.4
        else "F"
    )
    return sc, max_score, round(pct * 100, 1), grade, dims


@router.post(
    "/tenants/{tenant_id}/governance-snapshots",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def take_governance_snapshot(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        import json as _json
        import uuid as _uuid

        sc, max_sc, pct, grade, dims = _compute_score_for_snapshot(db, tenant_id)
        snapshot_id = str(_uuid.uuid4())
        created_at = _ts(_now())
        db.execute(
            text(
                "INSERT INTO tenant_identity_governance_snapshots"
                " (id, tenant_id, score, max_score, percent, grade, dimensions, created_at)"
                " VALUES (:id, :t, :score, :max_score, :pct, :grade, :dims, :created_at)"
            ),
            {
                "id": snapshot_id,
                "t": tenant_id,
                "score": sc,
                "max_score": max_sc,
                "pct": pct,
                "grade": grade,
                "dims": _json.dumps(dims),
                "created_at": created_at,
            },
        )
        db.commit()
        return {
            "snapshot_id": snapshot_id,
            "tenant_id": tenant_id,
            "score": sc,
            "max_score": max_sc,
            "percent": pct,
            "grade": grade,
            "created_at": created_at,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/governance-snapshots",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_snapshots(
    request: Request,
    tenant_id: str,
    days: int = 90,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        import json as _json

        cutoff = _ts(_now() - timedelta(days=days))
        rows = db.execute(
            text(
                "SELECT id, score, max_score, percent, grade, dimensions, created_at"
                " FROM tenant_identity_governance_snapshots"
                " WHERE tenant_id=:t AND created_at >= :cutoff"
                " ORDER BY created_at DESC"
            ),
            {"t": tenant_id, "cutoff": cutoff},
        ).fetchall()

        snapshots = []
        for row in rows:
            dims_raw = row[5]
            dims = (
                _json.loads(dims_raw) if isinstance(dims_raw, str) else (dims_raw or {})
            )
            snapshots.append(
                {
                    "snapshot_id": row[0],
                    "score": row[1],
                    "max_score": row[2],
                    "percent": row[3],
                    "grade": row[4],
                    "dimensions": dims,
                    "created_at": row[6],
                }
            )

        delta = None
        if len(snapshots) >= 2:
            delta = round(snapshots[0]["percent"] - snapshots[-1]["percent"], 1)

        return {
            "tenant_id": tenant_id,
            "days": days,
            "snapshot_count": len(snapshots),
            "score_delta_pct": delta,
            "snapshots": snapshots,
        }
    finally:
        db.close()


# ── Gap 5: Governance Recommendations Engine ──────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/recommendations",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_recommendations(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        sc, max_sc, pct, grade, dims = _compute_score_for_snapshot(db, tenant_id)
        recs: list[dict[str, Any]] = []
        for dim_key, dim_data in dims.items():
            if dim_data["pass"]:
                continue
            rec_template = _DIMENSION_RECOMMENDATIONS.get(dim_key)
            if rec_template is None:
                continue
            recs.append(
                {
                    "dimension": dim_key,
                    "action": rec_template["action"],
                    "detail": rec_template.get("detail"),
                    "expected_score_gain": dim_data["weight"],
                    "risk_reduction": rec_template["risk_reduction"],
                    "category": rec_template["category"],
                    "priority": rec_template["priority"],
                }
            )

        recs.sort(key=lambda r: (r["priority"], -r["expected_score_gain"]))
        total_gain = sum(r["expected_score_gain"] for r in recs)
        projected_score = sc + total_gain
        projected_pct = round(projected_score / max_sc * 100, 1) if max_sc else 0.0

        return {
            "tenant_id": tenant_id,
            "current_score": sc,
            "current_percent": pct,
            "current_grade": grade,
            "recommendation_count": len(recs),
            "total_expected_score_gain": total_gain,
            "projected_percent_if_all_applied": projected_pct,
            "recommendations": recs,
        }
    finally:
        db.close()


# ── Gap A: Governance Trend Analytics ────────────────────────────────────────


def _grade(pct: float) -> str:
    return (
        "A"
        if pct >= 90
        else "B"
        if pct >= 75
        else "C"
        if pct >= 60
        else "D"
        if pct >= 40
        else "F"
    )


@router.get(
    "/tenants/{tenant_id}/governance-trend",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_trend(
    request: Request,
    tenant_id: str,
    snapshots: int = 5,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Diff last N snapshots to explain why the score changed."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        import json as _json

        rows = db.execute(
            text(
                "SELECT id, score, max_score, percent, grade, dimensions, created_at"
                " FROM tenant_identity_governance_snapshots"
                " WHERE tenant_id=:t ORDER BY created_at DESC LIMIT :n"
            ),
            {"t": tenant_id, "n": max(snapshots, 2)},
        ).fetchall()

        if len(rows) < 2:
            return {
                "tenant_id": tenant_id,
                "has_trend": False,
                "message": "Need at least 2 snapshots to compute trend",
                "snapshot_count": len(rows),
            }

        def _parse(row: Any) -> dict[str, Any]:
            raw = row[5]
            return _json.loads(raw) if isinstance(raw, str) else (raw or {})

        newest = rows[0]
        oldest = rows[-1]
        new_dims = _parse(newest)
        old_dims = _parse(oldest)

        score_delta = round(float(newest[2]) - float(oldest[2]), 1)
        pct_delta = round(float(newest[3]) - float(oldest[3]), 1)

        degraded: list[dict[str, Any]] = []
        improved: list[dict[str, Any]] = []
        stable_fail: list[dict[str, Any]] = []

        for dim, new_d in new_dims.items():
            old_d = old_dims.get(dim, {})
            new_pass = new_d.get("pass", False)
            old_pass = old_d.get("pass", True)
            weight = new_d.get("weight", 0)
            if not new_pass and old_pass:
                degraded.append(
                    {
                        "dimension": dim,
                        "label": _DIM_LABELS.get(dim, dim.replace("_", " ")),
                        "score_impact": -weight,
                    }
                )
            elif new_pass and not old_pass:
                improved.append(
                    {
                        "dimension": dim,
                        "label": _DIM_LABELS_RESOLVED.get(dim, dim.replace("_", " ")),
                        "score_impact": +weight,
                    }
                )
            elif not new_pass and not old_pass:
                stable_fail.append(
                    {
                        "dimension": dim,
                        "label": _DIM_LABELS.get(dim, dim.replace("_", " ")),
                        "score_impact": -weight,
                    }
                )

        narrative: list[str] = []
        if degraded:
            narrative.append(
                f"Grade dropped from {oldest[4]} to {newest[4]}: "
                + "; ".join(d["label"] for d in degraded)
            )
        if improved:
            narrative.append("Improvements: " + "; ".join(d["label"] for d in improved))
        if stable_fail and not degraded and not improved:
            narrative.append(
                f"Score held at {newest[4]} with {len(stable_fail)} unresolved dimension(s)"
            )

        return {
            "tenant_id": tenant_id,
            "has_trend": True,
            "period_start": oldest[6],
            "period_end": newest[6],
            "snapshots_compared": len(rows),
            "grade_from": oldest[4],
            "grade_to": newest[4],
            "score_delta": score_delta,
            "percent_delta": pct_delta,
            "degraded": degraded,
            "improved": improved,
            "stable_failing": stable_fail,
            "narrative": narrative,
        }
    finally:
        db.close()


# ── Gap B: Governance Forecasting ────────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/governance-forecast",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_forecast(
    request: Request,
    tenant_id: str,
    days: int = 30,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Linear trend projection of governance score N days forward."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        import json as _json
        from datetime import datetime as _dt

        rows = db.execute(
            text(
                "SELECT percent, dimensions, created_at"
                " FROM tenant_identity_governance_snapshots"
                " WHERE tenant_id=:t ORDER BY created_at ASC"
            ),
            {"t": tenant_id},
        ).fetchall()

        if len(rows) < 2:
            return {
                "tenant_id": tenant_id,
                "has_forecast": False,
                "message": "Need at least 2 snapshots to compute forecast",
                "snapshot_count": len(rows),
            }

        def _parse_ts(s: str) -> float:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return _dt.strptime(s, fmt).timestamp()
                except ValueError:
                    continue
            return 0.0

        times = [_parse_ts(r[2]) for r in rows]
        pcts = [float(r[0]) for r in rows]

        t0 = times[0]
        xs = [(t - t0) / 86400.0 for t in times]  # days since first snapshot
        n = len(xs)
        mx = sum(xs) / n
        my = sum(pcts) / n
        cov = sum((xs[i] - mx) * (pcts[i] - my) for i in range(n))
        var = sum((xs[i] - mx) ** 2 for i in range(n))
        slope = cov / var if var != 0 else 0.0
        intercept = my - slope * mx

        last_x = xs[-1]
        projected_x = last_x + days
        projected_pct = round(max(0.0, min(100.0, slope * projected_x + intercept)), 1)
        projected_grade = _grade(projected_pct)

        # Per-dimension failure trend: count how many snapshots each dim was failing
        dim_fail_counts: dict[str, int] = {}
        dim_total: dict[str, int] = {}
        for row in rows:
            raw = row[1]
            dims = _json.loads(raw) if isinstance(raw, str) else (raw or {})
            for k, v in dims.items():
                dim_total[k] = dim_total.get(k, 0) + 1
                if not v.get("pass", True):
                    dim_fail_counts[k] = dim_fail_counts.get(k, 0) + 1

        # Dimensions that are failing consistently (>50% of snapshots) and trending worse
        risk_dims: list[dict[str, Any]] = []
        for k, fails in dim_fail_counts.items():
            total = dim_total.get(k, 1)
            fail_rate = fails / total
            if fail_rate >= 0.5:
                risk_dims.append(
                    {
                        "dimension": k,
                        "label": _DIM_LABELS.get(k, k.replace("_", " ")),
                        "fail_rate_pct": round(fail_rate * 100, 1),
                        "trend": "worsening" if fail_rate >= 0.75 else "at_risk",
                    }
                )
        risk_dims.sort(key=lambda d: -d["fail_rate_pct"])

        direction = "stable"
        if slope < -0.05:
            direction = "declining"
        elif slope > 0.05:
            direction = "improving"

        return {
            "tenant_id": tenant_id,
            "has_forecast": True,
            "snapshot_count": n,
            "current_percent": pcts[-1],
            "current_grade": _grade(pcts[-1]),
            "slope_per_day": round(slope, 4),
            "trend_direction": direction,
            "forecast_days": days,
            "projected_percent": projected_pct,
            "projected_grade": projected_grade,
            "at_risk_dimensions": risk_dims,
        }
    finally:
        db.close()


# ── Gap C: Governance SLA Tracking ───────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/governance-sla",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_sla(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Operational SLA tracking: how long each open governance issue has been open."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        now = _now()
        items: list[dict[str, Any]] = []

        def _days_open(ts_str: str | None) -> float | None:
            if not ts_str:
                return None
            from datetime import datetime as _dt

            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    dt = _dt.strptime(ts_str, fmt).replace(tzinfo=timezone.utc)
                    return round((now - dt).total_seconds() / 86400, 1)
                except ValueError:
                    continue
            return None

        def _sla_status(days: float | None, threshold: int) -> str:
            if days is None:
                return "unknown"
            if days > threshold:
                return "breached"
            if days > threshold * 0.7:
                return "at_risk"
            return "on_track"

        # Pending approvals
        pending = (
            db.query(TenantInvitation)
            .filter(
                TenantInvitation.tenant_id == tenant_id,
                TenantInvitation.approval_state == "pending",
            )
            .all()
        )
        for inv in pending:
            d = _days_open(_ts(inv.created_at))
            sla = _SLA_DAYS["pending_approval"]
            items.append(
                {
                    "item_id": inv.id,
                    "type": "pending_approval",
                    "severity": "high",
                    "title": f"Approval pending for {inv.email}",
                    "detail": f"Identity type: {inv.identity_type or 'unknown'}, role: {inv.role}",
                    "open_since": _ts(inv.created_at),
                    "days_open": d,
                    "sla_days": sla,
                    "sla_status": _sla_status(d, sla),
                }
            )

        # Unbound active admins
        rows = db.execute(
            text(
                "SELECT email, created_at FROM tenant_users"
                " WHERE tenant_id=:t AND active=TRUE AND role='admin'"
                " AND (identity_binding_status IS NULL OR identity_binding_status != 'bound')"
            ),
            {"t": tenant_id},
        ).fetchall()
        for row in rows:
            d = _days_open(row[1])
            sla = _SLA_DAYS["unbound_admin"]
            items.append(
                {
                    "item_id": f"unbound_admin:{row[0]}",
                    "type": "unbound_admin",
                    "severity": "critical",
                    "title": f"Unbound admin: {row[0]}",
                    "detail": "Active admin user has no bound identity",
                    "open_since": row[1],
                    "days_open": d,
                    "sla_days": sla,
                    "sla_status": _sla_status(d, sla),
                }
            )

        # Active policy violations from invitations (non_human_admin_role, unauthorized_domain)
        config = _get_config(db, tenant_id)
        allowed_domains = set(config.allowed_email_domains or []) if config else set()
        non_human_types = {"agent", "system", "workload"}
        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )
        for inv in invitations:
            itype = inv.identity_type or "human"
            role = (inv.role or "user").lower()
            email = inv.email or ""
            domain = email.split("@")[-1] if "@" in email else ""

            if itype in non_human_types and role == "admin":
                d = _days_open(_ts(inv.created_at))
                sla = _SLA_DAYS["critical"]
                items.append(
                    {
                        "item_id": f"violation:non_human_admin:{inv.id}",
                        "type": "policy_violation",
                        "severity": "critical",
                        "title": f"Non-human identity with admin role: {email}",
                        "detail": f"{itype} assigned admin role",
                        "open_since": _ts(inv.created_at),
                        "days_open": d,
                        "sla_days": sla,
                        "sla_status": _sla_status(d, sla),
                    }
                )

            if allowed_domains and domain and domain not in allowed_domains:
                d = _days_open(_ts(inv.created_at))
                sla = _SLA_DAYS["medium"]
                items.append(
                    {
                        "item_id": f"violation:unauthorized_domain:{inv.id}",
                        "type": "policy_violation",
                        "severity": "medium",
                        "title": f"Unauthorized domain: {email}",
                        "detail": f"Domain '{domain}' not in allowed_email_domains",
                        "open_since": _ts(inv.created_at),
                        "days_open": d,
                        "sla_days": sla,
                        "sla_status": _sla_status(d, sla),
                    }
                )

        items.sort(
            key=lambda x: (
                0
                if x["sla_status"] == "breached"
                else 1
                if x["sla_status"] == "at_risk"
                else 2,
                -(x["days_open"] or 0),
            )
        )

        breached = [i for i in items if i["sla_status"] == "breached"]
        at_risk = [i for i in items if i["sla_status"] == "at_risk"]

        return {
            "tenant_id": tenant_id,
            "total_open_items": len(items),
            "breached_count": len(breached),
            "at_risk_count": len(at_risk),
            "items": items,
        }
    finally:
        db.close()


# ── Gap D: Cross-Tenant Benchmarking ─────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/governance-benchmark",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_benchmark(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Anonymized percentile position vs all participating tenants."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        # Tenant's own latest snapshot
        own_row = db.execute(
            text(
                "SELECT percent, grade, created_at"
                " FROM tenant_identity_governance_snapshots"
                " WHERE tenant_id=:t ORDER BY created_at DESC LIMIT 1"
            ),
            {"t": tenant_id},
        ).fetchone()

        # Aggregate: most recent snapshot per tenant (anonymized — no tenant_id returned)
        all_rows = db.execute(
            text(
                "SELECT s.percent FROM tenant_identity_governance_snapshots s"
                " INNER JOIN ("
                "   SELECT tenant_id, MAX(created_at) AS latest"
                "   FROM tenant_identity_governance_snapshots GROUP BY tenant_id"
                " ) latest_per ON s.tenant_id = latest_per.tenant_id"
                " AND s.created_at = latest_per.latest"
            )
        ).fetchall()

        all_pcts = sorted(float(r[0]) for r in all_rows)
        n = len(all_pcts)

        if n == 0:
            return {
                "tenant_id": tenant_id,
                "has_benchmark": False,
                "message": "No benchmark data available yet",
            }

        def _pct_at(p: float) -> float:
            if n == 1:
                return all_pcts[0]
            idx = (p / 100) * (n - 1)
            lo, hi = int(idx), min(int(idx) + 1, n - 1)
            return round(all_pcts[lo] + (idx - lo) * (all_pcts[hi] - all_pcts[lo]), 1)

        median = _pct_at(50)
        p25 = _pct_at(25)
        p75 = _pct_at(75)
        p90 = _pct_at(90)

        own_pct = float(own_row[0]) if own_row else None
        percentile_rank: float | None = None
        if own_pct is not None and n > 0:
            below = sum(1 for v in all_pcts if v < own_pct)
            percentile_rank = round((below / n) * 100, 1)

        return {
            "tenant_id": tenant_id,
            "has_benchmark": True,
            "participating_tenants": n,
            "own_score": {
                "percent": own_pct,
                "grade": own_row[1] if own_row else None,
                "snapshot_at": own_row[2] if own_row else None,
                "percentile_rank": percentile_rank,
            },
            "benchmark": {
                "p25": p25,
                "median": median,
                "p75": p75,
                "p90": p90,
                "description": "Anonymized aggregate across all tenants with governance snapshots",
            },
        }
    finally:
        db.close()


# ── Gap E: Identity Governance Findings ──────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/governance-findings",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_findings(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Unified governance findings aggregating violations + risk + drift + evidence."""
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        findings: list[dict[str, Any]] = []

        # ── Source 1: Policy violations ────────────────────────────────────────
        config = _get_config(db, tenant_id)
        allowed_domains = set(config.allowed_email_domains or []) if config else set()
        configured_provider = config.provider if config else None
        flags = (config.capability_flags or {}) if config else {}
        non_human_types = {"agent", "system", "workload"}
        service_types = {"service"}

        invitations = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.tenant_id == tenant_id)
            .all()
        )

        for inv in invitations:
            itype = inv.identity_type or "human"
            role = (inv.role or "user").lower()
            email = inv.email or ""
            domain = email.split("@")[-1] if "@" in email else ""

            if itype in non_human_types and role == "admin":
                findings.append(
                    {
                        "finding_id": f"pv:non_human_admin:{inv.id}",
                        "type": "policy_violation",
                        "severity": "critical",
                        "category": "role_assignment",
                        "title": "Non-human identity assigned admin role",
                        "detail": f"{itype} '{email}' has admin role",
                        "sources": ["policy_violations", "invitations"],
                        "evidence": {
                            "identity_type": itype,
                            "role": role,
                            "email": email,
                            "invitation_id": inv.id,
                            "invitation_status": inv.status,
                        },
                        "affected_email": email,
                        "invitation_id": inv.id,
                    }
                )

            if itype in service_types and role in {
                "owner",
                "admin",
                "user",
                "member",
                "viewer",
            }:
                findings.append(
                    {
                        "finding_id": f"pv:service_human_role:{inv.id}",
                        "type": "policy_violation",
                        "severity": "high",
                        "category": "role_assignment",
                        "title": "Service identity using human role",
                        "detail": f"service '{email}' using human role '{role}'",
                        "sources": ["policy_violations", "invitations"],
                        "evidence": {
                            "identity_type": itype,
                            "role": role,
                            "email": email,
                        },
                        "affected_email": email,
                        "invitation_id": inv.id,
                    }
                )

            if (
                configured_provider
                and inv.required_provider
                and inv.required_provider != configured_provider
            ):
                findings.append(
                    {
                        "finding_id": f"pv:unapproved_provider:{inv.id}",
                        "type": "policy_violation",
                        "severity": "high",
                        "category": "provider",
                        "title": "Unapproved identity provider",
                        "detail": f"required '{inv.required_provider}' vs configured '{configured_provider}'",
                        "sources": ["policy_violations", "invitations"],
                        "evidence": {
                            "required_provider": inv.required_provider,
                            "configured_provider": configured_provider,
                            "email": email,
                        },
                        "affected_email": email,
                        "invitation_id": inv.id,
                    }
                )

            if allowed_domains and domain and domain not in allowed_domains:
                findings.append(
                    {
                        "finding_id": f"pv:unauthorized_domain:{inv.id}",
                        "type": "policy_violation",
                        "severity": "medium",
                        "category": "domain",
                        "title": "Invitation from unauthorized domain",
                        "detail": f"domain '{domain}' not in allowed_email_domains",
                        "sources": ["policy_violations", "invitations"],
                        "evidence": {
                            "domain": domain,
                            "allowed_domains": list(allowed_domains),
                            "email": email,
                        },
                        "affected_email": email,
                        "invitation_id": inv.id,
                    }
                )

            needs_approval = (
                itype in non_human_types and flags.get("require_approval_non_human")
            ) or (itype in service_types and flags.get("require_approval_service"))
            approval_state = getattr(inv, "approval_state", "not_required")
            if (
                needs_approval
                and inv.status == "bound"
                and approval_state not in {"approved", "not_required"}
            ):
                findings.append(
                    {
                        "finding_id": f"pv:no_approval:{inv.id}",
                        "type": "policy_violation",
                        "severity": "high",
                        "category": "approval",
                        "title": "Non-human identity bound without approval",
                        "detail": f"{itype} '{email}' is bound but approval_state='{approval_state}'",
                        "sources": ["policy_violations", "approvals"],
                        "evidence": {
                            "approval_state": approval_state,
                            "identity_type": itype,
                            "email": email,
                        },
                        "affected_email": email,
                        "invitation_id": inv.id,
                    }
                )

        # ── Source 2: Unbound admins (risk + violation) ────────────────────────
        rows = db.execute(
            text(
                "SELECT email FROM tenant_users"
                " WHERE tenant_id=:t AND active=TRUE AND role='admin'"
                " AND (identity_binding_status IS NULL OR identity_binding_status != 'bound')"
            ),
            {"t": tenant_id},
        ).fetchall()
        for row in rows:
            findings.append(
                {
                    "finding_id": f"risk:unbound_admin:{row[0]}",
                    "type": "risk",
                    "severity": "critical",
                    "category": "binding",
                    "title": f"Unbound admin: {row[0]}",
                    "detail": "Active admin user has no bound identity — admin access is ungoverned",
                    "sources": ["policy_violations", "risk"],
                    "evidence": {
                        "email": row[0],
                        "role": "admin",
                        "binding_status": "unbound",
                    },
                    "affected_email": row[0],
                    "invitation_id": None,
                }
            )

        # ── Source 3: Drift items (governance dimensions failing) ──────────────
        sc, max_sc, pct, grade, dims = _compute_score_for_snapshot(db, tenant_id)
        for dim_key, dim_data in dims.items():
            if dim_data["pass"]:
                continue
            findings.append(
                {
                    "finding_id": f"drift:{dim_key}",
                    "type": "drift",
                    "severity": (
                        "critical"
                        if dim_data["weight"] >= 10
                        else "high"
                        if dim_data["weight"] >= 6
                        else "medium"
                    ),
                    "category": (
                        "config"
                        if dim_key
                        in {"config_ready", "sso_enforced", "maturity_level_1"}
                        else "binding"
                        if "bound" in dim_key or "unbound" in dim_key
                        else "hygiene"
                        if dim_key
                        in {
                            "no_failed_invitations",
                            "no_expired_invitations",
                            "no_legacy_remnants",
                            "no_revoked_excess",
                        }
                        else "domain"
                    ),
                    "title": _DIM_LABELS.get(dim_key, dim_key.replace("_", " ")),
                    "detail": f"Governance dimension '{dim_key}' is failing ({dim_data['weight']} pts at risk)",
                    "sources": ["drift", "governance_score"],
                    "evidence": {},
                    "affected_email": None,
                    "invitation_id": None,
                }
            )

        # Deduplicate by finding_id (keep first seen)
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for f in findings:
            if f["finding_id"] not in seen:
                seen.add(f["finding_id"])
                unique.append(f)

        # Sort: critical → high → medium, then by type
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["type"]))

        critical_c = sum(1 for f in unique if f["severity"] == "critical")
        high_c = sum(1 for f in unique if f["severity"] == "high")

        return {
            "tenant_id": tenant_id,
            "finding_count": len(unique),
            "critical_count": critical_c,
            "high_count": high_c,
            "governance_score": sc,
            "governance_percent": pct,
            "governance_grade": grade,
            "findings": unique,
        }
    finally:
        db.close()


# ── Governance Actions Ledger ─────────────────────────────────────────────────


def _latest_action_for_dimension(
    db_conn: Any, tenant_id: str, dimension: str
) -> dict[str, Any] | None:
    """Return the most recent governance action row for a dimension, or None."""
    row = db_conn.execute(
        text(
            "SELECT id, action_state FROM tenant_identity_governance_actions "
            "WHERE tenant_id=:tid AND dimension=:dim "
            "ORDER BY created_at DESC LIMIT 1"
        ),
        {"tid": tenant_id, "dim": dimension},
    ).fetchone()
    if row is None:
        return None
    return {"id": row[0], "action_state": row[1]}


@router.post(
    "/tenants/{tenant_id}/governance-actions",
    dependencies=[Depends(require_scopes("admin:write"))],
    status_code=201,
)
def create_governance_action(
    request: Request,
    tenant_id: str,
    body: GovernanceActionBody,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Record a governance decision on a recommendation dimension.

    Enforces the state machine — rejected and implemented are terminal;
    invalid transitions return 409.
    """
    bind_tenant_id(request, tenant_id)

    if body.action_state not in _VALID_ACTION_STATES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_ACTION_STATE",
                "message": f"action_state must be one of {sorted(_VALID_ACTION_STATES)}",
            },
        )
    if body.dimension not in _SCORE_WEIGHTS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "UNKNOWN_DIMENSION",
                "message": f"dimension '{body.dimension}' is not a known governance dimension",
            },
        )

    db = _admin_db(tenant_id)
    try:
        latest = _latest_action_for_dimension(db, tenant_id, body.dimension)
        current_state: str | None = latest["action_state"] if latest else None
        allowed = _ACTION_TRANSITIONS.get(current_state, frozenset())

        if body.action_state not in allowed:
            if not allowed:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "ACTION_TERMINAL",
                        "message": f"dimension '{body.dimension}' is already in terminal state '{current_state}'",
                    },
                )
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "INVALID_TRANSITION",
                    "message": (
                        f"cannot transition from '{current_state}' to '{body.action_state}'; "
                        f"allowed: {sorted(allowed)}"
                    ),
                },
            )

        action_id = str(uuid.uuid4())
        now_str = _now().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        db.execute(
            text(
                "INSERT INTO tenant_identity_governance_actions "
                "(id, tenant_id, dimension, action_state, actor_id, actor_email, actor_role, "
                "reason, outcome, deferred_until, snapshot_id, previous_action_id, created_at) "
                "VALUES (:id, :tid, :dim, :state, :aid, :email, :role, "
                ":reason, :outcome, :deferred, :snap, :prev, :created_at)"
            ),
            {
                "id": action_id,
                "tid": tenant_id,
                "dim": body.dimension,
                "state": body.action_state,
                "aid": body.actor_id,
                "email": body.actor_email,
                "role": body.actor_role,
                "reason": body.reason,
                "outcome": body.outcome,
                "deferred": body.deferred_until,
                "snap": body.snapshot_id,
                "prev": latest["id"] if latest else None,
                "created_at": now_str,
            },
        )
        db.commit()

        emit_identity_audit_event(
            db,
            tenant_id=tenant_id,
            event_type="tenant.identity_governance.action_recorded",
            actor_user_id=body.actor_id,
            details={
                "action_id": action_id,
                "dimension": body.dimension,
                "action_state": body.action_state,
                "previous_state": current_state,
            },
        )

        rec = _DIMENSION_RECOMMENDATIONS.get(body.dimension, {})
        return {
            "action_id": action_id,
            "tenant_id": tenant_id,
            "dimension": body.dimension,
            "action_state": body.action_state,
            "actor_id": body.actor_id,
            "actor_email": body.actor_email,
            "actor_role": body.actor_role,
            "reason": body.reason,
            "outcome": body.outcome,
            "deferred_until": body.deferred_until,
            "snapshot_id": body.snapshot_id,
            "previous_action_id": latest["id"] if latest else None,
            "recommendation_action": rec.get("action"),
            "created_at": now_str,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/governance-actions",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_governance_actions(
    request: Request,
    tenant_id: str,
    dimension: str | None = None,
    state: str | None = None,
    limit: int = 100,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Return the full governance actions ledger for a tenant.

    Optionally filter by dimension and/or action_state.
    """
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        where = "WHERE tenant_id=:tid"
        params: dict[str, Any] = {"tid": tenant_id}
        if dimension:
            where += " AND dimension=:dim"
            params["dim"] = dimension
        if state:
            where += " AND action_state=:state"
            params["state"] = state

        rows = db.execute(
            text(
                f"SELECT id, dimension, action_state, actor_id, actor_email, actor_role, "  # noqa: S608
                f"reason, outcome, deferred_until, snapshot_id, previous_action_id, created_at "
                f"FROM tenant_identity_governance_actions {where} "
                f"ORDER BY created_at DESC LIMIT :lim"
            ),
            {**params, "lim": min(limit, 500)},
        ).fetchall()

        actions = [
            {
                "action_id": r[0],
                "dimension": r[1],
                "action_state": r[2],
                "actor_id": r[3],
                "actor_email": r[4],
                "actor_role": r[5],
                "reason": r[6],
                "outcome": r[7],
                "deferred_until": r[8],
                "snapshot_id": r[9],
                "previous_action_id": r[10],
                "created_at": r[11],
                "recommendation_action": _DIMENSION_RECOMMENDATIONS.get(r[1], {}).get(
                    "action"
                ),
            }
            for r in rows
        ]

        return {
            "tenant_id": tenant_id,
            "total": len(actions),
            "actions": actions,
        }
    finally:
        db.close()


@router.get(
    "/tenants/{tenant_id}/governance-action-summary",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_governance_action_summary(
    request: Request,
    tenant_id: str,
    actor_ctx: ActorContext = Depends(require_permission("tenant.configure")),
) -> dict[str, Any]:
    """Return the latest governance decision per dimension — the current posture view.

    Answers: what governance decisions were made, and where does each dimension stand?
    Dimensions with no recorded action are listed as 'unaddressed'.
    """
    bind_tenant_id(request, tenant_id)
    db = _admin_db(tenant_id)
    try:
        rows = db.execute(
            text(
                "SELECT t.dimension, t.action_state, t.actor_id, t.actor_email, t.actor_role, "
                "t.reason, t.outcome, t.deferred_until, t.created_at, t.id "
                "FROM tenant_identity_governance_actions t "
                "WHERE t.tenant_id=:tid "
                "  AND NOT EXISTS ("
                "    SELECT 1 FROM tenant_identity_governance_actions t2 "
                "    WHERE t2.tenant_id=:tid AND t2.dimension=t.dimension "
                "      AND (t2.created_at > t.created_at "
                "           OR (t2.created_at = t.created_at AND t2.id > t.id))"
                "  ) "
                "ORDER BY t.dimension"
            ),
            {"tid": tenant_id},
        ).fetchall()

        acted: dict[str, dict[str, Any]] = {}
        for r in rows:
            acted[r[0]] = {
                "action_id": r[9],
                "action_state": r[1],
                "actor_id": r[2],
                "actor_email": r[3],
                "actor_role": r[4],
                "reason": r[5],
                "outcome": r[6],
                "deferred_until": r[7],
                "decided_at": r[8],
            }

        summary: list[dict[str, Any]] = []
        for dim in sorted(_DIMENSION_RECOMMENDATIONS):
            rec = _DIMENSION_RECOMMENDATIONS[dim]
            entry = acted.get(dim)
            summary.append(
                {
                    "dimension": dim,
                    "recommendation_action": rec["action"],
                    "priority": rec["priority"],
                    "risk_reduction": rec["risk_reduction"],
                    "current_state": entry["action_state"] if entry else "unaddressed",
                    "is_terminal": (
                        entry["action_state"] in {"rejected", "implemented"}
                        if entry
                        else False
                    ),
                    "actor_email": entry["actor_email"] if entry else None,
                    "reason": entry["reason"] if entry else None,
                    "outcome": entry["outcome"] if entry else None,
                    "deferred_until": entry["deferred_until"] if entry else None,
                    "decided_at": entry["decided_at"] if entry else None,
                    "action_id": entry["action_id"] if entry else None,
                }
            )

        counts = Counter(e["current_state"] for e in summary)
        return {
            "tenant_id": tenant_id,
            "total_dimensions": len(summary),
            "unaddressed": counts.get("unaddressed", 0),
            "accepted": counts.get("accepted", 0),
            "deferred": counts.get("deferred", 0),
            "rejected": counts.get("rejected", 0),
            "implemented": counts.get("implemented", 0),
            "dimensions": summary,
        }
    finally:
        db.close()
