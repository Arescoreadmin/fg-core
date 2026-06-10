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

from api.auth_scopes import bind_tenant_id, require_scopes
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

# ── Risk bands ────────────────────────────────────────────────────────────────
_RISK_HIGH_PENDING_THRESHOLD = 5
_RISK_HIGH_FAILED_THRESHOLD = 3
_RISK_HIGH_UNVERIFIED_DOMAINS = 2


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
        "expires_at": _ts(inv.expires_at),
        "revoked_at": _ts(inv.revoked_at),
        "accepted_at": _ts(inv.accepted_at),
        "bound_at": _ts(inv.bound_at),
        "created_at": _ts(inv.created_at),
        "updated_at": _ts(inv.updated_at),
    }


# ── Routes ────────────────────────────────────────────────────────────────────


@router.get(
    "/tenants/{tenant_id}/config", dependencies=[Depends(require_scopes("admin:read"))]
)
def get_config(request: Request, tenant_id: str) -> dict[str, Any]:
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
    "/tenants/{tenant_id}/config", dependencies=[Depends(require_scopes("admin:write"))]
)
def upsert_config(
    request: Request, tenant_id: str, body: ConfigUpsertBody
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
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_readiness(request: Request, tenant_id: str) -> dict[str, Any]:
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
def list_invitations(request: Request, tenant_id: str) -> dict[str, Any]:
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
    request: Request, tenant_id: str, body: InviteCreateBody
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
        # FIX 3: persist identity_type on the invitation row
        inv.identity_type = body.identity_type
        db.commit()
        return _serialize_invitation(inv)
    finally:
        db.close()


@router.post(
    "/invitations/{invitation_id}/revoke",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_invitation(request: Request, invitation_id: str) -> dict[str, Any]:
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
def resend_invitation(request: Request, invitation_id: str) -> dict[str, Any]:
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
def get_audit_summary(request: Request, tenant_id: str) -> dict[str, Any]:
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
def get_governance_score(request: Request, tenant_id: str) -> dict[str, Any]:
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

        def _dim(key: str, passing: bool, detail: Any = None) -> None:
            nonlocal score
            w = _SCORE_WEIGHTS[key]
            if passing:
                score += w
            dimensions[key] = {"pass": passing, "weight": w, "detail": detail}

        # Core config health
        _dim(
            "config_ready",
            config.provisioning_status == "ready",
            config.provisioning_status,
        )
        _dim("sso_enforced", bool(config.sso_enforced), config.sso_enforced)
        _dim(
            "maturity_level_1",
            config.maturity_level not in {"level_0", None},
            config.maturity_level,
        )

        # Identity binding quality
        bound_pct = bound_users / max(total_active, 1) if total_active else 1.0
        _dim(
            "bound_identity_percent",
            bound_pct >= 0.9,
            f"{bound_users}/{total_active} ({round(bound_pct * 100)}%)",
        )
        _dim("no_unbound_active", unbound_active == 0, unbound_active)
        inv_bound_pct = bound_inv / max(total_inv, 1) if total_inv else 1.0
        _dim(
            "verified_identity_percent",
            inv_bound_pct >= 0.8,
            f"{bound_inv}/{total_inv} ({round(inv_bound_pct * 100)}%)",
        )

        # Invitation hygiene
        _dim("no_failed_invitations", failed_inv == 0, failed_inv)
        _dim("no_expired_invitations", expired_inv == 0, expired_inv)
        _dim("no_legacy_remnants", legacy_tokens == 0, legacy_tokens)
        revoke_rate = revoked_inv / max(total_inv, 1) if total_inv else 0.0
        _dim(
            "no_revoked_excess",
            revoke_rate <= 0.2,
            f"{revoked_inv}/{total_inv} ({round(revoke_rate * 100)}%)",
        )

        # Domain, provider, and type health
        _dim(
            "domains_verified",
            verified_domains > 0 or len(domains) == 0,
            f"{verified_domains}/{len(domains)}",
        )
        _dim("multi_provider", len(providers) > 1, len(providers))
        _dim(
            "identity_type_mix",
            len(identity_types_used) > 1,
            sorted(identity_types_used) if identity_types_used else [],
        )

        # Audit integrity
        _dim("audit_chain_intact", True, "chain_presence_verified")

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
def get_drift(request: Request, tenant_id: str) -> dict[str, Any]:
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
def get_timeline(request: Request, tenant_id: str, limit: int = 50) -> dict[str, Any]:
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
def get_readiness_history(request: Request, tenant_id: str) -> dict[str, Any]:
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
def get_risk(request: Request, tenant_id: str) -> dict[str, Any]:
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
def get_identity_types(request: Request, tenant_id: str) -> dict[str, Any]:
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
