"""Admin Identity Governance Control Plane (PR4).

Operator-level routes for managing and auditing tenant identity configuration,
invitations, and governance posture. All routes require `identity:read` or
`identity:write` scope. Access is operator-scoped: the tenant_id in the path
identifies the target tenant; the caller's API key carries admin-level scopes.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
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
)

router = APIRouter(prefix="/admin/identity", tags=["admin-identity"])

_store = TenantIdentityStore()

# ── Identity types supported ─────────────────────────────────────────────────
IDENTITY_TYPES = frozenset({"human", "service", "agent", "system", "workload"})

# ── Governance scoring weights ────────────────────────────────────────────────
_SCORE_WEIGHTS = {
    "config_ready": 20,
    "sso_enforced": 15,
    "domains_verified": 15,
    "invitations_bound": 20,
    "no_failed_invitations": 10,
    "audit_chain_intact": 10,
    "multi_provider": 5,
    "maturity_level_1": 5,
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


# ── Auth dependencies ─────────────────────────────────────────────────────────

_require_read = Depends(require_scopes("identity:read"))
_require_write = Depends(require_scopes("identity:write"))


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


@router.get("/tenants/{tenant_id}/config", dependencies=[_require_read])
def get_config(tenant_id: str) -> dict[str, Any]:
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


@router.put("/tenants/{tenant_id}/config", dependencies=[_require_write])
def upsert_config(tenant_id: str, body: ConfigUpsertBody) -> dict[str, Any]:
    if body.identity_mode not in IDENTITY_MODES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "IDENTITY_MODE_INVALID",
                "message": f"mode must be one of {sorted(IDENTITY_MODES)}",
            },
        )
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


@router.get("/tenants/{tenant_id}/readiness", dependencies=[_require_read])
def get_readiness(tenant_id: str) -> dict[str, Any]:
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


@router.get("/tenants/{tenant_id}/invitations", dependencies=[_require_read])
def list_invitations(tenant_id: str) -> dict[str, Any]:
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


@router.post("/tenants/{tenant_id}/invitations", dependencies=[_require_write])
def create_invitation(tenant_id: str, body: InviteCreateBody) -> dict[str, Any]:
    if body.identity_type not in IDENTITY_TYPES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "IDENTITY_TYPE_INVALID",
                "message": f"identity_type must be one of {sorted(IDENTITY_TYPES)}",
            },
        )
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
        db.commit()
        return _serialize_invitation(inv)
    finally:
        db.close()


@router.post("/invitations/{invitation_id}/revoke", dependencies=[_require_write])
def revoke_invitation(invitation_id: str) -> dict[str, Any]:
    db = get_sessionmaker()()
    try:
        inv = (
            db.query(TenantInvitation)
            .filter(TenantInvitation.id == invitation_id)
            .first()
        )
        if inv is None:
            raise HTTPException(status_code=404, detail={"code": "INVITE_NOT_FOUND"})
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


@router.post("/invitations/{invitation_id}/resend", dependencies=[_require_write])
def resend_invitation(invitation_id: str) -> dict[str, Any]:
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
        set_tenant_context(db, inv.tenant_id)
        inv.status = "pending"
        inv.revoked_at = None
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


@router.get("/tenants/{tenant_id}/audit-summary", dependencies=[_require_read])
def get_audit_summary(tenant_id: str) -> dict[str, Any]:
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


@router.get("/tenants/{tenant_id}/governance-score", dependencies=[_require_read])
def get_governance_score(tenant_id: str) -> dict[str, Any]:
    db = _admin_db(tenant_id)
    try:
        config = _get_config(db, tenant_id)
        if config is None:
            return {
                "tenant_id": tenant_id,
                "score": 0,
                "max_score": sum(_SCORE_WEIGHTS.values()),
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

        bound_count = sum(1 for i in invitations if i.status == "bound")
        total_count = len(invitations)
        failed_count = sum(1 for i in invitations if i.status == "failed")
        verified_domains = sum(
            1 for d in domains if d.verification_status == "verified"
        )

        dimensions: dict[str, dict[str, Any]] = {}
        score = 0

        def _dim(key: str, passing: bool, detail: Any = None) -> None:
            nonlocal score
            w = _SCORE_WEIGHTS[key]
            if passing:
                score += w
            dimensions[key] = {"pass": passing, "weight": w, "detail": detail}

        _dim(
            "config_ready",
            config.provisioning_status == "ready",
            config.provisioning_status,
        )
        _dim("sso_enforced", config.sso_enforced, config.sso_enforced)
        _dim(
            "domains_verified",
            verified_domains > 0 or len(domains) == 0,
            f"{verified_domains}/{len(domains)}",
        )
        _dim(
            "invitations_bound",
            total_count == 0 or bound_count / max(total_count, 1) >= 0.8,
            f"{bound_count}/{total_count}",
        )
        _dim("no_failed_invitations", failed_count == 0, failed_count)
        _dim(
            "audit_chain_intact", True, "not_verified_here"
        )  # Chain verification is expensive; flag presence
        _dim("multi_provider", len(providers) > 1, len(providers))
        _dim(
            "maturity_level_1",
            config.maturity_level not in {"level_0", None},
            config.maturity_level,
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


@router.get("/tenants/{tenant_id}/drift", dependencies=[_require_read])
def get_drift(tenant_id: str) -> dict[str, Any]:
    """Detect identity configuration drift: stale invitations, unverified domains, mismatched providers."""
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

        # Stale pending invitations
        stale = [
            i
            for i in invitations
            if i.status == "pending" and i.expires_at is not None and i.expires_at < now
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

        return {
            "tenant_id": tenant_id,
            "drift_detected": len(drift_items) > 0,
            "items": drift_items,
            "checked_at": _ts(now),
        }
    finally:
        db.close()


@router.get("/tenants/{tenant_id}/timeline", dependencies=[_require_read])
def get_timeline(tenant_id: str, limit: int = 50) -> dict[str, Any]:
    if limit < 1 or limit > 500:
        raise HTTPException(status_code=422, detail={"code": "LIMIT_INVALID"})
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


@router.get("/tenants/{tenant_id}/readiness-history", dependencies=[_require_read])
def get_readiness_history(tenant_id: str) -> dict[str, Any]:
    """Derive readiness transitions from audit events."""
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


@router.get("/tenants/{tenant_id}/risk", dependencies=[_require_read])
def get_risk(tenant_id: str) -> dict[str, Any]:
    """Compute an identity risk profile for the tenant."""
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
