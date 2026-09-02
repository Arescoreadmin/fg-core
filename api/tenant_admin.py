"""api/tenant_admin.py — TENANT-ADMIN-001 delegated administration routes.

Endpoints under ``/admin/tenants/{tenant_id}/...`` for delegated tenant
administration. Every mutation gates on ``require_tenant_admin()`` — the
canonical DB-authoritative check from ``tenant_admin_authority.py`` — which
consults ``tenant_users``, not JWT role claims.

The bootstrap endpoint is the ONE exception: it requires
``platform.admin`` and is intended for platform operators to seat the first
tenant_admin. It is idempotent and does not create a durable backdoor.

Route table:

    POST   /admin/tenants/{tenant_id}/bootstrap-admin        platform.admin only
    GET    /admin/tenants/{tenant_id}/users                  tenant_admin (own tenant)
    POST   /admin/tenants/{tenant_id}/users/invite           tenant_admin (own tenant)
    PATCH  /admin/tenants/{tenant_id}/users/{user_id}        tenant_admin (own tenant)
    GET    /admin/tenants/{tenant_id}/portal-access          tenant_admin (own tenant)
    POST   /admin/tenants/{tenant_id}/portal-access/invite   tenant_admin (own tenant)
    DELETE /admin/tenants/{tenant_id}/portal-access/{gid}    tenant_admin (own tenant)

Console and portal remain distinct authorization surfaces. Being a
console tenant_admin does not automatically grant portal access; explicit
portal-access mutations still call the portal grant service authority.

Non-goals (explicit — see docs/architecture/tenant-admin-001.md):
  * NOT a replacement for Auth0.
  * NOT a second RBAC engine.
  * NOT a mechanism to grant tenant admins any platform authority.
  * NOT a bypass of ``resolve_authoritative_tenant`` or RLS.
  * NOT the final client revenue gate — that is TENANT-ACCESS-001 → CLIENT-E2E-001.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text
from sqlalchemy.orm import Session

from api.actor_context import ActorContext
from api.auth_dispatch import require_permission
from api.auth_scopes import require_scopes, resolve_authoritative_tenant
import api.credential_authority as ca
import api.tenant_rbac as tenant_rbac
from api.credential_authority import (
    CredentialNotFoundError,
    CredentialStateError,
    TenantLifecycleError,
    TenantNotFoundError,
    list_credential_events,
)
from api.db import get_engine, set_tenant_context
from api.deps import auth_ctx_db_session
from api.identity.store import emit_identity_audit_event
from api.tenant_admin_authority import (
    TENANT_ADMIN_DENIED,
    TenantAdminAuthority,
    assert_role_delegatable,
    check_tenant_admin_authority,
    require_tenant_admin,
)
from services.identity_resolver import membership_version_svc

log = logging.getLogger("frostgate.tenant_admin")

router = APIRouter(prefix="/admin/tenants", tags=["tenant-admin-001"])


_INVITE_TTL_HOURS = 72
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _validate_email(email: str) -> str:
    e = _norm_email(email)
    if not _EMAIL_RE.match(e):
        raise HTTPException(
            status_code=422,
            detail={"code": "EMAIL_INVALID", "message": "email is invalid"},
        )
    return e


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class BootstrapAdminBody(BaseModel):
    email: str
    display_name: Optional[str] = None
    # Optional pre-bound principal identifier for identity flows that already
    # resolved a canonical principal (rare — normally the invitation flow
    # binds this later). If provided, must be a UUID string.
    principal_id: Optional[str] = None

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _validate_email(v)


class InviteUserBody(BaseModel):
    email: str
    display_name: str
    role: str = "user"

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _validate_email(v)

    @field_validator("display_name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("display_name must not be empty")
        return v


class UpdateUserBody(BaseModel):
    active: Optional[bool] = None
    role: Optional[str] = None
    display_name: Optional[str] = None


_PORTAL_ROLES: frozenset[str] = frozenset(
    {"general", "executive", "remediation", "technical", "compliance"}
)

SELF_SERVICE_CREDENTIAL_ROLES: frozenset[str] = frozenset(
    {
        "governance_admin",
        "analyst",
        "auditor",
        "read_only",
    }
)
PLATFORM_ONLY_CREDENTIAL_ROLES: frozenset[str] = frozenset(
    {
        "tenant_admin",
        "platform_admin",
    }
)


class PortalAccessInviteBody(BaseModel):
    engagement_id: str = Field(..., min_length=1)
    portal_role: str = "general"
    ttl_days: int = Field(default=30, ge=1, le=365)

    @field_validator("portal_role")
    @classmethod
    def _v_portal_role(cls, v: str) -> str:
        normalized = v.lower().strip()
        if normalized not in _PORTAL_ROLES:
            raise ValueError(
                f"portal_role must be one of: {', '.join(sorted(_PORTAL_ROLES))}"
            )
        return normalized


class IssueServiceCredentialBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)

    @field_validator("name")
    @classmethod
    def _v_name(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("name must not be empty")
        return v


class AssignCredentialRoleBody(BaseModel):
    role: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bootstrap_denied(reason: str) -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={
            "code": "BOOTSTRAP_ADMIN_DENIED",
            "message": reason,
        },
    )


def _fetch_tenant_user_by_email(db: Session, tenant_id: str, email: str) -> Any | None:
    return db.execute(
        text("""
            SELECT id, email, display_name, role, active, principal_id,
                   identity_binding_status
            FROM tenant_users
            WHERE tenant_id = :t AND email = :e
            """),
        {"t": tenant_id, "e": email},
    ).fetchone()


def _fetch_tenant_user_by_id(db: Session, tenant_id: str, user_id: str) -> Any | None:
    return db.execute(
        text("""
            SELECT id, email, display_name, role, active, principal_id,
                   identity_binding_status, identity_provider, identity_subject,
                   membership_lifecycle_state
            FROM tenant_users
            WHERE tenant_id = :t AND id = :u
            """),
        {"t": tenant_id, "u": user_id},
    ).fetchone()


def _enqueue_projection_if_bound(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    new_version: int,
) -> None:
    """Enqueue an Auth0 projection outbox row if the membership has a bound
    canonical identity and an auth0 provider record.

    Best-effort: on any error, log and continue. The authoritative mutation
    has already succeeded; projection failures are retried by the worker.
    """
    try:
        row = db.execute(
            text("""
                SELECT principal_id, identity_provider, identity_subject,
                       role, active
                FROM tenant_users
                WHERE tenant_id = :tid AND id = :uid
                """),
            {"tid": tenant_id, "uid": user_id},
        ).fetchone()
        if row is None:
            return
        if (
            row.identity_provider != "auth0"
            or not row.identity_subject
            or not row.principal_id
        ):
            return
        from admin_gateway.identity.projection_outbox import enqueue_projection

        enqueue_projection(
            db,
            membership_id=user_id,
            principal_id=str(row.principal_id),
            tenant_id=tenant_id,
            provider=str(row.identity_provider),
            provider_subject=str(row.identity_subject),
            roles=([] if not row.active else ([str(row.role)] if row.role else [])),
            projection_revision=new_version,
        )
    except Exception:
        log.exception(
            "tenant_admin.projection_enqueue_failed tenant_id=%s user_id=%s",
            tenant_id,
            user_id,
        )


def _credential_to_dict(rec: "ca.CredentialRecord") -> dict[str, Any]:
    meta = rec.metadata or {}
    return {
        "credential_id": rec.credential_id,
        "name": meta.get("name"),
        "status": rec.status,
        "credential_slot": rec.credential_slot,
        "generation": rec.generation,
        "issued_at": rec.issued_at.isoformat() if rec.issued_at else None,
        "expires_at": rec.expires_at.isoformat() if rec.expires_at else None,
        "last_used_at": rec.last_used_at.isoformat() if rec.last_used_at else None,
        "approximate_use_count": rec.approximate_use_count,
    }


def _cred_not_found(credential_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={
            "code": "CREDENTIAL_NOT_FOUND",
            "message": f"Credential {credential_id!r} not found in this tenant.",
        },
    )


def _cred_state_conflict(msg: str) -> HTTPException:
    return HTTPException(
        status_code=409,
        detail={"code": "CREDENTIAL_STATE_CONFLICT", "message": msg},
    )


# ---------------------------------------------------------------------------
# 3C. First-admin bootstrap — platform-only
# ---------------------------------------------------------------------------


@router.post(
    "/{tenant_id}/bootstrap-admin",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def bootstrap_tenant_admin(
    tenant_id: str,
    body: BootstrapAdminBody,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("platform.admin")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Seat the first tenant_admin for a tenant.

    Platform-only endpoint. Requires ``platform.admin``. Idempotent: calling
    twice for the same email is a no-op (returns 200 with ``bootstrapped=False``
    on the second call). Never creates a durable backdoor — after the first
    call the platform admin still has platform.admin, but the tenant_admin
    row it created is subject to the same authority checks as any other.
    """
    set_tenant_context(db, tenant_id)
    # Preserve tenant-context binding — the bootstrap endpoint operates
    # cross-tenant by design (platform authority). We do NOT call
    # resolve_authoritative_tenant here because the platform actor's
    # tenant_id typically differs from the target.
    email = body.email
    display_name = (body.display_name or email).strip() or email

    existing = _fetch_tenant_user_by_email(db, tenant_id, email)
    was_already_admin = False
    if existing is not None:
        was_already_admin = str(existing.role) == "tenant_admin" and bool(
            existing.active
        )
        if not was_already_admin:
            # Promote the existing row to tenant_admin (idempotent path 1).
            db.execute(
                text("""
                    UPDATE tenant_users
                    SET role = 'tenant_admin', active = TRUE,
                        display_name = COALESCE(display_name, :dn),
                        updated_at = :now
                    WHERE tenant_id = :t AND id = :u
                    """),
                {
                    "t": tenant_id,
                    "u": existing.id,
                    "dn": display_name,
                    "now": _now().isoformat(),
                },
            )
            try:
                new_version = membership_version_svc.bump_version(
                    db,
                    membership_id=str(existing.id),
                    tenant_id=tenant_id,
                    reason="tenant_admin_bootstrap",
                )
                _enqueue_projection_if_bound(
                    db,
                    tenant_id=tenant_id,
                    user_id=str(existing.id),
                    new_version=new_version,
                )
            except ValueError:
                pass
        user_id = str(existing.id)
    else:
        # Create the tenant_admin row fresh. principal_id may be null until
        # the identity binding flow completes; the authority check will fail
        # until then, which is the correct fail-closed behavior.
        user_id = str(uuid.uuid4())
        now_iso = _now().isoformat()
        db.execute(
            text("""
                INSERT INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_binding_status, principal_id, created_at,
                     updated_at)
                VALUES
                    (:id, :t, :e, :dn, 'tenant_admin', TRUE,
                     'unbound', :pid, :now, :now)
                """),
            {
                "id": user_id,
                "t": tenant_id,
                "e": email,
                "dn": display_name,
                "pid": body.principal_id,
                "now": now_iso,
            },
        )

    # Emit audit event on the bootstrap surface for chain-of-custody.
    emit_identity_audit_event(
        db,
        tenant_id=tenant_id,
        event_type="tenant.admin.bootstrap",
        actor_user_id=actor_ctx.subject,
        affected_email=email,
        membership_id=user_id,
        reason_code=(
            "ALREADY_TENANT_ADMIN" if was_already_admin else "TENANT_ADMIN_BOOTSTRAPPED"
        ),
        details={
            "actor_source": actor_ctx.auth_source,
            "principal_id_provided": bool(body.principal_id),
        },
    )
    db.commit()

    return {
        "tenant_id": tenant_id,
        "user_id": user_id,
        "email": email,
        "role": "tenant_admin",
        "bootstrapped": not was_already_admin,
    }


# ---------------------------------------------------------------------------
# 3D. Delegated user management — tenant_admin (own tenant only)
# ---------------------------------------------------------------------------


@router.get(
    "/{tenant_id}/users",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_tenant_users(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """List console users for the actor's own tenant."""
    resolved = resolve_authoritative_tenant(request, actor_ctx, tenant_id)
    # Authority check — fail-closed 403 if not canonical tenant_admin.
    check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=resolved)

    rows = db.execute(
        text("""
            SELECT id, email, display_name, role, active,
                   identity_binding_status, principal_id, last_active_at,
                   created_at
            FROM tenant_users
            WHERE tenant_id = :t
            ORDER BY created_at DESC
            """),
        {"t": resolved},
    ).fetchall()

    return {
        "tenant_id": resolved,
        "items": [
            {
                "user_id": str(r.id),
                "email": r.email,
                "display_name": r.display_name,
                "role": r.role,
                "active": bool(r.active),
                "identity_binding_status": r.identity_binding_status,
                "principal_id": (str(r.principal_id) if r.principal_id else None),
                "last_active_at": (
                    r.last_active_at.isoformat()
                    if r.last_active_at and not isinstance(r.last_active_at, str)
                    else r.last_active_at
                ),
                "created_at": (
                    r.created_at
                    if isinstance(r.created_at, str)
                    else r.created_at.isoformat()
                ),
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.post(
    "/{tenant_id}/users/invite",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def invite_tenant_user(
    tenant_id: str,
    body: InviteUserBody,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Invite a new console user to the actor's own tenant.

    Applies the delegation ceiling: only roles in DELEGATABLE_ROLES are
    accepted; tenant_admin, platform_admin, and FrostGate internal roles are
    rejected with ``ROLE_NOT_DELEGATABLE``.
    """
    from sqlalchemy.exc import IntegrityError as _IntegrityError

    assert_role_delegatable(body.role)

    existing = _fetch_tenant_user_by_email(db, authority.tenant_id, body.email)
    if existing is not None:
        # Idempotency: return the existing record; do not raise.
        return {
            "tenant_id": authority.tenant_id,
            "user_id": str(existing.id),
            "email": existing.email,
            "role": existing.role,
            "invited": False,
        }

    user_id = str(uuid.uuid4())
    now_iso = _now().isoformat()
    try:
        db.execute(
            text("""
                INSERT INTO tenant_users
                    (id, tenant_id, email, display_name, role, active,
                     identity_binding_status, created_at, updated_at)
                VALUES
                    (:id, :t, :e, :dn, :role, TRUE, 'unbound', :now, :now)
                """),
            {
                "id": user_id,
                "t": authority.tenant_id,
                "e": body.email,
                "dn": body.display_name,
                "role": body.role,
                "now": now_iso,
            },
        )
    except _IntegrityError:
        db.rollback()
        existing = _fetch_tenant_user_by_email(db, authority.tenant_id, body.email)
        if existing is not None:
            return {
                "tenant_id": authority.tenant_id,
                "user_id": str(existing.id),
                "email": existing.email,
                "role": existing.role,
                "invited": False,
            }
        raise
    emit_identity_audit_event(
        db,
        tenant_id=authority.tenant_id,
        event_type="tenant.member.invited",
        actor_user_id=authority.subject,
        affected_email=body.email,
        membership_id=user_id,
        reason_code="TENANT_ADMIN_INVITED",
        details={
            "role": body.role,
            "delegation_source": "tenant_admin",
        },
    )
    db.commit()

    return {
        "tenant_id": authority.tenant_id,
        "user_id": user_id,
        "email": body.email,
        "role": body.role,
        "invited": True,
    }


@router.patch(
    "/{tenant_id}/users/{user_id}",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def update_tenant_user(
    tenant_id: str,
    user_id: str,
    body: UpdateUserBody,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Update a console user for the actor's own tenant.

    Enforcement:
      * Target user must belong to the actor's tenant (else 404 — do not leak
        existence in other tenants).
      * Role changes go through the delegation ceiling.
      * A tenant_admin CANNOT edit their own row (self-escalation denial).
      * A tenant_admin CANNOT grant tenant_admin (delegation ceiling covers).
      * Role/active changes bump membership_version and enqueue projection.
    """
    row = _fetch_tenant_user_by_id(db, authority.tenant_id, user_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "TARGET_USER_NOT_FOUND",
                "message": "User not found in this tenant.",
            },
        )

    # Self-escalation denial: an admin cannot alter their own role/active.
    if str(row.id) == authority.membership_id and (
        body.role is not None or body.active is not None
    ):
        log.warning(
            "tenant_admin.self_escalation_denied",
            extra={
                "tenant_id": authority.tenant_id,
                "membership_id": authority.membership_id,
            },
        )
        raise HTTPException(
            status_code=403,
            detail={
                "code": "SELF_ESCALATION_DENIED",
                "message": (
                    "Tenant admins cannot modify their own role or active "
                    "flag; ask another tenant_admin or platform admin."
                ),
            },
        )

    # Terminal: revoked memberships cannot be modified through any update path
    if str(row.membership_lifecycle_state or "active") == "revoked":
        raise HTTPException(
            status_code=409,
            detail={
                "code": "MEMBERSHIP_REVOKED",
                "message": "This membership has been revoked and cannot be modified.",
            },
        )

    if body.role is not None:
        assert_role_delegatable(body.role)

    updates: list[str] = ["updated_at = :now"]
    params: dict[str, Any] = {
        "t": authority.tenant_id,
        "u": user_id,
        "now": _now().isoformat(),
    }
    if body.active is not None:
        updates.append("active = :active")
        params["active"] = bool(body.active)
    if body.role is not None:
        updates.append("role = :role")
        params["role"] = body.role
    if body.display_name is not None:
        if not body.display_name.strip():
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "DISPLAY_NAME_INVALID",
                    "message": "display_name must not be empty",
                },
            )
        updates.append("display_name = :dn")
        params["dn"] = body.display_name.strip()

    if len(updates) == 1:  # only updated_at — nothing to do
        return {"tenant_id": authority.tenant_id, "user_id": user_id, "changed": False}

    db.execute(
        text(
            f"UPDATE tenant_users SET {', '.join(updates)} "
            "WHERE tenant_id = :t AND id = :u"
        ),
        params,
    )

    projection_bumped = False
    if body.active is not None or body.role is not None:
        try:
            new_version = membership_version_svc.bump_version(
                db,
                membership_id=user_id,
                tenant_id=authority.tenant_id,
                reason="tenant_admin_update",
            )
            _enqueue_projection_if_bound(
                db,
                tenant_id=authority.tenant_id,
                user_id=user_id,
                new_version=new_version,
            )
            projection_bumped = True
        except ValueError:
            # Row removed between SELECT and UPDATE; treat as no-op.
            pass

    emit_identity_audit_event(
        db,
        tenant_id=authority.tenant_id,
        event_type="tenant.member.updated",
        actor_user_id=authority.subject,
        affected_email=row.email,
        membership_id=user_id,
        reason_code="TENANT_ADMIN_UPDATED",
        details={
            "role_changed": body.role is not None,
            "active_changed": body.active is not None,
            "display_name_changed": body.display_name is not None,
            "projection_bumped": projection_bumped,
        },
    )
    db.commit()

    return {
        "tenant_id": authority.tenant_id,
        "user_id": user_id,
        "changed": True,
    }


# ---------------------------------------------------------------------------
# 3E. Delegated portal access management — tenant_admin (own tenant only)
# ---------------------------------------------------------------------------


@router.get(
    "/{tenant_id}/portal-access",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_tenant_portal_access(
    tenant_id: str,
    request: Request,
    engagement_id: Optional[str] = None,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """List portal grants for the actor's tenant (optionally filtered by
    engagement).

    Delegates to the portal grant service list_grants when engagement_id is
    provided; otherwise returns a summary tally. This preserves the portal
    authority as a distinct surface — we do not re-implement portal read
    logic here.
    """
    from services.portal_grant_service import portal_grant_svc

    items: list[dict[str, Any]] = []
    if engagement_id:
        try:
            views = portal_grant_svc.list_grants(
                db,
                tenant_id=authority.tenant_id,
                engagement_id=engagement_id,
            )
        except Exception:
            log.exception(
                "tenant_admin.portal_list_failed tenant_id=%s engagement_id=%s",
                authority.tenant_id,
                engagement_id,
            )
            views = []
        for v in views:
            items.append(
                {
                    "grant_id": v.id,
                    "engagement_id": v.engagement_id,
                    "client_id": v.client_id,
                    "grant_type": v.grant_type,
                    "status": v.status,
                    "created_by": v.created_by,
                    "created_at": v.created_at,
                    "expires_at": v.expires_at,
                    "last_used_at": v.last_used_at,
                    "revoked_at": v.revoked_at,
                    "rotation_counter": v.rotation_counter,
                }
            )
    else:
        # Aggregate view — enumerate engagements for this tenant and count.
        try:
            rows = db.execute(
                text("""
                    SELECT id FROM fa_engagements WHERE tenant_id = :t
                    """),
                {"t": authority.tenant_id},
            ).fetchall()
            for r in rows:
                try:
                    views = portal_grant_svc.list_grants(
                        db,
                        tenant_id=authority.tenant_id,
                        engagement_id=str(r.id),
                    )
                except Exception:
                    continue
                for v in views:
                    items.append(
                        {
                            "grant_id": v.id,
                            "engagement_id": v.engagement_id,
                            "client_id": v.client_id,
                            "grant_type": v.grant_type,
                            "status": v.status,
                            "created_by": v.created_by,
                            "created_at": v.created_at,
                            "expires_at": v.expires_at,
                            "last_used_at": v.last_used_at,
                            "revoked_at": v.revoked_at,
                            "rotation_counter": v.rotation_counter,
                        }
                    )
        except Exception:
            log.exception(
                "tenant_admin.portal_aggregate_failed tenant_id=%s",
                authority.tenant_id,
            )

    return {
        "tenant_id": authority.tenant_id,
        "engagement_id": engagement_id,
        "items": items,
        "total": len(items),
    }


@router.post(
    "/{tenant_id}/portal-access/invite",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def invite_tenant_portal_access(
    tenant_id: str,
    body: PortalAccessInviteBody,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Grant portal access for an engagement within the actor's tenant.

    Delegates to the canonical portal grant authority (credential_authority
    via portal_grant_service). Engagement ownership is re-verified so a
    tenant_admin cannot grant access to another tenant's engagement.
    """
    from services.field_assessment.store import (
        EngagementNotFound,
        get_engagement,
    )
    from services.portal_grant_service import portal_grant_svc

    try:
        eng = get_engagement(
            db, engagement_id=body.engagement_id, tenant_id=authority.tenant_id
        )
    except EngagementNotFound as exc:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ENGAGEMENT_NOT_FOUND",
                "message": (
                    f"engagement {body.engagement_id!r} not found for this tenant"
                ),
            },
        ) from exc

    client_id = eng.client_name  # derived from engagement, never body

    result = portal_grant_svc.create_grant(
        db,
        tenant_id=authority.tenant_id,
        client_id=client_id,
        engagement_id=body.engagement_id,
        created_by=authority.subject,
        ttl_days=body.ttl_days,
        portal_role=body.portal_role,
    )
    emit_identity_audit_event(
        db,
        tenant_id=authority.tenant_id,
        event_type="tenant.portal_access.invited",
        actor_user_id=authority.subject,
        details={
            "engagement_id": body.engagement_id,
            "portal_role": body.portal_role,
            "credential_id": result.credential_id,
        },
    )
    db.commit()

    return {
        "tenant_id": authority.tenant_id,
        "engagement_id": body.engagement_id,
        "grant_id": result.credential_id,
        "credential_id": result.credential_id,
        "portal_role": body.portal_role,
        "expires_at": result.expires_at,
        "raw_secret": result.raw_secret,
    }


@router.delete(
    "/{tenant_id}/portal-access/{grant_id}",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_tenant_portal_access(
    tenant_id: str,
    grant_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Revoke a portal grant within the actor's tenant."""
    from services.portal_grant_service import portal_grant_svc

    found = portal_grant_svc.revoke_grant(
        db,
        grant_id=grant_id,
        tenant_id=authority.tenant_id,
        revoked_by=authority.subject,
        reason="tenant_admin_revocation",
    )
    if not found:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "GRANT_NOT_FOUND",
                "message": "Portal grant not found in this tenant.",
            },
        )
    emit_identity_audit_event(
        db,
        tenant_id=authority.tenant_id,
        event_type="tenant.portal_access.revoked",
        actor_user_id=authority.subject,
        details={"grant_id": grant_id},
    )
    db.commit()
    return {
        "tenant_id": authority.tenant_id,
        "grant_id": grant_id,
        "revoked": True,
    }


# ---------------------------------------------------------------------------
# CLIENT-LIFECYCLE-001: Canonical readiness evaluator endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/{tenant_id}/lifecycle",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_client_lifecycle(
    tenant_id: str,
    request: Request,
    actor_ctx: ActorContext = Depends(require_permission("user.invite")),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Return the canonical operational readiness snapshot for a tenant.

    Auth:
      - ``platform.admin`` — cross-tenant access; may read any tenant.
      - ``tenant_admin`` (DB-canonical) — own-tenant access only.

    The response is derived entirely from durable canonical facts —
    ``tenants.lifecycle_state``, active bound ``tenant_users`` rows —
    and never reflects unchecked JWT claims.

    On tenant_not_found the route returns 404 (not 200 with a state field)
    so callers can distinguish provisioning gaps from readiness degradation.
    """
    from api.client_lifecycle import (
        STATE_TENANT_NOT_FOUND,
        evaluate_client_lifecycle,
    )

    if "platform.admin" in actor_ctx.permissions:
        # Platform admin: cross-tenant read; skip resolve_authoritative_tenant
        # (which would 403 if actor's tenant != path tenant). Pattern follows
        # bootstrap_tenant_admin which explicitly avoids that check.
        resolved = tenant_id
    else:
        resolved = resolve_authoritative_tenant(request, actor_ctx, tenant_id)
        check_tenant_admin_authority(db, actor_ctx=actor_ctx, tenant_id=resolved)

    set_tenant_context(db, resolved)
    result = evaluate_client_lifecycle(db, resolved)

    if result.lifecycle_state == STATE_TENANT_NOT_FOUND:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "TENANT_NOT_FOUND",
                "message": "Tenant not found.",
            },
        )

    return {
        "lifecycle_version": result.lifecycle_version,
        "tenant_id": result.tenant_id,
        "lifecycle_state": result.lifecycle_state,
        "operational": result.operational,
        "repairable": result.repairable,
        "blockers": list(result.blockers),
        "warnings": list(result.warnings),
        "next_actions": list(result.next_actions),
        "diagnostics": {
            "tenant_canonical_state": result.tenant_canonical_state,
            "has_bound_admin": result.has_bound_admin,
            "active_member_count": result.active_member_count,
        },
    }


# ---------------------------------------------------------------------------
# 3F. Tenant service credential administration — tenant_admin (own tenant only)
# ---------------------------------------------------------------------------


@router.get(
    "/{tenant_id}/credential-administration",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_service_credentials(
    tenant_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """List all tenant_api_key credentials for the actor's own tenant."""
    engine = get_engine()
    records = ca.list_credentials(
        engine,
        authority.tenant_id,
        credential_type="tenant_api_key",
    )
    items = []
    for rec in records:
        d = _credential_to_dict(rec)
        d["role"] = tenant_rbac.get_credential_role(
            db, tenant_id=authority.tenant_id, credential_id=rec.credential_id
        )
        items.append(d)
    return {"tenant_id": authority.tenant_id, "items": items, "total": len(items)}


@router.post(
    "/{tenant_id}/credential-administration",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def issue_service_credential(
    tenant_id: str,
    body: IssueServiceCredentialBody,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Issue a new tenant_api_key credential. Plaintext secret returned exactly once."""
    engine = get_engine()
    credential_slot = str(uuid.uuid4())
    try:
        result = ca.issue_credential(
            engine,
            tenant_id=authority.tenant_id,
            credential_type="tenant_api_key",
            credential_slot=credential_slot,
            metadata={"name": body.name},
            actor_id=authority.subject,
        )
    except TenantNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except TenantLifecycleError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "TENANT_LIFECYCLE_DENIED", "message": str(exc)},
        )
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    d = _credential_to_dict(result.record)
    d["plaintext_secret"] = result.plaintext_secret
    return {"tenant_id": authority.tenant_id, **d}


@router.get(
    "/{tenant_id}/credential-administration/rbac",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_service_credential_roles(
    tenant_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """List all role assignments and the role change audit log for the actor's tenant."""
    assignments = tenant_rbac.list_role_assignments(db, tenant_id=authority.tenant_id)
    audit = tenant_rbac.get_role_audit_log(db, tenant_id=authority.tenant_id)
    return {
        "tenant_id": authority.tenant_id,
        "assignments": assignments,
        "audit": audit,
    }


@router.get(
    "/{tenant_id}/credential-administration/{credential_id}",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def get_service_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Fetch a single service credential by ID."""
    engine = get_engine()
    try:
        rec = ca.get_credential(engine, credential_id, authority.tenant_id)
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    if rec.credential_type != "tenant_api_key":
        raise _cred_not_found(credential_id)
    role = tenant_rbac.get_credential_role(
        db, tenant_id=authority.tenant_id, credential_id=credential_id
    )
    d = _credential_to_dict(rec)
    d["role"] = role
    return {"tenant_id": authority.tenant_id, **d}


@router.post(
    "/{tenant_id}/credential-administration/{credential_id}/rotate",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def rotate_service_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Rotate a service credential. Old credential is marked rotated; plaintext returned once."""
    engine = get_engine()
    try:
        existing = ca.get_credential(engine, credential_id, authority.tenant_id)
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    if existing.credential_type != "tenant_api_key":
        raise _cred_not_found(credential_id)
    try:
        result = ca.rotate_credential(
            engine,
            tenant_id=authority.tenant_id,
            credential_type="tenant_api_key",
            credential_slot=existing.credential_slot,
            actor_id=authority.subject,
        )
    except TenantLifecycleError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": "TENANT_LIFECYCLE_DENIED", "message": str(exc)},
        )
    except Exception as exc:
        raise _cred_state_conflict(str(exc))
    d = _credential_to_dict(result.record)
    d["plaintext_secret"] = result.plaintext_secret
    d["rotated_from_credential_id"] = credential_id
    return {"tenant_id": authority.tenant_id, **d}


@router.delete(
    "/{tenant_id}/credential-administration/{credential_id}",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def revoke_service_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Revoke a service credential. Idempotent."""
    engine = get_engine()
    try:
        existing = ca.get_credential(engine, credential_id, authority.tenant_id)
        if existing.credential_type != "tenant_api_key":
            raise CredentialNotFoundError()
        ca.revoke_credential(
            engine,
            credential_id=credential_id,
            tenant_id=authority.tenant_id,
            actor_id=authority.subject,
            reason="tenant_admin_revocation",
        )
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    except CredentialStateError as exc:
        raise _cred_state_conflict(str(exc))
    return {
        "tenant_id": authority.tenant_id,
        "credential_id": credential_id,
        "revoked": True,
    }


@router.post(
    "/{tenant_id}/credential-administration/{credential_id}/suspend",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def suspend_service_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Suspend a service credential. Reversible via resume."""
    engine = get_engine()
    try:
        existing = ca.get_credential(engine, credential_id, authority.tenant_id)
        if existing.credential_type != "tenant_api_key":
            raise CredentialNotFoundError()
        rec = ca.suspend_credential(
            engine,
            credential_id=credential_id,
            tenant_id=authority.tenant_id,
            actor_id=authority.subject,
            reason="tenant_admin_suspension",
        )
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    except CredentialStateError as exc:
        raise _cred_state_conflict(str(exc))
    return {"tenant_id": authority.tenant_id, **_credential_to_dict(rec)}


@router.post(
    "/{tenant_id}/credential-administration/{credential_id}/resume",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def resume_service_credential(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Resume a suspended service credential."""
    engine = get_engine()
    try:
        existing = ca.get_credential(engine, credential_id, authority.tenant_id)
        if existing.credential_type != "tenant_api_key":
            raise CredentialNotFoundError()
        rec = ca.resume_credential(
            engine,
            credential_id=credential_id,
            tenant_id=authority.tenant_id,
            actor_id=authority.subject,
        )
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    except CredentialStateError as exc:
        raise _cred_state_conflict(str(exc))
    return {"tenant_id": authority.tenant_id, **_credential_to_dict(rec)}


@router.put(
    "/{tenant_id}/credential-administration/{credential_id}/role",
    dependencies=[Depends(require_scopes("admin:write"))],
)
def assign_service_credential_role(
    tenant_id: str,
    credential_id: str,
    body: AssignCredentialRoleBody,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
) -> dict[str, Any]:
    """Assign a role to a service credential. Self-service ceiling applies.

    Unknown role → 422 INVALID_ROLE.
    Platform-only role (tenant_admin, platform_admin) → 403 ROLE_NOT_DELEGATABLE.
    Valid self-service role (governance_admin, analyst, auditor, read_only) → assigned.
    """
    if body.role in PLATFORM_ONLY_CREDENTIAL_ROLES:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "ROLE_NOT_DELEGATABLE",
                "message": (
                    f"Role {body.role!r} can only be assigned by platform administrators."
                ),
            },
        )
    if body.role not in SELF_SERVICE_CREDENTIAL_ROLES:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "INVALID_ROLE",
                "message": (
                    f"Unknown role {body.role!r}. "
                    f"Valid self-service roles: {sorted(SELF_SERVICE_CREDENTIAL_ROLES)}"
                ),
            },
        )
    engine = get_engine()
    try:
        existing = ca.get_credential(engine, credential_id, authority.tenant_id)
        if existing.credential_type != "tenant_api_key":
            raise CredentialNotFoundError()
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    try:
        result = tenant_rbac.assign_role(
            db,
            tenant_id=authority.tenant_id,
            actor_key_prefix=authority.subject,
            credential_id=credential_id,
            role_name=body.role,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return result


@router.get(
    "/{tenant_id}/credential-administration/{credential_id}/events",
    dependencies=[Depends(require_scopes("admin:read"))],
)
def list_service_credential_events(
    tenant_id: str,
    credential_id: str,
    request: Request,
    authority: TenantAdminAuthority = Depends(require_tenant_admin()),
    db: Session = Depends(auth_ctx_db_session),
    limit: int = Query(default=100, ge=1, le=500),
) -> dict[str, Any]:
    """Return lifecycle audit events for a single tenant_api_key credential, newest first.

    Metadata is deliberately excluded from the projection (same as the platform-admin
    events endpoint) to prevent any future accidental leakage of internal fields.
    """
    engine = get_engine()
    try:
        rec = ca.get_credential(engine, credential_id, authority.tenant_id)
    except CredentialNotFoundError:
        raise _cred_not_found(credential_id)
    if rec.credential_type != "tenant_api_key":
        raise _cred_not_found(credential_id)
    events = list_credential_events(
        engine,
        authority.tenant_id,
        credential_id=credential_id,
        limit=limit,
    )
    return {
        "tenant_id": authority.tenant_id,
        "credential_id": credential_id,
        "events": [
            {
                "event_id": e.event_id,
                "credential_id": e.credential_id,
                "credential_type": e.credential_type,
                "event_type": e.event_type,
                "outcome": e.outcome,
                "actor_id": e.actor_id,
                "occurred_at": e.occurred_at.isoformat(),
                "failure_reason": e.failure_reason,
            }
            for e in events
        ],
    }


__all__ = [
    "router",
    "TENANT_ADMIN_DENIED",
    "SELF_SERVICE_CREDENTIAL_ROLES",
    "PLATFORM_ONLY_CREDENTIAL_ROLES",
]
