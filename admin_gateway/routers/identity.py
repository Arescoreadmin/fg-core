"""Provider-neutral Admin Gateway identity enforcement routes."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, NoReturn

from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DBSession

from api.db import get_sessionmaker, set_tenant_context
from api.db_models_identity import TenantIdentityProvider, TenantInvitation
from api.identity.store import emit_identity_audit_event
from api.identity.tenant_identity_policy import (
    IdentityPolicyError,
    require_identity_configured,
)
from admin_gateway.auth.dependencies import get_current_session
from admin_gateway.auth.csrf import CSRFProtection
from admin_gateway.auth.session import Session, SessionManager
from admin_gateway.identity.invitation_flow import (
    IdentityFlowError,
    bind_identity,
    start_invitation_auth,
    validate_callback,
)
from admin_gateway.identity.provider_adapter import (
    ProviderAdapter,
    ProviderAdapterError,
    ProviderNeutralRedirectAdapter,
)
from admin_gateway.identity.session_service import (
    TenantSessionError,
    build_tenant_session_context,
    issue_tenant_session,
)

router = APIRouter(prefix="/identity", tags=["identity-enforcement"])


def get_provider_adapter() -> ProviderAdapter:
    return ProviderNeutralRedirectAdapter()


class StartAuthBody(BaseModel):
    model_config = {"extra": "forbid"}

    requested_provider: str | None = None
    requested_connection_id: str | None = None
    return_url: str | None = Field(default=None, max_length=1024)


class CallbackBody(BaseModel):
    model_config = {"extra": "forbid"}

    state: str = Field(min_length=16, max_length=512)
    provider: str
    issuer: str
    subject: str
    email: str
    email_verified: bool
    connection_id: str | None = None
    organization_id: str | None = None
    identity_type: str
    correlation_id: str | None = None


class BindBody(BaseModel):
    model_config = {"extra": "forbid"}

    state: str = Field(min_length=16, max_length=512)


def _db_for_tenant(
    x_tenant_id: str = Header(..., alias="X-Tenant-ID"),
) -> Iterator[DBSession]:
    db = get_sessionmaker()()
    set_tenant_context(db, x_tenant_id)
    db.info["tenant_id"] = x_tenant_id
    try:
        yield db
    finally:
        db.close()


def _session_db(session: Session = Depends(get_current_session)) -> Iterator[DBSession]:
    if not session.tenant_governed or not session.tenant_id:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "SESSION_CONTEXT_REQUIRED",
                "message": "Tenant session required",
            },
        )
    db = get_sessionmaker()()
    set_tenant_context(db, session.tenant_id)
    try:
        yield db
    finally:
        db.close()


def _fail(db: DBSession, exc: IdentityFlowError) -> NoReturn:
    db.commit()
    raise HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": "Identity request rejected"},
    )


@router.get("/invitations/{invitation_id}/requirements")
def invitation_requirements(
    invitation_id: str, db: DBSession = Depends(_db_for_tenant)
) -> dict[str, Any]:
    invitation = (
        db.query(TenantInvitation)
        .filter(
            TenantInvitation.tenant_id == db.info.get("tenant_id"),
            TenantInvitation.id == invitation_id,
        )
        .one_or_none()
    )
    if invitation is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "INVITE_NOT_FOUND", "message": "Invitation not found"},
        )
    try:
        policy = require_identity_configured(db, invitation.tenant_id)
    except IdentityPolicyError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "TENANT_POLICY_NOT_CONFIGURED",
                "message": "Identity policy unavailable",
            },
        ) from exc
    providers = (
        db.query(TenantIdentityProvider)
        .filter(TenantIdentityProvider.tenant_id == invitation.tenant_id)
        .all()
    )
    return {
        "invitation_id": invitation.id,
        "status": invitation.status,
        "identity_mode": policy.identity_mode,
        "required_provider": invitation.required_provider or policy.provider,
        "required_connection_id": invitation.required_connection_id
        or policy.required_connection_id,
        "providers": [
            {
                "provider": p.provider,
                "issuer": p.oidc_issuer,
                "connection_id": p.connection_id,
                "organization_id": p.organization_id,
            }
            for p in providers
        ],
        "expires_at": invitation.expires_at.isoformat()
        if invitation.expires_at
        else None,
    }


@router.post("/invitations/{invitation_id}/start-auth")
def start_auth(
    invitation_id: str,
    body: StartAuthBody,
    db: DBSession = Depends(_db_for_tenant),
    adapter: ProviderAdapter = Depends(get_provider_adapter),
) -> dict[str, Any]:
    try:
        result = start_invitation_auth(
            db,
            tenant_id=str(db.info["tenant_id"]),
            invitation_id=invitation_id,
            adapter=adapter,
            requested_provider=body.requested_provider,
            requested_connection_id=body.requested_connection_id,
            return_url=body.return_url,
        )
        db.commit()
        return result
    except IdentityFlowError as exc:
        _fail(db, exc)


def _tenant_from_invite(db: DBSession, invitation_id: str) -> str:
    invitation = (
        db.query(TenantInvitation)
        .filter(
            TenantInvitation.tenant_id == db.info.get("tenant_id"),
            TenantInvitation.id == invitation_id,
        )
        .one_or_none()
    )
    if invitation is None:
        raise IdentityFlowError("INVITE_NOT_FOUND", 404)
    return str(invitation.tenant_id)


@router.post("/invitations/{invitation_id}/callback")
def callback(
    invitation_id: str,
    body: CallbackBody,
    db: DBSession = Depends(_db_for_tenant),
    adapter: ProviderAdapter = Depends(get_provider_adapter),
) -> dict[str, Any]:
    try:
        tenant_id = _tenant_from_invite(db, invitation_id)
        identity = adapter.validate_callback(body.model_dump(exclude={"state"}))
        state = validate_callback(
            db,
            tenant_id=tenant_id,
            invitation_id=invitation_id,
            state=body.state,
            identity=identity,
        )
        db.commit()
        return {
            "invitation_id": invitation_id,
            "status": "accepted_identity_pending_binding",
            "correlation_id": state.correlation_id,
        }
    except ProviderAdapterError as exc:
        invitation = (
            db.query(TenantInvitation)
            .filter(
                TenantInvitation.tenant_id == db.info.get("tenant_id"),
                TenantInvitation.id == invitation_id,
            )
            .one_or_none()
        )
        if invitation is not None:
            emit_identity_audit_event(
                db,
                tenant_id=invitation.tenant_id,
                event_type="tenant.invite.callback_rejected",
                invitation_id=invitation.id,
                membership_id=invitation.membership_id,
                reason_code=exc.code,
                details={"invitation_status": invitation.status},
            )
        _fail(db, IdentityFlowError(exc.code, 503))
    except IdentityFlowError as exc:
        _fail(db, exc)


@router.post("/invitations/{invitation_id}/bind")
def bind(
    invitation_id: str,
    body: BindBody,
    db: DBSession = Depends(_db_for_tenant),
) -> JSONResponse:
    try:
        tenant_id = _tenant_from_invite(db, invitation_id)
        membership = bind_identity(
            db, tenant_id=tenant_id, invitation_id=invitation_id, state=body.state
        )
        try:
            context = build_tenant_session_context(membership)
            session = issue_tenant_session(SessionManager(), context)
        except TenantSessionError as exc:
            emit_identity_audit_event(
                db,
                tenant_id=tenant_id,
                event_type="tenant.identity_session.rejected",
                actor_user_id=membership.id,
                membership_id=membership.id,
                provider=membership.identity_provider,
                identity_type=membership.identity_type,
                identity_subject=membership.identity_subject,
                reason_code=exc.code,
                details={"session_status": "rejected"},
            )
            raise IdentityFlowError(exc.code, 403) from exc
        emit_identity_audit_event(
            db,
            tenant_id=tenant_id,
            event_type="tenant.identity_session.issued",
            actor_user_id=membership.id,
            membership_id=membership.id,
            provider=membership.identity_provider,
            connection_id=membership.identity_connection_id,
            identity_type=membership.identity_type,
            identity_subject=membership.identity_subject,
            policy_config_id=membership.identity_policy_config_id,
            provider_record_id=membership.identity_provider_record_id,
            correlation_id=session.session_id,
            details={
                "session_status": "issued",
                "role": membership.role,
                "membership_binding_status": membership.identity_binding_status,
            },
        )
        db.commit()
        response = JSONResponse(
            {
                "status": "bound",
                "tenant_id": tenant_id,
                "membership_id": membership.id,
                "session_id": session.session_id,
                "expires_at": session.expires_at,
            }
        )
        manager = SessionManager()
        manager.set_session_cookie(response, session)
        CSRFProtection().set_token_cookie(response)
        return response
    except IdentityFlowError as exc:
        _fail(db, exc)


@router.get("/session/current")
def current_session(session: Session = Depends(get_current_session)) -> dict[str, Any]:
    if (
        not session.tenant_governed
        or not session.tenant_id
        or session.binding_status != "bound"
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "code": "SESSION_CONTEXT_REQUIRED",
                "message": "Tenant session required",
            },
        )
    return {
        "authenticated": True,
        "tenant_id": session.tenant_id,
        "user_id": session.user_id,
        "membership_id": session.membership_id,
        "email": session.email,
        "identity_provider": session.identity_provider,
        "identity_issuer": session.identity_issuer,
        "identity_subject": session.identity_subject,
        "identity_type": session.identity_type,
        "roles": [session.role] if session.role else [],
        "scopes": sorted(session.scopes),
        "session_expires_at": session.expires_at,
    }


@router.post("/session/logout")
def logout(
    session: Session = Depends(get_current_session),
    db: DBSession = Depends(_session_db),
) -> JSONResponse:
    if not session.tenant_id:
        raise HTTPException(
            status_code=401,
            detail={
                "code": "SESSION_CONTEXT_REQUIRED",
                "message": "Tenant session required",
            },
        )
    emit_identity_audit_event(
        db,
        tenant_id=session.tenant_id,
        event_type="tenant.identity_session.logout",
        actor_user_id=session.user_id,
        membership_id=session.membership_id,
        provider=session.identity_provider,
        identity_type=session.identity_type,
        identity_subject=session.identity_subject,
        correlation_id=session.session_id,
        details={"session_status": "logged_out"},
    )
    db.commit()
    response = JSONResponse({"authenticated": False})
    SessionManager().clear_session_cookie(response)
    CSRFProtection().clear_token_cookie(response)
    return response
