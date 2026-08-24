"""Provider-neutral invitation callback validation and membership binding."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from admin_gateway.identity.audit import (
    emit_identity_audit_event,
    transition_invitation,
)
from admin_gateway.identity.models import (
    TenantIdentityAuthState,
    TenantInvitation,
    TenantUser,
)
from admin_gateway.identity.policy import (
    IdentityPolicyError,
    is_email_domain_allowed,
    require_identity_configured,
    validate_invite_email_matches_identity,
)
from admin_gateway.identity.identity_context import AuthenticatedIdentity
from admin_gateway.identity.provider_adapter import ProviderAdapter


class IdentityFlowError(ValueError):
    def __init__(self, code: str, status_code: int = 400):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _digest(state: str) -> str:
    return hashlib.sha256(state.encode()).hexdigest()


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _load_invitation(
    db: Session, tenant_id: str, invitation_id: str
) -> TenantInvitation:
    invitation = (
        db.query(TenantInvitation)
        .filter(
            TenantInvitation.tenant_id == tenant_id,
            TenantInvitation.id == invitation_id,
        )
        .one_or_none()
    )
    if invitation is None:
        raise IdentityFlowError("INVITE_NOT_FOUND", 404)
    if invitation.status == "revoked" or invitation.revoked_at is not None:
        raise IdentityFlowError("INVITE_REVOKED", 410)
    if invitation.status == "expired" or (
        invitation.expires_at and _utc(invitation.expires_at) <= _now()
    ):
        raise IdentityFlowError("INVITE_EXPIRED", 410)
    if invitation.status == "failed":
        raise IdentityFlowError("INVITE_FAILED", 409)
    return invitation


def _policy_error(exc: IdentityPolicyError) -> IdentityFlowError:
    mapping = {
        "TENANT_IDENTITY_NOT_CONFIGURED": "TENANT_POLICY_NOT_CONFIGURED",
        "TENANT_IDENTITY_NOT_READY": "TENANT_POLICY_NOT_CONFIGURED",
    }
    return IdentityFlowError(mapping.get(exc.code, exc.code), 403)


def _resolve_start_provider(policy, provider: str, connection_id: str | None):
    if policy.providers:
        provider_records = [
            record
            for record in policy.providers
            if record.status in {"configured", "ready"} and record.provider == provider
        ]
        if not provider_records:
            return None, "PROVIDER_NOT_ALLOWED"
        connection_records = [
            record
            for record in provider_records
            if record.connection_id == connection_id
        ]
        if not connection_records:
            return None, "CONNECTION_NOT_ALLOWED"
        return connection_records[0], None
    if provider != policy.provider:
        return None, "PROVIDER_NOT_ALLOWED"
    if policy.required_connection_id != connection_id:
        return None, "CONNECTION_NOT_ALLOWED"
    return None, None


def _resolve_callback_provider(policy, identity: AuthenticatedIdentity):
    if policy.providers:
        provider_records = [
            record
            for record in policy.providers
            if record.status in {"configured", "ready"}
            and record.provider == identity.provider
        ]
        if not provider_records:
            return None, "PROVIDER_NOT_ALLOWED"
        issuer_records = [
            record
            for record in provider_records
            if record.oidc_issuer is None or record.oidc_issuer == identity.issuer
        ]
        if not issuer_records:
            return None, "ISSUER_NOT_ALLOWED"
        connection_records = [
            record
            for record in issuer_records
            if record.connection_id == identity.connection_id
        ]
        if not connection_records:
            return None, "CONNECTION_NOT_ALLOWED"
        return connection_records[0], None
    if identity.provider != policy.provider:
        return None, "PROVIDER_NOT_ALLOWED"
    if policy.oidc_issuer is not None and policy.oidc_issuer != identity.issuer:
        return None, "ISSUER_NOT_ALLOWED"
    if policy.required_connection_id != identity.connection_id:
        return None, "CONNECTION_NOT_ALLOWED"
    return None, None


def _audit_rejection(
    db: Session,
    invitation: TenantInvitation,
    event_type: str,
    code: str,
    identity: AuthenticatedIdentity | None = None,
) -> None:
    emit_identity_audit_event(
        db,
        tenant_id=invitation.tenant_id,
        event_type=event_type,
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        identity_mode=invitation.identity_mode_at_invite,
        provider=identity.provider if identity else invitation.required_provider,
        connection_id=identity.connection_id
        if identity
        else invitation.required_connection_id,
        reason_code=code,
        identity_type=identity.identity_type if identity else None,
        identity_subject=identity.subject if identity else None,
        policy_config_id=invitation.identity_policy_config_id,
        provider_record_id=invitation.required_provider_record_id,
        correlation_id=identity.correlation_id if identity else None,
        details={"invitation_status": invitation.status},
    )


def start_invitation_auth(
    db: Session,
    *,
    tenant_id: str,
    invitation_id: str,
    adapter: ProviderAdapter,
    requested_provider: str | None = None,
    requested_connection_id: str | None = None,
    return_url: str | None = None,
) -> dict:
    invitation = _load_invitation(db, tenant_id, invitation_id)
    if return_url and (not return_url.startswith("/") or return_url.startswith("//")):
        _audit_rejection(
            db, invitation, "tenant.invite.callback_rejected", "RETURN_URL_NOT_ALLOWED"
        )
        raise IdentityFlowError("RETURN_URL_NOT_ALLOWED", 400)
    if invitation.status == "bound":
        raise IdentityFlowError("IDENTITY_ALREADY_BOUND", 409)
    try:
        policy = require_identity_configured(db, tenant_id)
    except IdentityPolicyError as exc:
        raise _policy_error(exc) from exc
    provider = requested_provider or invitation.required_provider or policy.provider
    connection = (
        requested_connection_id
        or invitation.required_connection_id
        or policy.required_connection_id
    )
    provider_record, provider_error = _resolve_start_provider(
        policy, provider, connection
    )
    if provider_error is not None:
        _audit_rejection(
            db, invitation, "tenant.invite.callback_rejected", provider_error
        )
        raise IdentityFlowError(provider_error, 403)
    if invitation.status == "pending":
        transition_invitation(db, invitation, to_status="auth_started")
    elif invitation.status != "auth_started":
        raise IdentityFlowError("INVITE_STATE_INVALID", 409)
    raw_state = secrets.token_urlsafe(32)
    correlation_id = str(uuid.uuid4())
    expiry = min(
        _utc(invitation.expires_at)
        if invitation.expires_at
        else _now() + timedelta(minutes=15),
        _now() + timedelta(minutes=15),
    )
    auth_state = TenantIdentityAuthState(
        id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        state_digest=_digest(raw_state),
        correlation_id=correlation_id,
        requested_provider=provider,
        requested_connection_id=connection,
        return_url=return_url,
        expires_at=expiry,
        created_at=_now(),
        updated_at=_now(),
    )
    db.add(auth_state)
    instructions = adapter.start_invitation_auth(
        provider=provider,
        state=raw_state,
        connection_id=connection,
        organization_id=provider_record.organization_id if provider_record else None,
    )
    return {
        "invitation_id": invitation.id,
        "tenant_id": tenant_id,
        "identity_mode": policy.identity_mode,
        "required_provider": provider,
        "required_connection_id": connection,
        "organization_id": instructions.organization_id,
        "auth_start_url": instructions.auth_start_url,
        "state": raw_state,
        "correlation_id": correlation_id,
        "expires_at": expiry.isoformat(),
        "adapter": instructions.adapter,
    }


def validate_callback(
    db: Session,
    *,
    tenant_id: str,
    invitation_id: str,
    state: str,
    identity: AuthenticatedIdentity,
) -> TenantIdentityAuthState:
    invitation = _load_invitation(db, tenant_id, invitation_id)
    auth_state = (
        db.query(TenantIdentityAuthState)
        .filter(
            TenantIdentityAuthState.tenant_id == tenant_id,
            TenantIdentityAuthState.invitation_id == invitation_id,
            TenantIdentityAuthState.state_digest == _digest(state),
        )
        .one_or_none()
    )
    if auth_state is None or _utc(auth_state.expires_at) <= _now():
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.callback_rejected",
            "CALLBACK_STATE_INVALID",
            identity,
        )
        raise IdentityFlowError("CALLBACK_STATE_INVALID", 401)
    if auth_state.status in {"bound", "rejected", "expired"}:
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.callback_rejected",
            "CALLBACK_REPLAY_REJECTED",
            identity,
        )
        raise IdentityFlowError("CALLBACK_REPLAY_REJECTED", 409)
    if auth_state.status == "validated":
        same = (
            auth_state.validated_provider,
            auth_state.validated_issuer,
            auth_state.validated_subject,
        ) == (identity.provider, identity.issuer, identity.subject)
        if same:
            return auth_state
        raise IdentityFlowError("CALLBACK_REPLAY_REJECTED", 409)
    emit_identity_audit_event(
        db,
        tenant_id=tenant_id,
        event_type="tenant.invite.callback_received",
        invitation_id=invitation.id,
        membership_id=invitation.membership_id,
        provider=identity.provider,
        connection_id=identity.connection_id,
        identity_type=identity.identity_type,
        identity_subject=identity.subject,
        correlation_id=auth_state.correlation_id,
        policy_config_id=invitation.identity_policy_config_id,
        details={"invitation_status": invitation.status},
    )
    try:
        policy = require_identity_configured(db, tenant_id)
    except IdentityPolicyError as exc:
        raise _policy_error(exc) from exc
    provider_record, provider_error = _resolve_callback_provider(policy, identity)
    checks = [
        (identity.identity_type == "human", "IDENTITY_TYPE_NOT_ALLOWED"),
        (identity.email_verified, "EMAIL_NOT_VERIFIED"),
        (
            validate_invite_email_matches_identity(
                invitation.normalized_email, identity.email
            ).allowed,
            "INVITE_EMAIL_MISMATCH",
        ),
        (provider_error is None, provider_error or "PROVIDER_NOT_ALLOWED"),
        (is_email_domain_allowed(policy, identity.email), "EMAIL_DOMAIN_NOT_ALLOWED"),
    ]
    if provider_record and provider_record.organization_id is not None:
        checks.append(
            (
                provider_record.organization_id == identity.organization_id,
                "ORG_NOT_ALLOWED",
            )
        )
    for allowed, code in checks:
        if not allowed:
            auth_state.status = "rejected"
            auth_state.updated_at = _now()
            _audit_rejection(
                db, invitation, "tenant.invite.callback_rejected", code, identity
            )
            raise IdentityFlowError(code, 403)
    membership = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == tenant_id, TenantUser.id == invitation.membership_id
        )
        .one_or_none()
    )
    if membership is None:
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.callback_rejected",
            "MEMBERSHIP_NOT_FOUND",
            identity,
        )
        raise IdentityFlowError("MEMBERSHIP_NOT_FOUND", 404)
    if not membership.active or membership.identity_binding_status == "disabled":
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.callback_rejected",
            "MEMBERSHIP_DISABLED",
            identity,
        )
        raise IdentityFlowError("MEMBERSHIP_DISABLED", 403)
    if membership.identity_type != "human":
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.callback_rejected",
            "IDENTITY_TYPE_NOT_ALLOWED",
            identity,
        )
        raise IdentityFlowError("IDENTITY_TYPE_NOT_ALLOWED", 403)
    if invitation.status == "auth_started":
        transition_invitation(
            db,
            invitation,
            to_status="accepted_identity_pending_binding",
            actor_user_id=membership.id,
        )
    membership.identity_binding_status = "pending"
    auth_state.status = "validated"
    auth_state.validated_provider = identity.provider
    auth_state.validated_issuer = identity.issuer
    auth_state.validated_subject = identity.subject
    auth_state.validated_email = identity.email.casefold()
    auth_state.validated_email_verified = True
    auth_state.validated_connection_id = identity.connection_id
    auth_state.validated_organization_id = identity.organization_id
    auth_state.validated_identity_type = identity.identity_type
    auth_state.validated_at = auth_state.updated_at = _now()
    emit_identity_audit_event(
        db,
        tenant_id=tenant_id,
        event_type="tenant.membership.identity_binding_pending",
        invitation_id=invitation.id,
        membership_id=membership.id,
        provider=identity.provider,
        connection_id=identity.connection_id,
        identity_type=identity.identity_type,
        identity_subject=identity.subject,
        correlation_id=auth_state.correlation_id,
        policy_config_id=invitation.identity_policy_config_id,
        details={"membership_binding_status": "pending"},
    )
    return auth_state


def bind_identity(
    db: Session, *, tenant_id: str, invitation_id: str, state: str
) -> TenantUser:
    invitation = _load_invitation(db, tenant_id, invitation_id)
    auth_state = (
        db.query(TenantIdentityAuthState)
        .filter(
            TenantIdentityAuthState.tenant_id == tenant_id,
            TenantIdentityAuthState.invitation_id == invitation_id,
            TenantIdentityAuthState.state_digest == _digest(state),
        )
        .one_or_none()
    )
    if (
        auth_state is None
        or auth_state.status not in {"validated", "bound"}
        or _utc(auth_state.expires_at) <= _now()
    ):
        _audit_rejection(
            db, invitation, "tenant.invite.binding_rejected", "CALLBACK_STATE_INVALID"
        )
        raise IdentityFlowError("CALLBACK_STATE_INVALID", 401)
    membership = (
        db.query(TenantUser)
        .filter(
            TenantUser.tenant_id == tenant_id, TenantUser.id == invitation.membership_id
        )
        .one_or_none()
    )
    if membership is None:
        raise IdentityFlowError("MEMBERSHIP_NOT_FOUND", 404)
    if not membership.active or membership.identity_binding_status == "disabled":
        _audit_rejection(
            db, invitation, "tenant.invite.binding_rejected", "MEMBERSHIP_DISABLED"
        )
        raise IdentityFlowError("MEMBERSHIP_DISABLED", 403)
    if (
        membership.identity_type != "human"
        or auth_state.validated_identity_type != "human"
    ):
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.binding_rejected",
            "IDENTITY_TYPE_NOT_ALLOWED",
        )
        raise IdentityFlowError("IDENTITY_TYPE_NOT_ALLOWED", 403)
    authority = (
        auth_state.validated_provider,
        auth_state.validated_issuer,
        auth_state.validated_subject,
    )
    current = (
        membership.identity_provider,
        membership.identity_issuer,
        membership.identity_subject,
    )
    if membership.identity_binding_status == "bound":
        if current == authority:
            auth_state.status = "bound"
            return membership
        _audit_rejection(
            db, invitation, "tenant.invite.binding_rejected", "IDENTITY_ALREADY_BOUND"
        )
        raise IdentityFlowError("IDENTITY_ALREADY_BOUND", 409)
    conflict = (
        db.query(TenantUser)
        .filter(
            TenantUser.id != membership.id,
            TenantUser.identity_binding_status == "bound",
            TenantUser.identity_provider == authority[0],
            TenantUser.identity_issuer == authority[1],
            TenantUser.identity_subject == authority[2],
        )
        .first()
    )
    if conflict is not None:
        _audit_rejection(
            db, invitation, "tenant.invite.binding_rejected", "IDENTITY_ALREADY_BOUND"
        )
        raise IdentityFlowError("IDENTITY_ALREADY_BOUND", 409)
    # PR-AUTH-004 — Canonical principal authority cutover.
    #
    # Order matters (atomicity requirement):
    #   1. Validate canonical triple (in resolver).
    #   2. Resolve or create the canonical fg_principals row + bind the
    #      external identity via fg_external_identities.
    #   3. Set membership.principal_id to the resolved value.
    #   4. Set legacy identity_* columns (kept for backward-compat / rollback
    #      evidence during the migration window; frozen data model §8).
    #   5. Set identity_binding_status='bound'.
    #   6. flush — all three invariants (principal_id populated, legacy
    #      columns populated, binding_status='bound') are satisfied atomically.
    #
    # If any step (2) fails, the row remains UNBOUND — no partial cutover.
    from api.principal_authority import (
        PrincipalResolutionError,
        resolve_or_create_principal_for_external_identity,
    )

    # `authority` fields are Optional at the ORM level but validate_callback()
    # only reaches `validated` status when all three are populated. Narrow for
    # mypy and fail closed if this assumption ever regresses.
    canonical_provider = authority[0]
    canonical_issuer = authority[1]
    canonical_subject = authority[2]
    if not (canonical_provider and canonical_issuer and canonical_subject):
        _audit_rejection(
            db, invitation, "tenant.invite.binding_rejected", "CANONICAL_TRIPLE_MISSING"
        )
        raise IdentityFlowError("CANONICAL_TRIPLE_MISSING", 500)

    try:
        resolution = resolve_or_create_principal_for_external_identity(
            db,
            provider=canonical_provider,
            issuer=canonical_issuer,
            subject=canonical_subject,
            display_name=getattr(membership, "display_name", None) or membership.email,
            primary_email=membership.email,
            provider_email=auth_state.validated_email,
        )
    except PrincipalResolutionError as exc:
        db.rollback()
        _audit_rejection(
            db,
            invitation,
            "tenant.invite.binding_rejected",
            exc.code,
        )
        # Preserve explicit resolver error codes rather than remapping to
        # IDENTITY_ALREADY_BOUND (misleading; would hide non-binding faults).
        raise IdentityFlowError(
            exc.code, 409 if exc.code == "PRINCIPAL_INACTIVE" else 400
        ) from exc
    membership.principal_id = resolution.principal_id
    (
        membership.identity_provider,
        membership.identity_issuer,
        membership.identity_subject,
    ) = authority
    membership.identity_email = auth_state.validated_email
    membership.identity_email_verified = bool(auth_state.validated_email_verified)
    membership.identity_connection_id = auth_state.validated_connection_id
    membership.identity_policy_config_id = invitation.identity_policy_config_id
    membership.identity_provider_record_id = invitation.required_provider_record_id
    membership.identity_binding_status = "bound"
    membership.identity_bound_at = membership.last_identity_login_at = _now()
    from services.identity_resolver import (
        membership_version_svc,
    )  # lazy: services/ not in admin_gateway Docker image

    membership.membership_version = membership_version_svc.bump_version(
        db, membership_id=membership.id, tenant_id=tenant_id, reason="identity_bound"
    )
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        # The one legitimate IntegrityError shape here is a cross-tenant
        # binding collision on the shadow index uq_tenant_users_bound_identity
        # (predicate identity_binding_status='bound' AND identity_subject IS
        # NOT NULL) — that is genuinely IDENTITY_ALREADY_BOUND. Any other
        # IntegrityError (FK on principal_id, principal_id CHECK if
        # HARD-002 ever ships) is a distinct fault; surface with an explicit
        # code rather than hide behind the legacy label.
        detail = str(exc.orig) if exc.orig is not None else str(exc)
        if "uq_tenant_users_bound_identity" in detail or "identity_subject" in detail:
            raise IdentityFlowError("IDENTITY_ALREADY_BOUND", 409) from exc
        if "principal_id" in detail or "fg_principals" in detail:
            raise IdentityFlowError("PRINCIPAL_LINKAGE_INVALID", 500) from exc
        raise IdentityFlowError("IDENTITY_BINDING_FAILED", 500) from exc
    if invitation.status == "accepted_identity_pending_binding":
        transition_invitation(
            db, invitation, to_status="bound", actor_user_id=membership.id
        )
    auth_state.status = "bound"
    auth_state.consumed_at = auth_state.updated_at = _now()
    emit_identity_audit_event(
        db,
        tenant_id=tenant_id,
        event_type="tenant.membership.identity_bound",
        actor_user_id=membership.id,
        invitation_id=invitation.id,
        membership_id=membership.id,
        provider=membership.identity_provider,
        connection_id=membership.identity_connection_id,
        identity_type=membership.identity_type,
        identity_subject=membership.identity_subject,
        correlation_id=auth_state.correlation_id,
        policy_config_id=membership.identity_policy_config_id,
        provider_record_id=membership.identity_provider_record_id,
        details={"membership_binding_status": "bound"},
    )
    return membership
