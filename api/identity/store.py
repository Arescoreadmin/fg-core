"""Persistence primitives for identity configuration and invitation lifecycle."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_identity import (
    TenantIdentityAuditEvent,
    TenantIdentityConfig,
    TenantIdentityDomain,
    TenantIdentityProvider,
    TenantIdentityRoleAssignment,
    TenantInvitation,
)
from api.identity.tenant_identity_policy import (
    IDENTITY_MODES,
    IdentityPolicyError,
    normalize_invite_email,
    normalized_domains,
)
from api.signed_artifacts import canonical_hash

IDENTITY_AUDIT_EVENTS = frozenset(
    {
        "tenant.identity_config.created",
        "tenant.identity_config.updated",
        "tenant.identity_config.provisioning_pending",
        "tenant.identity_config.provisioning_ready",
        "tenant.identity_config.provisioning_failed",
        "tenant.invite.created",
        "tenant.invite.auth_started",
        "tenant.invite.revoked",
        "tenant.invite.expired",
        "tenant.invite.binding_pending",
        "tenant.invite.bound",
        "tenant.membership.identity_binding_pending",
        "tenant.membership.identity_bound",
        "tenant.membership.identity_binding_failed",
        "tenant.membership.role_assigned",
        "tenant.membership.role_revoked",
        "tenant.identity_provider.configured",
        "tenant.identity_domain.configured",
    }
)
INVITATION_TRANSITIONS = {
    "pending": frozenset({"auth_started", "expired", "revoked", "failed"}),
    "auth_started": frozenset(
        {"accepted_identity_pending_binding", "expired", "revoked", "failed"}
    ),
    "accepted_identity_pending_binding": frozenset(
        {"bound", "expired", "revoked", "failed"}
    ),
    "bound": frozenset(),
    "expired": frozenset(),
    "revoked": frozenset(),
    "failed": frozenset(),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _canonical_timestamp(value: datetime) -> str:
    timestamp = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _identity_audit_hash_payload(
    *,
    event_id: str,
    tenant_id: str,
    event_type: str,
    actor_user_id: str | None,
    affected_email: str | None,
    invitation_id: str | None,
    membership_id: str | None,
    identity_mode: str | None,
    provider: str | None,
    connection_id: str | None,
    reason_code: str | None,
    identity_type: str | None,
    identity_subject: str | None,
    provider_record_id: str | None,
    policy_config_id: str | None,
    role_assignment_id: str | None,
    correlation_id: str | None,
    details: dict[str, Any],
    created_at: datetime,
    previous_event_hash: str | None,
) -> dict[str, Any]:
    return {
        "id": event_id,
        "tenant_id": tenant_id,
        "event_type": event_type,
        "actor_user_id": actor_user_id,
        "affected_email": affected_email,
        "invitation_id": invitation_id,
        "membership_id": membership_id,
        "identity_mode": identity_mode,
        "provider": provider,
        "connection_id": connection_id,
        "reason_code": reason_code,
        "identity_type": identity_type,
        "identity_subject": identity_subject,
        "provider_record_id": provider_record_id,
        "policy_config_id": policy_config_id,
        "role_assignment_id": role_assignment_id,
        "correlation_id": correlation_id,
        "details": details,
        "created_at": _canonical_timestamp(created_at),
        "previous_event_hash": previous_event_hash,
    }


def verify_identity_audit_chain(db: Session, tenant_id: str) -> bool:
    previous_hash: str | None = None
    rows = (
        db.query(TenantIdentityAuditEvent)
        .filter(TenantIdentityAuditEvent.tenant_id == tenant_id)
        .order_by(TenantIdentityAuditEvent.created_at, TenantIdentityAuditEvent.id)
        .all()
    )
    for row in rows:
        if row.previous_event_hash != previous_hash:
            return False
        expected = canonical_hash(
            _identity_audit_hash_payload(
                event_id=row.id,
                tenant_id=row.tenant_id,
                event_type=row.event_type,
                actor_user_id=row.actor_user_id,
                affected_email=row.affected_email,
                invitation_id=row.invitation_id,
                membership_id=row.membership_id,
                identity_mode=row.identity_mode,
                provider=row.provider,
                connection_id=row.connection_id,
                reason_code=row.reason_code,
                identity_type=row.identity_type,
                identity_subject=row.identity_subject,
                provider_record_id=row.provider_record_id,
                policy_config_id=row.policy_config_id,
                role_assignment_id=row.role_assignment_id,
                correlation_id=row.correlation_id,
                details=row.details_json or {},
                created_at=row.created_at,
                previous_event_hash=row.previous_event_hash,
            )
        )
        if row.event_hash != expected:
            return False
        previous_hash = row.event_hash
    return True


def emit_identity_audit_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    actor_user_id: str | None = None,
    affected_email: str | None = None,
    invitation_id: str | None = None,
    membership_id: str | None = None,
    identity_mode: str | None = None,
    provider: str | None = None,
    connection_id: str | None = None,
    reason_code: str | None = None,
    identity_type: str | None = None,
    identity_subject: str | None = None,
    provider_record_id: str | None = None,
    policy_config_id: str | None = None,
    role_assignment_id: str | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> TenantIdentityAuditEvent:
    if event_type not in IDENTITY_AUDIT_EVENTS:
        raise IdentityPolicyError("IDENTITY_AUDIT_EVENT_INVALID", event_type)
    safe_keys = {
        "provisioning_status",
        "invitation_status",
        "membership_binding_status",
        "sso_enforced",
        "identity_type",
        "role",
        "assignment_source",
        "approval_source",
        "domain_type",
        "verification_status",
        "provider_status",
        "maturity_level",
    }
    safe_details = {k: v for k, v in (details or {}).items() if k in safe_keys}
    created_at = _now()
    event_id = str(uuid.uuid4())
    previous = (
        db.query(TenantIdentityAuditEvent)
        .filter(TenantIdentityAuditEvent.tenant_id == tenant_id)
        .order_by(
            TenantIdentityAuditEvent.created_at.desc(),
            TenantIdentityAuditEvent.id.desc(),
        )
        .first()
    )
    previous_hash = previous.event_hash if previous is not None else None
    normalized_email = (
        normalize_invite_email(affected_email) if affected_email else None
    )
    event_hash = canonical_hash(
        _identity_audit_hash_payload(
            event_id=event_id,
            tenant_id=tenant_id,
            event_type=event_type,
            actor_user_id=actor_user_id,
            affected_email=normalized_email,
            invitation_id=invitation_id,
            membership_id=membership_id,
            identity_mode=identity_mode,
            provider=provider,
            connection_id=connection_id,
            reason_code=reason_code,
            identity_type=identity_type,
            identity_subject=identity_subject,
            provider_record_id=provider_record_id,
            policy_config_id=policy_config_id,
            role_assignment_id=role_assignment_id,
            correlation_id=correlation_id,
            details=safe_details,
            created_at=created_at,
            previous_event_hash=previous_hash,
        )
    )
    row = TenantIdentityAuditEvent(
        id=event_id,
        tenant_id=tenant_id,
        event_type=event_type,
        actor_user_id=actor_user_id,
        affected_email=normalized_email,
        invitation_id=invitation_id,
        membership_id=membership_id,
        identity_mode=identity_mode,
        provider=provider,
        connection_id=connection_id,
        reason_code=reason_code,
        identity_type=identity_type,
        identity_subject=identity_subject,
        provider_record_id=provider_record_id,
        policy_config_id=policy_config_id,
        role_assignment_id=role_assignment_id,
        correlation_id=correlation_id,
        previous_event_hash=previous_hash,
        event_hash=event_hash,
        details_json=safe_details,
        created_at=created_at,
    )
    db.add(row)
    db.flush()
    return row


class TenantIdentityStore:
    def create_config(
        self,
        db: Session,
        *,
        tenant_id: str,
        identity_mode: str,
        configured_by_user_id: str | None,
        provider: str = "auth0",
        oidc_issuer: str | None = None,
        auth0_organization_id: str | None = None,
        auth0_connection_id: str | None = None,
        allowed_email_domains: list[str] | tuple[str, ...] = (),
        sso_enforced: bool = False,
        provisioning_status: str = "not_configured",
        maturity_level: str = "level_0",
        capability_flags: dict[str, bool] | None = None,
    ) -> TenantIdentityConfig:
        if identity_mode not in IDENTITY_MODES:
            raise IdentityPolicyError("IDENTITY_MODE_INVALID", identity_mode)
        if (
            db.query(TenantIdentityConfig)
            .filter(TenantIdentityConfig.tenant_id == tenant_id)
            .first()
            is not None
        ):
            raise IdentityPolicyError(
                "TENANT_IDENTITY_CONFIG_EXISTS",
                "tenant already has an identity configuration",
            )
        now = _now()
        row = TenantIdentityConfig(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            identity_mode=identity_mode,
            maturity_level=maturity_level,
            capability_flags=capability_flags or {},
            provider=provider,
            oidc_issuer=oidc_issuer,
            auth0_organization_id=auth0_organization_id,
            auth0_connection_id=auth0_connection_id,
            allowed_email_domains=list(normalized_domains(allowed_email_domains)),
            sso_enforced=sso_enforced,
            provisioning_status=provisioning_status,
            configured_by_user_id=configured_by_user_id,
            configured_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        provider_record = TenantIdentityProvider(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            identity_config_id=row.id,
            provider=provider,
            oidc_issuer=oidc_issuer,
            organization_id=auth0_organization_id,
            connection_id=auth0_connection_id,
            status="ready" if provisioning_status == "ready" else "configured",
            is_primary=True,
            created_at=now,
            updated_at=now,
        )
        db.add(provider_record)
        for domain in normalized_domains(allowed_email_domains):
            db.add(
                TenantIdentityDomain(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    identity_config_id=row.id,
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
            event_type="tenant.identity_config.created",
            actor_user_id=configured_by_user_id,
            identity_mode=identity_mode,
            provider=provider,
            connection_id=auth0_connection_id,
            provider_record_id=provider_record.id,
            policy_config_id=row.id,
            details={
                "provisioning_status": provisioning_status,
                "sso_enforced": sso_enforced,
                "maturity_level": maturity_level,
            },
        )
        return row

    def set_provisioning_status(
        self,
        db: Session,
        config: TenantIdentityConfig,
        *,
        provisioning_status: str,
        actor_user_id: str | None,
        reason_code: str | None = None,
        error_message: str | None = None,
    ) -> TenantIdentityConfig:
        event_by_status = {
            "pending": "tenant.identity_config.provisioning_pending",
            "ready": "tenant.identity_config.provisioning_ready",
            "failed": "tenant.identity_config.provisioning_failed",
        }
        event_type = event_by_status.get(
            provisioning_status, "tenant.identity_config.updated"
        )
        config.provisioning_status = provisioning_status
        config.provisioning_error_code = reason_code
        config.provisioning_error_message = error_message
        config.updated_at = _now()
        emit_identity_audit_event(
            db,
            tenant_id=config.tenant_id,
            event_type=event_type,
            actor_user_id=actor_user_id,
            identity_mode=config.identity_mode,
            provider=config.provider,
            connection_id=config.auth0_connection_id,
            policy_config_id=config.id,
            reason_code=reason_code,
            details={
                "provisioning_status": provisioning_status,
                "sso_enforced": config.sso_enforced,
            },
        )
        return config

    def add_provider(
        self,
        db: Session,
        config: TenantIdentityConfig,
        *,
        provider: str,
        oidc_issuer: str | None = None,
        connection_id: str | None = None,
        organization_id: str | None = None,
        actor_user_id: str | None = None,
    ) -> TenantIdentityProvider:
        now = _now()
        row = TenantIdentityProvider(
            id=str(uuid.uuid4()),
            tenant_id=config.tenant_id,
            identity_config_id=config.id,
            provider=provider,
            oidc_issuer=oidc_issuer,
            connection_id=connection_id,
            organization_id=organization_id,
            status="configured",
            is_primary=False,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        emit_identity_audit_event(
            db,
            tenant_id=config.tenant_id,
            event_type="tenant.identity_provider.configured",
            actor_user_id=actor_user_id,
            identity_mode=config.identity_mode,
            provider=provider,
            connection_id=connection_id,
            provider_record_id=row.id,
            policy_config_id=config.id,
            details={"provider_status": row.status},
        )
        return row

    def add_domain(
        self,
        db: Session,
        config: TenantIdentityConfig,
        *,
        domain: str,
        domain_type: str = "trusted",
        verification_status: str = "unverified",
        provider_record_id: str | None = None,
        actor_user_id: str | None = None,
    ) -> TenantIdentityDomain:
        normalized = normalized_domains([domain])[0]
        now = _now()
        row = TenantIdentityDomain(
            id=str(uuid.uuid4()),
            tenant_id=config.tenant_id,
            identity_config_id=config.id,
            provider_record_id=provider_record_id,
            domain=normalized,
            domain_type=domain_type,
            verification_status=verification_status,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        emit_identity_audit_event(
            db,
            tenant_id=config.tenant_id,
            event_type="tenant.identity_domain.configured",
            actor_user_id=actor_user_id,
            identity_mode=config.identity_mode,
            provider_record_id=provider_record_id,
            policy_config_id=config.id,
            details={
                "domain_type": domain_type,
                "verification_status": verification_status,
            },
        )
        return row

    def record_role_assignment(
        self,
        db: Session,
        *,
        tenant_id: str,
        membership_id: str,
        role: str,
        assignment_source: str,
        approval_source: str | None = None,
        assigned_by_user_id: str | None = None,
        approved_by_user_id: str | None = None,
        source_reference: str | None = None,
        policy_config_id: str | None = None,
    ) -> TenantIdentityRoleAssignment:
        row = TenantIdentityRoleAssignment(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            membership_id=membership_id,
            role=role,
            assignment_source=assignment_source,
            approval_source=approval_source,
            source_reference=source_reference,
            assigned_by_user_id=assigned_by_user_id,
            approved_by_user_id=approved_by_user_id,
            assigned_at=_now(),
        )
        db.add(row)
        emit_identity_audit_event(
            db,
            tenant_id=tenant_id,
            event_type="tenant.membership.role_assigned",
            actor_user_id=assigned_by_user_id,
            membership_id=membership_id,
            policy_config_id=policy_config_id,
            role_assignment_id=row.id,
            details={
                "role": role,
                "assignment_source": assignment_source,
                "approval_source": approval_source,
            },
        )
        return row

    def create_invitation(
        self,
        db: Session,
        *,
        tenant_id: str,
        email: str,
        role: str,
        created_by_user_id: str | None,
        expires_at: datetime | None,
        identity_mode_at_invite: str | None,
        required_provider: str | None,
        required_connection_id: str | None = None,
        identity_policy_config_id: str | None = None,
        required_provider_record_id: str | None = None,
        membership_id: str | None = None,
    ) -> TenantInvitation:
        if (
            identity_mode_at_invite is not None
            and identity_mode_at_invite not in IDENTITY_MODES
        ):
            raise IdentityPolicyError("IDENTITY_MODE_INVALID", identity_mode_at_invite)
        now, normalized = _now(), normalize_invite_email(email)
        row = TenantInvitation(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            membership_id=membership_id,
            email=email.strip(),
            normalized_email=normalized,
            role=role,
            status="pending",
            identity_mode_at_invite=identity_mode_at_invite,
            required_provider=required_provider,
            identity_policy_config_id=identity_policy_config_id,
            required_provider_record_id=required_provider_record_id,
            required_connection_id=required_connection_id,
            expires_at=expires_at,
            created_by_user_id=created_by_user_id,
            created_at=now,
            updated_at=now,
        )
        db.add(row)
        emit_identity_audit_event(
            db,
            tenant_id=tenant_id,
            event_type="tenant.invite.created",
            actor_user_id=created_by_user_id,
            affected_email=normalized,
            invitation_id=row.id,
            membership_id=membership_id,
            identity_mode=identity_mode_at_invite,
            provider=required_provider,
            connection_id=required_connection_id,
            provider_record_id=required_provider_record_id,
            policy_config_id=identity_policy_config_id,
            details={"invitation_status": "pending"},
        )
        return row

    def transition_invitation(
        self,
        db: Session,
        invitation: TenantInvitation,
        *,
        to_status: str,
        actor_user_id: str | None = None,
        reason_code: str | None = None,
    ) -> TenantInvitation:
        if to_status not in INVITATION_TRANSITIONS.get(invitation.status, frozenset()):
            raise IdentityPolicyError(
                "INVITATION_TRANSITION_INVALID",
                f"{invitation.status!r} cannot transition to {to_status!r}",
            )
        events = {
            "auth_started": "tenant.invite.auth_started",
            "accepted_identity_pending_binding": "tenant.invite.binding_pending",
            "bound": "tenant.invite.bound",
            "expired": "tenant.invite.expired",
            "revoked": "tenant.invite.revoked",
            "failed": "tenant.membership.identity_binding_failed",
        }
        if to_status not in events:
            raise IdentityPolicyError("INVITATION_TRANSITION_AUDIT_REQUIRED", to_status)
        now = _now()
        invitation.status = to_status
        invitation.updated_at = now
        if to_status == "accepted_identity_pending_binding":
            invitation.accepted_at = now
            invitation.approved_by_user_id = actor_user_id
            invitation.approved_at = now
        if to_status == "bound":
            invitation.bound_at = now
        if to_status == "revoked":
            invitation.revoked_at = now
            invitation.revoked_by_user_id = actor_user_id
        emit_identity_audit_event(
            db,
            tenant_id=invitation.tenant_id,
            event_type=events[to_status],
            actor_user_id=actor_user_id,
            affected_email=invitation.normalized_email,
            invitation_id=invitation.id,
            membership_id=invitation.membership_id,
            identity_mode=invitation.identity_mode_at_invite,
            provider=invitation.required_provider,
            connection_id=invitation.required_connection_id,
            provider_record_id=invitation.required_provider_record_id,
            policy_config_id=invitation.identity_policy_config_id,
            reason_code=reason_code,
            details={"invitation_status": to_status},
        )
        return invitation
