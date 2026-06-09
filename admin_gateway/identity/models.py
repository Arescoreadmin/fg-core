"""Minimal Admin Gateway mappings for the shared identity governance schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class IdentityBase(DeclarativeBase):
    pass


class TenantIdentityConfig(IdentityBase):
    __tablename__ = "tenant_identity_configs"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    identity_mode: Mapped[str] = mapped_column(String(32))
    maturity_level: Mapped[str] = mapped_column(String(32))
    capability_flags: Mapped[Any] = mapped_column(JSON)
    provider: Mapped[str] = mapped_column(String(64))
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))
    auth0_organization_id: Mapped[str | None] = mapped_column(String(256))
    auth0_connection_id: Mapped[str | None] = mapped_column(String(256))
    allowed_email_domains: Mapped[Any] = mapped_column(JSON)
    sso_enforced: Mapped[bool] = mapped_column(Boolean)
    provisioning_status: Mapped[str] = mapped_column(String(32))


class TenantIdentityProvider(IdentityBase):
    __tablename__ = "tenant_identity_providers"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    identity_config_id: Mapped[str] = mapped_column(String(128))
    provider: Mapped[str] = mapped_column(String(64))
    oidc_issuer: Mapped[str | None] = mapped_column(String(512))
    organization_id: Mapped[str | None] = mapped_column(String(256))
    connection_id: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32))
    is_primary: Mapped[bool] = mapped_column(Boolean)


class TenantIdentityDomain(IdentityBase):
    __tablename__ = "tenant_identity_domains"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    provider_record_id: Mapped[str | None] = mapped_column(String(128))
    domain: Mapped[str] = mapped_column(String(256))
    domain_type: Mapped[str] = mapped_column(String(32))
    verification_status: Mapped[str] = mapped_column(String(32))


class TenantInvitation(IdentityBase):
    __tablename__ = "tenant_invitations"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    membership_id: Mapped[str | None] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(256))
    normalized_email: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(64))
    identity_mode_at_invite: Mapped[str | None] = mapped_column(String(32))
    required_provider: Mapped[str | None] = mapped_column(String(64))
    identity_policy_config_id: Mapped[str | None] = mapped_column(String(128))
    required_provider_record_id: Mapped[str | None] = mapped_column(String(128))
    required_connection_id: Mapped[str | None] = mapped_column(String(256))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_user_id: Mapped[str | None] = mapped_column(String(128))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approved_by_user_id: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    bound_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantIdentityAuthState(IdentityBase):
    __tablename__ = "tenant_identity_auth_states"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    invitation_id: Mapped[str] = mapped_column(String(128))
    membership_id: Mapped[str | None] = mapped_column(String(128))
    state_digest: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[str] = mapped_column(String(128))
    requested_provider: Mapped[str | None] = mapped_column(String(64))
    requested_connection_id: Mapped[str | None] = mapped_column(String(256))
    return_url: Mapped[str | None] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="started")
    validated_provider: Mapped[str | None] = mapped_column(String(64))
    validated_issuer: Mapped[str | None] = mapped_column(String(512))
    validated_subject: Mapped[str | None] = mapped_column(String(512))
    validated_email: Mapped[str | None] = mapped_column(String(256))
    validated_email_verified: Mapped[bool | None] = mapped_column(Boolean)
    validated_connection_id: Mapped[str | None] = mapped_column(String(256))
    validated_organization_id: Mapped[str | None] = mapped_column(String(256))
    validated_identity_type: Mapped[str | None] = mapped_column(String(32))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantIdentityAuditEvent(IdentityBase):
    __tablename__ = "tenant_identity_audit_events"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    event_type: Mapped[str] = mapped_column(String(128))
    actor_user_id: Mapped[str | None] = mapped_column(String(128))
    affected_email: Mapped[str | None] = mapped_column(String(256))
    invitation_id: Mapped[str | None] = mapped_column(String(128))
    membership_id: Mapped[str | None] = mapped_column(String(128))
    identity_mode: Mapped[str | None] = mapped_column(String(32))
    provider: Mapped[str | None] = mapped_column(String(64))
    connection_id: Mapped[str | None] = mapped_column(String(256))
    reason_code: Mapped[str | None] = mapped_column(String(128))
    identity_type: Mapped[str | None] = mapped_column(String(32))
    identity_subject: Mapped[str | None] = mapped_column(String(512))
    provider_record_id: Mapped[str | None] = mapped_column(String(128))
    policy_config_id: Mapped[str | None] = mapped_column(String(128))
    role_assignment_id: Mapped[str | None] = mapped_column(String(128))
    correlation_id: Mapped[str | None] = mapped_column(String(128))
    previous_event_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[Any] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class TenantUser(IdentityBase):
    __tablename__ = "tenant_users"
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32))
    active: Mapped[bool] = mapped_column(Boolean)
    identity_type: Mapped[str] = mapped_column(String(32))
    identity_provider: Mapped[str | None] = mapped_column(String(64))
    identity_provider_record_id: Mapped[str | None] = mapped_column(String(128))
    identity_policy_config_id: Mapped[str | None] = mapped_column(String(128))
    identity_connection_id: Mapped[str | None] = mapped_column(String(256))
    identity_subject: Mapped[str | None] = mapped_column(String(512))
    identity_issuer: Mapped[str | None] = mapped_column(String(512))
    identity_email: Mapped[str | None] = mapped_column(String(256))
    identity_email_verified: Mapped[bool] = mapped_column(Boolean)
    identity_bound_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    identity_binding_status: Mapped[str] = mapped_column(String(32))
    last_identity_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
