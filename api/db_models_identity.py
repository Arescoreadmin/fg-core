"""ORM records for provider-neutral tenant identity policy and invitations."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


class TenantIdentityConfig(Base):
    __tablename__ = "tenant_identity_configs"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_tenant_identity_configs_tenant"),
        Index("ix_tenant_identity_configs_status", "provisioning_status"),
        CheckConstraint(
            "identity_mode IN ('managed','sso','hybrid')",
            name="chk_tenant_identity_configs_mode",
        ),
        CheckConstraint(
            "provisioning_status IN ('not_configured','pending','ready','failed','disabled')",
            name="chk_tenant_identity_configs_status",
        ),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    identity_mode: Mapped[Any] = mapped_column(String(32), nullable=False)
    maturity_level: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="level_0", server_default=text("'level_0'")
    )
    capability_flags: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    provider: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="auth0", server_default=text("'auth0'")
    )
    oidc_issuer: Mapped[Any] = mapped_column(String(512), nullable=True)
    auth0_organization_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    auth0_connection_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    allowed_email_domains: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
    sso_enforced: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    provisioning_status: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="not_configured",
        server_default=text("'not_configured'"),
    )
    provisioning_error_code: Mapped[Any] = mapped_column(String(128), nullable=True)
    provisioning_error_message: Mapped[Any] = mapped_column(Text, nullable=True)
    configured_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    configured_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantIdentityProvider(Base):
    """Provider/issuer/connection records under a tenant governance policy."""

    __tablename__ = "tenant_identity_providers"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "provider",
            "oidc_issuer",
            "organization_id",
            "connection_id",
            name="uq_tenant_identity_providers_binding",
        ),
        Index("ix_tenant_identity_providers_tenant_status", "tenant_id", "status"),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    identity_config_id: Mapped[Any] = mapped_column(
        String(128),
        ForeignKey("tenant_identity_configs.id"),
        nullable=False,
        index=True,
    )
    provider: Mapped[Any] = mapped_column(String(64), nullable=False)
    oidc_issuer: Mapped[Any] = mapped_column(String(512), nullable=True)
    organization_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    connection_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    status: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="configured",
        server_default=text("'configured'"),
    )
    is_primary: Mapped[Any] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantIdentityDomain(Base):
    """Normalized domain governance record; no domain role is inferred from email alone."""

    __tablename__ = "tenant_identity_domains"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "domain",
            "domain_type",
            "provider_record_id",
            name="uq_tenant_identity_domains_type",
        ),
        Index(
            "ix_tenant_identity_domains_tenant_status",
            "tenant_id",
            "verification_status",
        ),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    identity_config_id: Mapped[Any] = mapped_column(
        String(128),
        ForeignKey("tenant_identity_configs.id"),
        nullable=False,
        index=True,
    )
    provider_record_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    domain: Mapped[Any] = mapped_column(String(256), nullable=False)
    domain_type: Mapped[Any] = mapped_column(
        String(32), nullable=False, default="trusted", server_default=text("'trusted'")
    )
    verification_status: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="unverified",
        server_default=text("'unverified'"),
    )
    verified_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantIdentityRoleAssignment(Base):
    """Role assignment lineage without implementing a role engine."""

    __tablename__ = "tenant_identity_role_assignments"
    __table_args__ = (
        Index("ix_tenant_identity_roles_membership", "tenant_id", "membership_id"),
        Index("ix_tenant_identity_roles_active", "tenant_id", "revoked_at"),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    membership_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    role: Mapped[Any] = mapped_column(String(64), nullable=False)
    assignment_source: Mapped[Any] = mapped_column(String(32), nullable=False)
    approval_source: Mapped[Any] = mapped_column(String(32), nullable=True)
    source_reference: Mapped[Any] = mapped_column(String(256), nullable=True)
    assigned_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    approved_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    assigned_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)


class TenantInvitation(Base):
    __tablename__ = "tenant_invitations"
    __table_args__ = (
        CheckConstraint(
            "identity_mode_at_invite IS NULL OR identity_mode_at_invite IN ('managed','sso','hybrid')",
            name="chk_tenant_invitations_mode",
        ),
        Index("ix_tenant_invitations_tenant_email", "tenant_id", "normalized_email"),
        Index("ix_tenant_invitations_tenant_status", "tenant_id", "status"),
        Index("ix_tenant_invitations_status_expiry", "status", "expires_at"),
        CheckConstraint(
            "status IN ('pending','auth_started','accepted_identity_pending_binding','bound','expired','revoked','failed')",
            name="chk_tenant_invitations_status",
        ),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    membership_id: Mapped[Any] = mapped_column(String(128), nullable=True, index=True)
    email: Mapped[Any] = mapped_column(String(256), nullable=False)
    normalized_email: Mapped[Any] = mapped_column(String(256), nullable=False)
    role: Mapped[Any] = mapped_column(String(32), nullable=False, default="user")
    status: Mapped[Any] = mapped_column(
        String(64), nullable=False, default="pending", server_default=text("'pending'")
    )
    identity_mode_at_invite: Mapped[Any] = mapped_column(String(32), nullable=True)
    required_provider: Mapped[Any] = mapped_column(String(64), nullable=True)
    identity_policy_config_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    required_provider_record_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    required_connection_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    auth0_invitation_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    accepted_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    bound_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    updated_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )


class TenantIdentityAuditEvent(Base):
    __tablename__ = "tenant_identity_audit_events"
    __table_args__ = (
        Index("ix_tenant_identity_audit_tenant_created", "tenant_id", "created_at"),
        Index("ix_tenant_identity_audit_invitation", "invitation_id"),
        Index("ix_tenant_identity_audit_membership", "membership_id"),
        Index("ix_tenant_identity_audit_event_type", "tenant_id", "event_type"),
    )
    id: Mapped[Any] = mapped_column(
        String(128), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False, index=True)
    event_type: Mapped[Any] = mapped_column(String(128), nullable=False)
    actor_user_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    affected_email: Mapped[Any] = mapped_column(String(256), nullable=True)
    invitation_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    membership_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    identity_mode: Mapped[Any] = mapped_column(String(32), nullable=True)
    provider: Mapped[Any] = mapped_column(String(64), nullable=True)
    connection_id: Mapped[Any] = mapped_column(String(256), nullable=True)
    reason_code: Mapped[Any] = mapped_column(String(128), nullable=True)
    identity_type: Mapped[Any] = mapped_column(String(32), nullable=True)
    identity_subject: Mapped[Any] = mapped_column(String(512), nullable=True)
    provider_record_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    policy_config_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    role_assignment_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    correlation_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    previous_event_hash: Mapped[Any] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[Any] = mapped_column(String(64), nullable=False, index=True)
    details_json: Mapped[Any] = mapped_column(
        JSON, nullable=False, default=dict, server_default=text("'{}'")
    )
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
