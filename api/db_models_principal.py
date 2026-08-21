"""ORM records for fg_principals and fg_external_identities.

PR-AUTH-001 introduces the Principal/ExternalIdentity split:
  fg_principals        — canonical cross-tenant human identity record
  fg_external_identities — immutable (provider, issuer, subject) binding per principal

Neither table is tenant-scoped (no RLS). Isolation is enforced through the
tenant_users membership table and application-layer capability checks.

Lookup path at session issuance:
  Auth0 sub claim
    → fg_external_identities WHERE provider='auth0' AND provider_issuer AND provider_subject
    → principal_id → fg_principals WHERE lifecycle_state='active'
    → tenant_users WHERE principal_id AND active=TRUE
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base, utcnow


class FgPrincipal(Base):
    __tablename__ = "fg_principals"
    __table_args__ = (
        CheckConstraint(
            "principal_type IN ('human')",
            name="chk_fg_principals_type",
        ),
        CheckConstraint(
            "lifecycle_state IN ('active', 'suspended', 'deactivated')",
            name="chk_fg_principals_lifecycle",
        ),
        Index("ix_fg_principals_lifecycle", "lifecycle_state"),
        Index(
            "ix_fg_principals_primary_email",
            "primary_email",
            postgresql_where=text("primary_email IS NOT NULL"),
        ),
    )

    id: Mapped[Any] = mapped_column(
        Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    display_name: Mapped[Any] = mapped_column(Text, nullable=True)
    primary_email: Mapped[Any] = mapped_column(Text, nullable=True)
    principal_type: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="human",
        server_default=text("'human'"),
    )
    lifecycle_state: Mapped[Any] = mapped_column(
        String(32),
        nullable=False,
        default="active",
        server_default=text("'active'"),
    )
    mfa_verified: Mapped[Any] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    authority_version: Mapped[Any] = mapped_column(
        BigInteger,
        nullable=False,
        default=1,
        server_default=text("1"),
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
        onupdate=utcnow,
    )


class FgExternalIdentity(Base):
    __tablename__ = "fg_external_identities"
    __table_args__ = (
        UniqueConstraint(
            "provider",
            "provider_issuer",
            "provider_subject",
            name="uq_fg_external_identities_binding",
        ),
        CheckConstraint(
            "provider IN ('auth0', 'entra', 'okta', 'saml', 'oidc_generic')",
            name="chk_fg_external_identities_provider",
        ),
        Index("ix_fg_external_identities_principal", "principal_id"),
    )

    id: Mapped[Any] = mapped_column(
        Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    principal_id: Mapped[Any] = mapped_column(
        Uuid(as_uuid=False),
        ForeignKey("fg_principals.id", ondelete="RESTRICT"),
        nullable=False,
    )
    provider: Mapped[Any] = mapped_column(String(64), nullable=False)
    provider_issuer: Mapped[Any] = mapped_column(Text, nullable=False)
    provider_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    provider_email: Mapped[Any] = mapped_column(Text, nullable=True)
    created_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        server_default=func.now(),
    )
    last_seen_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
