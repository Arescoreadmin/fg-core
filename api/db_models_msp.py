"""api/db_models_msp.py — MSP-001 MSP designation and service relationships.

ORM mirror of migrations/postgres/0206_msp_service_relationships.sql. Column
names, CHECK constraints and index names match the migration so the SQLite
create_all path and the Postgres migration path produce the same schema.

The customer tenant is stored in ``tenant_id`` (it owns the data); the service
provider is ``msp_tenant_id``. Both reference canonical ``tenants.tenant_id``;
neither table stores tenant attributes. See api/msp_authority.py.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base

OPEN_RELATIONSHIP_STATUSES = ("proposed", "approved", "suspended")
_OPEN_STATUS_SQL = "status IN ('proposed', 'approved', 'suspended')"


class MspOrganization(Base):
    """Platform designation of a canonical tenant as an MSP organization."""

    __tablename__ = "msp_organizations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('active', 'suspended')", name="msp_org_status_check"
        ),
    )

    tenant_id: Mapped[Any] = mapped_column(String(128), primary_key=True)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    designated_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    designated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    status_changed_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    status_changed_at: Mapped[Any] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class MspServiceRelationship(Base):
    """One MSP organization serving one customer tenant, approved by the customer."""

    __tablename__ = "msp_service_relationships"
    __table_args__ = (
        CheckConstraint(
            "status IN ('proposed', 'approved', 'suspended', 'revoked')",
            name="msp_rel_status_check",
        ),
        CheckConstraint(
            "revoked_by_party IS NULL OR revoked_by_party IN ('customer', 'msp')",
            name="msp_rel_revoked_by_party_check",
        ),
        CheckConstraint("msp_tenant_id <> tenant_id", name="msp_rel_distinct_parties"),
        CheckConstraint(
            "status NOT IN ('approved', 'suspended') OR ("
            "approved_by_subject IS NOT NULL AND approved_at IS NOT NULL "
            "AND authorized_capabilities IS NOT NULL AND effective_at IS NOT NULL)",
            name="msp_rel_approved_complete",
        ),
        CheckConstraint(
            "status <> 'revoked' OR "
            "(revoked_at IS NOT NULL AND revoked_by_subject IS NOT NULL)",
            name="msp_rel_revoked_complete",
        ),
        CheckConstraint(
            "expires_at IS NULL OR effective_at IS NULL OR expires_at > effective_at",
            name="msp_rel_window_order",
        ),
        Index(
            "uq_msp_rel_open_pair",
            "msp_tenant_id",
            "tenant_id",
            unique=True,
            sqlite_where=text(_OPEN_STATUS_SQL),
            postgresql_where=text(_OPEN_STATUS_SQL),
        ),
        Index("ix_msp_rel_msp_status", "msp_tenant_id", "status"),
        Index("ix_msp_rel_customer_status", "tenant_id", "status"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    msp_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    requested_capabilities: Mapped[Any] = mapped_column(Text, nullable=False)
    authorized_capabilities: Mapped[Any] = mapped_column(Text, nullable=True)
    proposed_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    proposed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    approved_by_membership_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    suspended_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    revoked_by_party: Mapped[Any] = mapped_column(String(16), nullable=True)
    version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
