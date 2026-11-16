"""api/db_models_msp.py — MSP designation, service relationships and payer assignments.

ORM mirror of migrations/postgres/0206_msp_service_relationships.sql (MSP-001)
and the msp_payer_assignments table of 0207_msp_006_partner_billing.sql (MSP-006),
0208 (MSP-003) and 0209_msp_007_report_shares.sql (MSP-007). Column
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
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
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


_ACTIVE_ASSIGNMENT_SQL = "status = 'active'"


class MspPayerAssignment(Base):
    """MSP-006: which party pays for one product delivered to one customer.

    A platform decision bound to the payer's existing commercial agreement
    (``subscription_contracts``). It is not consent (that is the relationship)
    and not a price (that is ``tenant_contracts`` / ``pricing_versions``).
    """

    __tablename__ = "msp_payer_assignments"
    __table_args__ = (
        CheckConstraint(
            "billing_mode IN ('msp_paid', 'customer_paid')",
            name="msp_payer_billing_mode_check",
        ),
        CheckConstraint(
            "status IN ('active', 'terminated')", name="msp_payer_status_check"
        ),
        CheckConstraint(
            "(billing_mode = 'msp_paid' AND payer_tenant_id = msp_tenant_id) OR "
            "(billing_mode = 'customer_paid' AND payer_tenant_id = tenant_id)",
            name="msp_payer_mode_matches_payer",
        ),
        CheckConstraint(
            "msp_tenant_id <> tenant_id", name="msp_payer_distinct_parties"
        ),
        CheckConstraint("expires_at > effective_at", name="msp_payer_window"),
        CheckConstraint(
            "length(currency) = 3 AND currency = upper(currency)",
            name="msp_payer_currency_code",
        ),
        CheckConstraint(
            "status <> 'terminated' OR "
            "(terminated_by_subject IS NOT NULL AND terminated_at IS NOT NULL)",
            name="msp_payer_terminated_fields",
        ),
        Index(
            "uq_msp_payer_one_active_per_product",
            "tenant_id",
            "product_code",
            unique=True,
            sqlite_where=text(_ACTIVE_ASSIGNMENT_SQL),
            postgresql_where=text(_ACTIVE_ASSIGNMENT_SQL),
        ),
        Index("ix_msp_payer_payer_status", "payer_tenant_id", "status"),
        Index("ix_msp_payer_relationship", "relationship_id"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    msp_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    relationship_id: Mapped[Any] = mapped_column(
        String(36), ForeignKey("msp_service_relationships.id"), nullable=False
    )
    payer_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    billing_mode: Mapped[Any] = mapped_column(String(16), nullable=False)
    product_code: Mapped[Any] = mapped_column(String(64), nullable=False)
    subscription_contract_id: Mapped[Any] = mapped_column(Text, nullable=False)
    currency: Mapped[Any] = mapped_column(String(3), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    effective_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    approved_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    terminated_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    terminated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)


class MspAssessmentGrant(Base):
    """MSP-003: one customer-approved, expiring, single-use assessment grant.

    Lets an MSP initiate exactly one Field Assessment engagement in the
    customer's tenant. Separate from the MSP-001 relationship, whose delegation
    ceiling stays read-only. The engagement lives in ``fa_engagements`` (owned
    by the customer); this row stores only the authorization and the link.
    """

    __tablename__ = "msp_assessment_grants"
    __table_args__ = (
        CheckConstraint(
            "status IN ('requested', 'approved', 'rejected', 'withdrawn', "
            "'initiated', 'revoked')",
            name="msp_assessment_grants_status_check",
        ),
        CheckConstraint(
            "msp_tenant_id <> tenant_id", name="msp_grant_distinct_parties"
        ),
        CheckConstraint("expires_at > requested_at", name="msp_grant_window"),
        CheckConstraint(
            "status <> 'initiated' OR (engagement_id IS NOT NULL AND "
            "initiated_by_subject IS NOT NULL AND initiated_at IS NOT NULL)",
            name="msp_grant_initiated_has_engagement",
        ),
        CheckConstraint(
            "engagement_id IS NULL OR status IN ('initiated', 'revoked')",
            name="msp_grant_engagement_only_when_used",
        ),
        CheckConstraint(
            "status IN ('requested', 'withdrawn') OR "
            "(decided_by_subject IS NOT NULL AND decided_at IS NOT NULL)",
            name="msp_grant_decided_fields",
        ),
        CheckConstraint(
            "status <> 'revoked' OR "
            "(revoked_by_subject IS NOT NULL AND revoked_at IS NOT NULL)",
            name="msp_grant_revoked_fields",
        ),
        UniqueConstraint(
            "msp_tenant_id",
            "tenant_id",
            "request_key",
            name="uq_msp_grant_request_key",
        ),
        UniqueConstraint("engagement_id", name="uq_msp_grant_engagement"),
        Index("ix_msp_grant_customer_status", "tenant_id", "status"),
        Index("ix_msp_grant_msp_status", "msp_tenant_id", "status"),
        Index("ix_msp_grant_relationship", "relationship_id"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    msp_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    relationship_id: Mapped[Any] = mapped_column(
        String(36), ForeignKey("msp_service_relationships.id"), nullable=False
    )
    request_key: Mapped[Any] = mapped_column(String(128), nullable=False)
    capabilities: Mapped[Any] = mapped_column(Text, nullable=False)
    assessment_type: Mapped[Any] = mapped_column(String(64), nullable=False)
    assessor_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    requested_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    requested_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    decided_by_membership_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    engagement_id: Mapped[Any] = mapped_column(String(64), nullable=True)
    initiated_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    initiated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)


class MspOnboardingRequest(Base):
    """MSP-003: an MSP's referral of an organization not yet on FrostGate.

    A review queue only. The platform provisions the tenant through the
    canonical routes, then links the request. Nothing here creates a tenant, a
    user or a relationship. Visible to the requesting MSP only.
    """

    __tablename__ = "msp_onboarding_requests"
    __table_args__ = (
        CheckConstraint(
            "status IN ('requested', 'rejected', 'canceled', 'linked')",
            name="msp_onboarding_requests_status_check",
        ),
        CheckConstraint("expires_at > requested_at", name="msp_onboarding_window"),
        CheckConstraint(
            "status <> 'linked' OR (customer_tenant_id IS NOT NULL AND "
            "reviewed_by_subject IS NOT NULL AND reviewed_at IS NOT NULL)",
            name="msp_onboarding_linked_fields",
        ),
        CheckConstraint(
            "customer_tenant_id IS NULL OR customer_tenant_id <> tenant_id",
            name="msp_onboarding_not_self",
        ),
        UniqueConstraint(
            "tenant_id", "request_key", name="uq_msp_onboarding_request_key"
        ),
        Index("ix_msp_onboarding_msp_status", "tenant_id", "status"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    request_key: Mapped[Any] = mapped_column(String(128), nullable=False)
    organization_name: Mapped[Any] = mapped_column(String(200), nullable=False)
    contact_email: Mapped[Any] = mapped_column(String(254), nullable=False)
    requested_capabilities: Mapped[Any] = mapped_column(Text, nullable=False)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    requested_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    requested_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    reviewed_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    customer_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)


class MspReportShare(Base):
    """MSP-007: a customer's decision to let one MSP read one exact, released
    report version (id, version and manifest fingerprint) until ``expires_at``.

    ORM mirror of migrations/postgres/0209_msp_007_report_shares.sql. The report
    stays in ``governance_reports``; this row is only the authorization. An
    MSP-origin row starts as a request; only the customer makes it active.
    Rows are never deleted, so the access history survives revocation.
    """

    __tablename__ = "msp_report_shares"
    __table_args__ = (
        CheckConstraint(
            "origin IN ('customer', 'msp')", name="msp_report_shares_origin_check"
        ),
        CheckConstraint(
            "status IN ('requested', 'active', 'rejected', 'withdrawn', 'revoked', "
            "'expired')",
            name="msp_report_shares_status_check",
        ),
        CheckConstraint(
            "msp_tenant_id <> tenant_id", name="msp_share_distinct_parties"
        ),
        CheckConstraint(
            "status NOT IN ('active', 'revoked', 'expired') OR (report_id IS NOT NULL AND "
            "report_version IS NOT NULL AND manifest_hash IS NOT NULL AND "
            "decided_by_subject IS NOT NULL AND decided_at IS NOT NULL AND "
            "expires_at IS NOT NULL AND expires_at > decided_at)",
            name="msp_share_bound_report",
        ),
        CheckConstraint(
            "status <> 'rejected' OR (decided_by_subject IS NOT NULL AND "
            "decided_at IS NOT NULL)",
            name="msp_share_rejected_fields",
        ),
        CheckConstraint(
            "status <> 'revoked' OR (revoked_by_subject IS NOT NULL AND "
            "revoked_at IS NOT NULL)",
            name="msp_share_revoked_fields",
        ),
        CheckConstraint(
            "origin <> 'msp' OR source_grant_id IS NOT NULL",
            name="msp_share_msp_origin_has_grant",
        ),
        UniqueConstraint(
            "tenant_id",
            "msp_tenant_id",
            "origin",
            "request_key",
            name="uq_msp_share_request_key",
        ),
        Index(
            "uq_msp_share_active_report",
            "tenant_id",
            "msp_tenant_id",
            "report_id",
            unique=True,
            postgresql_where=text("status = 'active'"),
            sqlite_where=text("status = 'active'"),
        ),
        Index("ix_msp_share_customer_status", "tenant_id", "status"),
        Index("ix_msp_share_msp_status", "msp_tenant_id", "status"),
        Index("ix_msp_share_relationship", "relationship_id"),
    )

    id: Mapped[Any] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    msp_tenant_id: Mapped[Any] = mapped_column(String(128), nullable=False)
    relationship_id: Mapped[Any] = mapped_column(
        String(36), ForeignKey("msp_service_relationships.id"), nullable=False
    )
    origin: Mapped[Any] = mapped_column(String(16), nullable=False)
    request_key: Mapped[Any] = mapped_column(String(128), nullable=False)
    engagement_id: Mapped[Any] = mapped_column(String(64), nullable=False)
    source_grant_id: Mapped[Any] = mapped_column(String(36), nullable=True)
    report_id: Mapped[Any] = mapped_column(String(255), nullable=True)
    report_version: Mapped[Any] = mapped_column(Integer, nullable=True)
    manifest_hash: Mapped[Any] = mapped_column(String(128), nullable=True)
    status: Mapped[Any] = mapped_column(String(16), nullable=False)
    requested_by_subject: Mapped[Any] = mapped_column(Text, nullable=False)
    requested_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    decided_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    decided_by_membership_id: Mapped[Any] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_subject: Mapped[Any] = mapped_column(Text, nullable=True)
    revoked_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[Any] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[Any] = mapped_column(DateTime(timezone=True), nullable=False)
