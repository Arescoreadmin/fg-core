# api/db_models_external_ai_risk.py
"""SQLAlchemy ORM model for the External AI Risk Register (PR 3).

Not standalone — requires the fg-core API, auth layer, and Postgres substrate.

One record per AI tool per engagement, generated deterministically from
PR 1 (AI Tool Discovery) and PR 2 (AI Data Access Mapping) evidence.

Tenant isolation:
  All queries must include a tenant_id predicate.

Uniqueness:
  One risk record per (engagement_id, tenant_id, tool_name) — regeneration
  updates the existing record rather than creating duplicates.

Review mutations:
  review_status, business_owner, and technical_owner may be updated
  by authorized operators via PATCH routes. All other fields are
  set deterministically at generation time and are read-only.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class FaExternalAiRiskRecord(Base):
    """Deterministic external AI risk record — one per tool per engagement."""

    __tablename__ = "fa_external_ai_risk_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Tool identification (from PR 1)
    tool_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)

    # Ownership — default Unknown; updatable via PATCH
    business_owner: Mapped[str] = mapped_column(
        String(255), nullable=False, default="Unknown"
    )
    technical_owner: Mapped[str] = mapped_column(
        String(255), nullable=False, default="Unknown"
    )

    # Permissions and data access (from PR 1 + PR 2)
    permissions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_access_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    sensitive_data_exposure: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )

    # Publisher trust (from PR 1)
    publisher_trust: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )

    # Access scope (from PR 1 + PR 2)
    user_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    admin_consent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Risk classification — deterministic, set at generation
    risk_score: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_reason: Mapped[str] = mapped_column(Text, nullable=False)
    risk_category: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)

    # Review — default unreviewed; updatable via PATCH
    review_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unreviewed"
    )

    # Addition 1 — Ownership model; updatable via PATCH
    risk_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="Unknown"
    )

    # Addition 2 — Governance state; deterministic at generation; exception_granted via PATCH
    governance_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )

    # Addition 3 — Decision linkage; updatable via PATCH
    decision_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    risk_acceptance_refs: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    exception_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    approval_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Addition 4 — Vendor governance status; defaults set at generation; future PR 3.5
    vendor_review_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_reviewed"
    )
    vendor_dpa_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    vendor_baa_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    vendor_security_review_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    vendor_last_reviewed_at: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Addition 5 — Regulatory impact flags; deterministic at generation
    regulatory_flags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Addition 6 — Risk aging
    risk_age_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    first_detected_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_observed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Addition 7 — Remediation tracking; updatable via PATCH
    remediation_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_started"
    )
    remediation_target_date: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    remediation_completed_at: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Evidence and finding cross-references
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    finding_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # Graph-ready identifiers (Addition 10)
    graph_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    risk_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    governance_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Source scan traceability
    source_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pr1_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "tenant_id",
            "tool_name",
            name="uq_fa_ext_ai_risk_tool",
        ),
        Index("ix_fa_ext_ai_risk_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_ext_ai_risk_tenant_score", "tenant_id", "risk_score"),
        Index("ix_fa_ext_ai_risk_tenant_category", "tenant_id", "risk_category"),
        Index("ix_fa_ext_ai_risk_tenant_gov", "tenant_id", "governance_state"),
        Index(
            "ix_fa_ext_ai_risk_tenant_remediation", "tenant_id", "remediation_status"
        ),
    )
