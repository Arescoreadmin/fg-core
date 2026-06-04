# api/db_models_ai_vendor_governance.py
"""SQLAlchemy ORM models for the Third-Party AI Governance Workflow Engine (PR 4).

Not standalone — requires the fg-core API, auth layer, and Postgres substrate.
This module is not standalone. It requires the fg-core API, auth layer, and Postgres substrate.

One governance record per (engagement_id, tenant_id, tool_name), generated
deterministically from PR 1/2/3 evidence. Represents an AI vendor progressing
through a structured governance lifecycle.

FaAiVendorGovernanceDecision rows are append-only. DB-level triggers on
fa_ai_vendor_governance_decisions block UPDATE and DELETE — enforced in
migration 0092.

Tenant isolation:
  All queries must include a tenant_id predicate.

Workflow states (enforced by state_machine.py):
  discovered → needs_owner → needs_review → approved / restricted /
  rejected / exception_granted → retired

Mutable fields (PATCH-updatable by authorized operators):
  ownership fields, business context, contract, DPA, BAA, security review,
  privacy review, compliance evidence, risk governance, lifecycle dates.

Immutable fields (set at generation, read-only):
  id, tenant_id, engagement_id, vendor, tool_name, tool_id, target_type,
  governance_readiness (always recomputed server-side), pr* source refs,
  risk_score, graph_node_ids, created_at.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

try:
    from sqlalchemy import JSON
except ImportError:  # pragma: no cover
    from sqlalchemy import JSON  # type: ignore[assignment]

from api.db_models import Base


class FaAiVendorGovernanceRecord(Base):
    """Deterministic governance record — one per vendor tool per engagement."""

    __tablename__ = "fa_ai_vendor_governance_records"

    # -----------------------------------------------------------------------
    # Core identity
    # -----------------------------------------------------------------------
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # extensible target type — supports vendor/ai_tool/ai_agent/autonomous_system/
    # agent_swarm/decision_engine/agi_provider without schema migration
    target_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="ai_tool"
    )

    # workflow state — server-enforced via state_machine.py
    workflow_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="discovered"
    )

    # -----------------------------------------------------------------------
    # Ownership
    # -----------------------------------------------------------------------
    business_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    technical_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    executive_sponsor: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # -----------------------------------------------------------------------
    # Business context
    # -----------------------------------------------------------------------
    business_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    business_process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(255), nullable=True)
    criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )

    # -----------------------------------------------------------------------
    # Data governance
    # -----------------------------------------------------------------------
    data_processed: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    sensitive_data_types: Mapped[list] = mapped_column(
        JSON, nullable=False, default=list
    )
    regulated_data_present: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    data_residency_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # -----------------------------------------------------------------------
    # Contract governance
    # -----------------------------------------------------------------------
    contract_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    contract_owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contract_expiration: Mapped[str | None] = mapped_column(String(64), nullable=True)
    renewal_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # DPA governance
    # -----------------------------------------------------------------------
    dpa_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    dpa_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    dpa_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Healthcare governance (BAA)
    # -----------------------------------------------------------------------
    baa_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    baa_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    baa_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Security governance
    # -----------------------------------------------------------------------
    security_review_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_started"
    )
    security_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    security_reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # -----------------------------------------------------------------------
    # Privacy governance
    # -----------------------------------------------------------------------
    privacy_review_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="not_started"
    )
    privacy_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    privacy_reviewer: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # -----------------------------------------------------------------------
    # Compliance evidence
    # -----------------------------------------------------------------------
    soc2_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    soc2_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    soc2_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    iso27001_available: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    iso27001_reviewed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    iso_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Risk governance
    # -----------------------------------------------------------------------
    risk_acceptance_required: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    risk_acceptance_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    risk_acceptance_owner: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    risk_acceptance_expiration: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # -----------------------------------------------------------------------
    # Lifecycle governance
    # -----------------------------------------------------------------------
    review_due_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_review_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    renewal_due_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    retirement_date: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Governance readiness — deterministic, recomputed server-side each run
    # -----------------------------------------------------------------------
    governance_readiness: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )

    # -----------------------------------------------------------------------
    # Source cross-references from PR 1/2/3
    # -----------------------------------------------------------------------
    pr1_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pr2_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pr3_risk_record_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[str] = mapped_column(
        String(32), nullable=False, default="unknown"
    )
    risk_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    regulatory_flags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # -----------------------------------------------------------------------
    # Evidence and finding cross-references
    # -----------------------------------------------------------------------
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    finding_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    # -----------------------------------------------------------------------
    # Graph-ready identifiers
    # -----------------------------------------------------------------------
    graph_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    vendor_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    owner_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    contract_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    evidence_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decision_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    governance_node_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # -----------------------------------------------------------------------
    # Source scan traceability
    # -----------------------------------------------------------------------
    source_scan_result_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # -----------------------------------------------------------------------
    # Timestamps
    # -----------------------------------------------------------------------
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    last_reviewed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "engagement_id",
            "tenant_id",
            "tool_name",
            name="uq_fa_ai_vendor_gov_tool",
        ),
        Index("ix_fa_ai_vendor_gov_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_ai_vendor_gov_tenant_state", "tenant_id", "workflow_state"),
        Index(
            "ix_fa_ai_vendor_gov_tenant_readiness", "tenant_id", "governance_readiness"
        ),
        Index("ix_fa_ai_vendor_gov_tenant_risk", "tenant_id", "risk_score"),
    )


class FaAiVendorGovernanceDecision(Base):
    """Append-only governance decision ledger — one row per governance action.

    DB-level triggers in migration 0092 block UPDATE and DELETE.
    Do not attempt to modify existing rows — create new ones for amendments.
    """

    __tablename__ = "fa_ai_vendor_governance_decisions"

    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    engagement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    governance_record_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Tool identity duplicated for auditability — survives record deletion
    vendor: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[str] = mapped_column(
        String(64), nullable=False, default="ai_tool"
    )

    # Decision record
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    previous_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    new_state: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Actor attribution — required for every decision
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_name: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_email: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Evidence and context
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    exception_expiration: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_ai_vendor_gov_dec_tenant_eng", "tenant_id", "engagement_id"),
        Index("ix_fa_ai_vendor_gov_dec_record", "governance_record_id"),
    )
