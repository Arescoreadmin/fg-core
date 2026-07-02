"""SQLAlchemy ORM models for PR 18.4 — Continuous Governance Orchestration Authority.

Tables:
  fa_gov_orch_policy              - governance orchestration policies
  fa_gov_orch_policy_version      - policy version history (append-only)
  fa_gov_orch_playbook            - playbook definitions
  fa_gov_orch_workflow            - workflow executions
  fa_gov_orch_reassessment        - reassessment records
  fa_gov_orch_trigger             - detected triggers
  fa_gov_orch_trigger_timeline    - trigger event history (append-only)
  fa_gov_orch_simulation          - governance impact simulations
  fa_gov_orch_approval            - approval records
  fa_gov_orch_maintenance_window  - maintenance/blackout windows
  fa_gov_orch_change_detection    - detected changes
  fa_gov_orch_timeline            - append-only orchestration timeline

Design:
  - Every table carries tenant_id NOT NULL.
  - Append-only tables (trigger_timeline, timeline, policy_version) install
    ORM before_update/before_delete guards and SQL PG rules that block
    UPDATE / DELETE.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Float, Index, Integer, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_gov_orch_policy
# ---------------------------------------------------------------------------


class GovOrchPolicy(Base):
    """Governance orchestration policy record."""

    __tablename__ = "fa_gov_orch_policy"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_level: Mapped[str] = mapped_column(
        String(32), nullable=False, default="MEDIUM"
    )
    policy_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    active: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_orch_policy_tenant_active", "tenant_id", "active"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_policy_version (append-only)
# ---------------------------------------------------------------------------


class GovOrchPolicyVersion(Base):
    """Append-only history of policy versions."""

    __tablename__ = "fa_gov_orch_policy_version"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    policy_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_policy_version_tenant_policy",
            "tenant_id",
            "policy_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovOrchPolicyVersion, "before_update")
def _block_policy_version_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_orch_policy_version is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovOrchPolicyVersion, "before_delete")
def _block_policy_version_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_orch_policy_version is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_playbook
# ---------------------------------------------------------------------------


class GovOrchPlaybook(Base):
    """Governance playbook (template) record."""

    __tablename__ = "fa_gov_orch_playbook"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    playbook_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    playbook_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_playbook_tenant_type",
            "tenant_id",
            "playbook_type",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_workflow
# ---------------------------------------------------------------------------


class GovOrchWorkflow(Base):
    """Governance workflow execution record."""

    __tablename__ = "fa_gov_orch_workflow"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    workflow_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    playbook_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trigger_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_fa_gov_orch_workflow_tenant_state", "tenant_id", "workflow_state"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_reassessment
# ---------------------------------------------------------------------------


class GovOrchReassessment(Base):
    """Reassessment record."""

    __tablename__ = "fa_gov_orch_reassessment"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    assessment_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    trigger_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reassessment_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="REQUESTED"
    )
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    scheduled_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_reassessment_tenant_state",
            "tenant_id",
            "reassessment_state",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_trigger
# ---------------------------------------------------------------------------


class GovOrchTrigger(Base):
    """Detected trigger record."""

    __tablename__ = "fa_gov_orch_trigger"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    trigger_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    policy_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="1.0"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_gov_orch_trigger_tenant_type", "tenant_id", "trigger_type"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_trigger_timeline (append-only)
# ---------------------------------------------------------------------------


class GovOrchTriggerTimeline(Base):
    """Append-only history of trigger-related events."""

    __tablename__ = "fa_gov_orch_trigger_timeline"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    trigger_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_trigger_timeline_tenant_trigger",
            "tenant_id",
            "trigger_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovOrchTriggerTimeline, "before_update")
def _block_trigger_timeline_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_orch_trigger_timeline is append-only - updates are forbidden"
    )


@sa_event.listens_for(GovOrchTriggerTimeline, "before_delete")
def _block_trigger_timeline_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError(
        "fa_gov_orch_trigger_timeline is append-only - deletes are forbidden"
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_simulation
# ---------------------------------------------------------------------------


class GovOrchSimulation(Base):
    """Governance impact simulation record."""

    __tablename__ = "fa_gov_orch_simulation"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    change_type: Mapped[str] = mapped_column(String(64), nullable=False)
    change_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    simulation_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_simulation_tenant_state",
            "tenant_id",
            "simulation_state",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_approval
# ---------------------------------------------------------------------------


class GovOrchApproval(Base):
    """Approval record."""

    __tablename__ = "fa_gov_orch_approval"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    workflow_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    stage: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    quorum: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    approval_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    delegated_to: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_approval_tenant_workflow",
            "tenant_id",
            "workflow_id",
            "stage",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_maintenance_window
# ---------------------------------------------------------------------------


class GovOrchMaintenanceWindow(Base):
    """Maintenance/blackout window record."""

    __tablename__ = "fa_gov_orch_maintenance_window"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    window_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="SCHEDULED"
    )
    starts_at: Mapped[str] = mapped_column(String(64), nullable=False)
    ends_at: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_mw_tenant_state",
            "tenant_id",
            "window_state",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_change_detection
# ---------------------------------------------------------------------------


class GovOrchChangeDetection(Base):
    """Detected change record."""

    __tablename__ = "fa_gov_orch_change_detection"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    change_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    impact_level: Mapped[str] = mapped_column(String(32), nullable=False, default="LOW")
    change_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_change_tenant_type",
            "tenant_id",
            "change_type",
            "created_at",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_gov_orch_timeline (append-only)
# ---------------------------------------------------------------------------


class GovOrchTimeline(Base):
    """Append-only orchestration timeline events."""

    __tablename__ = "fa_gov_orch_timeline"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    event_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_gov_orch_timeline_tenant_entity",
            "tenant_id",
            "entity_type",
            "entity_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


@sa_event.listens_for(GovOrchTimeline, "before_update")
def _block_timeline_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_gov_orch_timeline is append-only - updates are forbidden")


@sa_event.listens_for(GovOrchTimeline, "before_delete")
def _block_timeline_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_gov_orch_timeline is append-only - deletes are forbidden")
