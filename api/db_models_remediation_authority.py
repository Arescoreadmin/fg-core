"""SQLAlchemy ORM models for PR 18.3 — Enterprise Remediation Authority.

Tables:
  fa_rem_plan          - remediation plans
  fa_rem_task          - remediation tasks
  fa_rem_timeline      - append-only timeline of task events (guards + PG rules)
  fa_rem_assignment    - task assignments (owner/reviewer/approver/contributor)
  fa_rem_dependency    - dependency edges between tasks
  fa_rem_verification  - verification records against tasks
  fa_rem_evidence_link - links between evidence and remediation tasks

Design:
  - Every table carries tenant_id NOT NULL.
  - fa_rem_timeline is append-only: ORM guards raise on UPDATE/DELETE;
    the SQL migration also installs PG rules blocking mutation.
  - This module is separate from api.db_models_remediation which is the
    older, still-in-use remediation table. This module never modifies or
    touches those tables.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Float, Index, String, Text, event as sa_event
from sqlalchemy.orm import Mapped, mapped_column

from api.db_models import Base


# ---------------------------------------------------------------------------
# fa_rem_plan
# ---------------------------------------------------------------------------


class RemAuthPlan(Base):
    """A remediation plan groups one or more remediation tasks."""

    __tablename__ = "fa_rem_plan"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    plan_state: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    assessment_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_fa_rem_plan_tenant_state", "tenant_id", "plan_state"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_rem_task
# ---------------------------------------------------------------------------


class RemAuthTask(Base):
    """A single remediation task within a plan (plan_id nullable for orphans)."""

    __tablename__ = "fa_rem_task"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    task_state: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    priority: Mapped[str] = mapped_column(String(32), nullable=False, default="MEDIUM")
    owner_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approver_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_date: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    sla_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNSCHEDULED"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[str] = mapped_column(String(64), nullable=False)
    completed_at: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        Index("ix_fa_rem_task_tenant_state", "tenant_id", "task_state"),
        Index("ix_fa_rem_task_tenant_priority", "tenant_id", "priority"),
        Index("ix_fa_rem_task_tenant_owner", "tenant_id", "owner_id"),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_rem_timeline (append-only)
# ---------------------------------------------------------------------------


class RemAuthTimeline(Base):
    """Append-only timeline of state transitions and events on tasks."""

    __tablename__ = "fa_rem_timeline"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    to_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    actor_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index("ix_fa_rem_timeline_tenant_task", "tenant_id", "task_id", "created_at"),
        {"extend_existing": True},
    )


@sa_event.listens_for(RemAuthTimeline, "before_update")
def _block_rem_timeline_update(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_rem_timeline is append-only - updates are forbidden")


@sa_event.listens_for(RemAuthTimeline, "before_delete")
def _block_rem_timeline_delete(mapper, connection, target):  # type: ignore[no-untyped-def]
    raise RuntimeError("fa_rem_timeline is append-only - deletes are forbidden")


# ---------------------------------------------------------------------------
# fa_rem_assignment
# ---------------------------------------------------------------------------


class RemAuthAssignment(Base):
    """Assignment of an actor to a remediation task in a specific role."""

    __tablename__ = "fa_rem_assignment"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_rem_assignment_tenant_task_role",
            "tenant_id",
            "task_id",
            "role",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_rem_dependency
# ---------------------------------------------------------------------------


class RemAuthDependency(Base):
    """Directed dependency edge between two remediation tasks."""

    __tablename__ = "fa_rem_dependency"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source_task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    dependency_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="BLOCKS"
    )
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_rem_dependency_tenant_edge",
            "tenant_id",
            "source_task_id",
            "target_task_id",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_rem_verification
# ---------------------------------------------------------------------------


class RemAuthVerification(Base):
    """Verification record for a task closure."""

    __tablename__ = "fa_rem_verification"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    verifier_id: Mapped[str] = mapped_column(String(255), nullable=False)
    verification_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="PENDING"
    )
    evidence_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_rem_verification_tenant_task",
            "tenant_id",
            "task_id",
            "created_at",
        ),
        {"extend_existing": True},
    )


# ---------------------------------------------------------------------------
# fa_rem_evidence_link
# ---------------------------------------------------------------------------


class RemAuthEvidenceLink(Base):
    """Link between an evidence record and a remediation task."""

    __tablename__ = "fa_rem_evidence_link"

    id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        Index(
            "ix_fa_rem_evidence_link_tenant_task",
            "tenant_id",
            "task_id",
            "evidence_id",
        ),
        {"extend_existing": True},
    )
