# services/remediation/repository.py
"""Low-level database operations for the Remediation subsystem.

PR 13.1 — Remediation Management Foundation.

All functions are tenant-scoped. No function may execute a query without
filtering by tenant_id. Caller owns db.commit().
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEngagement, FaNormalizedFinding
from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from services.remediation.schemas import (
    RemediationNotFound,
    RemediationReferenceError,
    RemediationStatus,
    RemediationTenantViolation,
    TaskSnapshot,
)


# ---------------------------------------------------------------------------
# Reference validation
# ---------------------------------------------------------------------------


def assert_finding_exists(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
) -> None:
    """Raise RemediationReferenceError if finding does not exist for this tenant."""
    row = (
        db.query(FaNormalizedFinding)
        .filter(
            FaNormalizedFinding.id == finding_id,
            FaNormalizedFinding.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise RemediationReferenceError(
            f"finding_id={finding_id!r} not found for tenant"
        )


def assert_assessment_exists(
    db: Session,
    *,
    tenant_id: str,
    assessment_id: str,
) -> None:
    """Raise RemediationReferenceError if assessment (engagement) does not exist for this tenant."""
    row = (
        db.query(FaEngagement)
        .filter(
            FaEngagement.id == assessment_id,
            FaEngagement.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise RemediationReferenceError(
            f"assessment_id={assessment_id!r} not found for tenant"
        )


def assert_finding_belongs_to_assessment(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str,
    assessment_id: str,
) -> None:
    """Raise RemediationTenantViolation if finding is not part of the given assessment."""
    row = (
        db.query(FaNormalizedFinding)
        .filter(
            FaNormalizedFinding.id == finding_id,
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == assessment_id,
        )
        .first()
    )
    if row is None:
        raise RemediationTenantViolation(
            f"finding_id={finding_id!r} does not belong to assessment_id={assessment_id!r} "
            f"for this tenant"
        )


# ---------------------------------------------------------------------------
# Task CRUD
# ---------------------------------------------------------------------------


def insert_task(db: Session, *, task: RemediationTask) -> RemediationTask:
    """Persist a new task. Caller owns db.commit()."""
    db.add(task)
    return task


def fetch_task(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
) -> RemediationTask:
    """Return the task or raise RemediationNotFound."""
    row = (
        db.query(RemediationTask)
        .filter(
            RemediationTask.id == task_id,
            RemediationTask.tenant_id == tenant_id,
        )
        .first()
    )
    if row is None:
        raise RemediationNotFound(f"task_id={task_id!r} not found for tenant")
    return row


def fetch_tasks(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str | None = None,
    assessment_id: str | None = None,
    status: str | None = None,
    priority: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[RemediationTask]:
    """List tasks for tenant with optional filters. Hard-capped at 100 rows."""
    q = db.query(RemediationTask).filter(RemediationTask.tenant_id == tenant_id)
    if finding_id is not None:
        q = q.filter(RemediationTask.finding_id == finding_id)
    if assessment_id is not None:
        q = q.filter(RemediationTask.assessment_id == assessment_id)
    if status is not None:
        q = q.filter(RemediationTask.status == status)
    if priority is not None:
        q = q.filter(RemediationTask.priority == priority)
    q = q.order_by(RemediationTask.created_at.desc())
    return q.limit(min(limit, 100)).offset(offset).all()


def count_tasks(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str | None = None,
    assessment_id: str | None = None,
    status: str | None = None,
    priority: str | None = None,
) -> int:
    q = db.query(RemediationTask).filter(RemediationTask.tenant_id == tenant_id)
    if finding_id is not None:
        q = q.filter(RemediationTask.finding_id == finding_id)
    if assessment_id is not None:
        q = q.filter(RemediationTask.assessment_id == assessment_id)
    if status is not None:
        q = q.filter(RemediationTask.status == status)
    if priority is not None:
        q = q.filter(RemediationTask.priority == priority)
    return q.count()


def apply_task_updates(
    task: RemediationTask,
    *,
    updates: dict[str, Any],
) -> None:
    """Apply field updates to a task object in-memory. Caller owns db.commit()."""
    for field, value in updates.items():
        setattr(task, field, value)


def mark_task_deleted(db: Session, *, task: RemediationTask) -> None:
    """Remove the task row. Caller owns db.commit()."""
    db.delete(task)


# ---------------------------------------------------------------------------
# Audit trail (append-only)
# ---------------------------------------------------------------------------


def insert_audit_event(
    db: Session,
    *,
    audit: RemediationTaskAudit,
) -> RemediationTaskAudit:
    """Append an audit event. No UPDATE or DELETE on this table. Caller owns db.commit()."""
    db.add(audit)
    return audit


def fetch_audit_events(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
) -> list[RemediationTaskAudit]:
    """Return all audit events for a task, ordered chronologically."""
    return (
        db.query(RemediationTaskAudit)
        .filter(
            RemediationTaskAudit.tenant_id == tenant_id,
            RemediationTaskAudit.task_id == task_id,
        )
        .order_by(RemediationTaskAudit.event_at.asc())
        .all()
    )


# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------


def snapshot_task(task: RemediationTask) -> dict[str, Any]:
    """Produce an immutable dict snapshot of a task's current state for audit records."""

    def _dt(v: Any) -> str | None:
        return v.isoformat() if v is not None else None

    return TaskSnapshot(
        id=task.id,
        tenant_id=task.tenant_id,
        finding_id=task.finding_id,
        assessment_id=task.assessment_id,
        title=task.title,
        description=task.description,
        recommended_action=task.recommended_action,
        priority=task.priority,
        status=task.status,
        created_by=task.created_by,
        assigned_to=task.assigned_to,
        created_at=task.created_at,
        updated_at=task.updated_at,
        closed_at=task.closed_at,
        task_metadata=task.task_metadata or {},
        assigned_user_id=task.assigned_user_id,
        assigned_user_email=task.assigned_user_email,
        assigned_display_name=task.assigned_display_name,
        assigned_at=_dt(task.assigned_at),
        due_date=_dt(task.due_date),
        sla_target_days=task.sla_target_days,
        sla_breach_at=_dt(task.sla_breach_at),
        ownership_reason=task.ownership_reason,
        last_assignment_change_at=_dt(task.last_assignment_change_at),
    ).model_dump()


# ---------------------------------------------------------------------------
# PR 13.3 — Overdue / unassigned task queries
# ---------------------------------------------------------------------------


def fetch_overdue_tasks(
    db: Session,
    *,
    tenant_id: str,
    now: datetime,
    limit: int = 100,
    offset: int = 0,
) -> list[RemediationTask]:
    """Return tasks whose SLA breach timestamp is in the past (overdue, not terminal)."""
    terminal = {RemediationStatus.CLOSED.value, RemediationStatus.ACCEPTED_RISK.value}
    q = (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.sla_breach_at.isnot(None),
            RemediationTask.sla_breach_at < now,
            RemediationTask.status.notin_(terminal),
        )
        .order_by(RemediationTask.sla_breach_at.asc())
    )
    return q.limit(min(limit, 100)).offset(offset).all()


def count_overdue_tasks(db: Session, *, tenant_id: str, now: datetime) -> int:
    terminal = {RemediationStatus.CLOSED.value, RemediationStatus.ACCEPTED_RISK.value}
    return (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.sla_breach_at.isnot(None),
            RemediationTask.sla_breach_at < now,
            RemediationTask.status.notin_(terminal),
        )
        .count()
    )


def fetch_unassigned_tasks(
    db: Session,
    *,
    tenant_id: str,
    limit: int = 100,
    offset: int = 0,
) -> list[RemediationTask]:
    """Return tasks with no owner that are not in a terminal state."""
    terminal = {RemediationStatus.CLOSED.value, RemediationStatus.ACCEPTED_RISK.value}
    q = (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.assigned_user_id.is_(None),
            RemediationTask.status.notin_(terminal),
        )
        .order_by(RemediationTask.created_at.desc())
    )
    return q.limit(min(limit, 100)).offset(offset).all()


def count_unassigned_tasks(db: Session, *, tenant_id: str) -> int:
    terminal = {RemediationStatus.CLOSED.value, RemediationStatus.ACCEPTED_RISK.value}
    return (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.assigned_user_id.is_(None),
            RemediationTask.status.notin_(terminal),
        )
        .count()
    )
