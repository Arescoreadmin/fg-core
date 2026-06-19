# services/remediation_portal/repository.py
"""Low-level DB operations for the Portal Remediation subsystem.

All functions are tenant-scoped.
"""

from __future__ import annotations
from datetime import datetime
from sqlalchemy.orm import Session
from api.db_models_remediation import RemediationTask
from api.db_models_portal_remediation import (
    PortalEvidenceSubmission,
    PortalRemediationAuditEvent,
    PortalRemediationComment,
)
from services.remediation.schemas import RemediationStatus
from services.remediation_portal.schemas import (
    PortalCommentNotFound,
    PortalNotFound,
)


# ---------------------------------------------------------------------------
# Task reads (read-only projection of remediation_tasks)
# ---------------------------------------------------------------------------


def fetch_portal_task(db: Session, *, tenant_id: str, task_id: str) -> RemediationTask:
    row = (
        db.query(RemediationTask)
        .filter(RemediationTask.id == task_id, RemediationTask.tenant_id == tenant_id)
        .first()
    )
    if row is None:
        raise PortalNotFound(f"task_id={task_id!r} not found for tenant")
    return row


def count_tasks_by_status(db: Session, *, tenant_id: str, status: str) -> int:
    return (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id, RemediationTask.status == status
        )
        .count()
    )


def fetch_overdue_portal_tasks(
    db: Session, *, tenant_id: str, now: datetime, limit: int = 5
) -> list[RemediationTask]:
    terminal = {RemediationStatus.CLOSED.value, RemediationStatus.ACCEPTED_RISK.value}
    return (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.sla_breach_at.isnot(None),
            RemediationTask.sla_breach_at < now,
            RemediationTask.status.notin_(terminal),
        )
        .order_by(RemediationTask.sla_breach_at.asc())
        .limit(limit)
        .all()
    )


def count_overdue_portal_tasks(db: Session, *, tenant_id: str, now: datetime) -> int:
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


def count_unassigned_portal_tasks(db: Session, *, tenant_id: str) -> int:
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


def fetch_recent_open_portal_tasks(
    db: Session, *, tenant_id: str, limit: int = 5
) -> list[RemediationTask]:
    return (
        db.query(RemediationTask)
        .filter(
            RemediationTask.tenant_id == tenant_id,
            RemediationTask.status == RemediationStatus.OPEN.value,
        )
        .order_by(RemediationTask.created_at.desc())
        .limit(limit)
        .all()
    )


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


def insert_comment(
    db: Session, *, comment: PortalRemediationComment
) -> PortalRemediationComment:
    db.add(comment)
    return comment


def fetch_comment(
    db: Session, *, tenant_id: str, task_id: str, comment_id: str
) -> PortalRemediationComment:
    row = (
        db.query(PortalRemediationComment)
        .filter(
            PortalRemediationComment.id == comment_id,
            PortalRemediationComment.tenant_id == tenant_id,
            PortalRemediationComment.task_id == task_id,
        )
        .first()
    )
    if row is None:
        raise PortalCommentNotFound(f"comment_id={comment_id!r} not found")
    return row


def fetch_comments(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[PortalRemediationComment]:
    return (
        db.query(PortalRemediationComment)
        .filter(
            PortalRemediationComment.tenant_id == tenant_id,
            PortalRemediationComment.task_id == task_id,
        )
        .order_by(PortalRemediationComment.created_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_comments(db: Session, *, tenant_id: str, task_id: str) -> int:
    return (
        db.query(PortalRemediationComment)
        .filter(
            PortalRemediationComment.tenant_id == tenant_id,
            PortalRemediationComment.task_id == task_id,
        )
        .count()
    )


# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------


def insert_evidence(
    db: Session, *, evidence: PortalEvidenceSubmission
) -> PortalEvidenceSubmission:
    db.add(evidence)
    return evidence


def fetch_evidence_list(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[PortalEvidenceSubmission]:
    return (
        db.query(PortalEvidenceSubmission)
        .filter(
            PortalEvidenceSubmission.tenant_id == tenant_id,
            PortalEvidenceSubmission.task_id == task_id,
        )
        .order_by(PortalEvidenceSubmission.submitted_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_evidence(db: Session, *, tenant_id: str, task_id: str) -> int:
    return (
        db.query(PortalEvidenceSubmission)
        .filter(
            PortalEvidenceSubmission.tenant_id == tenant_id,
            PortalEvidenceSubmission.task_id == task_id,
        )
        .count()
    )


def evidence_sha256_exists(
    db: Session, *, tenant_id: str, task_id: str, sha256: str
) -> bool:
    return (
        db.query(PortalEvidenceSubmission)
        .filter(
            PortalEvidenceSubmission.tenant_id == tenant_id,
            PortalEvidenceSubmission.task_id == task_id,
            PortalEvidenceSubmission.sha256 == sha256,
        )
        .first()
    ) is not None


# ---------------------------------------------------------------------------
# Portal audit (append-only)
# ---------------------------------------------------------------------------


def insert_portal_audit_event(
    db: Session, *, event: PortalRemediationAuditEvent
) -> PortalRemediationAuditEvent:
    db.add(event)
    return event


def fetch_portal_audit_events(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    limit: int = 50,
    offset: int = 0,
) -> list[PortalRemediationAuditEvent]:
    return (
        db.query(PortalRemediationAuditEvent)
        .filter(
            PortalRemediationAuditEvent.tenant_id == tenant_id,
            PortalRemediationAuditEvent.task_id == task_id,
        )
        .order_by(PortalRemediationAuditEvent.event_at.asc())
        .limit(limit)
        .offset(offset)
        .all()
    )


def count_portal_audit_events(db: Session, *, tenant_id: str, task_id: str) -> int:
    return (
        db.query(PortalRemediationAuditEvent)
        .filter(
            PortalRemediationAuditEvent.tenant_id == tenant_id,
            PortalRemediationAuditEvent.task_id == task_id,
        )
        .count()
    )
