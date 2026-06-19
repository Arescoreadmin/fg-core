# services/remediation_portal/engine.py
"""Portal Remediation Engine — service layer for client-facing remediation access.

All methods are tenant-scoped. Routes must never access DB directly.
Caller owns db.commit().
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from api.db_models_remediation import RemediationTask
from api.db_models_portal_remediation import (
    PortalEvidenceSubmission,
    PortalRemediationAuditEvent,
    PortalRemediationComment,
)
from api.observability.metrics import (
    PORTAL_COMMENTS_TOTAL,
    PORTAL_EVIDENCE_UPLOADS_TOTAL,
    PORTAL_OWNER_ACKNOWLEDGEMENTS_TOTAL,
    PORTAL_OVERDUE_VIEWS_TOTAL,
    PORTAL_REMEDIATION_VIEWS_TOTAL,
)
from services.remediation.engine import _AT_RISK_THRESHOLD
from services.remediation.schemas import RemediationStatus
from services.remediation_portal.repository import (
    count_comments,
    count_evidence,
    count_overdue_portal_tasks,
    count_portal_audit_events,
    count_tasks_by_status,
    count_unassigned_portal_tasks,
    evidence_sha256_exists,
    fetch_comment,
    fetch_comments,
    fetch_evidence_list,
    fetch_overdue_portal_tasks,
    fetch_portal_audit_events,
    fetch_portal_task,
    fetch_recent_open_portal_tasks,
    insert_comment,
    insert_evidence,
    insert_portal_audit_event,
)
from services.remediation_portal.schemas import (
    AcknowledgeOwnershipRequest,
    AcknowledgeOwnershipResponse,
    AddCommentRequest,
    EditCommentRequest,
    PortalAuditEventResponse,
    PortalAuditEventType,
    PortalAuditListResponse,
    PortalCommentListResponse,
    PortalCommentResponse,
    PortalDashboardResponse,
    PortalEvidenceDuplicate,
    PortalEvidenceListResponse,
    PortalEvidenceResponse,
    PortalTaskSummary,
    PortalTaskView,
    SubmitEvidenceRequest,
    VerificationState,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _compute_portal_sla_status(task: RemediationTask) -> str:
    if task.status == RemediationStatus.CLOSED.value:
        return "closed"
    if task.status == RemediationStatus.ACCEPTED_RISK.value:
        return "accepted_risk"
    if task.sla_target_days is None:
        return "on_track"
    created = datetime.fromisoformat(task.created_at)
    now = datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = max(0, (now - created).days)
    if age_days > task.sla_target_days:
        return "overdue"
    if age_days >= task.sla_target_days * _AT_RISK_THRESHOLD:
        return "at_risk"
    return "on_track"


def _dt_str(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


def _task_to_portal_view(
    task: RemediationTask, comment_count: int = 0, evidence_count: int = 0
) -> PortalTaskView:
    return PortalTaskView(
        id=task.id,
        tenant_id=task.tenant_id,
        finding_id=task.finding_id,
        assessment_id=task.assessment_id,
        title=task.title,
        description=task.description,
        recommended_action=task.recommended_action,
        priority=task.priority,
        status=task.status,
        assigned_display_name=task.assigned_display_name,
        assigned_at=_dt_str(task.assigned_at),
        due_date=_dt_str(task.due_date),
        sla_target_days=task.sla_target_days,
        sla_breach_at=_dt_str(task.sla_breach_at),
        sla_status=_compute_portal_sla_status(task),
        created_at=task.created_at,
        updated_at=task.updated_at,
        closed_at=task.closed_at,
        comment_count=comment_count,
        evidence_count=evidence_count,
    )


def _task_to_summary(task: RemediationTask) -> PortalTaskSummary:
    return PortalTaskSummary(
        id=task.id,
        title=task.title,
        priority=task.priority,
        status=task.status,
        sla_status=_compute_portal_sla_status(task),
        assigned_display_name=task.assigned_display_name,
        due_date=_dt_str(task.due_date),
        sla_breach_at=_dt_str(task.sla_breach_at),
    )


def _comment_to_response(c: PortalRemediationComment) -> PortalCommentResponse:
    return PortalCommentResponse(
        id=c.id,
        task_id=c.task_id,
        author=c.author,
        body=c.body,
        is_edited=c.is_edited,
        created_at=c.created_at,
        updated_at=c.updated_at,
    )


def _evidence_to_response(e: PortalEvidenceSubmission) -> PortalEvidenceResponse:
    return PortalEvidenceResponse(
        id=e.id,
        task_id=e.task_id,
        filename=e.filename,
        content_type=e.content_type,
        sha256=e.sha256,
        submitted_by=e.submitted_by,
        submitted_at=e.submitted_at,
        classification=e.classification,
        description=e.description,
        verification_state=e.verification_state,
    )


def _audit_to_response(e: PortalRemediationAuditEvent) -> PortalAuditEventResponse:
    return PortalAuditEventResponse(
        id=e.id,
        task_id=e.task_id,
        event_type=e.event_type,
        actor=e.actor,
        event_at=e.event_at,
        event_metadata=e.event_metadata or {},
    )


def _emit_portal_audit(
    db: Session,
    *,
    tenant_id: str,
    task_id: str,
    event_type: PortalAuditEventType,
    actor: str,
    metadata: dict[str, Any] | None = None,
) -> None:
    event = PortalRemediationAuditEvent(
        id=_new_id(),
        tenant_id=tenant_id,
        task_id=task_id,
        event_type=event_type.value,
        actor=actor,
        event_at=_now(),
        event_metadata=metadata or {},
    )
    insert_portal_audit_event(db, event=event)


class PortalRemediationEngine:
    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def get_dashboard(self) -> PortalDashboardResponse:
        now = datetime.now(timezone.utc)
        open_count = count_tasks_by_status(
            self._db, tenant_id=self._tenant_id, status=RemediationStatus.OPEN.value
        )
        planned_count = count_tasks_by_status(
            self._db, tenant_id=self._tenant_id, status=RemediationStatus.PLANNED.value
        )
        in_progress_count = count_tasks_by_status(
            self._db,
            tenant_id=self._tenant_id,
            status=RemediationStatus.IN_PROGRESS.value,
        )
        closed_count = count_tasks_by_status(
            self._db, tenant_id=self._tenant_id, status=RemediationStatus.CLOSED.value
        )
        accepted_risk_count = count_tasks_by_status(
            self._db,
            tenant_id=self._tenant_id,
            status=RemediationStatus.ACCEPTED_RISK.value,
        )
        overdue_count = count_overdue_portal_tasks(
            self._db, tenant_id=self._tenant_id, now=now
        )
        unassigned_count = count_unassigned_portal_tasks(
            self._db, tenant_id=self._tenant_id
        )
        recent_open = fetch_recent_open_portal_tasks(
            self._db, tenant_id=self._tenant_id, limit=5
        )
        overdue_tasks = fetch_overdue_portal_tasks(
            self._db, tenant_id=self._tenant_id, now=now, limit=5
        )
        if overdue_count > 0:
            PORTAL_OVERDUE_VIEWS_TOTAL.inc()
        PORTAL_REMEDIATION_VIEWS_TOTAL.inc()
        return PortalDashboardResponse(
            open_count=open_count,
            planned_count=planned_count,
            in_progress_count=in_progress_count,
            closed_count=closed_count,
            accepted_risk_count=accepted_risk_count,
            overdue_count=overdue_count,
            unassigned_count=unassigned_count,
            recent_open=[_task_to_summary(t) for t in recent_open],
            overdue_tasks=[_task_to_summary(t) for t in overdue_tasks],
        )

    # ------------------------------------------------------------------
    # Task detail
    # ------------------------------------------------------------------

    def get_task(self, *, task_id: str, actor: str) -> PortalTaskView:
        task = fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        comment_count = count_comments(
            self._db, tenant_id=self._tenant_id, task_id=task_id
        )
        evidence_count = count_evidence(
            self._db, tenant_id=self._tenant_id, task_id=task_id
        )
        _emit_portal_audit(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=PortalAuditEventType.PORTAL_TASK_VIEWED,
            actor=actor,
        )
        PORTAL_REMEDIATION_VIEWS_TOTAL.inc()
        return _task_to_portal_view(
            task, comment_count=comment_count, evidence_count=evidence_count
        )

    # ------------------------------------------------------------------
    # Comments
    # ------------------------------------------------------------------

    def add_comment(
        self, *, task_id: str, request: AddCommentRequest, actor: str
    ) -> PortalCommentResponse:
        fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        now = _now()
        comment = PortalRemediationComment(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            author=request.author,
            body=request.body,
            is_edited=False,
            created_at=now,
            updated_at=now,
        )
        insert_comment(self._db, comment=comment)
        _emit_portal_audit(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=PortalAuditEventType.PORTAL_COMMENT_ADDED,
            actor=actor,
            metadata={"comment_id": comment.id, "author": request.author},
        )
        PORTAL_COMMENTS_TOTAL.inc()
        return _comment_to_response(comment)

    def edit_comment(
        self, *, task_id: str, comment_id: str, request: EditCommentRequest, actor: str
    ) -> PortalCommentResponse:
        comment = fetch_comment(
            self._db, tenant_id=self._tenant_id, task_id=task_id, comment_id=comment_id
        )
        comment.body = request.body
        comment.is_edited = True
        comment.updated_at = _now()
        _emit_portal_audit(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=PortalAuditEventType.PORTAL_COMMENT_EDITED,
            actor=actor,
            metadata={"comment_id": comment_id},
        )
        return _comment_to_response(comment)

    def list_comments(
        self, *, task_id: str, limit: int = 50, offset: int = 0
    ) -> PortalCommentListResponse:
        fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        total = count_comments(self._db, tenant_id=self._tenant_id, task_id=task_id)
        comments = fetch_comments(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            limit=limit,
            offset=offset,
        )
        return PortalCommentListResponse(
            task_id=task_id,
            comments=[_comment_to_response(c) for c in comments],
            total=total,
            limit=limit,
            offset=offset,
        )

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def submit_evidence(
        self, *, task_id: str, request: SubmitEvidenceRequest, actor: str
    ) -> PortalEvidenceResponse:
        fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        if evidence_sha256_exists(
            self._db, tenant_id=self._tenant_id, task_id=task_id, sha256=request.sha256
        ):
            raise PortalEvidenceDuplicate(
                f"Evidence with sha256={request.sha256!r} already submitted for this task."
            )
        evidence = PortalEvidenceSubmission(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            filename=request.filename,
            content_type=request.content_type,
            sha256=request.sha256,
            submitted_by=request.submitted_by,
            submitted_at=_now(),
            classification=request.classification,
            description=request.description,
            verification_state=VerificationState.PENDING.value,
            evidence_metadata=request.evidence_metadata or {},
        )
        insert_evidence(self._db, evidence=evidence)
        _emit_portal_audit(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=PortalAuditEventType.PORTAL_EVIDENCE_UPLOADED,
            actor=actor,
            metadata={
                "evidence_id": evidence.id,
                "filename": request.filename,
                "sha256": request.sha256,
                "classification": request.classification,
            },
        )
        PORTAL_EVIDENCE_UPLOADS_TOTAL.inc()
        return _evidence_to_response(evidence)

    def list_evidence(
        self, *, task_id: str, limit: int = 50, offset: int = 0
    ) -> PortalEvidenceListResponse:
        fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        total = count_evidence(self._db, tenant_id=self._tenant_id, task_id=task_id)
        evidence = fetch_evidence_list(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            limit=limit,
            offset=offset,
        )
        return PortalEvidenceListResponse(
            task_id=task_id,
            evidence=[_evidence_to_response(e) for e in evidence],
            total=total,
            limit=limit,
            offset=offset,
        )

    # ------------------------------------------------------------------
    # Ownership acknowledgement
    # ------------------------------------------------------------------

    def acknowledge_ownership(
        self, *, task_id: str, request: AcknowledgeOwnershipRequest, actor: str
    ) -> AcknowledgeOwnershipResponse:
        task = fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        now = _now()
        _emit_portal_audit(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=PortalAuditEventType.PORTAL_OWNER_ACKNOWLEDGED,
            actor=actor,
            metadata={
                "acknowledged_by": request.acknowledged_by,
                "note": request.acknowledgement_note,
                "acknowledged_at": now,
            },
        )
        PORTAL_OWNER_ACKNOWLEDGEMENTS_TOTAL.inc()
        return AcknowledgeOwnershipResponse(
            task_id=task_id,
            acknowledged_by=request.acknowledged_by,
            acknowledged_at=now,
            task_status=task.status,
            sla_status=_compute_portal_sla_status(task),
        )

    # ------------------------------------------------------------------
    # Portal audit trail
    # ------------------------------------------------------------------

    def get_portal_audit(
        self, *, task_id: str, limit: int = 50, offset: int = 0
    ) -> PortalAuditListResponse:
        fetch_portal_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        total = count_portal_audit_events(
            self._db, tenant_id=self._tenant_id, task_id=task_id
        )
        events = fetch_portal_audit_events(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
            limit=limit,
            offset=offset,
        )
        return PortalAuditListResponse(
            task_id=task_id,
            events=[_audit_to_response(e) for e in events],
            total=total,
            limit=limit,
            offset=offset,
        )
