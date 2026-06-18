# services/remediation/engine.py
"""Remediation Engine — authoritative service layer for the Remediation subsystem.

PR 13.1 — Remediation Management Foundation.

All public methods are tenant-scoped. No direct ORM access from routes.
Caller (route handler) owns db.commit() — every method prepares the
transaction but does not commit, enabling atomic route-level commits.

Extension points (future PRs):
  - PR 13.2: status workflow engine (add transition_task(), validate_transition())
  - PR 13.3: SLA engine (add sla_config to task_metadata, compute_sla_breach())
  - PR 13.4: portal integration (add portal_task_id linkage)
  - PR 13.5: notification hooks (emit_notification() after every mutation)
  - Risk acceptance: task_metadata["risk_acceptance"] reserved
  - Compensating controls: task_metadata["compensating_controls"] reserved
  - Control mapping: task_metadata["control_mappings"] reserved
  - Governance correlation: task_metadata["governance_refs"] reserved
  - Autonomous governance: actor_type field planned for future extension
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from api.observability.metrics import (
    REMEDIATION_TASK_DENIALS_TOTAL,
    REMEDIATION_TASKS_CLOSED_TOTAL,
    REMEDIATION_TASKS_CREATED_TOTAL,
    REMEDIATION_TASK_UPDATES_TOTAL,
)
from services.remediation.repository import (
    apply_task_updates,
    assert_assessment_exists,
    assert_finding_belongs_to_assessment,
    assert_finding_exists,
    count_tasks,
    fetch_audit_events,
    fetch_task,
    fetch_tasks,
    insert_audit_event,
    insert_task,
    mark_task_deleted,
    snapshot_task,
)
from services.remediation.schemas import (
    AuditEventResponse,
    CreateTaskRequest,
    RemediationAuditEventType,
    RemediationConflict,
    RemediationNotFound,
    RemediationPriority,
    RemediationStatus,
    RemediationTenantViolation,
    TaskListResponse,
    TaskResponse,
    UpdateTaskRequest,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _task_to_response(task: RemediationTask) -> TaskResponse:
    return TaskResponse(
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
        schema_version=task.schema_version,
    )


def _audit_to_response(audit: RemediationTaskAudit) -> AuditEventResponse:
    return AuditEventResponse(
        id=audit.id,
        tenant_id=audit.tenant_id,
        task_id=audit.task_id,
        event_type=audit.event_type,
        actor=audit.actor,
        old_state=audit.old_state,
        new_state=audit.new_state,
        event_at=audit.event_at,
    )


class RemediationEngine:
    """Stateless service object. Instantiated per request with a db session and tenant_id."""

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create_task(
        self,
        *,
        request: CreateTaskRequest,
        actor: str,
    ) -> TaskResponse:
        """Create a remediation task linked to a finding and assessment.

        Validates:
          - finding_id exists for tenant (REM-9)
          - assessment_id exists for tenant (REM-10)
          - finding belongs to the assessment (REM-18)
        Emits: task_created audit event (REM-11)
        Increments: frostgate_remediation_tasks_created_total
        """
        try:
            assert_finding_exists(
                self._db,
                tenant_id=self._tenant_id,
                finding_id=request.finding_id,
            )
            assert_assessment_exists(
                self._db,
                tenant_id=self._tenant_id,
                assessment_id=request.assessment_id,
            )
            assert_finding_belongs_to_assessment(
                self._db,
                tenant_id=self._tenant_id,
                finding_id=request.finding_id,
                assessment_id=request.assessment_id,
            )
        except (Exception,):
            REMEDIATION_TASK_DENIALS_TOTAL.inc()
            raise

        now = _utcnow()
        task = RemediationTask(
            id=_new_id(),
            tenant_id=self._tenant_id,
            finding_id=request.finding_id,
            assessment_id=request.assessment_id,
            title=request.title,
            description=request.description,
            recommended_action=request.recommended_action,
            priority=request.priority.value,
            status=RemediationStatus.OPEN.value,
            created_by=actor,
            assigned_to=request.assigned_to,
            created_at=now,
            updated_at=now,
            closed_at=None,
            task_metadata=request.task_metadata or {},
            schema_version="1.0",
        )
        insert_task(self._db, task=task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_CREATED,
            actor=actor,
            old_state=None,
            new_state=snapshot_task(task),
        )

        REMEDIATION_TASKS_CREATED_TOTAL.inc()
        return _task_to_response(task)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_task(self, *, task_id: str) -> TaskResponse:
        """Return a single task by ID, scoped to tenant."""
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        return _task_to_response(task)

    def list_tasks(
        self,
        *,
        finding_id: str | None = None,
        assessment_id: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> TaskListResponse:
        """List tasks for tenant with optional filters."""
        tasks = fetch_tasks(
            self._db,
            tenant_id=self._tenant_id,
            finding_id=finding_id,
            assessment_id=assessment_id,
            status=status,
            priority=priority,
            limit=limit,
            offset=offset,
        )
        total = count_tasks(
            self._db,
            tenant_id=self._tenant_id,
            finding_id=finding_id,
            assessment_id=assessment_id,
            status=status,
            priority=priority,
        )
        return TaskListResponse(
            tasks=[_task_to_response(t) for t in tasks],
            total=total,
        )

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_task(
        self,
        *,
        task_id: str,
        request: UpdateTaskRequest,
        actor: str,
    ) -> TaskResponse:
        """Partially update a task. Only provided fields are changed.

        Emits: task_updated audit event (REM-12)
        Increments: frostgate_remediation_task_updates_total
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        old_state = snapshot_task(task)

        updates: dict[str, Any] = {"updated_at": _utcnow()}
        if request.title is not None:
            updates["title"] = request.title
        if request.description is not None:
            updates["description"] = request.description
        if request.recommended_action is not None:
            updates["recommended_action"] = request.recommended_action
        if request.priority is not None:
            updates["priority"] = request.priority.value
        if request.assigned_to is not None:
            updates["assigned_to"] = request.assigned_to
        if request.task_metadata is not None:
            updates["task_metadata"] = request.task_metadata

        apply_task_updates(task, updates=updates)
        new_state = snapshot_task(task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_UPDATED,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
        )

        REMEDIATION_TASK_UPDATES_TOTAL.inc()
        return _task_to_response(task)

    # ------------------------------------------------------------------
    # Close
    # ------------------------------------------------------------------

    def close_task(
        self,
        *,
        task_id: str,
        actor: str,
    ) -> TaskResponse:
        """Transition a task to closed state.

        Emits: task_closed audit event (REM-13)
        Increments: frostgate_remediation_tasks_closed_total
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)

        if task.status == RemediationStatus.CLOSED.value:
            raise RemediationConflict(f"task_id={task_id!r} is already closed")

        old_state = snapshot_task(task)
        now = _utcnow()
        apply_task_updates(
            task,
            updates={
                "status": RemediationStatus.CLOSED.value,
                "closed_at": now,
                "updated_at": now,
            },
        )
        new_state = snapshot_task(task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_CLOSED,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
        )

        REMEDIATION_TASKS_CLOSED_TOTAL.inc()
        return _task_to_response(task)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete_task(
        self,
        *,
        task_id: str,
        actor: str,
    ) -> None:
        """Delete a task and emit a deletion audit event.

        Audit event is persisted before deletion so the trail is never lost.
        Emits: task_deleted audit event (REM-14)
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        old_state = snapshot_task(task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_DELETED,
            actor=actor,
            old_state=old_state,
            new_state=None,
        )

        mark_task_deleted(self._db, task=task)

    # ------------------------------------------------------------------
    # Audit trail
    # ------------------------------------------------------------------

    def get_task_audit_trail(
        self,
        *,
        task_id: str,
    ) -> list[AuditEventResponse]:
        """Return the full ordered audit trail for a task.

        Used for lifecycle reconstruction (REM-20).
        The task itself may have been deleted; audit events persist.
        """
        events = fetch_audit_events(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
        )
        return [_audit_to_response(e) for e in events]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        *,
        task_id: str,
        event_type: RemediationAuditEventType,
        actor: str,
        old_state: dict[str, Any] | None,
        new_state: dict[str, Any] | None,
    ) -> None:
        audit = RemediationTaskAudit(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=event_type.value,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            event_at=_utcnow(),
        )
        insert_audit_event(self._db, audit=audit)
