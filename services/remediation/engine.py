# services/remediation/engine.py
"""Remediation Engine — authoritative service layer for the Remediation subsystem.

PR 13.1 — Remediation Management Foundation.
PR 13.2 — Remediation Status Workflow Engine.

All public methods are tenant-scoped. No direct ORM access from routes.
Caller (route handler) owns db.commit() — every method prepares the
transaction but does not commit, enabling atomic route-level commits.

State machine (PR 13.2):
  OPEN → PLANNED → IN_PROGRESS → CLOSED
  OPEN | PLANNED | IN_PROGRESS → ACCEPTED_RISK (terminal, risk-bearing)
  CLOSED and ACCEPTED_RISK are terminal — no further transitions.

Extension points (future PRs):
  - PR 13.3: SLA engine (add sla_config to task_metadata, compute_sla_breach())
  - PR 13.4: portal integration (add portal_task_id linkage)
  - PR 13.5: notification hooks (emit_notification() after every transition)
  - PR 14:   risk acceptance workflow (enrich ACCEPTED_RISK with evidence links)
  - PR 15:   evidence verification (attach evidence_id to IN_PROGRESS tasks)
  - PR 17:   verification engine (reopen via separate workflow, not direct transition)
  - Compensating controls: task_metadata["compensating_controls"] reserved
  - Control mapping: task_metadata["control_mappings"] reserved
  - Governance correlation: task_metadata["governance_refs"] reserved
  - Autonomous governance: actor_type field planned for future extension
  - CGIN event hooks: emit_lifecycle_event() stubs for future integration
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_remediation import RemediationTask, RemediationTaskAudit
from api.observability.metrics import (
    REMEDIATION_ASSIGNMENTS_TOTAL,
    REMEDIATION_INVALID_TRANSITIONS_TOTAL,
    REMEDIATION_OVERDUE_TASKS_TOTAL,
    REMEDIATION_REASSIGNMENTS_TOTAL,
    REMEDIATION_SLA_BREACHES_TOTAL,
    REMEDIATION_STATUS_TRANSITIONS_TOTAL,
    REMEDIATION_TASK_DENIALS_TOTAL,
    REMEDIATION_TASK_UPDATES_TOTAL,
    REMEDIATION_TASKS_CLOSED_TOTAL,
    REMEDIATION_TASKS_CREATED_TOTAL,
    REMEDIATION_UNASSIGNED_TASKS_TOTAL,
)
from services.remediation.repository import (
    apply_task_updates,
    assert_assessment_exists,
    assert_finding_belongs_to_assessment,
    assert_finding_exists,
    count_overdue_tasks,
    count_tasks,
    count_unassigned_tasks,
    fetch_audit_events,
    fetch_overdue_tasks,
    fetch_task,
    fetch_tasks,
    fetch_unassigned_tasks,
    insert_audit_event,
    insert_task,
    mark_task_deleted,
    snapshot_task,
)
from services.remediation.schemas import (
    AllowedTransitionsResponse,
    AssignOwnerRequest,
    AuditEventResponse,
    AuditListResponse,
    CreateTaskRequest,
    RemediationAuditEventType,
    RemediationConflict,
    RemediationInvalidTransition,
    RemediationOwnershipError,
    RemediationStatus,
    SetDueDateRequest,
    SlaResponse,
    SlaStatus,
    TaskListResponse,
    TaskResponse,
    TransitionResponse,
    TransitionTaskRequest,
    UnassignRequest,
    UpdateTaskRequest,
)

# ---------------------------------------------------------------------------
# State machine definition
# ---------------------------------------------------------------------------

# Authoritative transition map. Keys are current states; values are permitted
# target states.  All other transitions are rejected with RemediationInvalidTransition.
#
# Future PR 17 (verification engine) will reopen CLOSED tasks through a
# separate compensating workflow — it will NOT add CLOSED → OPEN here.
_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    RemediationStatus.OPEN.value: {
        RemediationStatus.PLANNED.value,
        RemediationStatus.ACCEPTED_RISK.value,
    },
    RemediationStatus.PLANNED.value: {
        RemediationStatus.IN_PROGRESS.value,
        RemediationStatus.ACCEPTED_RISK.value,
    },
    RemediationStatus.IN_PROGRESS.value: {
        RemediationStatus.CLOSED.value,
        RemediationStatus.ACCEPTED_RISK.value,
    },
    RemediationStatus.CLOSED.value: set(),
    RemediationStatus.ACCEPTED_RISK.value: set(),
}

# Map each (from, to) pair to the audit event type that documents it.
_TRANSITION_EVENT: dict[tuple[str, str], RemediationAuditEventType] = {
    (
        RemediationStatus.OPEN.value,
        RemediationStatus.PLANNED.value,
    ): RemediationAuditEventType.TASK_PLANNED,
    (
        RemediationStatus.PLANNED.value,
        RemediationStatus.IN_PROGRESS.value,
    ): RemediationAuditEventType.TASK_STARTED,
    (
        RemediationStatus.IN_PROGRESS.value,
        RemediationStatus.CLOSED.value,
    ): RemediationAuditEventType.TASK_CLOSED,
    (
        RemediationStatus.OPEN.value,
        RemediationStatus.ACCEPTED_RISK.value,
    ): RemediationAuditEventType.TASK_RISK_ACCEPTED,
    (
        RemediationStatus.PLANNED.value,
        RemediationStatus.ACCEPTED_RISK.value,
    ): RemediationAuditEventType.TASK_RISK_ACCEPTED,
    (
        RemediationStatus.IN_PROGRESS.value,
        RemediationStatus.ACCEPTED_RISK.value,
    ): RemediationAuditEventType.TASK_RISK_ACCEPTED,
}


# ---------------------------------------------------------------------------
# SLA defaults (PR 13.3)
# ---------------------------------------------------------------------------

# SLA default targets by priority (days). None = no SLA target (informational).
SLA_DEFAULTS: dict[str, int | None] = {
    "critical": 14,
    "high": 30,
    "medium": 60,
    "low": 90,
    "informational": None,
}

# A task is AT_RISK when >= this fraction of the SLA period has elapsed.
_AT_RISK_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow() -> str:
    return _now_dt().isoformat()


def _new_id() -> str:
    return uuid.uuid4().hex


def _compute_sla_breach_at(created_at: str, sla_target_days: int) -> datetime:
    created = datetime.fromisoformat(created_at)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return created + timedelta(days=sla_target_days)


def _compute_age_days(task: RemediationTask) -> int:
    created = datetime.fromisoformat(task.created_at)
    now = datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, (now - created).days)


def _compute_sla_status(task: RemediationTask) -> SlaStatus:
    if task.status == RemediationStatus.CLOSED.value:
        return SlaStatus.CLOSED
    if task.status == RemediationStatus.ACCEPTED_RISK.value:
        return SlaStatus.ACCEPTED_RISK
    if task.sla_target_days is None:
        return SlaStatus.ON_TRACK
    age_days = _compute_age_days(task)
    if age_days > task.sla_target_days:
        return SlaStatus.OVERDUE
    if age_days >= task.sla_target_days * _AT_RISK_THRESHOLD:
        return SlaStatus.AT_RISK
    return SlaStatus.ON_TRACK


def _compute_sla_response(task: RemediationTask) -> SlaResponse:
    age_days = _compute_age_days(task)
    sla_status = _compute_sla_status(task)
    days_remaining = (
        task.sla_target_days - age_days if task.sla_target_days is not None else None
    )
    return SlaResponse(
        task_id=task.id,
        priority=task.priority,
        sla_status=sla_status.value,
        age_days=age_days,
        sla_target_days=task.sla_target_days,
        days_remaining=days_remaining,
        due_date=task.due_date,
        sla_breach_at=task.sla_breach_at,
    )


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
        assigned_user_id=task.assigned_user_id,
        assigned_user_email=task.assigned_user_email,
        assigned_display_name=task.assigned_display_name,
        assigned_at=task.assigned_at,
        due_date=task.due_date,
        sla_target_days=task.sla_target_days,
        sla_breach_at=task.sla_breach_at,
        ownership_reason=task.ownership_reason,
        last_assignment_change_at=task.last_assignment_change_at,
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
        reason=audit.reason,
        event_at=audit.event_at,
    )


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class RemediationEngine:
    """Stateless service object. Instantiated per request with a db session and tenant_id."""

    def __init__(self, db: Session, *, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # ------------------------------------------------------------------
    # State machine (PR 13.2)
    # ------------------------------------------------------------------

    @staticmethod
    def validate_transition(from_status: str, to_status: str) -> None:
        """Raise RemediationInvalidTransition if the transition is forbidden.

        Called before any state change. Centralises all workflow logic so
        routes, tests, and future integrations have a single enforcement point.
        """
        allowed = _ALLOWED_TRANSITIONS.get(from_status, set())
        if to_status not in allowed:
            allowed_list = sorted(allowed) if allowed else []
            msg = (
                f"Transition '{from_status}' → '{to_status}' is not permitted. "
                f"Allowed from '{from_status}': {allowed_list or 'none (terminal state)'}."
            )
            raise RemediationInvalidTransition(msg)

    @staticmethod
    def allowed_transitions(current_status: str) -> list[str]:
        """Return the sorted list of states reachable from current_status."""
        return sorted(_ALLOWED_TRANSITIONS.get(current_status, set()))

    def get_allowed_transitions(self, *, task_id: str) -> AllowedTransitionsResponse:
        """Return allowed next states for a specific task."""
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        return AllowedTransitionsResponse(
            task_id=task.id,
            current_status=task.status,
            allowed_next_states=self.allowed_transitions(task.status),
        )

    def transition_status(
        self,
        *,
        task_id: str,
        request: TransitionTaskRequest,
        actor: str,
    ) -> TransitionResponse:
        """Execute a governed status transition on a task.

        Validates:
          - Transition is permitted by the state machine
          - reason is provided when transitioning to ACCEPTED_RISK

        Emits: task_planned | task_started | task_closed | task_risk_accepted
        Increments: frostgate_remediation_status_transitions_total{from,to}
        """
        new_status = request.new_status.value
        reason = request.reason

        if new_status == RemediationStatus.ACCEPTED_RISK.value and not reason:
            REMEDIATION_INVALID_TRANSITIONS_TOTAL.inc()
            raise RemediationInvalidTransition(
                "reason is required when transitioning to 'accepted_risk'."
            )

        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        old_status = task.status

        if (
            new_status == RemediationStatus.IN_PROGRESS.value
            and not task.assigned_user_id
        ):
            REMEDIATION_INVALID_TRANSITIONS_TOTAL.inc()
            raise RemediationInvalidTransition(
                "Transitioning to 'in_progress' requires an assigned owner. "
                "Use POST /remediation/tasks/{task_id}/assign first."
            )

        try:
            self.validate_transition(old_status, new_status)
        except RemediationInvalidTransition:
            REMEDIATION_INVALID_TRANSITIONS_TOTAL.inc()
            raise

        old_state = snapshot_task(task)
        now = _utcnow()

        updates: dict[str, Any] = {"status": new_status, "updated_at": now}
        if new_status == RemediationStatus.CLOSED.value:
            updates["closed_at"] = now

        apply_task_updates(task, updates=updates)
        new_state = snapshot_task(task)

        event_type = _TRANSITION_EVENT[(old_status, new_status)]
        self._emit_audit(
            task_id=task.id,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
        )

        REMEDIATION_STATUS_TRANSITIONS_TOTAL.labels(
            from_status=old_status, to_status=new_status
        ).inc()
        if new_status == RemediationStatus.CLOSED.value:
            REMEDIATION_TASKS_CLOSED_TOTAL.inc()

        return TransitionResponse(
            task_id=task.id,
            old_status=old_status,
            new_status=new_status,
            transitioned_at=now,
            allowed_next_states=self.allowed_transitions(new_status),
        )

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
        sla_target_days = SLA_DEFAULTS.get(request.priority.value)
        sla_breach_at = (
            _compute_sla_breach_at(now, sla_target_days)
            if sla_target_days is not None
            else None
        )
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
            sla_target_days=sla_target_days,
            sla_breach_at=sla_breach_at,
            assigned_user_id=None,
            assigned_user_email=None,
            assigned_display_name=None,
            assigned_at=None,
            due_date=None,
            ownership_reason=None,
            last_assignment_change_at=None,
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
            if request.priority.value != task.priority:
                new_sla_target = SLA_DEFAULTS.get(request.priority.value)
                updates["sla_target_days"] = new_sla_target
                updates["sla_breach_at"] = (
                    _compute_sla_breach_at(task.created_at, new_sla_target)
                    if new_sla_target is not None
                    else None
                )
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
    # Close (convenience wrapper over transition_status)
    # ------------------------------------------------------------------

    def close_task(
        self,
        *,
        task_id: str,
        actor: str,
    ) -> TaskResponse:
        """Transition a task to CLOSED via the state machine.

        Requires current status to be IN_PROGRESS (enforced by state machine).
        Delegates to transition_status() so audit, metrics, and state validation
        are handled identically regardless of call path.

        Emits: task_closed audit event (REM-13)
        Increments: frostgate_remediation_tasks_closed_total (via transition_status)
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)

        if task.status == RemediationStatus.CLOSED.value:
            raise RemediationConflict(f"task_id={task_id!r} is already closed")

        req = TransitionTaskRequest(new_status=RemediationStatus.CLOSED, reason=None)
        self.transition_status(task_id=task_id, request=req, actor=actor)
        # Re-fetch to return the updated task state
        return _task_to_response(
            fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        )

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
    ) -> AuditListResponse:
        """Return the full ordered audit trail for a task.

        Used for lifecycle reconstruction (REM-20, REM-40).
        The task itself may have been deleted; audit events persist.
        """
        events = fetch_audit_events(
            self._db,
            tenant_id=self._tenant_id,
            task_id=task_id,
        )
        return AuditListResponse(
            task_id=task_id,
            events=[_audit_to_response(e) for e in events],
        )

    # ------------------------------------------------------------------
    # Ownership (PR 13.3)
    # ------------------------------------------------------------------

    def assign_owner(
        self,
        *,
        task_id: str,
        request: AssignOwnerRequest,
        actor: str,
    ) -> TaskResponse:
        """Assign or reassign the owner of a task.

        First assignment emits task_assigned; subsequent calls emit task_reassigned.
        All changes are tenant-scoped and audited.

        Increments: frostgate_remediation_assignments_total or reassignments_total
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        old_state = snapshot_task(task)
        is_reassignment = task.assigned_user_id is not None
        now_dt = _now_dt()
        now_str = now_dt.isoformat()

        updates: dict[str, Any] = {
            "assigned_user_id": request.user_id,
            "assigned_user_email": request.email,
            "assigned_display_name": request.display_name,
            "assigned_at": now_dt,
            "ownership_reason": request.reason,
            "last_assignment_change_at": now_dt,
            "updated_at": now_str,
        }
        apply_task_updates(task, updates=updates)
        new_state = snapshot_task(task)

        event_type = (
            RemediationAuditEventType.TASK_REASSIGNED
            if is_reassignment
            else RemediationAuditEventType.TASK_ASSIGNED
        )
        self._emit_audit(
            task_id=task.id,
            event_type=event_type,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=request.reason,
        )

        if is_reassignment:
            REMEDIATION_REASSIGNMENTS_TOTAL.inc()
        else:
            REMEDIATION_ASSIGNMENTS_TOTAL.inc()

        return _task_to_response(task)

    def remove_owner(
        self,
        *,
        task_id: str,
        request: UnassignRequest,
        actor: str,
    ) -> TaskResponse:
        """Remove the current owner from a task.

        Rejected if task is IN_PROGRESS (must reassign instead, not unassign).
        Rejected if task is already unassigned.
        Emits: task_unassigned
        Increments: frostgate_remediation_unassigned_tasks_total
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)

        if task.assigned_user_id is None:
            raise RemediationOwnershipError(
                f"task_id={task_id!r} has no assigned owner to remove."
            )
        if task.status == RemediationStatus.IN_PROGRESS.value:
            raise RemediationOwnershipError(
                "Cannot remove owner from an IN_PROGRESS task. "
                "Reassign to a different owner instead."
            )

        old_state = snapshot_task(task)
        now_dt = _now_dt()
        now_str = now_dt.isoformat()

        updates: dict[str, Any] = {
            "assigned_user_id": None,
            "assigned_user_email": None,
            "assigned_display_name": None,
            "assigned_at": None,
            "ownership_reason": None,
            "last_assignment_change_at": now_dt,
            "updated_at": now_str,
        }
        apply_task_updates(task, updates=updates)
        new_state = snapshot_task(task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_UNASSIGNED,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=request.reason,
        )

        REMEDIATION_UNASSIGNED_TASKS_TOTAL.inc()
        return _task_to_response(task)

    # ------------------------------------------------------------------
    # Due date + SLA (PR 13.3)
    # ------------------------------------------------------------------

    def set_due_date(
        self,
        *,
        task_id: str,
        request: SetDueDateRequest,
        actor: str,
    ) -> TaskResponse:
        """Set or update the explicit due date on a task.

        The due_date is an external commitment (contractual, managerial).
        It is separate from sla_breach_at (which is computed from priority SLA).
        Emits: task_due_date_changed
        """
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        old_state = snapshot_task(task)

        updates: dict[str, Any] = {
            "due_date": request.due_date,
            "updated_at": _utcnow(),
        }
        apply_task_updates(task, updates=updates)
        new_state = snapshot_task(task)

        self._emit_audit(
            task_id=task.id,
            event_type=RemediationAuditEventType.TASK_DUE_DATE_CHANGED,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=request.reason,
        )

        return _task_to_response(task)

    def get_sla(self, *, task_id: str) -> SlaResponse:
        """Return the SLA status for a task (computed, not stored)."""
        task = fetch_task(self._db, tenant_id=self._tenant_id, task_id=task_id)
        sla_response = _compute_sla_response(task)
        if sla_response.sla_status == SlaStatus.OVERDUE.value:
            REMEDIATION_OVERDUE_TASKS_TOTAL.inc()
            REMEDIATION_SLA_BREACHES_TOTAL.inc()
        return sla_response

    def list_overdue_tasks(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> TaskListResponse:
        """Return all active tasks whose SLA breach timestamp is in the past."""
        now = _now_dt()
        tasks = fetch_overdue_tasks(
            self._db,
            tenant_id=self._tenant_id,
            now=now,
            limit=limit,
            offset=offset,
        )
        total = count_overdue_tasks(
            self._db,
            tenant_id=self._tenant_id,
            now=now,
        )
        return TaskListResponse(
            tasks=[_task_to_response(t) for t in tasks],
            total=total,
        )

    def list_unassigned_tasks(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> TaskListResponse:
        """Return all active tasks with no assigned owner."""
        tasks = fetch_unassigned_tasks(
            self._db,
            tenant_id=self._tenant_id,
            limit=limit,
            offset=offset,
        )
        total = count_unassigned_tasks(self._db, tenant_id=self._tenant_id)
        return TaskListResponse(
            tasks=[_task_to_response(t) for t in tasks],
            total=total,
        )

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
        reason: str | None = None,
    ) -> None:
        audit = RemediationTaskAudit(
            id=_new_id(),
            tenant_id=self._tenant_id,
            task_id=task_id,
            event_type=event_type.value,
            actor=actor,
            old_state=old_state,
            new_state=new_state,
            reason=reason,
            event_at=_utcnow(),
        )
        insert_audit_event(self._db, audit=audit)
