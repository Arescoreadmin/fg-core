"""Workflow lifecycle management for governance orchestration."""

from __future__ import annotations

from typing import Any

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration.models import (
    TERMINAL_WORKFLOW_STATES,
    WorkflowState,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationWorkflowError,
)


_VALID_EVENTS: dict[WorkflowState, dict[str, WorkflowState]] = {
    WorkflowState.PENDING: {
        "start": WorkflowState.RUNNING,
        "cancel": WorkflowState.CANCELLED,
    },
    WorkflowState.RUNNING: {
        "wait_approval": WorkflowState.WAITING_APPROVAL,
        "pause": WorkflowState.PAUSED,
        "complete": WorkflowState.COMPLETED,
        "fail": WorkflowState.FAILED,
        "cancel": WorkflowState.CANCELLED,
    },
    WorkflowState.WAITING_APPROVAL: {
        "approve": WorkflowState.RUNNING,
        "reject": WorkflowState.FAILED,
        "cancel": WorkflowState.CANCELLED,
    },
    WorkflowState.PAUSED: {
        "resume": WorkflowState.RUNNING,
        "cancel": WorkflowState.CANCELLED,
    },
}


class WorkflowCoordinator:
    """Coordinates lifecycle events on governance workflows."""

    def start_workflow(self, db: Any, tenant_id: str, workflow_id: str) -> dict[str, Any]:
        return self._transition(db, tenant_id, workflow_id, "start")

    def advance_workflow(
        self, db: Any, tenant_id: str, workflow_id: str, event: str
    ) -> dict[str, Any]:
        if not isinstance(event, str) or not event.strip():
            raise GovernanceOrchestrationWorkflowError("event must be a non-empty string")
        return self._transition(db, tenant_id, workflow_id, event.strip())

    def pause_workflow(self, db: Any, tenant_id: str, workflow_id: str) -> dict[str, Any]:
        return self._transition(db, tenant_id, workflow_id, "pause")

    def cancel_workflow(self, db: Any, tenant_id: str, workflow_id: str) -> dict[str, Any]:
        return self._transition(db, tenant_id, workflow_id, "cancel")

    def get_workflow_summary(
        self, db: Any, tenant_id: str, workflow_id: str
    ) -> dict[str, Any]:
        repo = GovernanceOrchestrationRepository(db, tenant_id)
        row = repo.get_workflow(workflow_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Workflow {workflow_id!r} not found for tenant {tenant_id!r}"
            )
        return {
            "id": row.id,
            "workflow_state": row.workflow_state,
            "playbook_id": row.playbook_id,
            "trigger_id": row.trigger_id,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "completed_at": row.completed_at,
        }

    def _transition(
        self, db: Any, tenant_id: str, workflow_id: str, event: str
    ) -> dict[str, Any]:
        repo = GovernanceOrchestrationRepository(db, tenant_id)
        row = repo.get_workflow(workflow_id)
        if row is None:
            raise GovernanceOrchestrationNotFound(
                f"Workflow {workflow_id!r} not found for tenant {tenant_id!r}"
            )
        try:
            current = WorkflowState(row.workflow_state)
        except ValueError as exc:
            raise GovernanceOrchestrationWorkflowError(
                f"Unknown workflow state {row.workflow_state!r}"
            ) from exc
        if current in TERMINAL_WORKFLOW_STATES:
            raise GovernanceOrchestrationInvalidTransition(
                f"Workflow {workflow_id!r} is in terminal state {current.value!r}"
            )
        transitions = _VALID_EVENTS.get(current, {})
        target = transitions.get(event)
        if target is None:
            raise GovernanceOrchestrationInvalidTransition(
                f"Event {event!r} not valid from state {current.value!r}"
            )
        row.workflow_state = target.value
        if target in {WorkflowState.COMPLETED, WorkflowState.FAILED, WorkflowState.CANCELLED, WorkflowState.ROLLED_BACK}:
            row.completed_at = utc_iso8601_z_now()
        repo.update_workflow(row)
        return {
            "id": row.id,
            "workflow_state": row.workflow_state,
            "playbook_id": row.playbook_id,
            "trigger_id": row.trigger_id,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "completed_at": row.completed_at,
        }
