"""Deterministic rollback helpers for governance orchestration workflows."""

from __future__ import annotations

from typing import Any, Optional

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration.models import WorkflowState
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationWorkflowError,
)


def initiate_rollback(
    db: Any, tenant_id: str, workflow_id: str, reason: str
) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    workflow = repo.get_workflow(workflow_id)
    if workflow is None:
        raise GovernanceOrchestrationNotFound(
            f"Workflow {workflow_id!r} not found"
        )
    if workflow.workflow_state == WorkflowState.COMPLETED.value:
        raise GovernanceOrchestrationWorkflowError(
            "Cannot roll back completed workflow"
        )
    workflow.workflow_state = WorkflowState.ROLLED_BACK.value
    workflow.completed_at = utc_iso8601_z_now()
    repo.update_workflow(workflow)
    repo.append_timeline(
        entity_type="workflow",
        entity_id=workflow_id,
        event_type="rollback_initiated",
        actor_id=None,
        event_metadata={"reason": reason},
    )
    return {
        "workflow_id": workflow_id,
        "workflow_state": workflow.workflow_state,
        "reason": reason,
        "created_at": workflow.completed_at,
    }


def execute_rollback_step(
    db: Any, tenant_id: str, rollback_id: str, step: str
) -> dict[str, Any]:
    """Execute a rollback step (records only — deterministic)."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    repo.append_timeline(
        entity_type="rollback",
        entity_id=rollback_id,
        event_type="rollback_step",
        actor_id=None,
        event_metadata={"step": step},
    )
    return {
        "rollback_id": rollback_id,
        "step": step,
        "recorded_at": utc_iso8601_z_now(),
    }


def complete_rollback(
    db: Any, tenant_id: str, rollback_id: str
) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    repo.append_timeline(
        entity_type="rollback",
        entity_id=rollback_id,
        event_type="rollback_completed",
        actor_id=None,
        event_metadata={},
    )
    return {
        "rollback_id": rollback_id,
        "completed_at": utc_iso8601_z_now(),
    }


def get_rollback_status(
    db: Any, tenant_id: str, workflow_id: str
) -> Optional[dict[str, Any]]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    workflow = repo.get_workflow(workflow_id)
    if workflow is None:
        return None
    if workflow.workflow_state != WorkflowState.ROLLED_BACK.value:
        return None
    return {
        "workflow_id": workflow_id,
        "workflow_state": workflow.workflow_state,
        "completed_at": workflow.completed_at,
    }
