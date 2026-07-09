"""Analytics helpers for the Governance Orchestration Authority."""

from __future__ import annotations

from typing import Any

from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)


def compute_orchestration_statistics(db: Any, tenant_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    policies, total_policies = repo.list_policies(offset=0, limit=500)
    playbooks, total_playbooks = repo.list_playbooks(offset=0, limit=500)
    workflows, total_workflows = repo.list_workflows(offset=0, limit=500)
    reassessments, total_reassessments = repo.list_reassessments(offset=0, limit=500)
    triggers, total_triggers = repo.list_triggers(offset=0, limit=500)
    approvals = repo.list_approvals()

    workflow_by_state: dict[str, int] = {}
    for w in workflows:
        workflow_by_state[w.workflow_state] = (
            workflow_by_state.get(w.workflow_state, 0) + 1
        )

    reassessment_by_state: dict[str, int] = {}
    for r in reassessments:
        reassessment_by_state[r.reassessment_state] = (
            reassessment_by_state.get(r.reassessment_state, 0) + 1
        )

    trigger_by_type: dict[str, int] = {}
    for t in triggers:
        trigger_by_type[t.trigger_type] = trigger_by_type.get(t.trigger_type, 0) + 1

    approval_by_state: dict[str, int] = {}
    for a in approvals:
        approval_by_state[a.approval_state] = (
            approval_by_state.get(a.approval_state, 0) + 1
        )

    return {
        "total_policies": total_policies,
        "total_playbooks": total_playbooks,
        "total_workflows": total_workflows,
        "total_reassessments": total_reassessments,
        "total_triggers": total_triggers,
        "total_approvals": len(approvals),
        "workflow_by_state": workflow_by_state,
        "reassessment_by_state": reassessment_by_state,
        "trigger_by_type": trigger_by_type,
        "approval_by_state": approval_by_state,
    }


def compute_reassessment_velocity(db: Any, tenant_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows, total = repo.list_reassessments(offset=0, limit=500)
    completed = [r for r in rows if r.completed_at is not None]
    return {
        "total": total,
        "completed": len(completed),
        "in_progress": sum(1 for r in rows if r.reassessment_state == "IN_PROGRESS"),
        "scheduled": sum(1 for r in rows if r.reassessment_state == "SCHEDULED"),
    }


def compute_policy_effectiveness(db: Any, tenant_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    rows, total = repo.list_policies(offset=0, limit=500)
    active = sum(1 for r in rows if r.active)
    return {
        "total": total,
        "active": active,
        "inactive": total - active,
        "effectiveness_score": round(100.0 * active / total, 2) if total else 0.0,
    }


def compute_approval_cycle_time(db: Any, tenant_id: str) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    approvals = repo.list_approvals()
    if not approvals:
        return {"total": 0, "pending": 0, "approved": 0, "rejected": 0}
    return {
        "total": len(approvals),
        "pending": sum(1 for a in approvals if a.approval_state == "PENDING"),
        "approved": sum(1 for a in approvals if a.approval_state == "APPROVED"),
        "rejected": sum(1 for a in approvals if a.approval_state == "REJECTED"),
    }
