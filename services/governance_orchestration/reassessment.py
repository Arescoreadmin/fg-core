"""Reassessment orchestration for governance orchestration."""

from __future__ import annotations

from typing import Any

from services.canonical import utc_iso8601_z_now
from services.governance_orchestration.models import (
    TERMINAL_REASSESSMENT_STATES,
    ReassessmentState,
)
from services.governance_orchestration.repository import (
    GovernanceOrchestrationRepository,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationInvalidTransition,
    GovernanceOrchestrationNotFound,
    GovernanceOrchestrationValidationError,
)


def request_reassessment(
    db: Any,
    tenant_id: str,
    assessment_id: str,
    trigger_id: str | None,
    reason: str | None,
) -> dict[str, Any]:
    if not isinstance(assessment_id, str) or not assessment_id.strip():
        raise GovernanceOrchestrationValidationError(
            "assessment_id must be a non-empty string"
        )
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.create_reassessment(
        assessment_id=assessment_id,
        trigger_id=trigger_id,
        reassessment_state=ReassessmentState.REQUESTED.value,
        reason=reason,
    )
    return _to_dict(row)


def schedule_reassessment(
    db: Any, tenant_id: str, reassessment_id: str, scheduled_at: str
) -> dict[str, Any]:
    if not isinstance(scheduled_at, str) or not scheduled_at.strip():
        raise GovernanceOrchestrationValidationError(
            "scheduled_at must be a non-empty string"
        )
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.get_reassessment(reassessment_id)
    if row is None:
        raise GovernanceOrchestrationNotFound(
            f"Reassessment {reassessment_id!r} not found"
        )
    state = ReassessmentState(row.reassessment_state)
    if state in TERMINAL_REASSESSMENT_STATES:
        raise GovernanceOrchestrationInvalidTransition(
            f"Reassessment {reassessment_id!r} is terminal ({state.value})"
        )
    row.reassessment_state = ReassessmentState.SCHEDULED.value
    row.scheduled_at = scheduled_at
    repo.update_reassessment(row)
    return _to_dict(row)


def complete_reassessment(
    db: Any, tenant_id: str, reassessment_id: str, outcome: str
) -> dict[str, Any]:
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.get_reassessment(reassessment_id)
    if row is None:
        raise GovernanceOrchestrationNotFound(
            f"Reassessment {reassessment_id!r} not found"
        )
    state = ReassessmentState(row.reassessment_state)
    if state in TERMINAL_REASSESSMENT_STATES:
        raise GovernanceOrchestrationInvalidTransition(
            f"Reassessment {reassessment_id!r} is terminal ({state.value})"
        )
    row.reassessment_state = ReassessmentState.COMPLETED.value
    row.outcome = outcome
    row.completed_at = utc_iso8601_z_now()
    repo.update_reassessment(row)
    return _to_dict(row)


def get_reassessment_readiness(
    db: Any, tenant_id: str, reassessment_id: str
) -> dict[str, Any]:
    """Return a readiness dict describing whether a reassessment can proceed."""
    repo = GovernanceOrchestrationRepository(db, tenant_id)
    row = repo.get_reassessment(reassessment_id)
    if row is None:
        raise GovernanceOrchestrationNotFound(
            f"Reassessment {reassessment_id!r} not found"
        )
    state = ReassessmentState(row.reassessment_state)
    ready = state == ReassessmentState.SCHEDULED
    return {
        "reassessment_id": reassessment_id,
        "state": state.value,
        "ready": ready,
        "scheduled_at": row.scheduled_at,
    }


def _to_dict(row: Any) -> dict[str, Any]:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "assessment_id": row.assessment_id,
        "trigger_id": row.trigger_id,
        "reassessment_state": row.reassessment_state,
        "reason": row.reason,
        "scheduled_at": row.scheduled_at,
        "completed_at": row.completed_at,
        "outcome": row.outcome,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
