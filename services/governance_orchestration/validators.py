"""Input validators for the Governance Orchestration Authority."""

from __future__ import annotations

from services.governance_orchestration.models import (
    ChangeType,
    ImpactLevel,
    PlaybookType,
    PolicyRiskLevel,
    TriggerType,
    WorkflowState,
)
from services.governance_orchestration.schemas import (
    GovernanceOrchestrationTenantViolation,
    GovernanceOrchestrationValidationError,
)


def validate_tenant_id(tenant_id: str) -> None:
    """Raise if ``tenant_id`` is empty or whitespace."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise GovernanceOrchestrationTenantViolation(
            "tenant_id must be a non-empty string"
        )


def validate_limit_offset(limit: int, offset: int) -> None:
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise GovernanceOrchestrationValidationError(
            "limit must be between 1 and 500"
        )
    if not isinstance(offset, int) or offset < 0:
        raise GovernanceOrchestrationValidationError("offset must be >= 0")


def validate_search_query(query: str) -> None:
    if not isinstance(query, str) or not query.strip():
        raise GovernanceOrchestrationValidationError(
            "query must be a non-empty string"
        )
    if len(query) > 512:
        raise GovernanceOrchestrationValidationError(
            "query must be <= 512 characters"
        )


def validate_policy_risk_level(risk_level: str) -> None:
    valid = {m.value for m in PolicyRiskLevel}
    if risk_level not in valid:
        raise GovernanceOrchestrationValidationError(
            f"risk_level must be one of {sorted(valid)}"
        )


def validate_trigger_type(trigger_type: str) -> None:
    valid = {m.value for m in TriggerType}
    if trigger_type not in valid:
        raise GovernanceOrchestrationValidationError(
            f"trigger_type must be one of {sorted(valid)}"
        )


def validate_workflow_state(state: str) -> None:
    valid = {m.value for m in WorkflowState}
    if state not in valid:
        raise GovernanceOrchestrationValidationError(
            f"workflow_state must be one of {sorted(valid)}"
        )


def validate_confidence(confidence: float) -> None:
    if not isinstance(confidence, (int, float)):
        raise GovernanceOrchestrationValidationError(
            "confidence must be numeric"
        )
    if confidence < 0.0 or confidence > 1.0:
        raise GovernanceOrchestrationValidationError(
            "confidence must be between 0.0 and 1.0"
        )


def validate_playbook_type(playbook_type: str) -> None:
    valid = {m.value for m in PlaybookType}
    if playbook_type not in valid:
        raise GovernanceOrchestrationValidationError(
            f"playbook_type must be one of {sorted(valid)}"
        )


def validate_change_type(change_type: str) -> None:
    valid = {m.value for m in ChangeType}
    if change_type not in valid:
        raise GovernanceOrchestrationValidationError(
            f"change_type must be one of {sorted(valid)}"
        )


def validate_impact_level(impact_level: str) -> None:
    valid = {m.value for m in ImpactLevel}
    if impact_level not in valid:
        raise GovernanceOrchestrationValidationError(
            f"impact_level must be one of {sorted(valid)}"
        )
