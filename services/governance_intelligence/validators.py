"""Input validators for the Governance Intelligence Authority."""

from __future__ import annotations

from services.governance_intelligence.models import ForecastHorizon, SimulationState
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceTenantViolation,
    GovernanceIntelligenceValidationError,
)
from services.governance_intelligence.simulation import SUPPORTED_SCENARIO_TYPES


def validate_tenant_id(tenant_id: str) -> None:
    """Raise if tenant_id is empty or whitespace."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise GovernanceIntelligenceTenantViolation(
            "tenant_id must be a non-empty string"
        )


def validate_limit_offset(limit: int, offset: int) -> None:
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise GovernanceIntelligenceValidationError(
            "limit must be between 1 and 500"
        )
    if not isinstance(offset, int) or offset < 0:
        raise GovernanceIntelligenceValidationError("offset must be >= 0")


def validate_search_query(query: str) -> None:
    if not isinstance(query, str) or not query.strip():
        raise GovernanceIntelligenceValidationError(
            "query must be a non-empty string"
        )
    if len(query) > 512:
        raise GovernanceIntelligenceValidationError(
            "query must be <= 512 characters"
        )


def validate_scenario_type(scenario_type: str) -> None:
    if scenario_type not in SUPPORTED_SCENARIO_TYPES:
        raise GovernanceIntelligenceValidationError(
            f"scenario_type must be one of {sorted(SUPPORTED_SCENARIO_TYPES)}"
        )


def validate_metric_key(metric_key: str) -> None:
    if not isinstance(metric_key, str) or not metric_key.strip():
        raise GovernanceIntelligenceValidationError(
            "metric_key must be a non-empty string"
        )
    if len(metric_key) > 255:
        raise GovernanceIntelligenceValidationError(
            "metric_key must be <= 255 characters"
        )


def validate_horizon(horizon: str) -> None:
    valid = {h.value for h in ForecastHorizon}
    if horizon not in valid:
        raise GovernanceIntelligenceValidationError(
            f"horizon must be one of {sorted(valid)}"
        )


def validate_framework(framework: str) -> None:
    if not isinstance(framework, str) or not framework.strip():
        raise GovernanceIntelligenceValidationError(
            "framework must be a non-empty string"
        )
    if len(framework) > 128:
        raise GovernanceIntelligenceValidationError(
            "framework must be <= 128 characters"
        )
