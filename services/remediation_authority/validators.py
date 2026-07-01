"""Input validators for the Remediation Authority.

Pure functions. All raise domain-friendly exceptions on invalid input.
"""

from __future__ import annotations

from services.remediation_authority.schemas import (
    RemediationTenantViolation,
    RemediationValidationError,
)


def validate_tenant_id(tenant_id: str) -> None:
    """Raise RemediationTenantViolation if ``tenant_id`` is empty or whitespace."""
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise RemediationTenantViolation("tenant_id must be a non-empty string")


def validate_limit_offset(limit: int, offset: int) -> None:
    """Raise RemediationValidationError if pagination parameters are invalid."""
    if not isinstance(limit, int) or limit < 1 or limit > 500:
        raise RemediationValidationError("limit must be between 1 and 500")
    if not isinstance(offset, int) or offset < 0:
        raise RemediationValidationError("offset must be >= 0")


def validate_search_query(query: str) -> None:
    """Raise RemediationValidationError if ``query`` is empty/too long."""
    if not isinstance(query, str) or not query.strip():
        raise RemediationValidationError("query must be a non-empty string")
    if len(query) > 512:
        raise RemediationValidationError("query must be <= 512 characters")


def validate_horizon_days(horizon_days: int) -> None:
    """Raise RemediationValidationError if forecast horizon is invalid."""
    if not isinstance(horizon_days, int) or horizon_days < 1 or horizon_days > 365:
        raise RemediationValidationError("horizon_days must be between 1 and 365")


def validate_task_id(task_id: str) -> None:
    """Raise RemediationValidationError if ``task_id`` is empty."""
    if not isinstance(task_id, str) or not task_id.strip():
        raise RemediationValidationError("task_id must be a non-empty string")
