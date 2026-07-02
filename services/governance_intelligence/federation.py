"""Federation abstraction layer for the Governance Intelligence Authority.

No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import FederationRole
from services.governance_intelligence.schemas import GovernanceIntelligenceValidationError


VALID_ROLES: frozenset[str] = frozenset({r.value for r in FederationRole})


def validate_federation_request(instance_id: str, role: str) -> None:
    """Raise GovernanceIntelligenceValidationError if the federation request is invalid."""
    if not isinstance(instance_id, str) or not instance_id.strip():
        raise GovernanceIntelligenceValidationError(
            "instance_id must be a non-empty string"
        )
    if role not in VALID_ROLES:
        raise GovernanceIntelligenceValidationError(
            f"Invalid federation role '{role}'. Allowed: {sorted(VALID_ROLES)}"
        )


def build_governance_summary(tenant_data: dict[str, Any]) -> dict[str, Any]:
    """Build an anonymized governance summary for sharing.

    Strips all PII and tenant_id. Keeps only scores, percentiles, trend directions.
    NEVER exposes tenant_id in output.
    """
    # Explicitly build output without any tenant-identifying fields
    return {
        "governance_score": tenant_data.get("governance_score"),
        "risk_level": tenant_data.get("risk_level"),
        "trend": tenant_data.get("trend"),
        "benchmark_tier": tenant_data.get("benchmark_tier"),
        "active_simulations": tenant_data.get("active_simulations"),
        "confidence": {
            k: v
            for k, v in (tenant_data.get("confidence") or {}).items()
            if k not in {"tenant_id", "instance_id", "source"}
        },
        "schema_version": "1.0",
        "anonymized": True,
        # tenant_id is intentionally excluded from all outputs
    }
