"""Governance Asset Risk Engine — deterministic, pure, no DB calls.

Trust-but-Verify: the scoring function is a pure transformation from
RiskFactors → RiskScore.  The DB layer calls it; it never touches the DB.
This makes every score unit-testable, auditable, and reproducible from
the factors_json stored alongside each GaAssetRiskScore row.

Risk tiers:
  critical  ≥ 750
  high      ≥ 500
  medium    ≥ 250
  low       ≥ 100
  minimal   <  100
"""

from __future__ import annotations

from services.canonical import utc_iso8601_z_now
from services.governance_asset_registry.models import (
    AssetType,
    DataClassification,
    DiscoverySource,
    RiskFactors,
    RiskScore,
    RiskTier,
)

# ---------------------------------------------------------------------------
# Asset-type base scores
# ---------------------------------------------------------------------------
_ASSET_TYPE_BASE: dict[str, int] = {
    AssetType.model: 200,
    AssetType.ai_vendor: 180,
    AssetType.agent: 160,
    AssetType.ai_system: 140,
    AssetType.copilot: 120,
    AssetType.automation: 100,
    AssetType.oauth_app: 80,
    AssetType.data_flow: 60,
}

# ---------------------------------------------------------------------------
# Data classification sensitivity scores
# ---------------------------------------------------------------------------
_DATA_SENSITIVITY: dict[str, int] = {
    DataClassification.phi: 200,
    DataClassification.pii: 180,
    DataClassification.financial: 160,
    DataClassification.confidential: 120,
    DataClassification.internal: 80,
    DataClassification.public: 20,
    DataClassification.unknown: 60,  # unknown is penalised, not assumed safe
}

# ---------------------------------------------------------------------------
# Discovery source penalty
# ---------------------------------------------------------------------------
_DISCOVERY_PENALTY: dict[str, int] = {
    DiscoverySource.declared: 0,
    DiscoverySource.inferred: 25,
    DiscoverySource.discovered: 50,  # shadow asset
}


def asset_type_base_score(asset_type: str) -> int:
    return _ASSET_TYPE_BASE.get(asset_type, 80)


def data_sensitivity_score(data_classification: str) -> int:
    return _DATA_SENSITIVITY.get(data_classification, 60)


def discovery_penalty_score(discovery_source: str) -> int:
    return _DISCOVERY_PENALTY.get(discovery_source, 50)


def compute_attestation_staleness(days_overdue: int) -> int:
    """Return 0–100 staleness score.  Accrues +2 pts/day, capped at 100."""
    if days_overdue <= 0:
        return 0
    return min(100, days_overdue * 2)


def tier_from_score(score: int) -> RiskTier:
    if score >= 750:
        return RiskTier.critical
    if score >= 500:
        return RiskTier.high
    if score >= 250:
        return RiskTier.medium
    if score >= 100:
        return RiskTier.low
    return RiskTier.minimal


def compute_risk_score(factors: RiskFactors) -> RiskScore:
    """Pure function: RiskFactors → RiskScore.  No I/O, no side effects."""
    raw = (
        factors.asset_type_base
        + factors.vendor_risk
        + factors.data_sensitivity
        + factors.change_velocity
        + factors.open_findings_weight
        + factors.attestation_staleness
        + factors.discovery_penalty
    )
    score = min(1000, max(0, raw))
    return RiskScore(
        score=score,
        tier=tier_from_score(score),
        factors=factors,
        computed_at=utc_iso8601_z_now(),
    )


def build_factors(
    *,
    asset_type: str,
    discovery_source: str,
    days_attestation_overdue: int = 0,
    max_data_classification: str = DataClassification.unknown,
    vendor_risk_score: int = 0,
    change_velocity_score: int = 0,
    open_findings_weight: int = 0,
) -> RiskFactors:
    """Convenience constructor used by registry.py when recomputing a score."""
    return RiskFactors(
        asset_type_base=asset_type_base_score(asset_type),
        vendor_risk=min(200, vendor_risk_score),
        data_sensitivity=data_sensitivity_score(max_data_classification),
        change_velocity=min(100, change_velocity_score),
        open_findings_weight=min(150, open_findings_weight),
        attestation_staleness=compute_attestation_staleness(days_attestation_overdue),
        discovery_penalty=discovery_penalty_score(discovery_source),
    )
