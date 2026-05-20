"""Governance Asset Registry — domain enums and value objects."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AssetType(str, Enum):
    ai_system = "ai_system"
    ai_vendor = "ai_vendor"
    model = "model"
    oauth_app = "oauth_app"
    agent = "agent"
    copilot = "copilot"
    automation = "automation"
    data_flow = "data_flow"


class AssetStatus(str, Enum):
    active = "active"
    deprecated = "deprecated"
    under_review = "under_review"
    decommissioned = "decommissioned"


class RiskTier(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    minimal = "minimal"
    unclassified = "unclassified"


class OwnerRole(str, Enum):
    primary = "primary"
    secondary = "secondary"
    delegate = "delegate"


class RelationshipType(str, Enum):
    data_flow = "data_flow"
    depends_on = "depends_on"
    manages = "manages"
    monitors = "monitors"
    delegates_to = "delegates_to"
    trained_on = "trained_on"


class DataClassification(str, Enum):
    pii = "pii"
    phi = "phi"
    financial = "financial"
    confidential = "confidential"
    internal = "internal"
    public = "public"
    unknown = "unknown"


class TransferVolumeTier(str, Enum):
    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class DiscoverySource(str, Enum):
    declared = "declared"
    discovered = "discovered"
    inferred = "inferred"


class AttestationType(str, Enum):
    ownership = "ownership"
    accuracy = "accuracy"
    risk_review = "risk_review"
    access_review = "access_review"


class AttestationStatus(str, Enum):
    pending = "pending"
    completed = "completed"
    overdue = "overdue"
    waived = "waived"


class PolicyType(str, Enum):
    ai_use_policy = "ai_use_policy"
    data_retention = "data_retention"
    access_control = "access_control"
    output_filtering = "output_filtering"
    audit_logging = "audit_logging"


class PolicyBindingStatus(str, Enum):
    active = "active"
    superseded = "superseded"
    revoked = "revoked"


# ---------------------------------------------------------------------------
# Risk score value objects
# ---------------------------------------------------------------------------

# Attestation interval in days per risk tier (Trust-but-Verify cadence)
ATTESTATION_INTERVAL_BY_TIER: dict[RiskTier, int] = {
    RiskTier.critical: 30,
    RiskTier.high: 60,
    RiskTier.medium: 90,
    RiskTier.low: 90,
    RiskTier.minimal: 90,
    RiskTier.unclassified: 90,
}


@dataclass(frozen=True)
class RiskFactors:
    """Immutable factor breakdown for a risk score computation.

    All factors are non-negative integers summing to RiskScore.score (≤ 1000).
    Keeping the breakdown allows any score to be reproduced and explained.
    """

    asset_type_base: int = 0       # 0-200: model > agent > ai_system > copilot …
    vendor_risk: int = 0           # 0-200: inherited from GaAsset(asset_type=ai_vendor)
    data_sensitivity: int = 0      # 0-200: driven by relationship data_classification
    change_velocity: int = 0       # 0-100: >5 version changes / 7 days
    open_findings_weight: int = 0  # 0-150: from fa_normalized_findings (future join)
    attestation_staleness: int = 0 # 0-100: +2 pts/day overdue, capped at 100
    discovery_penalty: int = 0     # 0-50:  discovered/inferred vs declared


@dataclass(frozen=True)
class RiskScore:
    """Computed risk score with full factor breakdown."""

    score: int         # 0-1000
    tier: RiskTier
    factors: RiskFactors
    computed_at: str   # ISO8601Z
