"""Enums and constants for the Governance Intelligence Authority (PR 18.5).

Pure Python. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from enum import Enum


GOVERNANCE_INTELLIGENCE_SCHEMA_VERSION: str = "1.0"


class SimulationState(str, Enum):
    """Lifecycle state of an intelligence simulation."""

    DRAFT = "DRAFT"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    FAILED = "FAILED"
    ARCHIVED = "ARCHIVED"


class PolicyLifecycleState(str, Enum):
    """Lifecycle state of an intelligence policy."""

    DRAFT = "DRAFT"
    REVIEW = "REVIEW"
    APPROVED = "APPROVED"
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"


class BenchmarkTier(str, Enum):
    """Benchmark performance tier based on percentile rank."""

    PERCENTILE_25 = "PERCENTILE_25"
    PERCENTILE_50 = "PERCENTILE_50"
    PERCENTILE_75 = "PERCENTILE_75"
    PERCENTILE_90 = "PERCENTILE_90"
    PERCENTILE_95 = "PERCENTILE_95"


class TrendDirection(str, Enum):
    """Direction of a metric trend."""

    IMPROVING = "IMPROVING"
    STABLE = "STABLE"
    DECLINING = "DECLINING"
    VOLATILE = "VOLATILE"


class ConfidenceLevel(str, Enum):
    """Confidence level for intelligence outputs."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class ForecastHorizon(str, Enum):
    """Time horizon for a forecast."""

    DAYS_7 = "DAYS_7"
    DAYS_30 = "DAYS_30"
    DAYS_90 = "DAYS_90"
    DAYS_180 = "DAYS_180"


class ExternalEventType(str, Enum):
    """Classification of an external event."""

    SECURITY_INCIDENT = "SECURITY_INCIDENT"
    COMPLIANCE_CHANGE = "COMPLIANCE_CHANGE"
    VENDOR_CHANGE = "VENDOR_CHANGE"
    POLICY_UPDATE = "POLICY_UPDATE"
    AUDIT_FINDING = "AUDIT_FINDING"
    REGULATORY_UPDATE = "REGULATORY_UPDATE"


class FederationRole(str, Enum):
    """Role of an instance in a federated governance deployment."""

    COORDINATOR = "COORDINATOR"
    MEMBER = "MEMBER"
    OBSERVER = "OBSERVER"


class IntelligenceOutputType(str, Enum):
    """Type of intelligence output produced."""

    DASHBOARD = "DASHBOARD"
    EXPLAINABILITY = "EXPLAINABILITY"
    SIMULATION = "SIMULATION"
    BENCHMARK = "BENCHMARK"
    TREND = "TREND"
    FORECAST = "FORECAST"
    POLICY_DIFF = "POLICY_DIFF"
    CONFIDENCE = "CONFIDENCE"
    STATISTICS = "STATISTICS"


# Terminal simulation states (no further transitions possible)
TERMINAL_SIMULATION_STATES: frozenset[SimulationState] = frozenset(
    {
        SimulationState.COMPLETE,
        SimulationState.FAILED,
        SimulationState.ARCHIVED,
    }
)

# Mutable policy lifecycle states (editing allowed)
MUTABLE_POLICY_STATES: frozenset[PolicyLifecycleState] = frozenset(
    {
        PolicyLifecycleState.DRAFT,
        PolicyLifecycleState.REVIEW,
    }
)
