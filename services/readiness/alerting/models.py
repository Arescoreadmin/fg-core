"""Enterprise Readiness Alerting — domain models.

All types are:
  - Pure Python. No I/O. No randomness. No SQLAlchemy.
  - Frozen after construction (immutable).
  - Deterministic: identical governance state → identical canonical form.
  - Tenant-safe: all alert instances carry tenant_id.
  - Export-safe: no secrets, vectors, raw evidence bodies, provider payloads,
    prompts, PHI, or internal topology.

Alert certainty contract:
  - Mirrors DriftCertainty — never collapses unverifiable/unknown states.
  - Alert certainty is derived from source DriftEvent certainty.
  - CONFIRMED alert certainty requires CONFIRMED drift certainty.

Alert lifecycle contract:
  - AlertLifecycleState transitions are governed by an explicit FSM.
  - CRITICAL and BLOCKING alerts MUST NOT be silently suppressed.
  - Suppressed alerts remain visible as SUPPRESSED (never erased).
  - All lifecycle transitions produce an immutable AlertLifecycleTransition record.

Replay contract:
  - AlertInstance carries alert_generation_version and escalation_policy_version.
  - Historical alerts remain reconstructable against the version that produced them.
  - replay_contract_metadata carries all version pins for forensic replay.

Severity contract:
  - Alert severity derives from source drift severity (never downgraded).
  - CRITICAL and BLOCKING alerts are never suppressed by the engine.
  - Severity is deterministic given source drift state.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from services.readiness.monitoring.models import (
    DriftSnapshot,
    MonitoringEvaluationContext,
)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AlertSeverity(str, Enum):
    """Deterministic severity classification for an alert instance.

    Maps directly from DriftSeverity — never downgraded.
    """

    INFORMATIONAL = "informational"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"
    BLOCKING = "blocking"


_ALERT_SEVERITY_ORDER: dict[AlertSeverity, int] = {
    AlertSeverity.INFORMATIONAL: 0,
    AlertSeverity.LOW: 1,
    AlertSeverity.MODERATE: 2,
    AlertSeverity.HIGH: 3,
    AlertSeverity.CRITICAL: 4,
    AlertSeverity.BLOCKING: 5,
}


def alert_severity_rank(s: AlertSeverity) -> int:
    return _ALERT_SEVERITY_ORDER[s]


class AlertLifecycleState(str, Enum):
    """Explicit alert lifecycle states.

    ACTIVE:        Alert is open and requires attention.
    ACKNOWLEDGED:  Alert has been seen by an operator; still requires action.
    SUPPRESSED:    Alert is suppressed per suppression record; remains visible.
    RESOLVED:      Alert has been remediated and closed.
    EXPIRED:       Alert cooldown window expired without resolution.
    ESCALATED:     Alert has been escalated per escalation policy.
    """

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    EXPIRED = "expired"
    ESCALATED = "escalated"


class AlertCertainty(str, Enum):
    """Explicit certainty classification for an alert.

    Mirrors DriftCertainty — never collapses unverifiable states.
    """

    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    UNVERIFIABLE = "unverifiable"
    INCOMPLETE_EVALUATION = "incomplete_evaluation"
    DEGRADED_VISIBILITY = "degraded_visibility"
    MONITORING_SOURCE_FAILURE = "monitoring_source_failure"
    STALE_MONITORING_STATE = "stale_monitoring_state"
    UNKNOWN = "unknown"


class AlertRuleClass(str, Enum):
    """Classification of an alert rule by governance domain."""

    PROVENANCE = "provenance"
    PROVIDER = "provider"
    GROUNDING = "grounding"
    RETRIEVAL = "retrieval"
    AUDIT = "audit"
    POLICY = "policy"
    GOVERNANCE = "governance"
    RUNTIME = "runtime"
    REPLAY = "replay"
    SOVEREIGNTY = "sovereignty"
    MONITORING_VISIBILITY = "monitoring_visibility"


# ---------------------------------------------------------------------------
# Alert rule — deterministic configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertRule:
    """Immutable alert rule configuration.

    rule_id is a stable identifier; never changes meaning once published.
    severity_threshold is the minimum DriftSeverity that triggers this rule.
    cooldown_window_minutes controls deduplication window.
    burst_ceiling caps occurrences per cooldown window.
    """

    rule_id: str
    rule_class: AlertRuleClass
    name: str
    severity_threshold: AlertSeverity
    certainty_threshold: AlertCertainty
    cooldown_window_minutes: int
    burst_ceiling: int
    description: str
    alert_generation_version: str
    escalation_policy_version: str


# ---------------------------------------------------------------------------
# Alert instance — immutable output of the alerting engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertInstance:
    """Immutable, audit-safe alert instance.

    alert_instance_id is deterministic: identical rule_id + source_run_id +
    source_event_fingerprint + tenant_id → identical instance_id.

    alert_fingerprint is deterministic: identical rule_id + source_event_fingerprint
    + tenant_id + assessment_id → identical fingerprint. Used for deduplication.

    No prompts, vectors, embeddings, provider payloads, secrets, PHI, or
    raw evidence bodies appear in any field.
    """

    alert_instance_id: str
    alert_fingerprint: str
    alert_rule_id: str
    alert_rule_class: AlertRuleClass
    source_monitoring_run_id: str
    source_drift_event_fingerprint: str
    source_drift_snapshot_id: str
    tenant_id: str
    assessment_id: Optional[str]
    severity: AlertSeverity
    certainty: AlertCertainty
    lifecycle_state: AlertLifecycleState
    affected_scope: str
    affected_control_ids: tuple[str, ...]
    affected_evidence_ids: tuple[str, ...]
    affected_framework_ids: tuple[str, ...]
    alert_detail: str  # export-safe human-readable summary
    generated_at_iso: str
    evaluation_window_start_iso: str
    evaluation_window_end_iso: str
    alert_generation_version: str
    escalation_policy_version: str
    replay_contract_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Lifecycle transition — immutable audit record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertLifecycleTransition:
    """Immutable record of an alert state transition.

    transition_id is deterministic: identical alert_instance_id + from_state +
    to_state + transitioned_at_iso → identical transition_id.
    """

    transition_id: str
    alert_instance_id: str
    tenant_id: str
    from_state: AlertLifecycleState
    to_state: AlertLifecycleState
    actor: str
    reason: str
    transitioned_at_iso: str
    replay_safe_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Suppression record — immutable audit record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertSuppressionRecord:
    """Immutable record of an alert suppression.

    suppression_id is deterministic: identical alert_instance_id + actor + suppressed_at_iso
    → identical suppression_id.

    Suppressed alerts remain visible as SUPPRESSED. Suppressions expire explicitly.
    No permanent hidden suppression.
    """

    suppression_id: str
    alert_instance_id: str
    tenant_id: str
    suppression_reason: str
    suppression_actor: str
    suppression_source: str  # e.g. "operator", "policy_engine", "automation"
    suppressed_at_iso: str
    expires_at_iso: Optional[str]  # None = no expiration (explicit policy)
    suppression_lineage_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Escalation record — immutable audit record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertEscalationRecord:
    """Immutable record of an alert escalation.

    escalation_id is deterministic: identical alert_instance_id + escalation_target_class
    + escalated_at_iso → identical escalation_id.
    """

    escalation_id: str
    alert_instance_id: str
    tenant_id: str
    escalation_target_class: (
        str  # e.g. "soc", "operator", "compliance_team", "regulator"
    )
    escalation_routing_rule: str
    severity_at_escalation: AlertSeverity
    escalated_at_iso: str
    escalation_policy_version: str
    escalation_lineage_metadata: tuple[tuple[str, str], ...]


# ---------------------------------------------------------------------------
# Deduplication record — explainable dedup state
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertDeduplicationRecord:
    """Explainable deduplication record for a dedup window.

    dedup_window_key = (alert_fingerprint, tenant_id).
    occurrence_count reflects total seen; suppressed_count reflects cooldown suppression.
    """

    dedup_window_key: str
    alert_rule_id: str
    tenant_id: str
    first_seen_iso: str
    last_seen_iso: str
    occurrence_count: int
    suppressed_count: int
    window_start_iso: str
    window_end_iso: str


# ---------------------------------------------------------------------------
# Engine input / output
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertEngineInput:
    """Input to the alerting engine.

    context provides temporal boundaries and version pins from the monitoring run.
    drift_snapshot is the immutable output of the monitoring engine.
    """

    context: MonitoringEvaluationContext
    drift_snapshot: DriftSnapshot


@dataclass(frozen=True)
class AlertEngineOutput:
    """Immutable output of a single alerting engine run."""

    run_id: str
    alerts: tuple[AlertInstance, ...]
    dedup_records: tuple[AlertDeduplicationRecord, ...]
    generation_timestamp_iso: str
    total_alerts_generated: int
    total_alerts_deduplicated: int
    total_alerts_suppressed: int


# ---------------------------------------------------------------------------
# Alert run record — domain object for persistence layer
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertRunRecord:
    """Domain object returned by AlertingStore — no SQLAlchemy types."""

    run_id: str
    tenant_id: str
    source_monitoring_run_id: str
    assessment_id: Optional[str]
    alert_generation_version: str
    escalation_policy_version: str
    total_alerts_generated: int
    total_alerts_deduplicated: int
    total_alerts_suppressed: int
    generation_timestamp_iso: str
    alert_run_output_json: str  # stored internally; never exposed in API responses
    completed: bool
    error_summary: Optional[str]
    created_at_iso: str
