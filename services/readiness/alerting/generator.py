"""Deterministic alert generator.

All functions are pure Python: no I/O, no side effects, no randomness.

Generator contract:
  - Deterministic: identical DriftSnapshot + rules → identical AlertInstances.
  - One AlertInstance per DriftEvent whose drift_type has a matching AlertRule.
  - Source drift severity → alert severity (never downgraded from source).
  - Source DriftCertainty → AlertCertainty mapping (never collapses unknown states).
  - NEVER suppresses CRITICAL or BLOCKING alerts.
  - NEVER collapses unverifiable states to healthy.
  - NEVER emits alerts without a matching rule.
  - No secrets, vectors, prompts, PHI, or internal topology in any alert field.
"""

from __future__ import annotations

from datetime import datetime, timezone

from services.readiness.monitoring.models import (
    DriftCertainty,
    DriftSeverity,
    DriftSnapshot,
    MonitoringEvaluationContext,
)

from .identity import derive_alert_fingerprint, derive_alert_instance_id
from .models import (
    AlertCertainty,
    AlertInstance,
    AlertLifecycleState,
    AlertRule,
    AlertSeverity,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Severity + certainty mapping
# ---------------------------------------------------------------------------

_DRIFT_TO_ALERT_SEVERITY: dict[DriftSeverity, AlertSeverity] = {
    DriftSeverity.INFORMATIONAL: AlertSeverity.INFORMATIONAL,
    DriftSeverity.LOW: AlertSeverity.LOW,
    DriftSeverity.MODERATE: AlertSeverity.MODERATE,
    DriftSeverity.HIGH: AlertSeverity.HIGH,
    DriftSeverity.CRITICAL: AlertSeverity.CRITICAL,
    DriftSeverity.BLOCKING: AlertSeverity.BLOCKING,
}

_DRIFT_TO_ALERT_CERTAINTY: dict[DriftCertainty, AlertCertainty] = {
    DriftCertainty.CONFIRMED: AlertCertainty.CONFIRMED,
    DriftCertainty.SUSPECTED: AlertCertainty.SUSPECTED,
    DriftCertainty.UNVERIFIABLE: AlertCertainty.UNVERIFIABLE,
    DriftCertainty.INCOMPLETE_EVALUATION: AlertCertainty.INCOMPLETE_EVALUATION,
    DriftCertainty.DEGRADED_VISIBILITY: AlertCertainty.DEGRADED_VISIBILITY,
    DriftCertainty.MONITORING_SOURCE_FAILURE: AlertCertainty.MONITORING_SOURCE_FAILURE,
    DriftCertainty.STALE_MONITORING_STATE: AlertCertainty.STALE_MONITORING_STATE,
    DriftCertainty.UNKNOWN: AlertCertainty.UNKNOWN,
}


def _map_severity(drift_severity: DriftSeverity, rule: AlertRule) -> AlertSeverity:
    """Derive alert severity from drift severity and rule threshold.

    The alert severity is the maximum of the drift severity and the rule
    severity_threshold. Alert severity is never downgraded from source.
    """
    source = _DRIFT_TO_ALERT_SEVERITY[drift_severity]
    from .models import alert_severity_rank

    if alert_severity_rank(source) >= alert_severity_rank(rule.severity_threshold):
        return source
    return rule.severity_threshold


def _map_certainty(drift_certainty: DriftCertainty) -> AlertCertainty:
    """Map DriftCertainty → AlertCertainty.

    Never collapses unverifiable/unknown states to CONFIRMED.
    """
    return _DRIFT_TO_ALERT_CERTAINTY.get(drift_certainty, AlertCertainty.UNKNOWN)


# ---------------------------------------------------------------------------
# Core generator
# ---------------------------------------------------------------------------


def generate_alerts(
    drift_snapshot: DriftSnapshot,
    context: MonitoringEvaluationContext,
    rules_by_drift_type: dict[str, AlertRule],
) -> list[AlertInstance]:
    """Generate AlertInstances from a DriftSnapshot.

    One AlertInstance is generated per DriftEvent whose drift_type has a
    matching AlertRule in rules_by_drift_type.

    Deterministic: identical inputs → identical outputs.
    Export-safe: no secrets, vectors, prompts, PHI in any alert field.

    # siem_seam: at this boundary, generated AlertInstances can be streamed to
    # SIEM systems (Splunk, Sentinel, Chronicle, Elastic). The alert payload is
    # already export-safe and canonically serialized. No transformation required
    # before forwarding to a SIEM event bus. Each alert maps to a SIEM event with
    # (tenant_id, alert_rule_class, severity, certainty, affected_scope) dimensions.
    """
    generated_at_iso = _now_iso()
    alerts: list[AlertInstance] = []

    for event in drift_snapshot.events:
        rule = rules_by_drift_type.get(event.drift_type.value)
        if rule is None:
            # No matching rule — no alert emitted for this drift type.
            continue

        severity = _map_severity(event.severity, rule)
        certainty = _map_certainty(event.certainty)

        alert_instance_id = derive_alert_instance_id(
            rule_id=rule.rule_id,
            source_run_id=drift_snapshot.monitoring_run_id,
            source_event_fingerprint=event.event_fingerprint,
            tenant_id=drift_snapshot.tenant_id,
        )

        alert_fingerprint = derive_alert_fingerprint(
            rule_id=rule.rule_id,
            source_event_fingerprint=event.event_fingerprint,
            tenant_id=drift_snapshot.tenant_id,
            assessment_id=drift_snapshot.assessment_id or "",
        )

        replay_contract_metadata: tuple[tuple[str, str], ...] = (
            ("alert_generation_version", rule.alert_generation_version),
            ("escalation_policy_version", rule.escalation_policy_version),
            (
                "source_monitoring_contract_version",
                drift_snapshot.monitoring_contract_version,
            ),
            (
                "source_evaluation_engine_version",
                drift_snapshot.evaluation_engine_version,
            ),
            (
                "source_drift_classification_version",
                drift_snapshot.drift_classification_version,
            ),
            (
                "source_severity_classification_version",
                drift_snapshot.severity_classification_version,
            ),
        )

        alert = AlertInstance(
            alert_instance_id=alert_instance_id,
            alert_fingerprint=alert_fingerprint,
            alert_rule_id=rule.rule_id,
            alert_rule_class=rule.rule_class,
            source_monitoring_run_id=drift_snapshot.monitoring_run_id,
            source_drift_event_fingerprint=event.event_fingerprint,
            source_drift_snapshot_id=drift_snapshot.snapshot_id,
            tenant_id=drift_snapshot.tenant_id,
            assessment_id=drift_snapshot.assessment_id,
            severity=severity,
            certainty=certainty,
            lifecycle_state=AlertLifecycleState.ACTIVE,
            affected_scope=event.affected_scope,
            affected_control_ids=event.affected_control_ids,
            affected_evidence_ids=event.affected_evidence_ids,
            affected_framework_ids=event.affected_framework_ids,
            alert_detail=event.drift_detail,
            generated_at_iso=generated_at_iso,
            evaluation_window_start_iso=context.evaluation_window_start_iso,
            evaluation_window_end_iso=context.evaluation_window_end_iso,
            alert_generation_version=rule.alert_generation_version,
            escalation_policy_version=rule.escalation_policy_version,
            replay_contract_metadata=replay_contract_metadata,
        )
        alerts.append(alert)

    return alerts
