"""Enterprise Readiness Alerting Engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Engine contract:
  - Deterministic: identical AlertEngineInput → identical AlertEngineOutput.
  - No side effects: the engine never mutates its inputs or any module-level state.
  - Replay-safe: all version pins are recorded in the output for forensic replay.
  - Fail-closed: an exception during generation → explicit MONITORING_VISIBILITY_DEGRADATION
    alert rather than corrupting the output or returning an empty result.
  - CRITICAL and BLOCKING alerts are NEVER suppressed or deduplicated away.
  - Uncertainty-explicit: unverifiable/unknown certainty states remain in AlertCertainty,
    never collapsed into a healthy or resolved state.

Architecture:
  1. Generator: DriftSnapshot → list[AlertInstance] (one per matched drift type)
  2. Deduplication: collapse duplicates by fingerprint+tenant, preserve highest severity
  3. Output assembly: AlertEngineOutput with version pins and dedup metadata
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .deduplication import deduplicate_alerts
from .generator import generate_alerts
from .identity import derive_alert_fingerprint, derive_alert_instance_id
from .models import (
    AlertCertainty,
    AlertEngineInput,
    AlertEngineOutput,
    AlertInstance,
    AlertLifecycleState,
    AlertRuleClass,
    AlertSeverity,
)
from .rules import (
    ALERT_GENERATION_VERSION,
    ESCALATION_POLICY_VERSION,
    RULES_BY_DRIFT_TYPE,
    _MONITORING_VISIBILITY_RULE,
)

logger = logging.getLogger("frostgate.readiness.alerting")

_VISIBILITY_DEGRADATION_DRIFT_TYPE = "monitoring_visibility_degradation"
_VISIBILITY_DEGRADATION_SCOPE = "alerting:engine"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _engine_failure_alert(
    run_id: str,
    tenant_id: str,
    assessment_id: Optional[str],
    snapshot_id: str,
    error_detail: str,
    generated_at_iso: str,
    eval_window_start_iso: str,
    eval_window_end_iso: str,
) -> AlertInstance:
    """Produce an explicit MONITORING_VISIBILITY_DEGRADATION alert on engine failure.

    Fail-closed: the engine never returns an empty result on error.
    """
    rule = _MONITORING_VISIBILITY_RULE
    # Use a stable synthetic fingerprint for the engine failure event
    synthetic_event_fingerprint = derive_alert_fingerprint(
        rule_id=rule.rule_id,
        source_event_fingerprint=f"engine_failure:{run_id}",
        tenant_id=tenant_id,
        assessment_id=assessment_id or "",
    )
    alert_instance_id = derive_alert_instance_id(
        rule_id=rule.rule_id,
        source_run_id=run_id,
        source_event_fingerprint=f"engine_failure:{run_id}",
        tenant_id=tenant_id,
    )
    return AlertInstance(
        alert_instance_id=alert_instance_id,
        alert_fingerprint=synthetic_event_fingerprint,
        alert_rule_id=rule.rule_id,
        alert_rule_class=AlertRuleClass.MONITORING_VISIBILITY,
        source_monitoring_run_id=run_id,
        source_drift_event_fingerprint=f"engine_failure:{run_id}",
        source_drift_snapshot_id=snapshot_id,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        severity=AlertSeverity.HIGH,
        certainty=AlertCertainty.MONITORING_SOURCE_FAILURE,
        lifecycle_state=AlertLifecycleState.ACTIVE,
        affected_scope=_VISIBILITY_DEGRADATION_SCOPE,
        affected_control_ids=(),
        affected_evidence_ids=(),
        affected_framework_ids=(),
        alert_detail=(
            f"Alerting engine encountered an error during generation. "
            f"Governance alert coverage may be degraded. "
            f"Detail: {error_detail}"
        ),
        generated_at_iso=generated_at_iso,
        evaluation_window_start_iso=eval_window_start_iso,
        evaluation_window_end_iso=eval_window_end_iso,
        alert_generation_version=ALERT_GENERATION_VERSION,
        escalation_policy_version=ESCALATION_POLICY_VERSION,
        replay_contract_metadata=(
            ("alert_generation_version", ALERT_GENERATION_VERSION),
            ("escalation_policy_version", ESCALATION_POLICY_VERSION),
            ("failure_scope", _VISIBILITY_DEGRADATION_SCOPE),
        ),
    )


class AlertingEngine:
    """Deterministic alerting engine — pure computation, no I/O.

    Call generate() with a run_id and AlertEngineInput.
    The engine calls the generator, deduplicates results, and assembles an
    immutable AlertEngineOutput.

    # longitudinal_intelligence_seam: at this boundary, historical alert runs
    # (queried by tenant_id, assessment_id) can be correlated for recurrence
    # scoring, alert fatigue detection, MTTR computation, and governance trend
    # analysis. The full alert history is the input; annotated AlertInstances
    # with recurrence metadata are the output. This enables governance health
    # scoring and chronic degradation detection.
    """

    def generate(
        self,
        run_id: str,
        engine_input: AlertEngineInput,
    ) -> AlertEngineOutput:
        """Generate alerts from a DriftSnapshot.

        Fail-closed: exceptions produce an explicit MONITORING_VISIBILITY_DEGRADATION
        alert rather than corrupting the output or returning empty.
        """
        generated_at_iso = _now_iso()
        snapshot = engine_input.drift_snapshot
        context = engine_input.context

        try:
            raw_alerts = generate_alerts(
                drift_snapshot=snapshot,
                context=context,
                rules_by_drift_type=RULES_BY_DRIFT_TYPE,
            )

            # Use per-rule cooldown and burst ceiling from the first matching alert.
            # For multi-rule dedup, we use the minimum cooldown and burst ceiling
            # from rules referenced in this batch.
            cooldown_minutes = 60  # default
            burst_ceiling = 10  # default
            if raw_alerts:
                # Use the tightest constraint across all rules present in this batch
                rules_seen = {a.alert_rule_id for a in raw_alerts}
                matched_rules = [
                    r for r in RULES_BY_DRIFT_TYPE.values() if r.rule_id in rules_seen
                ]
                if matched_rules:
                    cooldown_minutes = min(
                        r.cooldown_window_minutes for r in matched_rules
                    )
                    burst_ceiling = min(r.burst_ceiling for r in matched_rules)

            dedup_result = deduplicate_alerts(
                alerts=raw_alerts,
                cooldown_minutes=cooldown_minutes,
                burst_ceiling=burst_ceiling,
            )

            return AlertEngineOutput(
                run_id=run_id,
                alerts=dedup_result.alerts_after,
                dedup_records=dedup_result.dedup_records,
                generation_timestamp_iso=generated_at_iso,
                total_alerts_generated=dedup_result.total_before,
                total_alerts_deduplicated=dedup_result.total_deduplicated,
                total_alerts_suppressed=sum(
                    r.suppressed_count for r in dedup_result.dedup_records
                ),
            )

        except Exception as exc:
            logger.exception("AlertingEngine.generate() failed: %s", exc)
            failure_alert = _engine_failure_alert(
                run_id=run_id,
                tenant_id=snapshot.tenant_id,
                assessment_id=snapshot.assessment_id,
                snapshot_id=snapshot.snapshot_id,
                error_detail="Evaluation incomplete; alerting coverage is degraded.",
                generated_at_iso=generated_at_iso,
                eval_window_start_iso=context.evaluation_window_start_iso,
                eval_window_end_iso=context.evaluation_window_end_iso,
            )
            return AlertEngineOutput(
                run_id=run_id,
                alerts=(failure_alert,),
                dedup_records=(),
                generation_timestamp_iso=generated_at_iso,
                total_alerts_generated=1,
                total_alerts_deduplicated=0,
                total_alerts_suppressed=0,
            )
