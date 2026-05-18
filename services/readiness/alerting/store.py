"""Alerting persistence store.

All methods take a SQLAlchemy Session. No module-level state. No side effects beyond DB.

Tenant isolation contract:
  - All read methods (get_alert_run, list_alert_runs, list_alerts, get_alert) filter by tenant_id.
  - Cross-tenant access returns None / empty list (no disclosure).
  - All create methods record tenant_id from the governance context.

Immutability contract:
  - Alert runs and alert instances are write-once; no UPDATE methods on records.
  - Lifecycle transitions, suppressions, and escalations are append-only.
  - Historical records remain reconstructable.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from .models import (
    AlertEscalationRecord,
    AlertInstance,
    AlertLifecycleState,
    AlertLifecycleTransition,
    AlertRunRecord,
    AlertSeverity,
    AlertSuppressionRecord,
)

logger = logging.getLogger("frostgate.readiness.alerting.store")


class AlertRunNotFound(Exception):
    pass


class AlertNotFound(Exception):
    pass


class AlertTenantIsolationError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AlertingStore:
    """Write-once persistence for immutable alerting records."""

    # -----------------------------------------------------------------------
    # Alert run methods
    # -----------------------------------------------------------------------

    def create_alert_run(
        self,
        db: Session,
        *,
        run_id: str,
        tenant_id: str,
        source_monitoring_run_id: str,
        assessment_id: Optional[str],
        alert_generation_version: str,
        escalation_policy_version: str,
        total_alerts_generated: int,
        total_alerts_deduplicated: int,
        total_alerts_suppressed: int,
        generation_timestamp_iso: str,
        alert_run_output_json: str,
        completed: bool,
        error_summary: Optional[str],
    ) -> AlertRunRecord:
        from api.db_models_alerting import AlertRunModel

        now = _now()
        row = AlertRunModel(
            run_id=run_id,
            tenant_id=tenant_id,
            source_monitoring_run_id=source_monitoring_run_id,
            assessment_id=assessment_id,
            alert_generation_version=alert_generation_version,
            escalation_policy_version=escalation_policy_version,
            total_alerts_generated=total_alerts_generated,
            total_alerts_deduplicated=total_alerts_deduplicated,
            total_alerts_suppressed=total_alerts_suppressed,
            generation_timestamp_iso=generation_timestamp_iso,
            alert_run_output_json=alert_run_output_json,
            completed=completed,
            error_summary=error_summary,
            created_at=now,
        )
        db.add(row)
        db.flush()
        # siem_seam: alert run created — dispatch to SIEM event bus here.
        # The alert_run_output_json is already export-safe and canonical.
        # siem_seam: Splunk/Sentinel/Chronicle/Elastic dispatch after flush.
        return self._run_to_domain(row)

    def get_alert_run(
        self, db: Session, *, run_id: str, tenant_id: str
    ) -> AlertRunRecord:
        from api.db_models_alerting import AlertRunModel

        row = db.query(AlertRunModel).filter_by(run_id=run_id).first()
        if row is None:
            raise AlertRunNotFound(run_id)
        if row.tenant_id != tenant_id:
            raise AlertTenantIsolationError(run_id)
        return self._run_to_domain(row)

    def list_alert_runs(
        self,
        db: Session,
        *,
        tenant_id: str,
        assessment_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AlertRunRecord]:
        from api.db_models_alerting import AlertRunModel

        q = db.query(AlertRunModel).filter_by(tenant_id=tenant_id)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        rows = (
            q.order_by(AlertRunModel.created_at.desc())
            .limit(min(limit, 200))
            .offset(offset)
            .all()
        )
        return [self._run_to_domain(r) for r in rows]

    # -----------------------------------------------------------------------
    # Alert instance methods
    # -----------------------------------------------------------------------

    def upsert_alerts(
        self,
        db: Session,
        *,
        alerts: list[AlertInstance],
        alert_run_id: str,
    ) -> None:
        """Write alerts to the DB.

        Write-once: if alert_instance_id already exists (idempotent re-run),
        skip the insert rather than overwriting the existing record.
        """
        from api.db_models_alerting import AlertInstanceModel

        for alert in alerts:
            existing = (
                db.query(AlertInstanceModel)
                .filter_by(alert_instance_id=alert.alert_instance_id)
                .first()
            )
            if existing is not None:
                continue  # idempotent — already stored

            row = AlertInstanceModel(
                alert_instance_id=alert.alert_instance_id,
                alert_fingerprint=alert.alert_fingerprint,
                alert_run_id=alert_run_id,
                alert_rule_id=alert.alert_rule_id,
                alert_rule_class=alert.alert_rule_class.value,
                source_monitoring_run_id=alert.source_monitoring_run_id,
                source_drift_event_fingerprint=alert.source_drift_event_fingerprint,
                source_drift_snapshot_id=alert.source_drift_snapshot_id,
                tenant_id=alert.tenant_id,
                assessment_id=alert.assessment_id,
                severity=alert.severity.value,
                certainty=alert.certainty.value,
                lifecycle_state=alert.lifecycle_state.value,
                affected_scope=alert.affected_scope,
                affected_control_ids_json=json.dumps(
                    sorted(alert.affected_control_ids)
                ),
                affected_evidence_ids_json=json.dumps(
                    sorted(alert.affected_evidence_ids)
                ),
                affected_framework_ids_json=json.dumps(
                    sorted(alert.affected_framework_ids)
                ),
                alert_detail=alert.alert_detail,
                generated_at_iso=alert.generated_at_iso,
                evaluation_window_start_iso=alert.evaluation_window_start_iso,
                evaluation_window_end_iso=alert.evaluation_window_end_iso,
                alert_generation_version=alert.alert_generation_version,
                escalation_policy_version=alert.escalation_policy_version,
                replay_contract_metadata_json=json.dumps(
                    {k: v for k, v in alert.replay_contract_metadata},
                    sort_keys=True,
                ),
                created_at=_now(),
            )
            db.add(row)
        db.flush()

    def list_alerts(
        self,
        db: Session,
        *,
        tenant_id: str,
        lifecycle_state: Optional[str] = None,
        severity: Optional[str] = None,
        assessment_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AlertInstance]:
        from api.db_models_alerting import AlertInstanceModel

        q = db.query(AlertInstanceModel).filter_by(tenant_id=tenant_id)
        if lifecycle_state:
            q = q.filter_by(lifecycle_state=lifecycle_state)
        if severity:
            q = q.filter_by(severity=severity)
        if assessment_id:
            q = q.filter_by(assessment_id=assessment_id)
        rows = (
            q.order_by(AlertInstanceModel.created_at.desc())
            .limit(min(limit, 200))
            .offset(offset)
            .all()
        )
        return [self._alert_to_domain(r) for r in rows]

    def get_alert(
        self, db: Session, *, alert_instance_id: str, tenant_id: str
    ) -> AlertInstance:
        from api.db_models_alerting import AlertInstanceModel

        row = (
            db.query(AlertInstanceModel)
            .filter_by(alert_instance_id=alert_instance_id)
            .first()
        )
        if row is None:
            raise AlertNotFound(alert_instance_id)
        if row.tenant_id != tenant_id:
            raise AlertTenantIsolationError(alert_instance_id)
        return self._alert_to_domain(row)

    def update_alert_lifecycle_state(
        self,
        db: Session,
        *,
        alert_instance_id: str,
        tenant_id: str,
        new_state: str,
    ) -> None:
        """Update the mutable lifecycle_state of an alert instance.

        Lifecycle state is the only mutable field on an alert record.
        All other fields are immutable (write-once).
        """
        from api.db_models_alerting import AlertInstanceModel

        row = (
            db.query(AlertInstanceModel)
            .filter_by(alert_instance_id=alert_instance_id, tenant_id=tenant_id)
            .first()
        )
        if row is None:
            raise AlertNotFound(alert_instance_id)
        row.lifecycle_state = new_state
        db.flush()

    # -----------------------------------------------------------------------
    # Lifecycle transition methods (append-only)
    # -----------------------------------------------------------------------

    def record_lifecycle_transition(
        self,
        db: Session,
        *,
        transition: AlertLifecycleTransition,
    ) -> None:
        """Append an immutable lifecycle transition record."""
        from api.db_models_alerting import AlertLifecycleTransitionModel

        row = AlertLifecycleTransitionModel(
            transition_id=transition.transition_id,
            alert_instance_id=transition.alert_instance_id,
            tenant_id=transition.tenant_id,
            from_state=transition.from_state.value,
            to_state=transition.to_state.value,
            actor=transition.actor,
            reason=transition.reason,
            transitioned_at_iso=transition.transitioned_at_iso,
            replay_safe_metadata_json=json.dumps(
                {k: v for k, v in transition.replay_safe_metadata}, sort_keys=True
            ),
            created_at=_now(),
        )
        db.add(row)
        db.flush()
        # escalation_routing_seam: when to_state is ESCALATED, dispatch to SOC/Jira/
        # ServiceNow/PagerDuty escalation queues here. Payload includes
        # (tenant_id, alert_instance_id, severity, actor, reason, transitioned_at_iso).

    # -----------------------------------------------------------------------
    # Suppression methods (append-only)
    # -----------------------------------------------------------------------

    def record_suppression(
        self,
        db: Session,
        *,
        suppression: AlertSuppressionRecord,
    ) -> None:
        """Append an immutable suppression record."""
        from api.db_models_alerting import AlertSuppressionModel

        row = AlertSuppressionModel(
            suppression_id=suppression.suppression_id,
            alert_instance_id=suppression.alert_instance_id,
            tenant_id=suppression.tenant_id,
            suppression_reason=suppression.suppression_reason,
            suppression_actor=suppression.suppression_actor,
            suppression_source=suppression.suppression_source,
            suppressed_at_iso=suppression.suppressed_at_iso,
            expires_at_iso=suppression.expires_at_iso,
            suppression_lineage_metadata_json=json.dumps(
                {k: v for k, v in suppression.suppression_lineage_metadata},
                sort_keys=True,
            ),
            created_at=_now(),
        )
        db.add(row)
        db.flush()

    # -----------------------------------------------------------------------
    # Escalation methods (append-only)
    # -----------------------------------------------------------------------

    def record_escalation(
        self,
        db: Session,
        *,
        escalation: AlertEscalationRecord,
    ) -> None:
        """Append an immutable escalation record."""
        from api.db_models_alerting import AlertEscalationModel

        row = AlertEscalationModel(
            escalation_id=escalation.escalation_id,
            alert_instance_id=escalation.alert_instance_id,
            tenant_id=escalation.tenant_id,
            escalation_target_class=escalation.escalation_target_class,
            escalation_routing_rule=escalation.escalation_routing_rule,
            severity_at_escalation=escalation.severity_at_escalation.value,
            escalated_at_iso=escalation.escalated_at_iso,
            escalation_policy_version=escalation.escalation_policy_version,
            escalation_lineage_metadata_json=json.dumps(
                {k: v for k, v in escalation.escalation_lineage_metadata},
                sort_keys=True,
            ),
            created_at=_now(),
        )
        db.add(row)
        db.flush()

    # -----------------------------------------------------------------------
    # Domain conversion helpers
    # -----------------------------------------------------------------------

    def _run_to_domain(self, row) -> AlertRunRecord:  # type: ignore[no-untyped-def]
        return AlertRunRecord(
            run_id=row.run_id,
            tenant_id=row.tenant_id,
            source_monitoring_run_id=row.source_monitoring_run_id,
            assessment_id=row.assessment_id,
            alert_generation_version=row.alert_generation_version,
            escalation_policy_version=row.escalation_policy_version,
            total_alerts_generated=row.total_alerts_generated,
            total_alerts_deduplicated=row.total_alerts_deduplicated,
            total_alerts_suppressed=row.total_alerts_suppressed,
            generation_timestamp_iso=row.generation_timestamp_iso,
            alert_run_output_json=row.alert_run_output_json,
            completed=row.completed,
            error_summary=row.error_summary,
            created_at_iso=row.created_at.isoformat() if row.created_at else "",
        )

    def _alert_to_domain(self, row) -> AlertInstance:  # type: ignore[no-untyped-def]
        from .models import AlertCertainty, AlertRuleClass

        return AlertInstance(
            alert_instance_id=row.alert_instance_id,
            alert_fingerprint=row.alert_fingerprint,
            alert_rule_id=row.alert_rule_id,
            alert_rule_class=AlertRuleClass(row.alert_rule_class),
            source_monitoring_run_id=row.source_monitoring_run_id,
            source_drift_event_fingerprint=row.source_drift_event_fingerprint,
            source_drift_snapshot_id=row.source_drift_snapshot_id,
            tenant_id=row.tenant_id,
            assessment_id=row.assessment_id,
            severity=AlertSeverity(row.severity),
            certainty=AlertCertainty(row.certainty),
            lifecycle_state=AlertLifecycleState(row.lifecycle_state),
            affected_scope=row.affected_scope,
            affected_control_ids=tuple(
                json.loads(row.affected_control_ids_json or "[]")
            ),
            affected_evidence_ids=tuple(
                json.loads(row.affected_evidence_ids_json or "[]")
            ),
            affected_framework_ids=tuple(
                json.loads(row.affected_framework_ids_json or "[]")
            ),
            alert_detail=row.alert_detail,
            generated_at_iso=row.generated_at_iso,
            evaluation_window_start_iso=row.evaluation_window_start_iso,
            evaluation_window_end_iso=row.evaluation_window_end_iso,
            alert_generation_version=row.alert_generation_version,
            escalation_policy_version=row.escalation_policy_version,
            replay_contract_metadata=tuple(
                (k, v)
                for k, v in json.loads(
                    row.replay_contract_metadata_json or "{}"
                ).items()
            ),
        )
