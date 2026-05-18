"""Readiness Alerting API — governance alert generation and lifecycle endpoints.

All routes require control-plane:read scope for reads, control-plane:write for mutations.
Tenant isolation: tenant_id is always resolved from auth context, never from request body.

Routes:
  POST /control-plane/readiness/alerting/runs
      Trigger alert generation from a monitoring run_id.
      Idempotent: identical monitoring run_id → same alert run_id.

  GET  /control-plane/readiness/alerting/runs
      List alert runs for the authenticated tenant.

  GET  /control-plane/readiness/alerting/runs/{run_id}
      Get a single alert run by id.

  GET  /control-plane/readiness/alerting/alerts
      List alerts for tenant (filter by lifecycle_state, severity, assessment_id).

  GET  /control-plane/readiness/alerting/alerts/{alert_instance_id}
      Get a single alert by id.

  POST /control-plane/readiness/alerting/alerts/{alert_instance_id}/lifecycle
      Apply a lifecycle transition to an alert.

  POST /control-plane/readiness/alerting/alerts/{alert_instance_id}/suppress
      Create a suppression record for an alert.

Security invariants:
  - tenant_id resolved from auth context only — never from request body/query.
  - No secrets, credentials, raw evidence bodies, vectors, prompts, or PHI in responses.
  - All alert records are tenant-scoped; cross-tenant access returns 404.
  - alert_run_output_json stored internally; API exposes deserialized export-safe dict.
  - snapshot_json never appears in any response payload.

# siem_seam: alert generation results are dispatched to SIEM systems at the store boundary.
# Downstream consumers: Splunk, Sentinel, Chronicle, Elastic. No transformation required —
# alert payloads are already export-safe and canonically serialized.

# escalation_routing_seam: lifecycle transitions to ESCALATED state trigger SOC workflow
# dispatch at the store boundary. Downstream consumers: PagerDuty, Jira, ServiceNow.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.readiness.alerting import (
    AlertingEngine,
    AlertingStore,
    AlertEngineInput,
    AlertInstance,
    AlertLifecycleState,
    AlertNotFound,
    AlertRunNotFound,
    AlertTenantIsolationError,
    InvalidAlertTransition,
    create_suppression,
)
from services.readiness.alerting.lifecycle import apply_transition
from services.readiness.alerting.models import AlertRunRecord
from services.readiness.alerting.serialization import alert_output_to_json
from services.readiness.monitoring import (
    MonitoringRunNotFound,
    MonitoringRunStore,
    MonitoringRunTenantIsolationError,
)
from services.readiness.monitoring.models import MonitoringEvaluationContext

logger = logging.getLogger("frostgate.api.readiness_alerting")

router = APIRouter(tags=["readiness"])

_alerting_store = AlertingStore()
_alert_engine = AlertingEngine()
_monitoring_store = MonitoringRunStore()

ALERT_GENERATION_VERSION = "1.0"
ESCALATION_POLICY_VERSION = "1.0"


def _tenant_from_auth(request: Request) -> Optional[str]:
    auth = getattr(request.state, "auth", None) or getattr(
        request.state, "api_key", None
    )
    return getattr(getattr(request, "state", None), "tenant_id", None) or getattr(
        auth, "tenant_id", None
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _window_iso(hours_back: int) -> tuple[str, str]:
    from datetime import timedelta

    now = datetime.now(timezone.utc)
    # Bucket end to the hour boundary so retries within the same hour derive an
    # identical run_id and hit the idempotency path rather than creating duplicates.
    bucketed_end = now.replace(minute=0, second=0, microsecond=0)
    start = bucketed_end - timedelta(hours=hours_back)
    return start.isoformat(), bucketed_end.isoformat()


def _derive_alert_run_id(source_monitoring_run_id: str, tenant_id: str) -> str:
    """Derive a deterministic alert run ID from the monitoring run and tenant."""
    payload = json.dumps(
        {
            "source_monitoring_run_id": source_monitoring_run_id,
            "tenant_id": tenant_id,
            "alert_generation_version": ALERT_GENERATION_VERSION,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class CreateAlertRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    monitoring_run_id: str = Field(
        ..., description="The monitoring run_id to generate alerts from."
    )


class AlertInstanceResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alert_instance_id: str
    alert_fingerprint: str
    alert_rule_id: str
    alert_rule_class: str
    source_monitoring_run_id: str
    source_drift_event_fingerprint: str
    source_drift_snapshot_id: str
    tenant_id: str
    assessment_id: Optional[str]
    severity: str
    certainty: str
    lifecycle_state: str
    affected_scope: str
    affected_control_ids: list[str]
    affected_evidence_ids: list[str]
    affected_framework_ids: list[str]
    alert_detail: str
    generated_at_iso: str
    evaluation_window_start_iso: str
    evaluation_window_end_iso: str
    alert_generation_version: str
    escalation_policy_version: str
    replay_contract_metadata: dict[str, str]

    @classmethod
    def from_domain(cls, alert: AlertInstance) -> "AlertInstanceResponse":
        return cls(
            alert_instance_id=alert.alert_instance_id,
            alert_fingerprint=alert.alert_fingerprint,
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
            affected_control_ids=list(alert.affected_control_ids),
            affected_evidence_ids=list(alert.affected_evidence_ids),
            affected_framework_ids=list(alert.affected_framework_ids),
            alert_detail=alert.alert_detail,
            generated_at_iso=alert.generated_at_iso,
            evaluation_window_start_iso=alert.evaluation_window_start_iso,
            evaluation_window_end_iso=alert.evaluation_window_end_iso,
            alert_generation_version=alert.alert_generation_version,
            escalation_policy_version=alert.escalation_policy_version,
            replay_contract_metadata={k: v for k, v in alert.replay_contract_metadata},
        )

    @classmethod
    def from_dict(cls, d: dict) -> "AlertInstanceResponse":
        return cls(
            alert_instance_id=d["alert_instance_id"],
            alert_fingerprint=d["alert_fingerprint"],
            alert_rule_id=d["alert_rule_id"],
            alert_rule_class=d["alert_rule_class"],
            source_monitoring_run_id=d["source_monitoring_run_id"],
            source_drift_event_fingerprint=d["source_drift_event_fingerprint"],
            source_drift_snapshot_id=d["source_drift_snapshot_id"],
            tenant_id=d["tenant_id"],
            assessment_id=d.get("assessment_id"),
            severity=d["severity"],
            certainty=d["certainty"],
            lifecycle_state=d["lifecycle_state"],
            affected_scope=d["affected_scope"],
            affected_control_ids=d.get("affected_control_ids", []),
            affected_evidence_ids=d.get("affected_evidence_ids", []),
            affected_framework_ids=d.get("affected_framework_ids", []),
            alert_detail=d["alert_detail"],
            generated_at_iso=d["generated_at_iso"],
            evaluation_window_start_iso=d["evaluation_window_start_iso"],
            evaluation_window_end_iso=d["evaluation_window_end_iso"],
            alert_generation_version=d["alert_generation_version"],
            escalation_policy_version=d["escalation_policy_version"],
            replay_contract_metadata=d.get("replay_contract_metadata", {}),
        )


class AlertRunResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

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
    completed: bool
    error_summary: Optional[str]
    created_at_iso: str
    alerts: list[AlertInstanceResponse]

    @classmethod
    def from_record(cls, record: AlertRunRecord) -> "AlertRunResponse":
        # Deserialize stored output to get alert list.
        # alert_run_output_json is NEVER exposed directly in the response.
        from services.readiness.alerting.serialization import alert_output_from_json

        output_dict = alert_output_from_json(record.alert_run_output_json)
        alerts = [
            AlertInstanceResponse.from_dict(a) for a in output_dict.get("alerts", [])
        ]
        return cls(
            run_id=record.run_id,
            tenant_id=record.tenant_id,
            source_monitoring_run_id=record.source_monitoring_run_id,
            assessment_id=record.assessment_id,
            alert_generation_version=record.alert_generation_version,
            escalation_policy_version=record.escalation_policy_version,
            total_alerts_generated=record.total_alerts_generated,
            total_alerts_deduplicated=record.total_alerts_deduplicated,
            total_alerts_suppressed=record.total_alerts_suppressed,
            generation_timestamp_iso=record.generation_timestamp_iso,
            completed=record.completed,
            error_summary=record.error_summary,
            created_at_iso=record.created_at_iso,
            alerts=alerts,
        )


class AlertRunSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    source_monitoring_run_id: str
    assessment_id: Optional[str]
    alert_generation_version: str
    escalation_policy_version: str
    total_alerts_generated: int
    total_alerts_deduplicated: int
    total_alerts_suppressed: int
    generation_timestamp_iso: str
    completed: bool
    created_at_iso: str

    @classmethod
    def from_record(cls, record: AlertRunRecord) -> "AlertRunSummaryResponse":
        return cls(
            run_id=record.run_id,
            source_monitoring_run_id=record.source_monitoring_run_id,
            assessment_id=record.assessment_id,
            alert_generation_version=record.alert_generation_version,
            escalation_policy_version=record.escalation_policy_version,
            total_alerts_generated=record.total_alerts_generated,
            total_alerts_deduplicated=record.total_alerts_deduplicated,
            total_alerts_suppressed=record.total_alerts_suppressed,
            generation_timestamp_iso=record.generation_timestamp_iso,
            completed=record.completed,
            created_at_iso=record.created_at_iso,
        )


class LifecycleTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_state: str = Field(..., description="Target lifecycle state.")
    actor: str = Field(..., description="Actor applying the transition.")
    reason: str = Field(..., description="Reason for the transition.")


class SuppressAlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(..., description="Reason for suppression.")
    actor: str = Field(..., description="Actor creating the suppression.")
    source: str = Field(
        "operator",
        description="Source of suppression (operator, policy_engine, automation).",
    )
    expires_at_iso: Optional[str] = Field(
        None,
        description="ISO 8601 expiration timestamp. None = policy-driven no-expiration.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/alerting/runs",
    dependencies=[Depends(require_scopes("control-plane:write"))],
    response_model=AlertRunResponse,
    status_code=201,
)
def create_alert_run(
    body: CreateAlertRunRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AlertRunResponse:
    """Trigger alert generation from an existing monitoring run.

    Idempotent: submitting the same monitoring_run_id twice returns the
    stored result rather than re-generating alerts.

    # siem_seam: on successful alert run creation, alerts can be dispatched to
    # SIEM systems at the store boundary. Payload is already export-safe.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "ALERTING_NO_TENANT",
                "Tenant context required for alert generation.",
            ),
        )

    monitoring_run_id = body.monitoring_run_id
    alert_run_id = _derive_alert_run_id(monitoring_run_id, tenant_id)

    # Idempotency: return stored result if this alert run_id already exists.
    try:
        existing = _alerting_store.get_alert_run(
            db, run_id=alert_run_id, tenant_id=tenant_id
        )
        return AlertRunResponse.from_record(existing)
    except AlertRunNotFound:
        pass

    # Load the monitoring run to get the drift snapshot.
    try:
        monitoring_record = _monitoring_store.get_run(
            db, run_id=monitoring_run_id, tenant_id=tenant_id
        )
    except MonitoringRunNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "MONITORING_RUN_NOT_FOUND",
                "Monitoring run not found.",
            ),
        )
    except MonitoringRunTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error(
                "MONITORING_RUN_NOT_FOUND",
                "Monitoring run not found.",
            ),
        )

    # Deserialize the drift snapshot from the monitoring record.
    from services.readiness.monitoring.serialization import snapshot_from_json

    snap_dict = snapshot_from_json(monitoring_record.snapshot_json)

    # Reconstruct the DriftSnapshot domain object.
    from services.readiness.monitoring.models import (
        DriftCertainty,
        DriftEvent,
        DriftSeverity,
        DriftSnapshot,
        DriftType,
    )

    events = []
    for ev in snap_dict.get("events", []):
        events.append(
            DriftEvent(
                event_fingerprint=ev["event_fingerprint"],
                drift_type=DriftType(ev["drift_type"]),
                severity=DriftSeverity(ev["severity"]),
                certainty=DriftCertainty(ev["certainty"]),
                affected_scope=ev["affected_scope"],
                affected_control_ids=tuple(ev.get("affected_control_ids", [])),
                affected_evidence_ids=tuple(ev.get("affected_evidence_ids", [])),
                affected_framework_ids=tuple(ev.get("affected_framework_ids", [])),
                drift_detail=ev["drift_detail"],
                monitoring_source=ev["monitoring_source"],
                evaluation_timestamp_iso=ev["evaluation_timestamp_iso"],
                temporal_boundary_start=ev["temporal_boundary_start"],
                temporal_boundary_end=ev["temporal_boundary_end"],
                provenance_metadata=tuple(
                    (k, v) for k, v in ev.get("provenance_metadata", {}).items()
                ),
            )
        )

    replay_meta = snap_dict.get("replay_contract_metadata", {})
    drift_snapshot = DriftSnapshot(
        snapshot_id=snap_dict["snapshot_id"],
        monitoring_run_id=snap_dict["monitoring_run_id"],
        evaluation_timestamp_iso=snap_dict["evaluation_timestamp_iso"],
        monitoring_contract_version=snap_dict.get("monitoring_contract_version", "1.0"),
        evaluation_engine_version=snap_dict.get("evaluation_engine_version", "1.0"),
        drift_classification_version=snap_dict.get(
            "drift_classification_version", "1.0"
        ),
        severity_classification_version=snap_dict.get(
            "severity_classification_version", "1.0"
        ),
        events=tuple(events),
        tenant_id=snap_dict["tenant_id"],
        assessment_id=snap_dict.get("assessment_id"),
        framework_ids=tuple(snap_dict.get("framework_ids", [])),
        eval_window_start_iso=snap_dict.get(
            "eval_window_start_iso", monitoring_record.eval_window_start_iso
        ),
        eval_window_end_iso=snap_dict.get(
            "eval_window_end_iso", monitoring_record.eval_window_end_iso
        ),
        evidence_freshness_window_days=snap_dict.get(
            "evidence_freshness_window_days", 30
        ),
        total_drift_events=snap_dict.get("total_drift_events", len(events)),
        critical_or_blocking_count=snap_dict.get("critical_or_blocking_count", 0),
        domains_evaluated=tuple(snap_dict.get("domains_evaluated", [])),
        replay_contract_metadata=tuple((k, v) for k, v in replay_meta.items()),
    )

    context = MonitoringEvaluationContext(
        tenant_id=tenant_id,
        evaluation_window_start_iso=monitoring_record.eval_window_start_iso,
        evaluation_window_end_iso=monitoring_record.eval_window_end_iso,
        evidence_freshness_window_days=snap_dict.get(
            "evidence_freshness_window_days", 30
        ),
        retrieval_degradation_window_hours=24,
        policy_drift_comparison_window_hours=24,
        audit_continuity_window_hours=24,
        runtime_governance_window_hours=24,
        monitoring_contract_version=monitoring_record.monitoring_contract_version,
        evaluation_engine_version=monitoring_record.evaluation_engine_version,
        drift_classification_version=snap_dict.get(
            "drift_classification_version", "1.0"
        ),
        severity_classification_version=snap_dict.get(
            "severity_classification_version", "1.0"
        ),
        assessment_id=monitoring_record.assessment_id,
    )

    engine_input = AlertEngineInput(
        context=context,
        drift_snapshot=drift_snapshot,
    )

    output = _alert_engine.generate(alert_run_id, engine_input)
    output_json = alert_output_to_json(output)

    record = _alerting_store.create_alert_run(
        db,
        run_id=alert_run_id,
        tenant_id=tenant_id,
        source_monitoring_run_id=monitoring_run_id,
        assessment_id=monitoring_record.assessment_id,
        alert_generation_version=ALERT_GENERATION_VERSION,
        escalation_policy_version=ESCALATION_POLICY_VERSION,
        total_alerts_generated=output.total_alerts_generated,
        total_alerts_deduplicated=output.total_alerts_deduplicated,
        total_alerts_suppressed=output.total_alerts_suppressed,
        generation_timestamp_iso=output.generation_timestamp_iso,
        alert_run_output_json=output_json,
        completed=True,
        error_summary=None,
    )

    # Write-once persist alert instances.
    _alerting_store.upsert_alerts(
        db,
        alerts=list(output.alerts),
        alert_run_id=alert_run_id,
    )

    db.commit()

    logger.info(
        "alert_run_created run_id=%s tenant=%s monitoring_run=%s "
        "alerts=%d dedup=%d suppressed=%d",
        alert_run_id,
        tenant_id,
        monitoring_run_id,
        output.total_alerts_generated,
        output.total_alerts_deduplicated,
        output.total_alerts_suppressed,
    )

    return AlertRunResponse.from_record(record)


@router.get(
    "/control-plane/readiness/alerting/runs",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_alert_runs(
    request: Request,
    assessment_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(auth_ctx_db_session),
) -> list[AlertRunSummaryResponse]:
    """List alert runs for the authenticated tenant."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    records = _alerting_store.list_alert_runs(
        db,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        limit=min(limit, 200),
        offset=offset,
    )
    return [AlertRunSummaryResponse.from_record(r) for r in records]


@router.get(
    "/control-plane/readiness/alerting/runs/{run_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    response_model=AlertRunResponse,
)
def get_alert_run(
    run_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AlertRunResponse:
    """Get a single alert run by its deterministic run_id."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    try:
        record = _alerting_store.get_alert_run(db, run_id=run_id, tenant_id=tenant_id)
    except AlertRunNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_RUN_NOT_FOUND", "Alert run not found."),
        )
    except AlertTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_RUN_NOT_FOUND", "Alert run not found."),
        )

    return AlertRunResponse.from_record(record)


@router.get(
    "/control-plane/readiness/alerting/alerts",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_alerts(
    request: Request,
    lifecycle_state: Optional[str] = None,
    severity: Optional[str] = None,
    assessment_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(auth_ctx_db_session),
) -> list[AlertInstanceResponse]:
    """List alerts for the authenticated tenant.

    Supports filtering by lifecycle_state, severity, and assessment_id.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    alerts = _alerting_store.list_alerts(
        db,
        tenant_id=tenant_id,
        lifecycle_state=lifecycle_state,
        severity=severity,
        assessment_id=assessment_id,
        limit=min(limit, 200),
        offset=offset,
    )
    return [AlertInstanceResponse.from_domain(a) for a in alerts]


@router.get(
    "/control-plane/readiness/alerting/alerts/{alert_instance_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    response_model=AlertInstanceResponse,
)
def get_alert(
    alert_instance_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> AlertInstanceResponse:
    """Get a single alert by its deterministic alert_instance_id."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    try:
        alert = _alerting_store.get_alert(
            db, alert_instance_id=alert_instance_id, tenant_id=tenant_id
        )
    except AlertNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )
    except AlertTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )

    return AlertInstanceResponse.from_domain(alert)


@router.post(
    "/control-plane/readiness/alerting/alerts/{alert_instance_id}/lifecycle",
    dependencies=[Depends(require_scopes("control-plane:write"))],
    status_code=200,
)
def apply_alert_lifecycle_transition(
    alert_instance_id: str,
    body: LifecycleTransitionRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict:
    """Apply a lifecycle transition to an alert.

    Returns the transition record. Raises 422 for invalid transitions.
    Cross-tenant access returns 404.

    # escalation_routing_seam: ESCALATED transitions dispatch to SOC/Jira/ServiceNow
    # at the store boundary.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    try:
        alert = _alerting_store.get_alert(
            db, alert_instance_id=alert_instance_id, tenant_id=tenant_id
        )
    except AlertNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )
    except AlertTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )

    try:
        to_state = AlertLifecycleState(body.to_state)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "INVALID_LIFECYCLE_STATE",
                f"Invalid lifecycle state: {body.to_state}",
            ),
        )

    now_iso = _now_iso()
    try:
        transition = apply_transition(
            alert=alert,
            from_state=alert.lifecycle_state,
            to_state=to_state,
            actor=body.actor,
            reason=body.reason,
            timestamp_iso=now_iso,
        )
    except InvalidAlertTransition as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error("INVALID_ALERT_TRANSITION", str(exc)),
        )

    # Update mutable lifecycle state.
    _alerting_store.update_alert_lifecycle_state(
        db,
        alert_instance_id=alert_instance_id,
        tenant_id=tenant_id,
        new_state=to_state.value,
    )

    # Append immutable transition record.
    _alerting_store.record_lifecycle_transition(db, transition=transition)

    db.commit()

    logger.info(
        "alert_lifecycle_transition alert_id=%s tenant=%s %s→%s actor=%s",
        alert_instance_id,
        tenant_id,
        alert.lifecycle_state.value,
        to_state.value,
        body.actor,
    )

    return {
        "transition_id": transition.transition_id,
        "alert_instance_id": transition.alert_instance_id,
        "from_state": transition.from_state.value,
        "to_state": transition.to_state.value,
        "actor": transition.actor,
        "reason": transition.reason,
        "transitioned_at_iso": transition.transitioned_at_iso,
    }


@router.post(
    "/control-plane/readiness/alerting/alerts/{alert_instance_id}/suppress",
    dependencies=[Depends(require_scopes("control-plane:write"))],
    status_code=201,
)
def suppress_alert(
    alert_instance_id: str,
    body: SuppressAlertRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> dict:
    """Create a suppression record for an alert.

    CRITICAL and BLOCKING alerts cannot be suppressed — returns 422.
    Returns the suppression record.

    # signed_attestation_seam: suppression records can be cryptographically signed
    # for regulator-grade governance attestation at this boundary.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("ALERTING_NO_TENANT", "Tenant context required."),
        )

    try:
        alert = _alerting_store.get_alert(
            db, alert_instance_id=alert_instance_id, tenant_id=tenant_id
        )
    except AlertNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )
    except AlertTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("ALERT_NOT_FOUND", "Alert not found."),
        )

    # CRITICAL and BLOCKING alerts cannot be suppressed.
    from services.readiness.alerting.models import AlertSeverity

    if alert.severity in {AlertSeverity.CRITICAL, AlertSeverity.BLOCKING}:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "ALERT_SUPPRESSION_FORBIDDEN",
                f"Alerts with severity {alert.severity.value} cannot be suppressed.",
            ),
        )

    now_iso = _now_iso()

    # Validate and apply the FSM transition BEFORE writing any records.
    # If the alert is in a terminal or non-suppressible state (e.g. RESOLVED,
    # ESCALATED), reject with 422 rather than persisting a misleading suppression
    # row and then silently swallowing the InvalidAlertTransition.
    try:
        transition = apply_transition(
            alert=alert,
            from_state=alert.lifecycle_state,
            to_state=AlertLifecycleState.SUPPRESSED,
            actor=body.actor,
            reason=body.reason,
            timestamp_iso=now_iso,
        )
    except InvalidAlertTransition as exc:
        raise HTTPException(
            status_code=422,
            detail=api_error(
                "INVALID_ALERT_TRANSITION",
                f"Cannot suppress alert in state {alert.lifecycle_state.value}: {exc}",
            ),
        )

    suppression = create_suppression(
        alert_instance_id=alert_instance_id,
        tenant_id=tenant_id,
        reason=body.reason,
        actor=body.actor,
        source=body.source,
        now_iso=now_iso,
        expires_at_iso=body.expires_at_iso,
    )

    _alerting_store.record_suppression(db, suppression=suppression)
    _alerting_store.update_alert_lifecycle_state(
        db,
        alert_instance_id=alert_instance_id,
        tenant_id=tenant_id,
        new_state=AlertLifecycleState.SUPPRESSED.value,
    )
    _alerting_store.record_lifecycle_transition(db, transition=transition)

    db.commit()

    logger.info(
        "alert_suppressed alert_id=%s tenant=%s actor=%s expires=%s",
        alert_instance_id,
        tenant_id,
        body.actor,
        body.expires_at_iso,
    )

    return {
        "suppression_id": suppression.suppression_id,
        "alert_instance_id": suppression.alert_instance_id,
        "suppression_reason": suppression.suppression_reason,
        "suppression_actor": suppression.suppression_actor,
        "suppression_source": suppression.suppression_source,
        "suppressed_at_iso": suppression.suppressed_at_iso,
        "expires_at_iso": suppression.expires_at_iso,
    }


# regulator_export_seam: GET /control-plane/readiness/alerting/alerts/{alert_instance_id}/export
# Signed governance export for regulator/auditor pipelines goes here.
# The alert payload is already canonical JSON; wrapping with a detached signature
# produces a self-verifying governance artifact. This is the next integration point
# for enterprise compliance attestation.

# longitudinal_intelligence_seam: GET /control-plane/readiness/alerting/analytics
# Alert trend analysis, MTTR computation, recurrence scoring, and chronic degradation
# detection extend from the alert history stored in readiness_alert_instances.
# The full alert history by (tenant_id, assessment_id) is the input for governance
# health scoring and alert fatigue analysis.
