"""Readiness Monitoring API — deterministic drift detection endpoints.

All routes require control-plane:read scope.
Tenant isolation: tenant_id is always resolved from auth context, never from request body.

Routes:
  POST /control-plane/readiness/monitoring/run
      Execute a deterministic monitoring evaluation for the authenticated tenant.
      Loads assessment data from DB, runs MonitoringEngine, persists immutable result.
      Idempotent: identical governance scope + evaluation window → same run_id.

  GET  /control-plane/readiness/monitoring/runs
      List monitoring runs for the authenticated tenant. Supports assessment_id filter.

  GET  /control-plane/readiness/monitoring/runs/{run_id}
      Retrieve a single monitoring run by its deterministic run_id.

Security invariants:
  - tenant_id resolved from auth context only — never from request body/query.
  - No secrets, credentials, raw evidence bodies, vectors, prompts, or PHI in responses.
  - All monitoring runs are tenant-scoped; cross-tenant access returns 404.
  - snapshot_json stored internally; API exposes deserialized export-safe dict.

Monitoring coverage note:
  The API populates only the evaluators for which data is available in the
  readiness DB (evidence freshness, framework compliance, readiness regression).
  Provider, retrieval, policy, and runtime evaluators require data from external
  systems and are not populated in this release — their inputs remain empty,
  which is honest about monitoring coverage rather than fabricating healthy status.
  The domains_evaluated field in the response documents exactly what was evaluated.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from api.auth_scopes import require_scopes
from api.deps import auth_ctx_db_session
from api.error_contracts import api_error
from services.readiness import ReadinessStore
from services.readiness.monitoring import (
    EvidenceFreshnessInput,
    FrameworkComplianceInput,
    MonitoringEngine,
    MonitoringEngineInput,
    MonitoringEvaluationContext,
    MonitoringRunNotFound,
    MonitoringRunRecord,
    MonitoringRunStore,
    MonitoringRunTenantIsolationError,
    ReadinessRegressionInput,
    derive_monitoring_run_id,
)
from services.readiness.monitoring.serialization import snapshot_from_json

logger = logging.getLogger("frostgate.api.readiness_monitoring")

router = APIRouter(tags=["readiness"])

_readiness_store = ReadinessStore()
_monitoring_store = MonitoringRunStore()
_monitor = MonitoringEngine()

MONITORING_CONTRACT_VERSION = "1.0"
EVALUATION_ENGINE_VERSION = "1.0"
DRIFT_CLASSIFICATION_VERSION = "1.0"
SEVERITY_CLASSIFICATION_VERSION = "1.0"


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
    now = datetime.now(timezone.utc)
    from datetime import timedelta

    start = now - timedelta(hours=hours_back)
    return start.isoformat(), now.isoformat()


def _stale_days(submitted_at_iso: str, now_iso: str) -> Optional[float]:
    try:
        from datetime import datetime as _dt

        submitted = _dt.fromisoformat(submitted_at_iso.replace("Z", "+00:00"))
        now = _dt.fromisoformat(now_iso.replace("Z", "+00:00"))
        return max(0.0, (now - submitted).total_seconds() / 86400)
    except Exception:
        return None


def _fetch_all_pages(fn, **kwargs) -> list:  # type: ignore[no-untyped-def]
    items: list = []
    offset = 0
    page_size = 200
    while True:
        page = fn(**kwargs, limit=page_size, offset=offset)
        items.extend(page)
        if len(page) < page_size:
            break
        offset += page_size
    return items


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class MonitoringRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: Optional[str] = Field(
        None, description="Scope to a specific assessment."
    )
    eval_window_hours: int = Field(
        24, ge=1, le=720, description="Evaluation window in hours."
    )
    evidence_freshness_window_days: int = Field(
        30, ge=1, le=365, description="Days after which evidence is considered stale."
    )
    retrieval_degradation_window_hours: int = Field(24, ge=1, le=720)
    policy_drift_comparison_window_hours: int = Field(24, ge=1, le=720)
    audit_continuity_window_hours: int = Field(24, ge=1, le=720)
    runtime_governance_window_hours: int = Field(24, ge=1, le=720)
    regression_threshold: float = Field(
        0.05,
        ge=0.0,
        le=1.0,
        description="Fractional completion drop that triggers regression detection.",
    )


class DriftEventResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    event_fingerprint: str
    drift_type: str
    severity: str
    certainty: str
    affected_scope: str
    affected_control_ids: list[str]
    affected_evidence_ids: list[str]
    affected_framework_ids: list[str]
    drift_detail: str
    monitoring_source: str
    evaluation_timestamp_iso: str
    temporal_boundary_start: str
    temporal_boundary_end: str
    provenance_metadata: dict[str, str]

    @classmethod
    def from_dict(cls, d: dict) -> "DriftEventResponse":
        return cls(
            event_fingerprint=d["event_fingerprint"],
            drift_type=d["drift_type"],
            severity=d["severity"],
            certainty=d["certainty"],
            affected_scope=d["affected_scope"],
            affected_control_ids=d.get("affected_control_ids", []),
            affected_evidence_ids=d.get("affected_evidence_ids", []),
            affected_framework_ids=d.get("affected_framework_ids", []),
            drift_detail=d["drift_detail"],
            monitoring_source=d["monitoring_source"],
            evaluation_timestamp_iso=d["evaluation_timestamp_iso"],
            temporal_boundary_start=d["temporal_boundary_start"],
            temporal_boundary_end=d["temporal_boundary_end"],
            provenance_metadata=d.get("provenance_metadata", {}),
        )


class MonitoringRunResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    tenant_id: str
    assessment_id: Optional[str]
    snapshot_id: str
    monitoring_contract_version: str
    evaluation_engine_version: str
    drift_classification_version: str
    severity_classification_version: str
    eval_window_start_iso: str
    eval_window_end_iso: str
    evidence_freshness_window_days: int
    framework_ids: list[str]
    domains_evaluated: list[str]
    total_drift_events: int
    critical_or_blocking_count: int
    evaluation_success: bool
    error_summary: Optional[str]
    completed_at_iso: str
    created_at_iso: str
    events: list[DriftEventResponse]
    replay_contract_metadata: dict[str, str]

    @classmethod
    def from_record(cls, record: MonitoringRunRecord) -> "MonitoringRunResponse":
        snap = snapshot_from_json(record.snapshot_json)
        return cls(
            run_id=record.run_id,
            tenant_id=record.tenant_id,
            assessment_id=record.assessment_id,
            snapshot_id=record.snapshot_id,
            monitoring_contract_version=record.monitoring_contract_version,
            evaluation_engine_version=record.evaluation_engine_version,
            drift_classification_version=snap.get("drift_classification_version", ""),
            severity_classification_version=snap.get(
                "severity_classification_version", ""
            ),
            eval_window_start_iso=record.eval_window_start_iso,
            eval_window_end_iso=record.eval_window_end_iso,
            evidence_freshness_window_days=snap.get(
                "evidence_freshness_window_days", 0
            ),
            framework_ids=list(record.framework_ids),
            domains_evaluated=list(record.domains_evaluated),
            total_drift_events=record.total_drift_events,
            critical_or_blocking_count=record.critical_or_blocking_count,
            evaluation_success=record.evaluation_success,
            error_summary=record.error_summary,
            completed_at_iso=record.completed_at_iso,
            created_at_iso=record.created_at_iso,
            events=[DriftEventResponse.from_dict(e) for e in snap.get("events", [])],
            replay_contract_metadata=snap.get("replay_contract_metadata", {}),
        )


class MonitoringRunSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    run_id: str
    assessment_id: Optional[str]
    snapshot_id: str
    monitoring_contract_version: str
    evaluation_engine_version: str
    total_drift_events: int
    critical_or_blocking_count: int
    evaluation_success: bool
    domains_evaluated: list[str]
    completed_at_iso: str
    created_at_iso: str

    @classmethod
    def from_record(cls, record: MonitoringRunRecord) -> "MonitoringRunSummaryResponse":
        return cls(
            run_id=record.run_id,
            assessment_id=record.assessment_id,
            snapshot_id=record.snapshot_id,
            monitoring_contract_version=record.monitoring_contract_version,
            evaluation_engine_version=record.evaluation_engine_version,
            total_drift_events=record.total_drift_events,
            critical_or_blocking_count=record.critical_or_blocking_count,
            evaluation_success=record.evaluation_success,
            domains_evaluated=list(record.domains_evaluated),
            completed_at_iso=record.completed_at_iso,
            created_at_iso=record.created_at_iso,
        )


# ---------------------------------------------------------------------------
# Input builders — construct evaluator inputs from DB data
# ---------------------------------------------------------------------------


def _build_evidence_inputs(
    db: Session, assessment_id: str, tenant_id: str, now_iso: str
) -> tuple[EvidenceFreshnessInput, ...]:
    try:
        refs = _fetch_all_pages(
            _readiness_store.list_evidence_references,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
    except Exception:
        return ()
    inputs = []
    for ref in refs:
        staleness = _stale_days(ref.submitted_at.isoformat(), now_iso)
        # Extract validation_status and integrity_verified from safe metadata
        meta = ref.evidence_source_metadata or {}
        validation_status = str(meta.get("validation_status", "unknown"))
        integrity_verified_raw = meta.get("integrity_verified")
        if integrity_verified_raw is None:
            integrity_verified = None
        else:
            integrity_verified = str(integrity_verified_raw).lower() == "true"
        inputs.append(
            EvidenceFreshnessInput(
                evidence_id=ref.evidence_id,
                evidence_title=ref.evidence_title,
                evidence_type=ref.evidence_type.value
                if hasattr(ref.evidence_type, "value")
                else str(ref.evidence_type),
                submitted_at_iso=ref.submitted_at.isoformat(),
                control_ids=tuple(ref.control_ids or []),
                integrity_verified=integrity_verified,
                validation_status=validation_status,
                staleness_days=staleness,
            )
        )
    return tuple(inputs)


def _build_framework_inputs(
    db: Session, assessment_id: str, tenant_id: str
) -> tuple[FrameworkComplianceInput, ...]:
    try:
        assessment = _readiness_store.get_assessment(
            db, assessment_id=assessment_id, tenant_id=tenant_id
        )
    except Exception:
        return ()

    try:
        results = _fetch_all_pages(
            _readiness_store.list_assessment_results,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
    except Exception:
        return ()

    try:
        controls = _fetch_all_pages(
            _readiness_store.list_controls,
            db=db,
            framework_id=assessment.framework_id,
            tenant_id=tenant_id,
        )
    except Exception:
        return ()

    total = len(controls)
    evaluated = len(results)

    from services.readiness.models import AssessmentOutcome

    failed = sum(
        1
        for r in results
        if r.outcome
        in (AssessmentOutcome.NON_COMPLIANT, AssessmentOutcome.PARTIALLY_COMPLIANT)
    )
    not_evaluated = total - evaluated
    completion = evaluated / total if total > 0 else 0.0

    # Missing required controls: controls with no result or NON_COMPLIANT result.
    # For now, identify controls with NON_COMPLIANT outcome.
    missing_required = tuple(
        r.control_id for r in results if r.outcome == AssessmentOutcome.NON_COMPLIANT
    )[:50]

    return (
        FrameworkComplianceInput(
            framework_id=assessment.framework_id,
            framework_version_tag=assessment.framework_version_tag or "",
            framework_status="active",
            assessment_id=assessment_id,
            total_controls=total,
            evaluated_controls=evaluated,
            failed_controls=failed,
            not_evaluated_controls=not_evaluated,
            missing_required_control_ids=missing_required,
            invalid_evidence_linkage_ids=(),
            assessment_completion_percentage=completion,
        ),
    )


def _build_regression_input(
    db: Session, assessment_id: str, tenant_id: str, regression_threshold: float
) -> Optional[ReadinessRegressionInput]:
    try:
        assessment = _readiness_store.get_assessment(
            db, assessment_id=assessment_id, tenant_id=tenant_id
        )
    except Exception:
        return None

    try:
        results = _fetch_all_pages(
            _readiness_store.list_assessment_results,
            db=db,
            assessment_id=assessment_id,
            tenant_id=tenant_id,
        )
        controls = _fetch_all_pages(
            _readiness_store.list_controls,
            db=db,
            framework_id=assessment.framework_id,
            tenant_id=tenant_id,
        )
    except Exception:
        return None

    from services.readiness.models import AssessmentOutcome

    total = len(controls)
    evaluated = len(results)
    failed = sum(
        1
        for r in results
        if r.outcome
        in (AssessmentOutcome.NON_COMPLIANT, AssessmentOutcome.PARTIALLY_COMPLIANT)
    )
    completion = evaluated / total if total > 0 else 0.0

    return ReadinessRegressionInput(
        assessment_id=assessment_id,
        framework_id=assessment.framework_id,
        current_completion_percentage=completion,
        baseline_completion_percentage=None,  # no stored baseline yet
        current_failed_controls=failed,
        baseline_failed_controls=None,
        regression_threshold=regression_threshold,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/control-plane/readiness/monitoring/run",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    response_model=MonitoringRunResponse,
    status_code=201,
)
def create_monitoring_run(
    body: MonitoringRunRequest,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MonitoringRunResponse:
    """Execute a deterministic readiness monitoring evaluation.

    Idempotent: submitting the same evaluation scope and window twice returns
    the stored result rather than re-evaluating.
    """
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error(
                "MONITORING_NO_TENANT",
                "Tenant context required for monitoring runs.",
            ),
        )

    assessment_id = body.assessment_id
    now_iso = _now_iso()
    eval_window_start_iso, eval_window_end_iso = _window_iso(body.eval_window_hours)

    # Validate assessment exists for this tenant if provided.
    framework_id = ""
    if assessment_id:
        try:
            assessment = _readiness_store.get_assessment(
                db, assessment_id=assessment_id, tenant_id=tenant_id
            )
            framework_id = assessment.framework_id
        except Exception:
            raise HTTPException(
                status_code=404,
                detail=api_error("ASSESSMENT_NOT_FOUND", "Assessment not found."),
            )

    run_id = derive_monitoring_run_id(
        tenant_id=tenant_id,
        assessment_id=assessment_id or "",
        framework_id=framework_id,
        eval_window_start_iso=eval_window_start_iso,
        eval_window_end_iso=eval_window_end_iso,
        monitoring_contract_version=MONITORING_CONTRACT_VERSION,
    )

    # Idempotency: return stored result if this run_id already exists.
    try:
        existing = _monitoring_store.get_run(db, run_id=run_id, tenant_id=tenant_id)
        return MonitoringRunResponse.from_record(existing)
    except MonitoringRunNotFound:
        pass

    context = MonitoringEvaluationContext(
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        evaluation_window_start_iso=eval_window_start_iso,
        evaluation_window_end_iso=eval_window_end_iso,
        evidence_freshness_window_days=body.evidence_freshness_window_days,
        retrieval_degradation_window_hours=body.retrieval_degradation_window_hours,
        policy_drift_comparison_window_hours=body.policy_drift_comparison_window_hours,
        audit_continuity_window_hours=body.audit_continuity_window_hours,
        runtime_governance_window_hours=body.runtime_governance_window_hours,
        monitoring_contract_version=MONITORING_CONTRACT_VERSION,
        evaluation_engine_version=EVALUATION_ENGINE_VERSION,
        drift_classification_version=DRIFT_CLASSIFICATION_VERSION,
        severity_classification_version=SEVERITY_CLASSIFICATION_VERSION,
    )

    # Build evaluator inputs from available DB data.
    evidence_inputs: tuple[EvidenceFreshnessInput, ...] = ()
    framework_inputs: tuple[FrameworkComplianceInput, ...] = ()
    regression_input: Optional[ReadinessRegressionInput] = None

    if assessment_id:
        evidence_inputs = _build_evidence_inputs(db, assessment_id, tenant_id, now_iso)
        framework_inputs = _build_framework_inputs(db, assessment_id, tenant_id)
        regression_input = _build_regression_input(
            db, assessment_id, tenant_id, body.regression_threshold
        )

    engine_input = MonitoringEngineInput(
        context=context,
        policy_inputs=(),  # not wired in this release
        provenance_inputs=(),  # not wired in this release
        provider_inputs=(),  # not wired in this release
        retrieval_inputs=(),  # not wired in this release
        evidence_inputs=evidence_inputs,
        audit_inputs=(),  # not wired in this release
        regression_input=regression_input,
        runtime_inputs=(),  # not wired in this release
        framework_inputs=framework_inputs,
    )

    result = _monitor.evaluate(run_id, engine_input)
    snap = result.snapshot

    from services.readiness.monitoring.serialization import snapshot_to_json

    snap_json = snapshot_to_json(snap)

    record = _monitoring_store.create_run(
        db,
        run_id=run_id,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        framework_ids=snap.framework_ids,
        eval_window_start_iso=eval_window_start_iso,
        eval_window_end_iso=eval_window_end_iso,
        monitoring_contract_version=MONITORING_CONTRACT_VERSION,
        evaluation_engine_version=EVALUATION_ENGINE_VERSION,
        snapshot_id=snap.snapshot_id,
        snapshot_json=snap_json,
        domains_evaluated=snap.domains_evaluated,
        total_drift_events=snap.total_drift_events,
        critical_or_blocking_count=snap.critical_or_blocking_count,
        completed_at_iso=result.completed_at_iso,
        evaluation_success=result.evaluation_success,
        error_summary=result.error_summary,
    )
    db.commit()

    logger.info(
        "monitoring_run_created run_id=%s tenant=%s assessment=%s "
        "drift_events=%d critical=%d success=%s",
        run_id,
        tenant_id,
        assessment_id,
        snap.total_drift_events,
        snap.critical_or_blocking_count,
        result.evaluation_success,
    )

    return MonitoringRunResponse.from_record(record)


@router.get(
    "/control-plane/readiness/monitoring/runs",
    dependencies=[Depends(require_scopes("control-plane:read"))],
)
def list_monitoring_runs(
    request: Request,
    assessment_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(auth_ctx_db_session),
) -> list[MonitoringRunSummaryResponse]:
    """List monitoring runs for the authenticated tenant."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("MONITORING_NO_TENANT", "Tenant context required."),
        )

    records = _monitoring_store.list_runs(
        db,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        limit=min(limit, 200),
        offset=offset,
    )
    return [MonitoringRunSummaryResponse.from_record(r) for r in records]


@router.get(
    "/control-plane/readiness/monitoring/runs/{run_id}",
    dependencies=[Depends(require_scopes("control-plane:read"))],
    response_model=MonitoringRunResponse,
)
def get_monitoring_run(
    run_id: str,
    request: Request,
    db: Session = Depends(auth_ctx_db_session),
) -> MonitoringRunResponse:
    """Retrieve a monitoring run by its deterministic run_id."""
    tenant_id = _tenant_from_auth(request)
    if not tenant_id:
        raise HTTPException(
            status_code=403,
            detail=api_error("MONITORING_NO_TENANT", "Tenant context required."),
        )

    try:
        record = _monitoring_store.get_run(db, run_id=run_id, tenant_id=tenant_id)
    except MonitoringRunNotFound:
        raise HTTPException(
            status_code=404,
            detail=api_error("MONITORING_RUN_NOT_FOUND", "Monitoring run not found."),
        )
    except MonitoringRunTenantIsolationError:
        raise HTTPException(
            status_code=404,
            detail=api_error("MONITORING_RUN_NOT_FOUND", "Monitoring run not found."),
        )

    return MonitoringRunResponse.from_record(record)


# replay_investigation_seam: GET /control-plane/readiness/monitoring/runs/{run_id}/replay
# Forensic timeline reconstruction and comparative replay go here. The endpoint would
# deserialize snapshot_json, reconstruct the governance state at eval_window boundaries,
# and return a structured replay trace for operator investigation. All inputs needed for
# reconstruction are already present in the stored snapshot.

# monitoring_dashboard_seam: GET /control-plane/readiness/monitoring/stream
# Real-time drift feed (SSE or WebSocket) for live operational surfaces, operator triage
# flows, and escalation UX. The event shape is already defined by DriftEventResponse;
# streaming requires only a push mechanism, not new governance contracts.
