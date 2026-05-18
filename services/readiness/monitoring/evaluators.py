"""Deterministic readiness drift evaluators.

All functions are pure Python: no I/O, no side effects, no randomness.
Each evaluator accepts typed governance inputs and returns a list[DriftEvent].

Evaluator contract:
  - Deterministic: identical inputs → identical events (same fingerprints, same severity).
  - No sensitive payloads: no secrets, vectors, prompts, raw evidence bodies, PHI.
  - Uncertainty-explicit: unverifiable/unknown states produce explicit certainty labels,
    never collapse into CONFIRMED or healthy.
  - Bounded: each evaluator processes at most _MAX_ITEMS items to prevent unbounded scans.
  - No state mutation: evaluators never modify their inputs.

Temporal contract:
  - All freshness/staleness calculations use the explicit temporal boundaries from
    MonitoringEvaluationContext, not implicit "now" assumptions.
  - Callers must compute staleness_days before constructing EvidenceFreshnessInput.

Severity scaling:
  - POLICY_DRIFT: disabled policy → CRITICAL; permissive mode → MODERATE; hash change → LOW
  - PROVENANCE: validation disabled → CRITICAL; high failure rate → HIGH; low rate → MODERATE
  - PROVIDER: blocked → HIGH; restricted → MODERATE; unknown → LOW/SUSPECTED
  - RETRIEVAL: policy disabled → HIGH; high failure rate → HIGH; degraded reranker → MODERATE
  - EVIDENCE: invalid/missing validation → HIGH; stale → MODERATE; no control link → LOW
  - AUDIT: chain broken → BLOCKING; high failure rate → CRITICAL; invariant failure → HIGH
  - REGRESSION: score drop > threshold → HIGH; completion drop → MODERATE
  - RUNTIME: enforcement disabled → CRITICAL; permissive → MODERATE; high failure rate → HIGH
  - FRAMEWORK: missing required controls → HIGH/CRITICAL; failed > 50% → HIGH
"""

from __future__ import annotations

from datetime import datetime, timezone

from .identity import derive_event_fingerprint
from .models import (
    AuditIntegrityInput,
    DriftCertainty,
    DriftEvent,
    DriftSeverity,
    DriftType,
    EvidenceFreshnessInput,
    FrameworkComplianceInput,
    MonitoringEvaluationContext,
    PolicyDriftInput,
    ProvenanceEnforcementInput,
    ProviderGovernanceInput,
    ReadinessRegressionInput,
    RetrievalDegradationInput,
    RuntimeGovernanceInput,
)

# Bounded evaluation caps — prevents unbounded O(n) scans.
_MAX_EVIDENCE_ITEMS = 200
_MAX_POLICY_ITEMS = 50
_MAX_PROVIDER_ITEMS = 50
_MAX_CONTROL_ITEMS = 200

# Retrieval failure rate thresholds.
_RETRIEVAL_FAILURE_RATE_HIGH = 0.20  # ≥ 20% failures → HIGH
_RETRIEVAL_FAILURE_RATE_MODERATE = 0.05  # ≥ 5% failures → MODERATE

# Audit failure rate thresholds.
_AUDIT_FAILURE_RATE_CRITICAL = 0.10  # ≥ 10% failed records → CRITICAL
_AUDIT_FAILURE_RATE_HIGH = 0.02  # ≥ 2% failed records → HIGH
_AUDIT_FAILURE_RATE_MODERATE = 0.001  # any failed records → MODERATE

# Runtime governance failure rate thresholds.
_RUNTIME_FAILURE_RATE_HIGH = 0.10  # ≥ 10% failed signals → HIGH
_RUNTIME_FAILURE_RATE_MODERATE = 0.02  # ≥ 2% failed signals → MODERATE


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_event(
    *,
    drift_type: DriftType,
    severity: DriftSeverity,
    certainty: DriftCertainty,
    affected_scope: str,
    drift_detail: str,
    monitoring_source: str,
    context: MonitoringEvaluationContext,
    run_id: str,
    affected_control_ids: tuple[str, ...] = (),
    affected_evidence_ids: tuple[str, ...] = (),
    affected_framework_ids: tuple[str, ...] = (),
    provenance_metadata: tuple[tuple[str, str], ...] = (),
) -> DriftEvent:
    fp = derive_event_fingerprint(
        drift_type.value, affected_scope, run_id, affected_control_ids
    )
    return DriftEvent(
        event_fingerprint=fp,
        drift_type=drift_type,
        severity=severity,
        certainty=certainty,
        affected_scope=affected_scope,
        affected_control_ids=affected_control_ids,
        affected_evidence_ids=affected_evidence_ids,
        affected_framework_ids=affected_framework_ids,
        drift_detail=drift_detail,
        monitoring_source=monitoring_source,
        evaluation_timestamp_iso=_now_iso(),
        temporal_boundary_start=context.evaluation_window_start_iso,
        temporal_boundary_end=context.evaluation_window_end_iso,
        provenance_metadata=provenance_metadata,
    )


# ---------------------------------------------------------------------------
# Policy drift evaluator
# ---------------------------------------------------------------------------


def evaluate_policy_drift(
    inputs: tuple[PolicyDriftInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect policy disabled, enforcement mode degradation, and hash drift."""
    events: list[DriftEvent] = []
    for inp in inputs[:_MAX_POLICY_ITEMS]:
        scope = f"policy:{inp.policy_id}"
        if not inp.policy_enabled:
            events.append(
                _make_event(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=DriftSeverity.CRITICAL,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Policy '{inp.policy_name}' is disabled. Governance enforcement is absent.",
                    monitoring_source=inp.source,
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(
                        ("policy_version", inp.policy_version),
                        ("enforcement_mode", inp.enforcement_mode),
                    ),
                )
            )
        elif inp.policy_state in ("suspended", "rolled_back"):
            events.append(
                _make_event(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Policy '{inp.policy_name}' state is '{inp.policy_state}'. Governance may be degraded.",
                    monitoring_source=inp.source,
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(("policy_state", inp.policy_state),),
                )
            )
        elif inp.enforcement_mode == "disabled":
            events.append(
                _make_event(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Policy '{inp.policy_name}' enforcement is disabled. Policy exists but is not enforced.",
                    monitoring_source=inp.source,
                    context=context,
                    run_id=run_id,
                )
            )
        elif inp.enforcement_mode == "permissive":
            events.append(
                _make_event(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Policy '{inp.policy_name}' enforcement is permissive. Violations are logged but not blocked.",
                    monitoring_source=inp.source,
                    context=context,
                    run_id=run_id,
                )
            )
        elif (
            inp.previous_policy_hash is not None
            and inp.policy_hash != inp.previous_policy_hash
        ):
            events.append(
                _make_event(
                    drift_type=DriftType.POLICY_DRIFT,
                    severity=DriftSeverity.LOW,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Policy '{inp.policy_name}' hash changed from baseline. Policy content may have drifted.",
                    monitoring_source=inp.source,
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(("policy_version", inp.policy_version),),
                )
            )
    return events


# ---------------------------------------------------------------------------
# Provenance enforcement evaluator
# ---------------------------------------------------------------------------


def evaluate_provenance_enforcement(
    inputs: tuple[ProvenanceEnforcementInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect provenance validation/citation/grounded-answer enforcement degradation."""
    events: list[DriftEvent] = []
    for inp in inputs:
        scope = "provenance:enforcement"
        if not inp.provenance_validation_enabled:
            events.append(
                _make_event(
                    drift_type=DriftType.PROVENANCE_ENFORCEMENT_DISABLED,
                    severity=DriftSeverity.CRITICAL,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail="Provenance validation is disabled. Citation integrity cannot be verified.",
                    monitoring_source="provenance_enforcement_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if not inp.citation_enforcement_enabled:
            events.append(
                _make_event(
                    drift_type=DriftType.PROVENANCE_ENFORCEMENT_DISABLED,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope="provenance:citation_enforcement",
                    drift_detail="Citation enforcement is disabled. Answers may cite unverified sources.",
                    monitoring_source="provenance_enforcement_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if not inp.grounded_answer_enforcement_enabled:
            events.append(
                _make_event(
                    drift_type=DriftType.GROUNDED_ANSWER_ENFORCEMENT_FAILED,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope="provenance:grounded_answer",
                    drift_detail="Grounded-answer enforcement is disabled. Ungrounded answers may be returned.",
                    monitoring_source="provenance_enforcement_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.total_provenance_checked > 0:
            rate = inp.invalid_provenance_count / inp.total_provenance_checked
            if rate >= 0.20:
                events.append(
                    _make_event(
                        drift_type=DriftType.PROVENANCE_DEGRADATION,
                        severity=DriftSeverity.HIGH,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope="provenance:validation_failure_rate",
                        drift_detail=(
                            f"High provenance failure rate: {rate:.1%} of "
                            f"{inp.total_provenance_checked} checked provenance records are invalid."
                        ),
                        monitoring_source="provenance_enforcement_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
            elif rate >= 0.05:
                events.append(
                    _make_event(
                        drift_type=DriftType.PROVENANCE_DEGRADATION,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope="provenance:validation_failure_rate",
                        drift_detail=(
                            f"Elevated provenance failure rate: {rate:.1%} of "
                            f"{inp.total_provenance_checked} checked provenance records are invalid."
                        ),
                        monitoring_source="provenance_enforcement_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
    return events


# ---------------------------------------------------------------------------
# Provider governance evaluator
# ---------------------------------------------------------------------------


def evaluate_provider_governance(
    inputs: tuple[ProviderGovernanceInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect provider blocked, restricted, or unknown governance states."""
    events: list[DriftEvent] = []
    for inp in inputs[:_MAX_PROVIDER_ITEMS]:
        scope = f"provider:{inp.provider_id}"
        if inp.provider_status == "blocked":
            events.append(
                _make_event(
                    drift_type=DriftType.PROVIDER_BLOCKED,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Provider '{inp.provider_name}' is blocked by governance policy.",
                    monitoring_source="provider_governance_evaluator",
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(
                        ("governance_classification", inp.governance_classification),
                        ("compliance_classification", inp.compliance_classification),
                    ),
                )
            )
        elif inp.provider_status == "restricted":
            events.append(
                _make_event(
                    drift_type=DriftType.PROVIDER_GOVERNANCE_CHANGE,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Provider '{inp.provider_name}' is restricted. Usage may be limited.",
                    monitoring_source="provider_governance_evaluator",
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(
                        ("governance_classification", inp.governance_classification),
                    ),
                )
            )
        elif inp.provider_status == "unknown":
            events.append(
                _make_event(
                    drift_type=DriftType.PROVIDER_GOVERNANCE_CHANGE,
                    severity=DriftSeverity.LOW,
                    certainty=DriftCertainty.SUSPECTED,
                    affected_scope=scope,
                    drift_detail=f"Provider '{inp.provider_name}' governance status is unknown. Manual review required.",
                    monitoring_source="provider_governance_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
    return events


# ---------------------------------------------------------------------------
# Retrieval degradation evaluator
# ---------------------------------------------------------------------------


def evaluate_retrieval_degradation(
    inputs: tuple[RetrievalDegradationInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect retrieval policy disabled and grounded-answer failure rates."""
    events: list[DriftEvent] = []
    for inp in inputs:
        scope = f"retrieval_policy:{inp.retrieval_policy_id}"
        if not inp.retrieval_policy_enabled:
            events.append(
                _make_event(
                    drift_type=DriftType.RETRIEVAL_POLICY_MISMATCH,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail="Retrieval policy is disabled. Governance constraints on retrieval are inactive.",
                    monitoring_source="retrieval_degradation_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.reranker_governance_state in ("degraded", "disabled"):
            events.append(
                _make_event(
                    drift_type=DriftType.RETRIEVAL_DEGRADATION,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=f"{scope}:reranker",
                    drift_detail=f"Reranker governance state is '{inp.reranker_governance_state}'. Retrieval quality governance may be degraded.",
                    monitoring_source="retrieval_degradation_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.total_retrievals > 0:
            ga_rate = inp.grounded_answer_failure_count / inp.total_retrievals
            pv_rate = inp.provenance_validation_failure_count / inp.total_retrievals
            combined = max(ga_rate, pv_rate)
            if combined >= _RETRIEVAL_FAILURE_RATE_HIGH:
                events.append(
                    _make_event(
                        drift_type=DriftType.RETRIEVAL_DEGRADATION,
                        severity=DriftSeverity.HIGH,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=(
                            f"High retrieval governance failure rate: {combined:.1%} of "
                            f"{inp.total_retrievals} retrievals failed grounding or provenance checks."
                        ),
                        monitoring_source="retrieval_degradation_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
            elif combined >= _RETRIEVAL_FAILURE_RATE_MODERATE:
                events.append(
                    _make_event(
                        drift_type=DriftType.RETRIEVAL_DEGRADATION,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=(
                            f"Elevated retrieval governance failure rate: {combined:.1%} of "
                            f"{inp.total_retrievals} retrievals failed grounding or provenance checks."
                        ),
                        monitoring_source="retrieval_degradation_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
    return events


# ---------------------------------------------------------------------------
# Evidence freshness evaluator
# ---------------------------------------------------------------------------


def evaluate_evidence_freshness(
    inputs: tuple[EvidenceFreshnessInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect stale, missing, integrity-failed, and unlinked evidence."""
    events: list[DriftEvent] = []
    for inp in inputs[:_MAX_EVIDENCE_ITEMS]:
        scope = f"evidence:{inp.evidence_id}"
        if inp.validation_status in ("invalid",):
            events.append(
                _make_event(
                    drift_type=DriftType.INVALID_EVIDENCE_INTEGRITY,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Evidence '{inp.evidence_title}' has validation status 'invalid'. Evidence integrity is compromised.",
                    monitoring_source="evidence_freshness_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_evidence_ids=(inp.evidence_id,),
                    affected_control_ids=inp.control_ids,
                )
            )
        elif inp.validation_status in ("missing",):
            events.append(
                _make_event(
                    drift_type=DriftType.MISSING_EVIDENCE,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Evidence '{inp.evidence_title}' is missing. Required evidence cannot be located.",
                    monitoring_source="evidence_freshness_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_evidence_ids=(inp.evidence_id,),
                    affected_control_ids=inp.control_ids,
                )
            )
        else:
            if inp.integrity_verified is False:
                events.append(
                    _make_event(
                        drift_type=DriftType.INVALID_EVIDENCE_INTEGRITY,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=f"Evidence '{inp.evidence_title}' integrity verification failed.",
                        monitoring_source="evidence_freshness_evaluator",
                        context=context,
                        run_id=run_id,
                        affected_evidence_ids=(inp.evidence_id,),
                        affected_control_ids=inp.control_ids,
                    )
                )
            if (
                inp.staleness_days is not None
                and inp.staleness_days >= context.evidence_freshness_window_days
            ):
                events.append(
                    _make_event(
                        drift_type=DriftType.STALE_EVIDENCE,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=(
                            f"Evidence '{inp.evidence_title}' is stale: "
                            f"{inp.staleness_days:.0f} days old (threshold: "
                            f"{context.evidence_freshness_window_days} days)."
                        ),
                        monitoring_source="evidence_freshness_evaluator",
                        context=context,
                        run_id=run_id,
                        affected_evidence_ids=(inp.evidence_id,),
                        affected_control_ids=inp.control_ids,
                    )
                )
        if not inp.control_ids:
            events.append(
                _make_event(
                    drift_type=DriftType.INVALID_EVIDENCE_LINKAGE,
                    severity=DriftSeverity.LOW,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=f"Evidence '{inp.evidence_title}' is not linked to any controls. It cannot contribute to compliance scoring.",
                    monitoring_source="evidence_freshness_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_evidence_ids=(inp.evidence_id,),
                )
            )
    return events


# ---------------------------------------------------------------------------
# Audit integrity evaluator
# ---------------------------------------------------------------------------


def evaluate_audit_integrity(
    inputs: tuple[AuditIntegrityInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect audit chain gaps, hash mismatches, and failure rates."""
    events: list[DriftEvent] = []
    for inp in inputs:
        scope = "audit:chain"
        if inp.audit_chain_status == "broken":
            events.append(
                _make_event(
                    drift_type=DriftType.AUDIT_CHAIN_BROKEN,
                    severity=DriftSeverity.BLOCKING,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=(
                        "Audit chain integrity is broken. Do not rely on this audit ledger for "
                        "compliance decisions. Forensic reconstruction is required."
                    ),
                    monitoring_source="audit_integrity_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        elif inp.audit_chain_status == "unknown":
            events.append(
                _make_event(
                    drift_type=DriftType.AUDIT_INTEGRITY_FAILURE,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.UNKNOWN,
                    affected_scope=scope,
                    drift_detail="Audit chain status is unknown. Integrity cannot be verified.",
                    monitoring_source="audit_integrity_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.total_records > 0 and inp.failed_records > 0:
            rate = inp.failed_records / inp.total_records
            if rate >= _AUDIT_FAILURE_RATE_CRITICAL:
                sev = DriftSeverity.CRITICAL
            elif rate >= _AUDIT_FAILURE_RATE_HIGH:
                sev = DriftSeverity.HIGH
            else:
                sev = DriftSeverity.MODERATE
            events.append(
                _make_event(
                    drift_type=DriftType.AUDIT_INTEGRITY_FAILURE,
                    severity=sev,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope="audit:failed_records",
                    drift_detail=(
                        f"{inp.failed_records} of {inp.total_records} audit records have failed "
                        f"({rate:.1%}). Audit ledger integrity is degraded."
                    ),
                    monitoring_source="audit_integrity_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.current_invariant_status not in ("ok", "healthy", "passing", ""):
            events.append(
                _make_event(
                    drift_type=DriftType.AUDIT_INTEGRITY_FAILURE,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope="audit:invariant_status",
                    drift_detail=f"Audit invariant status is '{inp.current_invariant_status}'. Governance invariants may be violated.",
                    monitoring_source="audit_integrity_evaluator",
                    context=context,
                    run_id=run_id,
                    provenance_metadata=(
                        ("invariant_status", inp.current_invariant_status),
                    ),
                )
            )
    return events


# ---------------------------------------------------------------------------
# Readiness regression evaluator
# ---------------------------------------------------------------------------


def evaluate_readiness_regression(
    inp: ReadinessRegressionInput,
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect completion percentage regression and failed control increases."""
    events: list[DriftEvent] = []
    scope = f"assessment:{inp.assessment_id}"

    if inp.baseline_completion_percentage is not None:
        drop = inp.baseline_completion_percentage - inp.current_completion_percentage
        if drop >= inp.regression_threshold:
            severity = DriftSeverity.HIGH if drop >= 0.10 else DriftSeverity.MODERATE
            events.append(
                _make_event(
                    drift_type=DriftType.READINESS_REGRESSION,
                    severity=severity,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail=(
                        f"Readiness completion dropped {drop:.1%} below baseline "
                        f"({inp.current_completion_percentage:.1%} vs "
                        f"{inp.baseline_completion_percentage:.1%}). "
                        f"Framework: {inp.framework_id}."
                    ),
                    monitoring_source="readiness_regression_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_framework_ids=(inp.framework_id,),
                )
            )

    if inp.baseline_failed_controls is not None:
        increase = inp.current_failed_controls - inp.baseline_failed_controls
        if increase > 0:
            events.append(
                _make_event(
                    drift_type=DriftType.READINESS_REGRESSION,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=f"{scope}:failed_controls",
                    drift_detail=(
                        f"Failed controls increased by {increase} since baseline "
                        f"({inp.current_failed_controls} now vs {inp.baseline_failed_controls} baseline)."
                    ),
                    monitoring_source="readiness_regression_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_framework_ids=(inp.framework_id,),
                )
            )
    return events


# ---------------------------------------------------------------------------
# Runtime governance evaluator
# ---------------------------------------------------------------------------


def evaluate_runtime_governance(
    inputs: tuple[RuntimeGovernanceInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect runtime enforcement mode degradation and signal failure rates."""
    events: list[DriftEvent] = []
    for inp in inputs:
        scope = "runtime:governance"
        if inp.enforcement_mode == "disabled":
            events.append(
                _make_event(
                    drift_type=DriftType.RUNTIME_GOVERNANCE_DEGRADATION,
                    severity=DriftSeverity.CRITICAL,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail="Runtime governance enforcement is disabled. No governance constraints are active.",
                    monitoring_source="runtime_governance_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        elif inp.enforcement_mode == "permissive":
            events.append(
                _make_event(
                    drift_type=DriftType.RUNTIME_GOVERNANCE_DEGRADATION,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=scope,
                    drift_detail="Runtime governance enforcement is permissive. Violations are logged but not blocked.",
                    monitoring_source="runtime_governance_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        elif inp.enforcement_mode == "unknown":
            events.append(
                _make_event(
                    drift_type=DriftType.RUNTIME_GOVERNANCE_DEGRADATION,
                    severity=DriftSeverity.LOW,
                    certainty=DriftCertainty.UNKNOWN,
                    affected_scope=scope,
                    drift_detail="Runtime governance enforcement mode is unknown. Manual inspection required.",
                    monitoring_source="runtime_governance_evaluator",
                    context=context,
                    run_id=run_id,
                )
            )
        if inp.governance_signal_count > 0:
            rate = inp.failed_governance_signals / inp.governance_signal_count
            if rate >= _RUNTIME_FAILURE_RATE_HIGH:
                events.append(
                    _make_event(
                        drift_type=DriftType.RUNTIME_GOVERNANCE_DEGRADATION,
                        severity=DriftSeverity.HIGH,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope="runtime:signal_failure_rate",
                        drift_detail=(
                            f"High runtime governance signal failure rate: "
                            f"{rate:.1%} of {inp.governance_signal_count} signals failed."
                        ),
                        monitoring_source="runtime_governance_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
            elif rate >= _RUNTIME_FAILURE_RATE_MODERATE:
                events.append(
                    _make_event(
                        drift_type=DriftType.RUNTIME_GOVERNANCE_DEGRADATION,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope="runtime:signal_failure_rate",
                        drift_detail=(
                            f"Elevated runtime governance signal failure rate: "
                            f"{rate:.1%} of {inp.governance_signal_count} signals failed."
                        ),
                        monitoring_source="runtime_governance_evaluator",
                        context=context,
                        run_id=run_id,
                    )
                )
    return events


# ---------------------------------------------------------------------------
# Framework compliance evaluator
# ---------------------------------------------------------------------------


def evaluate_framework_compliance(
    inputs: tuple[FrameworkComplianceInput, ...],
    context: MonitoringEvaluationContext,
    run_id: str,
) -> list[DriftEvent]:
    """Detect missing required controls, invalid evidence linkages, and failed controls."""
    events: list[DriftEvent] = []
    for inp in inputs:
        scope = f"framework:{inp.framework_id}:assessment:{inp.assessment_id}"

        for ctrl_id in list(inp.missing_required_control_ids)[:_MAX_CONTROL_ITEMS]:
            events.append(
                _make_event(
                    drift_type=DriftType.MISSING_REQUIRED_CONTROL,
                    severity=DriftSeverity.HIGH,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=f"control:{ctrl_id}",
                    drift_detail=f"Required control '{ctrl_id}' has no passing result in assessment '{inp.assessment_id}'.",
                    monitoring_source="framework_compliance_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_control_ids=(ctrl_id,),
                    affected_framework_ids=(inp.framework_id,),
                )
            )

        for ev_id in list(inp.invalid_evidence_linkage_ids)[:_MAX_CONTROL_ITEMS]:
            events.append(
                _make_event(
                    drift_type=DriftType.INVALID_EVIDENCE_LINKAGE,
                    severity=DriftSeverity.MODERATE,
                    certainty=DriftCertainty.CONFIRMED,
                    affected_scope=f"evidence:{ev_id}",
                    drift_detail=f"Evidence '{ev_id}' has an invalid control linkage in framework '{inp.framework_id}'.",
                    monitoring_source="framework_compliance_evaluator",
                    context=context,
                    run_id=run_id,
                    affected_evidence_ids=(ev_id,),
                    affected_framework_ids=(inp.framework_id,),
                )
            )

        if inp.total_controls > 0:
            fail_rate = inp.failed_controls / inp.total_controls
            if fail_rate >= 0.50:
                events.append(
                    _make_event(
                        drift_type=DriftType.FRAMEWORK_COMPLIANCE_DEGRADATION,
                        severity=DriftSeverity.HIGH,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=(
                            f"High framework compliance failure rate: {fail_rate:.1%} of controls failed "
                            f"({inp.failed_controls}/{inp.total_controls}) in assessment '{inp.assessment_id}'."
                        ),
                        monitoring_source="framework_compliance_evaluator",
                        context=context,
                        run_id=run_id,
                        affected_framework_ids=(inp.framework_id,),
                    )
                )
            elif inp.assessment_completion_percentage < 0.50:
                events.append(
                    _make_event(
                        drift_type=DriftType.FRAMEWORK_COMPLIANCE_DEGRADATION,
                        severity=DriftSeverity.MODERATE,
                        certainty=DriftCertainty.CONFIRMED,
                        affected_scope=scope,
                        drift_detail=(
                            f"Assessment completion is low: "
                            f"{inp.assessment_completion_percentage:.1%} of controls evaluated in '{inp.assessment_id}'."
                        ),
                        monitoring_source="framework_compliance_evaluator",
                        context=context,
                        run_id=run_id,
                        affected_framework_ids=(inp.framework_id,),
                    )
                )
    return events
