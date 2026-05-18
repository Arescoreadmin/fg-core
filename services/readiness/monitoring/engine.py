"""Enterprise Continuous Readiness Monitoring Engine.

Pure Python. No I/O. No SQLAlchemy. No LLMs. No randomness.

Engine contract:
  - Deterministic: identical MonitoringEngineInput → identical DriftSnapshot.
  - No side effects: the engine never mutates its inputs or any module-level state.
  - Replay-safe: all version pins are recorded in the snapshot for forensic replay.
  - Uncertainty-explicit: unverifiable/unknown states remain in DriftCertainty labels,
    never collapsed into healthy status.
  - Bounded: each evaluator is bounded; the engine itself adds no additional bounds
    beyond those enforced in evaluators.py.
  - Failure-safe: an evaluator exception is caught, logged, and produces a
    MONITORING_VISIBILITY_DEGRADATION event rather than corrupting the snapshot.

Domains evaluated:
  The engine always documents which monitoring domains were included in an evaluation
  via DriftSnapshot.domains_evaluated. Callers can inspect this to understand
  monitoring coverage without guessing.

Version pins (for replay reconstruction):
  All four version fields are recorded in the snapshot:
  - monitoring_contract_version
  - evaluation_engine_version
  - drift_classification_version
  - severity_classification_version
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .deduplication import deduplicate_drift_events
from .evaluators import (
    evaluate_audit_integrity,
    evaluate_evidence_freshness,
    evaluate_framework_compliance,
    evaluate_policy_drift,
    evaluate_provenance_enforcement,
    evaluate_provider_governance,
    evaluate_readiness_regression,
    evaluate_retrieval_degradation,
    evaluate_runtime_governance,
)
from .identity import derive_event_fingerprint, derive_snapshot_id
from .models import (
    DriftCertainty,
    DriftEvent,
    DriftSeverity,
    DriftSnapshot,
    DriftType,
    MonitoringEngineInput,
    MonitoringResult,
    severity_rank,
)

logger = logging.getLogger("frostgate.readiness.monitoring")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evaluator_failure_event(
    domain: str,
    run_id: str,
    context_start: str,
    context_end: str,
    error_detail: str,
) -> DriftEvent:
    """Produce an explicit MONITORING_VISIBILITY_DEGRADATION event on evaluator failure."""
    fp = derive_event_fingerprint(
        DriftType.MONITORING_VISIBILITY_DEGRADATION.value,
        f"evaluator:{domain}",
        run_id,
        (),
    )
    return DriftEvent(
        event_fingerprint=fp,
        drift_type=DriftType.MONITORING_VISIBILITY_DEGRADATION,
        severity=DriftSeverity.LOW,
        certainty=DriftCertainty.MONITORING_SOURCE_FAILURE,
        affected_scope=f"evaluator:{domain}",
        affected_control_ids=(),
        affected_evidence_ids=(),
        affected_framework_ids=(),
        drift_detail=f"Monitoring evaluator '{domain}' failed. {error_detail}",
        monitoring_source=f"{domain}_evaluator",
        evaluation_timestamp_iso=_now_iso(),
        temporal_boundary_start=context_start,
        temporal_boundary_end=context_end,
        provenance_metadata=(),
    )


class MonitoringEngine:
    """Deterministic monitoring engine — pure computation, no I/O.

    Call evaluate() with a MonitoringEngineInput and a pre-derived run_id.
    The engine calls all evaluators, deduplicates events, and assembles an
    immutable DriftSnapshot.
    """

    def evaluate(
        self,
        run_id: str,
        engine_input: MonitoringEngineInput,
    ) -> MonitoringResult:
        ctx = engine_input.context
        events: list[DriftEvent] = []
        domains_evaluated: list[str] = []
        error_summary: str | None = None
        evaluation_success = True

        evaluation_timestamp_iso = _now_iso()

        def _run(domain: str, fn, *args):  # type: ignore[no-untyped-def]
            domains_evaluated.append(domain)
            try:
                result = fn(*args)
                events.extend(result)
            except Exception as exc:
                nonlocal evaluation_success, error_summary
                evaluation_success = False
                error_summary = f"Evaluator '{domain}' encountered an error (details omitted for export safety)."
                logger.exception("Monitoring evaluator '%s' failed: %s", domain, exc)
                events.append(
                    _evaluator_failure_event(
                        domain,
                        run_id,
                        ctx.evaluation_window_start_iso,
                        ctx.evaluation_window_end_iso,
                        "Evaluation incomplete; monitoring coverage is degraded.",
                    )
                )

        if engine_input.policy_inputs:
            _run(
                "policy_drift",
                evaluate_policy_drift,
                engine_input.policy_inputs,
                ctx,
                run_id,
            )

        if engine_input.provenance_inputs:
            _run(
                "provenance_enforcement",
                evaluate_provenance_enforcement,
                engine_input.provenance_inputs,
                ctx,
                run_id,
            )

        if engine_input.provider_inputs:
            _run(
                "provider_governance",
                evaluate_provider_governance,
                engine_input.provider_inputs,
                ctx,
                run_id,
            )

        if engine_input.retrieval_inputs:
            _run(
                "retrieval_degradation",
                evaluate_retrieval_degradation,
                engine_input.retrieval_inputs,
                ctx,
                run_id,
            )

        if engine_input.evidence_inputs:
            _run(
                "evidence_freshness",
                evaluate_evidence_freshness,
                engine_input.evidence_inputs,
                ctx,
                run_id,
            )

        if engine_input.audit_inputs:
            _run(
                "audit_integrity",
                evaluate_audit_integrity,
                engine_input.audit_inputs,
                ctx,
                run_id,
            )

        if engine_input.regression_input is not None:
            _run(
                "readiness_regression",
                evaluate_readiness_regression,
                engine_input.regression_input,
                ctx,
                run_id,
            )

        if engine_input.runtime_inputs:
            _run(
                "runtime_governance",
                evaluate_runtime_governance,
                engine_input.runtime_inputs,
                ctx,
                run_id,
            )

        if engine_input.framework_inputs:
            _run(
                "framework_compliance",
                evaluate_framework_compliance,
                engine_input.framework_inputs,
                ctx,
                run_id,
            )

        dedup = deduplicate_drift_events(events)

        critical_or_blocking = sum(
            1
            for e in dedup.events
            if severity_rank(e.severity) >= severity_rank(DriftSeverity.CRITICAL)
        )

        framework_ids = tuple(
            sorted({fid for e in dedup.events for fid in e.affected_framework_ids})
        )

        snapshot_id = derive_snapshot_id(run_id, evaluation_timestamp_iso)

        replay_contract_metadata = (
            ("monitoring_contract_version", ctx.monitoring_contract_version),
            ("evaluation_engine_version", ctx.evaluation_engine_version),
            ("drift_classification_version", ctx.drift_classification_version),
            ("severity_classification_version", ctx.severity_classification_version),
            ("eval_window_start", ctx.evaluation_window_start_iso),
            ("eval_window_end", ctx.evaluation_window_end_iso),
        )

        snapshot = DriftSnapshot(
            snapshot_id=snapshot_id,
            monitoring_run_id=run_id,
            evaluation_timestamp_iso=evaluation_timestamp_iso,
            monitoring_contract_version=ctx.monitoring_contract_version,
            evaluation_engine_version=ctx.evaluation_engine_version,
            drift_classification_version=ctx.drift_classification_version,
            severity_classification_version=ctx.severity_classification_version,
            events=dedup.events,
            tenant_id=ctx.tenant_id,
            assessment_id=engine_input.framework_inputs[0].assessment_id
            if engine_input.framework_inputs
            else None,
            framework_ids=framework_ids,
            eval_window_start_iso=ctx.evaluation_window_start_iso,
            eval_window_end_iso=ctx.evaluation_window_end_iso,
            evidence_freshness_window_days=ctx.evidence_freshness_window_days,
            total_drift_events=dedup.total_after,
            critical_or_blocking_count=critical_or_blocking,
            domains_evaluated=tuple(domains_evaluated),
            replay_contract_metadata=replay_contract_metadata,
        )

        return MonitoringResult(
            run_id=run_id,
            snapshot=snapshot,
            completed_at_iso=_now_iso(),
            evaluation_success=evaluation_success,
            error_summary=error_summary,
        )
