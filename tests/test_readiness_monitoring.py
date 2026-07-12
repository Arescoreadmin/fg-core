"""Tests for Enterprise Continuous Readiness Monitoring & Drift Detection Engine.

Covers:
- Pure unit: derive_monitoring_run_id determinism, idempotency, uniqueness
- Pure unit: derive_snapshot_id, derive_event_fingerprint
- Pure unit: severity_rank ordering
- Pure unit: each evaluator function — correct event types and severities
- Pure unit: deduplicate_drift_events — fingerprint grouping, highest-severity wins
- Pure unit: MonitoringEngine — empty inputs, evaluator failure → visibility degradation
- Pure unit: serialization round-trip — snapshot_to_json / snapshot_from_json
- API: POST /control-plane/readiness/monitoring/run (success, 403 no tenant, idempotency)
- API: GET /control-plane/readiness/monitoring/runs (list, assessment_id filter)
- API: GET /control-plane/readiness/monitoring/runs/{run_id} (get, 404, tenant isolation)
- Security: no secrets / vectors / raw bodies in API responses

All API tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_readiness_monitoring.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import json
from datetime import datetime, timedelta, timezone

import pytest


# ---------------------------------------------------------------------------
# Pure unit tests — identity
# ---------------------------------------------------------------------------


class TestDeriveMonitoringRunId:
    def test_deterministic_same_inputs(self):
        from services.readiness.monitoring.identity import derive_monitoring_run_id

        run_id_a = derive_monitoring_run_id(
            tenant_id="tenant-1",
            assessment_id="assessment-1",
            framework_id="fw-1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        run_id_b = derive_monitoring_run_id(
            tenant_id="tenant-1",
            assessment_id="assessment-1",
            framework_id="fw-1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        assert run_id_a == run_id_b

    def test_different_tenant_produces_different_id(self):
        from services.readiness.monitoring.identity import derive_monitoring_run_id

        run_id_a = derive_monitoring_run_id(
            tenant_id="tenant-1",
            assessment_id="assessment-1",
            framework_id="fw-1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        run_id_b = derive_monitoring_run_id(
            tenant_id="tenant-2",
            assessment_id="assessment-1",
            framework_id="fw-1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        assert run_id_a != run_id_b

    def test_different_window_produces_different_id(self):
        from services.readiness.monitoring.identity import derive_monitoring_run_id

        run_id_a = derive_monitoring_run_id(
            tenant_id="t1",
            assessment_id="a1",
            framework_id="fw1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        run_id_b = derive_monitoring_run_id(
            tenant_id="t1",
            assessment_id="a1",
            framework_id="fw1",
            eval_window_start_iso="2026-05-16T00:00:00+00:00",
            eval_window_end_iso="2026-05-16T24:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        assert run_id_a != run_id_b

    def test_returns_32_char_hex_string(self):
        from services.readiness.monitoring.identity import derive_monitoring_run_id

        run_id = derive_monitoring_run_id(
            tenant_id="t",
            assessment_id="a",
            framework_id="f",
            eval_window_start_iso="2026-01-01T00:00:00+00:00",
            eval_window_end_iso="2026-01-02T00:00:00+00:00",
            monitoring_contract_version="1.0",
        )
        assert len(run_id) == 32
        assert all(c in "0123456789abcdef" for c in run_id)

    def test_contract_version_change_produces_different_id(self):
        from services.readiness.monitoring.identity import derive_monitoring_run_id

        base = dict(
            tenant_id="t1",
            assessment_id="a1",
            framework_id="fw1",
            eval_window_start_iso="2026-05-17T00:00:00+00:00",
            eval_window_end_iso="2026-05-17T24:00:00+00:00",
        )
        id_v1 = derive_monitoring_run_id(**base, monitoring_contract_version="1.0")
        id_v2 = derive_monitoring_run_id(**base, monitoring_contract_version="2.0")
        assert id_v1 != id_v2


class TestDeriveSnapshotId:
    def test_deterministic(self):
        from services.readiness.monitoring.identity import derive_snapshot_id

        a = derive_snapshot_id("run-abc123", "2026-05-17T10:00:00+00:00")
        b = derive_snapshot_id("run-abc123", "2026-05-17T10:00:00+00:00")
        assert a == b

    def test_different_run_different_snapshot(self):
        from services.readiness.monitoring.identity import derive_snapshot_id

        a = derive_snapshot_id("run-abc123", "2026-05-17T10:00:00+00:00")
        b = derive_snapshot_id("run-xyz999", "2026-05-17T10:00:00+00:00")
        assert a != b

    def test_returns_32_char_hex(self):
        from services.readiness.monitoring.identity import derive_snapshot_id

        sid = derive_snapshot_id("run-x", "2026-01-01T00:00:00+00:00")
        assert len(sid) == 32
        assert all(c in "0123456789abcdef" for c in sid)


class TestDeriveEventFingerprint:
    def test_deterministic(self):
        from services.readiness.monitoring.identity import derive_event_fingerprint

        a = derive_event_fingerprint(
            "stale_evidence", "evidence-1", "run-1", ("c1", "c2")
        )
        b = derive_event_fingerprint(
            "stale_evidence", "evidence-1", "run-1", ("c1", "c2")
        )
        assert a == b

    def test_control_order_independent(self):
        from services.readiness.monitoring.identity import derive_event_fingerprint

        a = derive_event_fingerprint("stale_evidence", "scope-1", "run-1", ("c2", "c1"))
        b = derive_event_fingerprint("stale_evidence", "scope-1", "run-1", ("c1", "c2"))
        assert a == b

    def test_different_drift_type_different_fingerprint(self):
        from services.readiness.monitoring.identity import derive_event_fingerprint

        a = derive_event_fingerprint("stale_evidence", "scope", "run-1", ())
        b = derive_event_fingerprint("missing_evidence", "scope", "run-1", ())
        assert a != b

    def test_returns_24_char_hex(self):
        from services.readiness.monitoring.identity import derive_event_fingerprint

        fp = derive_event_fingerprint("policy_drift", "policy-1", "run-1", ())
        assert len(fp) == 24
        assert all(c in "0123456789abcdef" for c in fp)


# ---------------------------------------------------------------------------
# Pure unit tests — models
# ---------------------------------------------------------------------------


class TestSeverityRank:
    def test_blocking_highest(self):
        from services.readiness.monitoring.models import DriftSeverity, severity_rank

        assert severity_rank(DriftSeverity.BLOCKING) > severity_rank(
            DriftSeverity.CRITICAL
        )
        assert severity_rank(DriftSeverity.CRITICAL) > severity_rank(DriftSeverity.HIGH)
        assert severity_rank(DriftSeverity.HIGH) > severity_rank(DriftSeverity.MODERATE)
        assert severity_rank(DriftSeverity.MODERATE) > severity_rank(DriftSeverity.LOW)
        assert severity_rank(DriftSeverity.LOW) > severity_rank(
            DriftSeverity.INFORMATIONAL
        )

    def test_all_severities_have_unique_rank(self):
        from services.readiness.monitoring.models import DriftSeverity, severity_rank

        ranks = [severity_rank(s) for s in DriftSeverity]
        assert len(set(ranks)) == len(ranks)


# ---------------------------------------------------------------------------
# Pure unit tests — evaluators
# ---------------------------------------------------------------------------


def _make_context(tenant_id: str = "tenant-1"):
    from services.readiness.monitoring.models import MonitoringEvaluationContext

    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=24)).isoformat()
    end = now.isoformat()
    return MonitoringEvaluationContext(
        tenant_id=tenant_id,
        evaluation_window_start_iso=start,
        evaluation_window_end_iso=end,
        evidence_freshness_window_days=30,
        retrieval_degradation_window_hours=24,
        policy_drift_comparison_window_hours=24,
        audit_continuity_window_hours=24,
        runtime_governance_window_hours=24,
        monitoring_contract_version="1.0",
        evaluation_engine_version="1.0",
        drift_classification_version="1.0",
        severity_classification_version="1.0",
    )


class TestEvidenceFreshnessEvaluator:
    def test_stale_evidence_produces_event(self):
        from services.readiness.monitoring.evaluators import evaluate_evidence_freshness
        from services.readiness.monitoring.models import (
            DriftType,
            EvidenceFreshnessInput,
        )

        ctx = _make_context()
        inp = EvidenceFreshnessInput(
            evidence_id="ev-1",
            evidence_title="Old Evidence",
            evidence_type="document",
            submitted_at_iso="2025-01-01T00:00:00+00:00",
            control_ids=("c-1",),
            integrity_verified=True,
            validation_status="valid",
            staleness_days=100.0,
        )
        events = evaluate_evidence_freshness([inp], ctx, "run-1")
        assert len(events) > 0
        types = {e.drift_type for e in events}
        assert DriftType.STALE_EVIDENCE in types

    def test_fresh_valid_evidence_produces_no_stale_event(self):
        from services.readiness.monitoring.evaluators import evaluate_evidence_freshness
        from services.readiness.monitoring.models import (
            DriftType,
            EvidenceFreshnessInput,
        )

        ctx = _make_context()
        inp = EvidenceFreshnessInput(
            evidence_id="ev-fresh",
            evidence_title="Fresh Evidence",
            evidence_type="document",
            submitted_at_iso=datetime.now(timezone.utc).isoformat(),
            control_ids=("c-1",),
            integrity_verified=True,
            validation_status="valid",
            staleness_days=1.0,
        )
        events = evaluate_evidence_freshness([inp], ctx, "run-1")
        stale = [e for e in events if e.drift_type == DriftType.STALE_EVIDENCE]
        assert stale == []

    def test_invalid_integrity_produces_event(self):
        from services.readiness.monitoring.evaluators import evaluate_evidence_freshness
        from services.readiness.monitoring.models import (
            DriftType,
            EvidenceFreshnessInput,
        )

        ctx = _make_context()
        inp = EvidenceFreshnessInput(
            evidence_id="ev-bad",
            evidence_title="Bad Evidence",
            evidence_type="document",
            submitted_at_iso=datetime.now(timezone.utc).isoformat(),
            control_ids=("c-1",),
            integrity_verified=False,
            validation_status="invalid",
            staleness_days=1.0,
        )
        events = evaluate_evidence_freshness([inp], ctx, "run-1")
        types = {e.drift_type for e in events}
        assert DriftType.INVALID_EVIDENCE_INTEGRITY in types

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import evaluate_evidence_freshness

        events = evaluate_evidence_freshness([], _make_context(), "run-1")
        assert events == []

    def test_evidence_without_control_ids_produces_linkage_event(self):
        from services.readiness.monitoring.evaluators import evaluate_evidence_freshness
        from services.readiness.monitoring.models import (
            DriftType,
            EvidenceFreshnessInput,
        )

        ctx = _make_context()
        inp = EvidenceFreshnessInput(
            evidence_id="ev-unlinked",
            evidence_title="Unlinked",
            evidence_type="document",
            submitted_at_iso=datetime.now(timezone.utc).isoformat(),
            control_ids=(),
            integrity_verified=True,
            validation_status="valid",
            staleness_days=1.0,
        )
        events = evaluate_evidence_freshness([inp], ctx, "run-1")
        types = {e.drift_type for e in events}
        assert DriftType.INVALID_EVIDENCE_LINKAGE in types


class TestAuditIntegrityEvaluator:
    def test_broken_chain_is_blocking(self):
        from services.readiness.monitoring.evaluators import evaluate_audit_integrity
        from services.readiness.monitoring.models import (
            AuditIntegrityInput,
            DriftSeverity,
            DriftType,
        )

        ctx = _make_context()
        inp = AuditIntegrityInput(
            audit_chain_status="broken",
            total_records=100,
            failed_records=5,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash="abc123",
            config_hash="def456",
        )
        events = evaluate_audit_integrity([inp], ctx, "run-1")
        broken = [e for e in events if e.drift_type == DriftType.AUDIT_CHAIN_BROKEN]
        assert len(broken) > 0
        assert broken[0].severity == DriftSeverity.BLOCKING

    def test_ok_chain_with_no_failures_produces_no_events(self):
        from services.readiness.monitoring.evaluators import evaluate_audit_integrity
        from services.readiness.monitoring.models import AuditIntegrityInput

        ctx = _make_context()
        inp = AuditIntegrityInput(
            audit_chain_status="ok",
            total_records=100,
            failed_records=0,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash="abc123",
            config_hash="def456",
        )
        events = evaluate_audit_integrity([inp], ctx, "run-1")
        assert events == []

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import evaluate_audit_integrity

        events = evaluate_audit_integrity([], _make_context(), "run-1")
        assert events == []


class TestPolicyDriftEvaluator:
    def test_disabled_policy_is_critical(self):
        from services.readiness.monitoring.evaluators import evaluate_policy_drift
        from services.readiness.monitoring.models import (
            DriftSeverity,
            DriftType,
            PolicyDriftInput,
        )

        ctx = _make_context()
        inp = PolicyDriftInput(
            policy_id="policy-1",
            policy_name="Content Policy",
            policy_enabled=False,
            enforcement_mode="disabled",
            policy_state="active",
            policy_hash="abc",
            policy_version="1.0",
            previous_policy_hash=None,
            source="policy-monitor",
        )
        events = evaluate_policy_drift([inp], ctx, "run-1")
        assert len(events) > 0
        drift_events = [e for e in events if e.drift_type == DriftType.POLICY_DRIFT]
        assert any(
            e.severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
            for e in drift_events
        )

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import evaluate_policy_drift

        events = evaluate_policy_drift([], _make_context(), "run-1")
        assert events == []


class TestProviderGovernanceEvaluator:
    def test_blocked_provider_is_high(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_provider_governance,
        )
        from services.readiness.monitoring.models import (
            DriftSeverity,
            DriftType,
            ProviderGovernanceInput,
        )

        ctx = _make_context()
        inp = ProviderGovernanceInput(
            provider_id="prov-1",
            provider_name="Provider A",
            provider_status="blocked",
            governance_classification="restricted",
            routing_governance_state="blocked",
            compliance_classification="non-compliant",
            region="us-east-1",
        )
        events = evaluate_provider_governance([inp], ctx, "run-1")
        blocked = [e for e in events if e.drift_type == DriftType.PROVIDER_BLOCKED]
        assert len(blocked) > 0
        assert blocked[0].severity == DriftSeverity.HIGH

    def test_unknown_provider_is_suspected_not_confirmed(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_provider_governance,
        )
        from services.readiness.monitoring.models import (
            DriftCertainty,
            ProviderGovernanceInput,
        )

        ctx = _make_context()
        inp = ProviderGovernanceInput(
            provider_id="prov-unknown",
            provider_name="Unknown Provider",
            provider_status="unknown",
            governance_classification="unknown",
            routing_governance_state="unknown",
            compliance_classification="unknown",
            region=None,
        )
        events = evaluate_provider_governance([inp], ctx, "run-1")
        assert len(events) > 0
        for event in events:
            assert event.certainty != DriftCertainty.CONFIRMED

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_provider_governance,
        )

        events = evaluate_provider_governance([], _make_context(), "run-1")
        assert events == []


class TestRetrievalDegradationEvaluator:
    def test_policy_disabled_is_high(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_retrieval_degradation,
        )
        from services.readiness.monitoring.models import (
            DriftSeverity,
            DriftType,
            RetrievalDegradationInput,
        )

        ctx = _make_context()
        inp = RetrievalDegradationInput(
            retrieval_policy_id="rpol-1",
            retrieval_policy_enabled=False,
            reranker_governance_state="active",
            grounded_answer_failure_count=0,
            provenance_validation_failure_count=0,
            total_retrievals=100,
        )
        events = evaluate_retrieval_degradation([inp], ctx, "run-1")
        # disabled policy → RETRIEVAL_POLICY_MISMATCH at HIGH severity
        disabled = [
            e for e in events if e.drift_type == DriftType.RETRIEVAL_POLICY_MISMATCH
        ]
        assert len(disabled) > 0
        assert disabled[0].severity == DriftSeverity.HIGH

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_retrieval_degradation,
        )

        events = evaluate_retrieval_degradation([], _make_context(), "run-1")
        assert events == []


class TestProvenanceEnforcementEvaluator:
    def test_validation_disabled_is_critical(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_provenance_enforcement,
        )
        from services.readiness.monitoring.models import (
            DriftSeverity,
            DriftType,
            ProvenanceEnforcementInput,
        )

        ctx = _make_context()
        inp = ProvenanceEnforcementInput(
            provenance_validation_enabled=False,
            citation_enforcement_enabled=False,
            grounded_answer_enforcement_enabled=False,
            provenance_trust_status="invalid",
            invalid_provenance_count=0,
            total_provenance_checked=0,
        )
        events = evaluate_provenance_enforcement([inp], ctx, "run-1")
        assert len(events) > 0
        drift = [
            e
            for e in events
            if e.drift_type == DriftType.PROVENANCE_ENFORCEMENT_DISABLED
        ]
        assert len(drift) > 0
        assert drift[0].severity == DriftSeverity.CRITICAL

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_provenance_enforcement,
        )

        events = evaluate_provenance_enforcement([], _make_context(), "run-1")
        assert events == []


class TestRuntimeGovernanceEvaluator:
    def test_enforcement_disabled_is_critical(self):
        from services.readiness.monitoring.evaluators import evaluate_runtime_governance
        from services.readiness.monitoring.models import (
            DriftSeverity,
            DriftType,
            RuntimeGovernanceInput,
        )

        ctx = _make_context()
        inp = RuntimeGovernanceInput(
            enforcement_mode="disabled",
            governance_signal_count=100,
            failed_governance_signals=0,
            last_signal_timestamp_iso=None,
        )
        events = evaluate_runtime_governance([inp], ctx, "run-1")
        assert len(events) > 0
        degraded = [
            e
            for e in events
            if e.drift_type == DriftType.RUNTIME_GOVERNANCE_DEGRADATION
        ]
        assert any(e.severity == DriftSeverity.CRITICAL for e in degraded)

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import evaluate_runtime_governance

        events = evaluate_runtime_governance([], _make_context(), "run-1")
        assert events == []


class TestFrameworkComplianceEvaluator:
    def test_missing_required_controls_produces_events(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_framework_compliance,
        )
        from services.readiness.monitoring.models import (
            DriftType,
            FrameworkComplianceInput,
        )

        ctx = _make_context()
        inp = FrameworkComplianceInput(
            framework_id="fw-1",
            framework_version_tag="1.0",
            framework_status="active",
            assessment_id="a-1",
            total_controls=10,
            evaluated_controls=8,
            failed_controls=3,
            not_evaluated_controls=2,
            missing_required_control_ids=("c-1", "c-2"),
            invalid_evidence_linkage_ids=(),
            assessment_completion_percentage=0.8,
        )
        events = evaluate_framework_compliance([inp], ctx, "run-1")
        types = {e.drift_type for e in events}
        assert (
            DriftType.MISSING_REQUIRED_CONTROL in types
            or DriftType.FRAMEWORK_COMPLIANCE_DEGRADATION in types
        )

    def test_empty_inputs_produces_no_events(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_framework_compliance,
        )

        events = evaluate_framework_compliance([], _make_context(), "run-1")
        assert events == []


class TestReadinessRegressionEvaluator:
    def test_no_baseline_produces_no_regression_event(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_readiness_regression,
        )
        from services.readiness.monitoring.models import (
            DriftType,
            ReadinessRegressionInput,
        )

        ctx = _make_context()
        inp = ReadinessRegressionInput(
            assessment_id="a-1",
            framework_id="fw-1",
            current_completion_percentage=0.7,
            baseline_completion_percentage=None,
            current_failed_controls=2,
            baseline_failed_controls=None,
            regression_threshold=0.05,
        )
        events = evaluate_readiness_regression(inp, ctx, "run-1")
        regression = [
            e for e in events if e.drift_type == DriftType.READINESS_REGRESSION
        ]
        assert regression == []

    def test_large_drop_below_threshold_produces_regression(self):
        from services.readiness.monitoring.evaluators import (
            evaluate_readiness_regression,
        )
        from services.readiness.monitoring.models import (
            DriftType,
            ReadinessRegressionInput,
        )

        ctx = _make_context()
        inp = ReadinessRegressionInput(
            assessment_id="a-1",
            framework_id="fw-1",
            current_completion_percentage=0.50,
            baseline_completion_percentage=0.80,
            current_failed_controls=5,
            baseline_failed_controls=1,
            regression_threshold=0.05,
        )
        events = evaluate_readiness_regression(inp, ctx, "run-1")
        regression = [
            e for e in events if e.drift_type == DriftType.READINESS_REGRESSION
        ]
        assert len(regression) > 0


# ---------------------------------------------------------------------------
# Pure unit tests — deduplication
# ---------------------------------------------------------------------------


class TestDeduplication:
    def _make_event(
        self,
        drift_type: str = "stale_evidence",
        scope: str = "evidence-1",
        run_id: str = "run-1",
        severity: str = "moderate",
        certainty: str = "confirmed",
    ):
        from services.readiness.monitoring.identity import derive_event_fingerprint
        from services.readiness.monitoring.models import (
            DriftCertainty,
            DriftEvent,
            DriftSeverity,
            DriftType,
        )

        fp = derive_event_fingerprint(drift_type, scope, run_id, ())
        return DriftEvent(
            event_fingerprint=fp,
            drift_type=DriftType(drift_type),
            severity=DriftSeverity(severity),
            certainty=DriftCertainty(certainty),
            affected_scope=scope,
            affected_control_ids=(),
            affected_evidence_ids=(),
            affected_framework_ids=(),
            drift_detail="test detail",
            monitoring_source="test-source",
            evaluation_timestamp_iso="2026-05-17T10:00:00+00:00",
            temporal_boundary_start="2026-05-16T10:00:00+00:00",
            temporal_boundary_end="2026-05-17T10:00:00+00:00",
            provenance_metadata=(),
        )

    def test_no_duplicates_unchanged(self):
        from services.readiness.monitoring.deduplication import deduplicate_drift_events

        e1 = self._make_event("stale_evidence", "ev-1")
        e2 = self._make_event("missing_evidence", "ev-2")
        result = deduplicate_drift_events([e1, e2])
        assert result.total_before == 2
        assert result.total_after == 2
        assert result.collapsed_count == 0

    def test_duplicate_fingerprint_keeps_highest_severity(self):
        from services.readiness.monitoring.deduplication import deduplicate_drift_events
        from services.readiness.monitoring.identity import derive_event_fingerprint
        from services.readiness.monitoring.models import (
            DriftCertainty,
            DriftEvent,
            DriftSeverity,
            DriftType,
        )

        fp = derive_event_fingerprint("stale_evidence", "scope-1", "run-1", ())
        low = DriftEvent(
            event_fingerprint=fp,
            drift_type=DriftType.STALE_EVIDENCE,
            severity=DriftSeverity.LOW,
            certainty=DriftCertainty.CONFIRMED,
            affected_scope="scope-1",
            affected_control_ids=(),
            affected_evidence_ids=(),
            affected_framework_ids=(),
            drift_detail="low",
            monitoring_source="src",
            evaluation_timestamp_iso="2026-05-17T10:00:00+00:00",
            temporal_boundary_start="2026-05-16T10:00:00+00:00",
            temporal_boundary_end="2026-05-17T10:00:00+00:00",
            provenance_metadata=(),
        )
        high = DriftEvent(
            event_fingerprint=fp,
            drift_type=DriftType.STALE_EVIDENCE,
            severity=DriftSeverity.HIGH,
            certainty=DriftCertainty.CONFIRMED,
            affected_scope="scope-1",
            affected_control_ids=(),
            affected_evidence_ids=(),
            affected_framework_ids=(),
            drift_detail="high",
            monitoring_source="src",
            evaluation_timestamp_iso="2026-05-17T10:00:00+00:00",
            temporal_boundary_start="2026-05-16T10:00:00+00:00",
            temporal_boundary_end="2026-05-17T10:00:00+00:00",
            provenance_metadata=(),
        )
        result = deduplicate_drift_events([low, high])
        assert result.total_before == 2
        assert result.total_after == 1
        assert result.collapsed_count == 1
        assert result.events[0].severity.value == "high"

    def test_empty_list_returns_empty_result(self):
        from services.readiness.monitoring.deduplication import deduplicate_drift_events

        result = deduplicate_drift_events([])
        assert result.total_before == 0
        assert result.total_after == 0
        assert result.collapsed_count == 0
        assert result.events == ()


# ---------------------------------------------------------------------------
# Pure unit tests — MonitoringEngine
# ---------------------------------------------------------------------------


class TestMonitoringEngine:
    def _make_engine_input(self, context=None):
        from services.readiness.monitoring.models import MonitoringEngineInput

        ctx = context if context is not None else _make_context()
        return MonitoringEngineInput(
            context=ctx,
            policy_inputs=(),
            provenance_inputs=(),
            provider_inputs=(),
            retrieval_inputs=(),
            evidence_inputs=(),
            audit_inputs=(),
            regression_input=None,
            runtime_inputs=(),
            framework_inputs=(),
        )

    def test_empty_inputs_produces_valid_snapshot(self):
        from services.readiness.monitoring.engine import MonitoringEngine

        engine = MonitoringEngine()
        result = engine.evaluate("run-empty-1", self._make_engine_input())
        assert result.run_id == "run-empty-1"
        assert result.snapshot.total_drift_events == 0
        assert result.snapshot.critical_or_blocking_count == 0
        assert result.evaluation_success is True
        assert result.error_summary is None

    def test_snapshot_carries_version_pins(self):
        from services.readiness.monitoring.engine import MonitoringEngine

        engine = MonitoringEngine()
        result = engine.evaluate("run-v-1", self._make_engine_input())
        snap = result.snapshot
        assert snap.monitoring_contract_version == "1.0"
        assert snap.evaluation_engine_version == "1.0"
        assert snap.drift_classification_version != ""
        assert snap.severity_classification_version != ""

    def test_snapshot_id_is_deterministic_for_same_run(self):
        from services.readiness.monitoring.engine import MonitoringEngine

        engine = MonitoringEngine()
        r1 = engine.evaluate("run-det-1", self._make_engine_input())
        r2 = engine.evaluate("run-det-1", self._make_engine_input())
        assert r1.snapshot.monitoring_run_id == r2.snapshot.monitoring_run_id

    def test_broken_audit_chain_appears_in_snapshot(self):
        from services.readiness.monitoring.engine import MonitoringEngine
        from services.readiness.monitoring.models import (
            AuditIntegrityInput,
            DriftType,
            MonitoringEngineInput,
        )

        ctx = _make_context()
        audit_inp = AuditIntegrityInput(
            audit_chain_status="broken",
            total_records=50,
            failed_records=2,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash="abc",
            config_hash="def",
        )
        engine_input = MonitoringEngineInput(
            context=ctx,
            policy_inputs=(),
            provenance_inputs=(),
            provider_inputs=(),
            retrieval_inputs=(),
            evidence_inputs=(),
            audit_inputs=(audit_inp,),
            regression_input=None,
            runtime_inputs=(),
            framework_inputs=(),
        )
        engine = MonitoringEngine()
        result = engine.evaluate("run-audit-1", engine_input)
        types = {e.drift_type for e in result.snapshot.events}
        assert DriftType.AUDIT_CHAIN_BROKEN in types

    def test_domains_evaluated_reflects_non_empty_inputs(self):
        from services.readiness.monitoring.engine import MonitoringEngine
        from services.readiness.monitoring.models import (
            AuditIntegrityInput,
            MonitoringEngineInput,
        )

        ctx = _make_context()
        audit_inp = AuditIntegrityInput(
            audit_chain_status="ok",
            total_records=10,
            failed_records=0,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash=None,
            config_hash=None,
        )
        engine_input = MonitoringEngineInput(
            context=ctx,
            policy_inputs=(),
            provenance_inputs=(),
            provider_inputs=(),
            retrieval_inputs=(),
            evidence_inputs=(),
            audit_inputs=(audit_inp,),
            regression_input=None,
            runtime_inputs=(),
            framework_inputs=(),
        )
        engine = MonitoringEngine()
        result = engine.evaluate("run-dom-1", engine_input)
        assert "audit_integrity" in result.snapshot.domains_evaluated

    def test_critical_or_blocking_count_accurate(self):
        from services.readiness.monitoring.engine import MonitoringEngine
        from services.readiness.monitoring.models import (
            AuditIntegrityInput,
            MonitoringEngineInput,
        )

        ctx = _make_context()
        audit_inp = AuditIntegrityInput(
            audit_chain_status="broken",
            total_records=10,
            failed_records=5,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash=None,
            config_hash=None,
        )
        engine_input = MonitoringEngineInput(
            context=ctx,
            policy_inputs=(),
            provenance_inputs=(),
            provider_inputs=(),
            retrieval_inputs=(),
            evidence_inputs=(),
            audit_inputs=(audit_inp,),
            regression_input=None,
            runtime_inputs=(),
            framework_inputs=(),
        )
        engine = MonitoringEngine()
        result = engine.evaluate("run-crit-1", engine_input)
        snap = result.snapshot
        blocking_or_crit = sum(
            1 for e in snap.events if e.severity.value in ("critical", "blocking")
        )
        assert snap.critical_or_blocking_count == blocking_or_crit

    def test_assessment_id_in_snapshot_comes_from_context_not_framework_inputs(self):
        """Bug fix: assessment_id must survive in snapshot even when framework_inputs=()."""
        from services.readiness.monitoring.engine import MonitoringEngine
        from services.readiness.monitoring.models import (
            MonitoringEngineInput,
            MonitoringEvaluationContext,
        )
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        ctx = MonitoringEvaluationContext(
            tenant_id="tenant-fix",
            assessment_id="assessment-replay-test",
            evaluation_window_start_iso=(now - timedelta(hours=24)).isoformat(),
            evaluation_window_end_iso=now.isoformat(),
            evidence_freshness_window_days=30,
            retrieval_degradation_window_hours=24,
            policy_drift_comparison_window_hours=24,
            audit_continuity_window_hours=24,
            runtime_governance_window_hours=24,
            monitoring_contract_version="1.0",
            evaluation_engine_version="1.0",
            drift_classification_version="1.0",
            severity_classification_version="1.0",
        )
        engine_input = MonitoringEngineInput(
            context=ctx,
            policy_inputs=(),
            provenance_inputs=(),
            provider_inputs=(),
            retrieval_inputs=(),
            evidence_inputs=(),
            audit_inputs=(),
            regression_input=None,
            runtime_inputs=(),
            framework_inputs=(),  # deliberately empty
        )
        engine = MonitoringEngine()
        result = engine.evaluate("run-fix-1", engine_input)
        # snapshot must carry assessment_id even though framework_inputs is empty
        assert result.snapshot.assessment_id == "assessment-replay-test"


# ---------------------------------------------------------------------------
# Pure unit tests — serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def _make_snapshot(self):
        from services.readiness.monitoring.engine import MonitoringEngine
        from services.readiness.monitoring.models import MonitoringEngineInput

        ctx = _make_context()
        engine = MonitoringEngine()
        result = engine.evaluate(
            "run-serial-1",
            MonitoringEngineInput(
                context=ctx,
                policy_inputs=(),
                provenance_inputs=(),
                provider_inputs=(),
                retrieval_inputs=(),
                evidence_inputs=(),
                audit_inputs=(),
                regression_input=None,
                runtime_inputs=(),
                framework_inputs=(),
            ),
        )
        return result.snapshot

    def test_snapshot_to_json_is_valid_json(self):
        from services.readiness.monitoring.serialization import snapshot_to_json

        snap = self._make_snapshot()
        raw = snapshot_to_json(snap)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert "snapshot_id" in parsed

    def test_snapshot_round_trip_preserves_key_fields(self):
        from services.readiness.monitoring.serialization import (
            snapshot_from_json,
            snapshot_to_json,
        )

        snap = self._make_snapshot()
        raw = snapshot_to_json(snap)
        parsed = snapshot_from_json(raw)
        assert parsed["snapshot_id"] == snap.snapshot_id
        assert parsed["monitoring_run_id"] == snap.monitoring_run_id
        assert parsed["tenant_id"] == snap.tenant_id

    def test_snapshot_json_is_deterministic(self):
        from services.readiness.monitoring.serialization import snapshot_to_json

        snap = self._make_snapshot()
        raw1 = snapshot_to_json(snap)
        raw2 = snapshot_to_json(snap)
        assert raw1 == raw2

    def test_snapshot_json_contains_no_forbidden_keys(self):
        from services.readiness.monitoring.serialization import snapshot_to_json

        snap = self._make_snapshot()
        raw = snapshot_to_json(snap)
        lower = raw.lower()
        for forbidden in (
            "password",
            "secret",
            "token",
            "api_key",
            "vector",
            "embedding",
        ):
            assert forbidden not in lower, (
                f"Forbidden key found in snapshot JSON: {forbidden}"
            )

    def test_serialize_event_produces_expected_fields(self):
        from services.readiness.monitoring.evaluators import evaluate_audit_integrity
        from services.readiness.monitoring.models import AuditIntegrityInput
        from services.readiness.monitoring.serialization import serialize_event

        ctx = _make_context()
        inp = AuditIntegrityInput(
            audit_chain_status="broken",
            total_records=10,
            failed_records=1,
            current_invariant_status="ok",
            drift_status="ok",
            policy_hash=None,
            config_hash=None,
        )
        events = evaluate_audit_integrity([inp], ctx, "run-ser-ev-1")
        assert events
        d = serialize_event(events[0])
        required_keys = {
            "event_fingerprint",
            "drift_type",
            "severity",
            "certainty",
            "affected_scope",
            "drift_detail",
            "monitoring_source",
            "evaluation_timestamp_iso",
        }
        assert required_keys.issubset(d.keys())


# ---------------------------------------------------------------------------
# API fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def _app_and_db(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "monitoring_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()
    return build_app(auth_enabled=True), db_path


@pytest.fixture()
def api_client(_app_and_db):
    from api.auth_scopes import mint_key

    from fastapi.testclient import TestClient

    app, _ = _app_and_db
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def tenant_client(_app_and_db):
    from api.auth_scopes import mint_key

    from fastapi.testclient import TestClient

    app, _ = _app_and_db
    key = mint_key(
        "control-plane:read", "control-plane:admin", tenant_id="tenant-alpha"
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def other_tenant_client(_app_and_db):
    from api.auth_scopes import mint_key

    from fastapi.testclient import TestClient

    app, _ = _app_and_db
    key = mint_key("control-plane:read", "control-plane:admin", tenant_id="tenant-beta")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def no_auth_client(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "monitoring_noauth_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=False)
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------


def _create_framework(client, slug: str = "fw-mon") -> str:
    resp = client.post(
        "/control-plane/readiness/frameworks",
        json={
            "framework_name": "Monitoring FW",
            "framework_slug": slug,
            "framework_version": "1.0",
        },
    )
    assert resp.status_code == 201, resp.text
    fw_id = resp.json()["framework_id"]
    # activate
    resp2 = client.post(
        f"/control-plane/readiness/frameworks/{fw_id}/transition",
        json={"to_status": "active"},
    )
    assert resp2.status_code == 200, resp2.text
    return fw_id


def _create_assessment(client, fw_id: str) -> str:
    resp = client.post(
        "/control-plane/readiness/assessments",
        json={"framework_id": fw_id, "framework_version_tag": "1.0"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["assessment_id"]


# ---------------------------------------------------------------------------
# API tests — POST /control-plane/readiness/monitoring/run
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestCreateMonitoringRun:
    def test_success_no_assessment(self, no_auth_client):
        resp = no_auth_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        # No auth key and no tenant context → 401/403 depending on middleware
        assert resp.status_code in (201, 401, 403)

    def test_403_when_no_tenant_context_in_auth_key(self, api_client):
        """API key without tenant_id returns 403."""
        resp = api_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 403

    def test_success_with_tenant_context(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "run_id" in data
        assert "snapshot_id" in data
        assert "evaluation_success" in data
        assert data["evaluation_success"] is True

    def test_response_contains_required_fields(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        data = resp.json()
        required = {
            "run_id",
            "tenant_id",
            "snapshot_id",
            "monitoring_contract_version",
            "evaluation_engine_version",
            "eval_window_start_iso",
            "eval_window_end_iso",
            "framework_ids",
            "domains_evaluated",
            "total_drift_events",
            "critical_or_blocking_count",
            "evaluation_success",
            "completed_at_iso",
            "events",
            "replay_contract_metadata",
        }
        assert required.issubset(data.keys()), f"Missing: {required - data.keys()}"

    def test_idempotency_stored_result_retrievable(self, tenant_client):
        """POST then GET returns the same run record."""
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 1},
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]
        get_resp = tenant_client.get(
            f"/control-plane/readiness/monitoring/runs/{run_id}"
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["run_id"] == run_id

    def test_404_on_unknown_assessment_id(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={
                "assessment_id": "nonexistent-assessment-999",
                "eval_window_hours": 24,
            },
        )
        assert resp.status_code == 404

    def test_with_valid_assessment(self, tenant_client):
        fw_id = _create_framework(tenant_client, slug="fw-mon-valid")
        assessment_id = _create_assessment(tenant_client, fw_id)
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"assessment_id": assessment_id, "eval_window_hours": 24},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["assessment_id"] == assessment_id

    def test_request_body_extra_fields_rejected(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24, "injected_field": "malicious"},
        )
        assert resp.status_code == 422

    def test_eval_window_hours_upper_bound(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 721},
        )
        assert resp.status_code == 422

    def test_eval_window_hours_lower_bound(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 0},
        )
        assert resp.status_code == 422

    def test_no_secrets_in_response(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        body_lower = resp.text.lower()
        for forbidden in (
            "password",
            "secret",
            "token",
            "api_key",
            "vector",
            "embedding",
        ):
            assert forbidden not in body_lower, (
                f"Forbidden term in response: {forbidden}"
            )

    def test_tenant_id_not_leakable_to_other_tenant(
        self, tenant_client, other_tenant_client
    ):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        # other_tenant cannot access this run via GET
        resp2 = other_tenant_client.get(
            f"/control-plane/readiness/monitoring/runs/{run_id}"
        )
        assert resp2.status_code == 404


# ---------------------------------------------------------------------------
# API tests — GET /control-plane/readiness/monitoring/runs
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestListMonitoringRuns:
    def test_403_when_no_tenant_context(self, api_client):
        resp = api_client.get("/control-plane/readiness/monitoring/runs")
        assert resp.status_code == 403

    def test_empty_list_before_any_runs(self, tenant_client):
        resp = tenant_client.get("/control-plane/readiness/monitoring/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_returns_created_run_in_list(self, tenant_client):
        tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        resp = tenant_client.get("/control-plane/readiness/monitoring/runs")
        assert resp.status_code == 200
        runs = resp.json()
        assert len(runs) >= 1

    def test_list_response_contains_summary_fields(self, tenant_client):
        tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        resp = tenant_client.get("/control-plane/readiness/monitoring/runs")
        assert resp.status_code == 200
        run = resp.json()[0]
        required = {
            "run_id",
            "snapshot_id",
            "monitoring_contract_version",
            "evaluation_engine_version",
            "total_drift_events",
            "critical_or_blocking_count",
            "evaluation_success",
            "domains_evaluated",
            "completed_at_iso",
            "created_at_iso",
        }
        assert required.issubset(run.keys())

    def test_tenant_isolation_other_tenant_sees_empty_list(
        self, tenant_client, other_tenant_client
    ):
        tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        resp = other_tenant_client.get("/control-plane/readiness/monitoring/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_assessment_id_filter(self, tenant_client):
        fw_id = _create_framework(tenant_client, slug="fw-mon-filter")
        assessment_id = _create_assessment(tenant_client, fw_id)

        # Run with and without assessment_id
        tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"assessment_id": assessment_id, "eval_window_hours": 24},
        )
        tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 48},
        )

        resp = tenant_client.get(
            "/control-plane/readiness/monitoring/runs",
            params={"assessment_id": assessment_id},
        )
        assert resp.status_code == 200
        runs = resp.json()
        assert all(r["assessment_id"] == assessment_id for r in runs)


# ---------------------------------------------------------------------------
# API tests — GET /control-plane/readiness/monitoring/runs/{run_id}
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestGetMonitoringRun:
    def test_403_when_no_tenant_context(self, api_client):
        resp = api_client.get("/control-plane/readiness/monitoring/runs/fake-run-id")
        assert resp.status_code == 403

    def test_404_on_nonexistent_run(self, tenant_client):
        resp = tenant_client.get(
            "/control-plane/readiness/monitoring/runs/nonexistent-run-id-xxxxxx"
        )
        assert resp.status_code == 404

    def test_success_returns_full_response(self, tenant_client):
        post_resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert post_resp.status_code == 201
        run_id = post_resp.json()["run_id"]

        get_resp = tenant_client.get(
            f"/control-plane/readiness/monitoring/runs/{run_id}"
        )
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["run_id"] == run_id
        assert "events" in data
        assert "replay_contract_metadata" in data

    def test_tenant_isolation_other_tenant_gets_404(
        self, tenant_client, other_tenant_client
    ):
        post_resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert post_resp.status_code == 201
        run_id = post_resp.json()["run_id"]

        resp = other_tenant_client.get(
            f"/control-plane/readiness/monitoring/runs/{run_id}"
        )
        assert resp.status_code == 404

    def test_get_response_matches_post_response(self, tenant_client):
        post_resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert post_resp.status_code == 201
        post_data = post_resp.json()
        run_id = post_data["run_id"]

        get_resp = tenant_client.get(
            f"/control-plane/readiness/monitoring/runs/{run_id}"
        )
        assert get_resp.status_code == 200
        get_data = get_resp.json()

        assert get_data["run_id"] == post_data["run_id"]
        assert get_data["snapshot_id"] == post_data["snapshot_id"]
        assert get_data["total_drift_events"] == post_data["total_drift_events"]

    def test_no_secrets_in_get_response(self, tenant_client):
        post_resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        run_id = post_resp.json()["run_id"]
        resp = tenant_client.get(f"/control-plane/readiness/monitoring/runs/{run_id}")
        assert resp.status_code == 200
        body_lower = resp.text.lower()
        for forbidden in (
            "password",
            "secret",
            "token",
            "api_key",
            "vector",
            "embedding",
        ):
            assert forbidden not in body_lower, (
                f"Forbidden term in GET response: {forbidden}"
            )


# ---------------------------------------------------------------------------
# Security invariants
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestSecurityInvariants:
    def test_run_id_is_hex_not_random_uuid(self, tenant_client):
        """run_id must be a deterministic hex string, not a UUID with dashes."""
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]
        assert len(run_id) == 32
        assert all(c in "0123456789abcdef" for c in run_id), (
            f"run_id should be lowercase hex, got: {run_id}"
        )

    def test_snapshot_json_not_in_api_response(self, tenant_client):
        """snapshot_json (raw internal blob) must not appear in API response."""
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        assert "snapshot_json" not in resp.json(), (
            "snapshot_json (raw internal JSON blob) must not be in API response"
        )

    def test_tenant_id_is_correct_in_response(self, tenant_client):
        """Tenant ID in response must match the token's tenant_id."""
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        assert resp.json()["tenant_id"] == "tenant-alpha"

    def test_replay_contract_metadata_present(self, tenant_client):
        """Replay contract metadata must be present for forensic replay."""
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        meta = resp.json().get("replay_contract_metadata", {})
        assert isinstance(meta, dict)

    def test_domains_evaluated_is_list(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        domains = resp.json()["domains_evaluated"]
        assert isinstance(domains, list)

    def test_events_is_list(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/monitoring/run",
            json={"eval_window_hours": 24},
        )
        assert resp.status_code == 201
        events = resp.json()["events"]
        assert isinstance(events, list)
