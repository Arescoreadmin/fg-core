"""tests/test_governance_timeline_adapters.py — Unit tests for timeline adapters.

Covers:
  - simulation_entry_to_timeline_event: field mapping, event_id determinism,
    payload contents, replay_eligible, classification passthrough
  - governance_report_to_timeline_event: field mapping, manifest_hash,
    findings_count, event_id determinism
  - Payload schema_version, event_version, event_origin in every event
  - Causal lineage fields present (parent_event_id, causation_id, correlation_id)
  - Lineage passthrough when caller provides values
  - Deterministic payload key ordering
  - event_version on envelope matches payload schema_version
  - Cross-tenant event ID isolation
  - TIMELINE_ADAPTERS registry completeness

All tests are pure-unit: no DB, no network, no fixtures.
"""

from __future__ import annotations

import os
from datetime import datetime

os.environ.setdefault("FG_ENV", "test")


from services.governance.timeline.adapters import (
    TIMELINE_ADAPTERS,
    _normalize_iso,
    alert_run_to_timeline_event,
    evidence_submitted_to_timeline_event,
    governance_report_to_timeline_event,
    monitoring_run_to_timeline_event,
    simulation_entry_to_timeline_event,
)
from services.governance.timeline.models import SourceType


# ---------------------------------------------------------------------------
# Stub helpers
# ---------------------------------------------------------------------------


def _make_simulation_entry(
    tenant_id: str = "tenant-a",
    simulation_id: str = "sim-abc123",
    scenario_type_value: str = "policy_change",
    uncertainty_value: str = "confirmed",
    risk_direction_value: str = "degraded",
    classification_value: str = "internal",
    total_warnings: int = 2,
    total_critical_warnings: int = 1,
    simulated_at_iso: str = "2026-05-19T00:00:00.000Z",
    assessment_id: str | None = "asmt-001",
    framework_id: str | None = "NIST_AI_RMF",
):
    class _FakeEnum(str):
        def __new__(cls, v):
            obj = str.__new__(cls, v)
            obj.value = v
            return obj

    class _Entry:
        pass

    e = _Entry()
    e.tenant_id = tenant_id
    e.simulation_id = simulation_id
    e.scenario_type = _FakeEnum(scenario_type_value)
    e.uncertainty = _FakeEnum(uncertainty_value)
    e.risk_direction = _FakeEnum(risk_direction_value)
    e.classification = _FakeEnum(classification_value)
    e.total_warnings = total_warnings
    e.total_critical_warnings = total_critical_warnings
    e.simulated_at_iso = simulated_at_iso
    e.assessment_id = assessment_id
    e.framework_id = framework_id
    e.timeline_summary = (
        "Readiness direction: degraded. 2 warning(s) (1 critical/blocking)."
    )
    return e


def _make_report(
    report_id: str = "gr-deadbeef0001",
    assessment_id: str = "asmt-001",
    tenant_id: str = "tenant-a",
    manifest_hash: str = "cafebabe12345678",
    generated_at: str = "2026-05-19T00:00:00.000Z",
    schema_version: str = "1.0",
    findings_count: int = 3,
):
    class _Finding:
        pass

    class _Report:
        pass

    r = _Report()
    r.report_id = report_id
    r.assessment_id = assessment_id
    r.tenant_id = tenant_id
    r.manifest_hash = manifest_hash
    r.generated_at = generated_at
    r.schema_version = schema_version
    r.findings = [_Finding() for _ in range(findings_count)]
    return r


# ---------------------------------------------------------------------------
# TestSimulationAdapter
# ---------------------------------------------------------------------------


class TestSimulationAdapter:
    def test_source_type_is_simulation(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.source_type == SourceType.SIMULATION

    def test_source_id_is_simulation_id(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulation_id="sim-xyz")
        )
        assert evt.source_id == "sim-xyz"

    def test_event_type_is_simulation_completed(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.event_type == "simulation.completed"

    def test_tenant_id_passthrough(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(tenant_id="tenant-b")
        )
        assert evt.tenant_id == "tenant-b"

    def test_occurred_at_matches_simulated_at(self):
        ts = "2026-05-19T12:00:00.000Z"
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulated_at_iso=ts)
        )
        assert evt.occurred_at == ts

    def test_replay_eligible_true(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.replay_eligible is True

    def test_classification_passthrough(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(classification_value="regulator")
        )
        assert evt.classification == "regulator"

    def test_envelope_event_version(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.event_version == "1.0"

    # --- Payload contract ---

    def test_payload_schema_version(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.payload["schema_version"] == "1.0"

    def test_payload_event_origin_is_live(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.payload["event_origin"] == "live"

    def test_payload_contains_scenario_type(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(scenario_type_value="provider_change")
        )
        assert evt.payload["scenario_type"] == "provider_change"

    def test_payload_contains_warning_counts(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(total_warnings=5, total_critical_warnings=2)
        )
        assert evt.payload["total_warnings"] == 5
        assert evt.payload["total_critical_warnings"] == 2

    def test_payload_contains_assessment_id_when_present(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(assessment_id="asmt-999")
        )
        assert evt.payload["assessment_id"] == "asmt-999"

    def test_payload_omits_assessment_id_when_none(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(assessment_id=None)
        )
        assert "assessment_id" not in evt.payload

    def test_payload_omits_framework_id_when_none(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(framework_id=None)
        )
        assert "framework_id" not in evt.payload

    # --- Causal lineage ---

    def test_payload_lineage_fields_present_by_default(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert "parent_event_id" in evt.payload
        assert "causation_id" in evt.payload
        assert "correlation_id" in evt.payload

    def test_payload_lineage_default_none(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.payload["parent_event_id"] is None
        assert evt.payload["causation_id"] is None
        assert evt.payload["correlation_id"] is None

    def test_payload_lineage_passthrough(self):
        evt = simulation_entry_to_timeline_event(
            _make_simulation_entry(),
            parent_event_id="evt-parent",
            causation_id="cause-001",
            correlation_id="corr-abc",
        )
        assert evt.payload["parent_event_id"] == "evt-parent"
        assert evt.payload["causation_id"] == "cause-001"
        assert evt.payload["correlation_id"] == "corr-abc"

    # --- Deterministic ordering ---

    def test_payload_keys_sorted(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        keys = list(evt.payload.keys())
        assert keys == sorted(keys)

    def test_payload_ordering_stable_across_calls(self):
        e1 = simulation_entry_to_timeline_event(_make_simulation_entry())
        e2 = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert list(e1.payload.keys()) == list(e2.payload.keys())

    # --- Event ID ---

    def test_event_id_is_16_hex_chars(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert len(evt.event_id) == 16
        int(evt.event_id, 16)

    def test_event_id_deterministic_same_inputs(self):
        e1 = simulation_entry_to_timeline_event(_make_simulation_entry())
        e2 = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_across_tenants(self):
        ea = simulation_entry_to_timeline_event(
            _make_simulation_entry(tenant_id="tenant-a")
        )
        eb = simulation_entry_to_timeline_event(
            _make_simulation_entry(tenant_id="tenant-b")
        )
        assert ea.event_id != eb.event_id

    def test_event_id_differs_across_simulation_ids(self):
        e1 = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulation_id="sim-001")
        )
        e2 = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulation_id="sim-002")
        )
        assert e1.event_id != e2.event_id

    def test_manifest_hash_is_none(self):
        evt = simulation_entry_to_timeline_event(_make_simulation_entry())
        assert evt.manifest_hash is None


# ---------------------------------------------------------------------------
# TestGovernanceReportAdapter
# ---------------------------------------------------------------------------


class TestGovernanceReportAdapter:
    def test_source_type_is_governance_report(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.source_type == SourceType.GOVERNANCE_REPORT

    def test_source_id_is_report_id(self):
        evt = governance_report_to_timeline_event(_make_report(report_id="gr-aabbcc"))
        assert evt.source_id == "gr-aabbcc"

    def test_event_type_is_report_generated(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.event_type == "report.generated"

    def test_tenant_id_passthrough(self):
        evt = governance_report_to_timeline_event(_make_report(tenant_id="tenant-x"))
        assert evt.tenant_id == "tenant-x"

    def test_occurred_at_matches_generated_at(self):
        ts = "2026-05-19T08:00:00.000Z"
        evt = governance_report_to_timeline_event(_make_report(generated_at=ts))
        assert evt.occurred_at == ts

    def test_manifest_hash_passthrough(self):
        evt = governance_report_to_timeline_event(
            _make_report(manifest_hash="deadbeef1234")
        )
        assert evt.manifest_hash == "deadbeef1234"

    def test_replay_eligible_true(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.replay_eligible is True

    def test_classification_is_internal(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.classification == "internal"

    def test_envelope_event_version(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.event_version == "1.0"

    # --- Payload contract ---

    def test_payload_schema_version(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.payload["schema_version"] == "1.0"

    def test_payload_event_origin_is_live(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.payload["event_origin"] == "live"

    def test_payload_findings_count(self):
        evt = governance_report_to_timeline_event(_make_report(findings_count=7))
        assert evt.payload["findings_count"] == 7

    def test_payload_assessment_id(self):
        evt = governance_report_to_timeline_event(
            _make_report(assessment_id="asmt-007")
        )
        assert evt.payload["assessment_id"] == "asmt-007"

    def test_payload_report_schema_version(self):
        evt = governance_report_to_timeline_event(_make_report(schema_version="1.0"))
        assert evt.payload["report_schema_version"] == "1.0"

    # --- Causal lineage ---

    def test_payload_lineage_fields_present_by_default(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert "parent_event_id" in evt.payload
        assert "causation_id" in evt.payload
        assert "correlation_id" in evt.payload

    def test_payload_lineage_default_none(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert evt.payload["parent_event_id"] is None
        assert evt.payload["causation_id"] is None
        assert evt.payload["correlation_id"] is None

    def test_payload_lineage_passthrough(self):
        evt = governance_report_to_timeline_event(
            _make_report(),
            parent_event_id="evt-sim-001",
            causation_id="trigger-assessment",
            correlation_id="flow-abc",
        )
        assert evt.payload["parent_event_id"] == "evt-sim-001"
        assert evt.payload["causation_id"] == "trigger-assessment"
        assert evt.payload["correlation_id"] == "flow-abc"

    # --- Deterministic ordering ---

    def test_payload_keys_sorted(self):
        evt = governance_report_to_timeline_event(_make_report())
        keys = list(evt.payload.keys())
        assert keys == sorted(keys)

    def test_payload_ordering_stable_across_calls(self):
        e1 = governance_report_to_timeline_event(_make_report())
        e2 = governance_report_to_timeline_event(_make_report())
        assert list(e1.payload.keys()) == list(e2.payload.keys())

    # --- Event ID ---

    def test_event_id_is_16_hex_chars(self):
        evt = governance_report_to_timeline_event(_make_report())
        assert len(evt.event_id) == 16
        int(evt.event_id, 16)

    def test_event_id_deterministic_same_inputs(self):
        e1 = governance_report_to_timeline_event(_make_report())
        e2 = governance_report_to_timeline_event(_make_report())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_across_tenants(self):
        ea = governance_report_to_timeline_event(_make_report(tenant_id="tenant-a"))
        eb = governance_report_to_timeline_event(_make_report(tenant_id="tenant-b"))
        assert ea.event_id != eb.event_id

    def test_event_id_differs_across_report_ids(self):
        e1 = governance_report_to_timeline_event(_make_report(report_id="gr-001"))
        e2 = governance_report_to_timeline_event(_make_report(report_id="gr-002"))
        assert e1.event_id != e2.event_id


# ---------------------------------------------------------------------------
# TestAdapterRegistry
# ---------------------------------------------------------------------------


class TestAdapterRegistry:
    def test_simulation_registered(self):
        assert SourceType.SIMULATION in TIMELINE_ADAPTERS

    def test_governance_report_registered(self):
        assert SourceType.GOVERNANCE_REPORT in TIMELINE_ADAPTERS

    def test_simulation_adapter_callable(self):
        adapter = TIMELINE_ADAPTERS[SourceType.SIMULATION]
        evt = adapter(_make_simulation_entry())
        assert evt.source_type == SourceType.SIMULATION

    def test_governance_report_adapter_callable(self):
        adapter = TIMELINE_ADAPTERS[SourceType.GOVERNANCE_REPORT]
        evt = adapter(_make_report())
        assert evt.source_type == SourceType.GOVERNANCE_REPORT

    def test_monitoring_is_registered(self):
        assert SourceType.MONITORING in TIMELINE_ADAPTERS

    def test_alert_is_registered(self):
        assert SourceType.ALERT in TIMELINE_ADAPTERS

    def test_evidence_is_registered(self):
        assert SourceType.EVIDENCE in TIMELINE_ADAPTERS


# ---------------------------------------------------------------------------
# TestNormalizeIso
# ---------------------------------------------------------------------------


class TestNormalizeIso:
    def test_z_suffix_passthrough(self):
        assert _normalize_iso("2026-05-19T12:00:00.000Z") == "2026-05-19T12:00:00.000Z"

    def test_plus_offset_converted_to_z(self):
        result = _normalize_iso("2026-05-19T12:00:00.000000+00:00")
        assert result.endswith("Z")
        assert "+" not in result

    def test_microseconds_truncated_to_millis(self):
        result = _normalize_iso("2026-05-19T12:00:00.123456+00:00")
        assert result == "2026-05-19T12:00:00.123Z"

    def test_canonical_format_yyyy_mm_ddthhmmss_mmmz(self):
        result = _normalize_iso("2026-05-19T00:00:00.000000+00:00")
        assert result == "2026-05-19T00:00:00.000Z"

    def test_same_instant_different_format_produces_same_string(self):
        a = _normalize_iso("2026-05-19T12:34:56.789Z")
        b = _normalize_iso("2026-05-19T12:34:56.789000+00:00")
        assert a == b

    def test_simulation_adapter_normalizes_plus_offset_timestamp(self):
        entry = _make_simulation_entry(
            simulated_at_iso="2026-05-19T00:00:00.000000+00:00"
        )
        evt = simulation_entry_to_timeline_event(entry)
        assert evt.occurred_at == "2026-05-19T00:00:00.000Z"

    def test_simulation_event_id_stable_across_timestamp_formats(self):
        e_z = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulated_at_iso="2026-05-19T00:00:00.000Z")
        )
        e_plus = simulation_entry_to_timeline_event(
            _make_simulation_entry(simulated_at_iso="2026-05-19T00:00:00.000000+00:00")
        )
        assert e_z.event_id == e_plus.event_id

    def test_report_adapter_normalizes_plus_offset_timestamp(self):
        report = _make_report(generated_at="2026-05-19T08:00:00.000000+00:00")
        evt = governance_report_to_timeline_event(report)
        assert evt.occurred_at == "2026-05-19T08:00:00.000Z"

    def test_report_event_id_stable_across_timestamp_formats(self):
        e_z = governance_report_to_timeline_event(
            _make_report(generated_at="2026-05-19T08:00:00.000Z")
        )
        e_plus = governance_report_to_timeline_event(
            _make_report(generated_at="2026-05-19T08:00:00.000000+00:00")
        )
        assert e_z.event_id == e_plus.event_id


# ---------------------------------------------------------------------------
# Stub helpers — monitoring, alerting, evidence
# ---------------------------------------------------------------------------


def _make_monitoring_record(
    run_id: str = "mon-abc123",
    tenant_id: str = "tenant-a",
    assessment_id: str | None = "asmt-001",
    framework_ids: tuple = ("NIST_AI_RMF",),
    domains_evaluated: tuple = ("evidence_freshness", "framework_compliance"),
    total_drift_events: int = 3,
    critical_or_blocking_count: int = 1,
    evaluation_success: bool = True,
    monitoring_contract_version: str = "1.0",
    evaluation_engine_version: str = "1.0",
    snapshot_id: str = "snap-deadbeef",
    completed_at_iso: str = "2026-05-19T10:00:00.000Z",
    error_summary: str | None = None,
):
    class _Record:
        pass

    r = _Record()
    r.run_id = run_id
    r.tenant_id = tenant_id
    r.assessment_id = assessment_id
    r.framework_ids = framework_ids
    r.domains_evaluated = domains_evaluated
    r.total_drift_events = total_drift_events
    r.critical_or_blocking_count = critical_or_blocking_count
    r.evaluation_success = evaluation_success
    r.monitoring_contract_version = monitoring_contract_version
    r.evaluation_engine_version = evaluation_engine_version
    r.snapshot_id = snapshot_id
    r.completed_at_iso = completed_at_iso
    r.error_summary = error_summary
    r.created_at_iso = "2026-05-19T10:00:00.100Z"
    return r


def _make_alert_run_record(
    run_id: str = "alert-run-001",
    tenant_id: str = "tenant-a",
    source_monitoring_run_id: str = "mon-abc123",
    assessment_id: str | None = "asmt-001",
    total_alerts_generated: int = 2,
    total_alerts_deduplicated: int = 0,
    total_alerts_suppressed: int = 0,
    alert_generation_version: str = "1.0",
    escalation_policy_version: str = "1.0",
    generation_timestamp_iso: str = "2026-05-19T10:05:00.000Z",
    completed: bool = True,
    error_summary: str | None = None,
):
    class _Record:
        pass

    r = _Record()
    r.run_id = run_id
    r.tenant_id = tenant_id
    r.source_monitoring_run_id = source_monitoring_run_id
    r.assessment_id = assessment_id
    r.total_alerts_generated = total_alerts_generated
    r.total_alerts_deduplicated = total_alerts_deduplicated
    r.total_alerts_suppressed = total_alerts_suppressed
    r.alert_generation_version = alert_generation_version
    r.escalation_policy_version = escalation_policy_version
    r.generation_timestamp_iso = generation_timestamp_iso
    r.completed = completed
    r.error_summary = error_summary
    r.created_at_iso = "2026-05-19T10:05:00.100Z"
    return r


def _make_evidence_reference(
    evidence_id: str = "ev-deadbeef",
    assessment_id: str = "asmt-001",
    tenant_id: str = "tenant-a",
    evidence_type_value: str = "document",
    evidence_classification: str | None = "internal",
    control_ids: list | None = None,
    submitted_at_iso: str = "2026-05-19T09:00:00.000Z",
):

    class _FakeEnum(str):
        def __new__(cls, v):
            obj = str.__new__(cls, v)
            obj.value = v
            return obj

    class _EvidenceRef:
        pass

    e = _EvidenceRef()
    e.evidence_id = evidence_id
    e.assessment_id = assessment_id
    e.tenant_id = tenant_id
    e.evidence_type = _FakeEnum(evidence_type_value)
    e.evidence_classification = evidence_classification
    e.control_ids = ["ctrl-001"] if control_ids is None else control_ids
    dt = datetime.fromisoformat(
        submitted_at_iso[:-1] + "+00:00"
        if submitted_at_iso.endswith("Z")
        else submitted_at_iso
    )
    e.submitted_at = dt
    return e


# ---------------------------------------------------------------------------
# TestMonitoringAdapter
# ---------------------------------------------------------------------------


class TestMonitoringAdapter:
    def test_source_type_is_monitoring(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.source_type == SourceType.MONITORING

    def test_source_id_is_run_id(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(run_id="mon-xyz")
        )
        assert evt.source_id == "mon-xyz"

    def test_event_type_is_monitoring_completed(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.event_type == "monitoring.completed"

    def test_tenant_id_passthrough(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(tenant_id="tenant-b")
        )
        assert evt.tenant_id == "tenant-b"

    def test_occurred_at_matches_completed_at(self):
        ts = "2026-05-19T10:00:00.000Z"
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(completed_at_iso=ts)
        )
        assert evt.occurred_at == ts

    def test_replay_eligible_true(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.replay_eligible is True

    def test_classification_is_internal(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.classification == "internal"

    def test_envelope_event_version(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.event_version == "1.0"

    def test_manifest_hash_is_none(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.manifest_hash is None

    # --- Payload contract ---

    def test_payload_schema_version(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.payload["schema_version"] == "1.0"

    def test_payload_event_origin_is_live(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert evt.payload["event_origin"] == "live"

    def test_payload_snapshot_id(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(snapshot_id="snap-cafebabe")
        )
        assert evt.payload["snapshot_id"] == "snap-cafebabe"

    def test_payload_drift_counts(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(total_drift_events=5, critical_or_blocking_count=2)
        )
        assert evt.payload["total_drift_events"] == 5
        assert evt.payload["critical_or_blocking_count"] == 2

    def test_payload_evaluation_success(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(evaluation_success=False)
        )
        assert evt.payload["evaluation_success"] is False

    def test_payload_domains_evaluated_is_list(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert isinstance(evt.payload["domains_evaluated"], list)

    def test_payload_assessment_id_when_present(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(assessment_id="asmt-999")
        )
        assert evt.payload["assessment_id"] == "asmt-999"

    def test_payload_omits_assessment_id_when_none(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(assessment_id=None)
        )
        assert "assessment_id" not in evt.payload

    def test_payload_framework_ids_when_present(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(framework_ids=("NIST_AI_RMF", "ISO_42001"))
        )
        assert evt.payload["framework_ids"] == ["NIST_AI_RMF", "ISO_42001"]

    def test_payload_omits_framework_ids_when_empty(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(framework_ids=())
        )
        assert "framework_ids" not in evt.payload

    def test_payload_error_summary_when_present(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(error_summary="engine_timeout")
        )
        assert evt.payload["error_summary"] == "engine_timeout"

    def test_payload_omits_error_summary_when_none(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(error_summary=None)
        )
        assert "error_summary" not in evt.payload

    def test_payload_keys_sorted(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        keys = list(evt.payload.keys())
        assert keys == sorted(keys)

    def test_payload_lineage_fields_present(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        for field in ("parent_event_id", "causation_id", "correlation_id"):
            assert field in evt.payload

    def test_payload_lineage_passthrough(self):
        evt = monitoring_run_to_timeline_event(
            _make_monitoring_record(),
            parent_event_id="evt-sim",
            causation_id="cause-mon",
            correlation_id="corr-xyz",
        )
        assert evt.payload["parent_event_id"] == "evt-sim"
        assert evt.payload["causation_id"] == "cause-mon"
        assert evt.payload["correlation_id"] == "corr-xyz"

    def test_event_id_deterministic(self):
        e1 = monitoring_run_to_timeline_event(_make_monitoring_record())
        e2 = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_across_tenants(self):
        ea = monitoring_run_to_timeline_event(
            _make_monitoring_record(tenant_id="tenant-a")
        )
        eb = monitoring_run_to_timeline_event(
            _make_monitoring_record(tenant_id="tenant-b")
        )
        assert ea.event_id != eb.event_id

    def test_event_id_is_16_hex_chars(self):
        evt = monitoring_run_to_timeline_event(_make_monitoring_record())
        assert len(evt.event_id) == 16
        int(evt.event_id, 16)


# ---------------------------------------------------------------------------
# TestAlertRunAdapter
# ---------------------------------------------------------------------------


class TestAlertRunAdapter:
    def test_source_type_is_alert(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.source_type == SourceType.ALERT

    def test_source_id_is_run_id(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(run_id="alert-run-xyz")
        )
        assert evt.source_id == "alert-run-xyz"

    def test_event_type_is_alert_run_completed(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.event_type == "alert.run_completed"

    def test_tenant_id_passthrough(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record(tenant_id="tenant-b"))
        assert evt.tenant_id == "tenant-b"

    def test_occurred_at_matches_generation_timestamp(self):
        ts = "2026-05-19T10:05:00.000Z"
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(generation_timestamp_iso=ts)
        )
        assert evt.occurred_at == ts

    def test_replay_eligible_true(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.replay_eligible is True

    def test_classification_is_internal(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.classification == "internal"

    def test_envelope_event_version(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.event_version == "1.0"

    def test_manifest_hash_is_none(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.manifest_hash is None

    # --- Payload contract ---

    def test_payload_schema_version(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.payload["schema_version"] == "1.0"

    def test_payload_event_origin_is_live(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.payload["event_origin"] == "live"

    def test_payload_source_monitoring_run_id(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(source_monitoring_run_id="mon-parent")
        )
        assert evt.payload["source_monitoring_run_id"] == "mon-parent"

    def test_payload_alert_counts(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(
                total_alerts_generated=4,
                total_alerts_deduplicated=1,
                total_alerts_suppressed=0,
            )
        )
        assert evt.payload["total_alerts_generated"] == 4
        assert evt.payload["total_alerts_deduplicated"] == 1
        assert evt.payload["total_alerts_suppressed"] == 0

    def test_payload_version_pins(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert evt.payload["alert_generation_version"] == "1.0"
        assert evt.payload["escalation_policy_version"] == "1.0"

    def test_payload_completed_flag(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record(completed=True))
        assert evt.payload["completed"] is True

    def test_payload_assessment_id_when_present(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(assessment_id="asmt-007")
        )
        assert evt.payload["assessment_id"] == "asmt-007"

    def test_payload_omits_assessment_id_when_none(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record(assessment_id=None))
        assert "assessment_id" not in evt.payload

    def test_payload_error_summary_when_present(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(error_summary="engine_timeout")
        )
        assert evt.payload["error_summary"] == "engine_timeout"

    def test_payload_omits_error_summary_when_none(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record(error_summary=None))
        assert "error_summary" not in evt.payload

    def test_payload_keys_sorted(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        keys = list(evt.payload.keys())
        assert keys == sorted(keys)

    def test_payload_lineage_fields_present(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        for field in ("parent_event_id", "causation_id", "correlation_id"):
            assert field in evt.payload

    def test_payload_lineage_passthrough(self):
        evt = alert_run_to_timeline_event(
            _make_alert_run_record(),
            parent_event_id="evt-mon",
            causation_id="cause-alert",
            correlation_id="corr-xyz",
        )
        assert evt.payload["parent_event_id"] == "evt-mon"
        assert evt.payload["causation_id"] == "cause-alert"
        assert evt.payload["correlation_id"] == "corr-xyz"

    def test_event_id_deterministic(self):
        e1 = alert_run_to_timeline_event(_make_alert_run_record())
        e2 = alert_run_to_timeline_event(_make_alert_run_record())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_across_tenants(self):
        ea = alert_run_to_timeline_event(_make_alert_run_record(tenant_id="tenant-a"))
        eb = alert_run_to_timeline_event(_make_alert_run_record(tenant_id="tenant-b"))
        assert ea.event_id != eb.event_id

    def test_event_id_is_16_hex_chars(self):
        evt = alert_run_to_timeline_event(_make_alert_run_record())
        assert len(evt.event_id) == 16
        int(evt.event_id, 16)


# ---------------------------------------------------------------------------
# TestEvidenceAdapter
# ---------------------------------------------------------------------------


class TestEvidenceAdapter:
    def test_source_type_is_evidence(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.source_type == SourceType.EVIDENCE

    def test_source_id_is_evidence_id(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_id="ev-xyz")
        )
        assert evt.source_id == "ev-xyz"

    def test_event_type_is_evidence_submitted(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.event_type == "evidence.submitted"

    def test_tenant_id_passthrough(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(tenant_id="tenant-b")
        )
        assert evt.tenant_id == "tenant-b"

    def test_occurred_at_matches_submitted_at(self):
        ts = "2026-05-19T09:00:00.000Z"
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(submitted_at_iso=ts)
        )
        assert evt.occurred_at == ts

    def test_replay_eligible_false(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.replay_eligible is False

    def test_classification_from_evidence_classification(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_classification="confidential")
        )
        assert evt.classification == "confidential"

    def test_classification_defaults_to_internal_when_none(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_classification=None)
        )
        assert evt.classification == "internal"

    def test_envelope_event_version(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.event_version == "1.0"

    def test_manifest_hash_is_none(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.manifest_hash is None

    # --- Payload contract ---

    def test_payload_schema_version(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.payload["schema_version"] == "1.0"

    def test_payload_event_origin_is_live(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert evt.payload["event_origin"] == "live"

    def test_payload_assessment_id(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(assessment_id="asmt-777")
        )
        assert evt.payload["assessment_id"] == "asmt-777"

    def test_payload_evidence_type(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_type_value="attestation")
        )
        assert evt.payload["evidence_type"] == "attestation"

    def test_payload_evidence_classification_when_present(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_classification="restricted")
        )
        assert evt.payload["evidence_classification"] == "restricted"

    def test_payload_omits_evidence_classification_when_none(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(evidence_classification=None)
        )
        assert "evidence_classification" not in evt.payload

    def test_payload_control_ids_when_present(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(control_ids=["ctrl-A", "ctrl-B"])
        )
        assert evt.payload["control_ids"] == ["ctrl-A", "ctrl-B"]

    def test_payload_omits_control_ids_when_empty(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(control_ids=[])
        )
        assert "control_ids" not in evt.payload

    def test_payload_keys_sorted(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        keys = list(evt.payload.keys())
        assert keys == sorted(keys)

    def test_payload_lineage_fields_present(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        for field in ("parent_event_id", "causation_id", "correlation_id"):
            assert field in evt.payload

    def test_payload_lineage_passthrough(self):
        evt = evidence_submitted_to_timeline_event(
            _make_evidence_reference(),
            parent_event_id="evt-report",
            causation_id="cause-ev",
            correlation_id="corr-abc",
        )
        assert evt.payload["parent_event_id"] == "evt-report"
        assert evt.payload["causation_id"] == "cause-ev"
        assert evt.payload["correlation_id"] == "corr-abc"

    def test_event_id_deterministic(self):
        e1 = evidence_submitted_to_timeline_event(_make_evidence_reference())
        e2 = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert e1.event_id == e2.event_id

    def test_event_id_differs_across_tenants(self):
        ea = evidence_submitted_to_timeline_event(
            _make_evidence_reference(tenant_id="tenant-a")
        )
        eb = evidence_submitted_to_timeline_event(
            _make_evidence_reference(tenant_id="tenant-b")
        )
        assert ea.event_id != eb.event_id

    def test_event_id_is_16_hex_chars(self):
        evt = evidence_submitted_to_timeline_event(_make_evidence_reference())
        assert len(evt.event_id) == 16
        int(evt.event_id, 16)

    def test_naive_datetime_treated_as_utc(self):
        class _EvidenceRef:
            evidence_id = "ev-naive"
            assessment_id = "asmt-001"
            tenant_id = "tenant-a"
            evidence_classification = "internal"
            control_ids = ["ctrl-001"]

            class evidence_type:
                value = "document"

            submitted_at = datetime(2026, 5, 19, 9, 0, 0)  # naive, no tz

        evt = evidence_submitted_to_timeline_event(_EvidenceRef())
        assert evt.occurred_at == "2026-05-19T09:00:00.000Z"


# ---------------------------------------------------------------------------
# TestAdapterRegistry — updated for PR 101
# ---------------------------------------------------------------------------


class TestAdapterRegistryPR101:
    def test_monitoring_registered(self):
        assert SourceType.MONITORING in TIMELINE_ADAPTERS

    def test_alert_registered(self):
        assert SourceType.ALERT in TIMELINE_ADAPTERS

    def test_evidence_registered(self):
        assert SourceType.EVIDENCE in TIMELINE_ADAPTERS

    def test_monitoring_adapter_callable(self):
        adapter = TIMELINE_ADAPTERS[SourceType.MONITORING]
        evt = adapter(_make_monitoring_record())
        assert evt.source_type == SourceType.MONITORING

    def test_alert_adapter_callable(self):
        adapter = TIMELINE_ADAPTERS[SourceType.ALERT]
        evt = adapter(_make_alert_run_record())
        assert evt.source_type == SourceType.ALERT

    def test_evidence_adapter_callable(self):
        adapter = TIMELINE_ADAPTERS[SourceType.EVIDENCE]
        evt = adapter(_make_evidence_reference())
        assert evt.source_type == SourceType.EVIDENCE
