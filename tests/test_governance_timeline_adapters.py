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

os.environ.setdefault("FG_ENV", "test")


from services.governance.timeline.adapters import (
    TIMELINE_ADAPTERS,
    governance_report_to_timeline_event,
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

    def test_monitoring_not_yet_registered(self):
        assert SourceType.MONITORING not in TIMELINE_ADAPTERS

    def test_alert_not_yet_registered(self):
        assert SourceType.ALERT not in TIMELINE_ADAPTERS

    def test_evidence_not_yet_registered(self):
        assert SourceType.EVIDENCE not in TIMELINE_ADAPTERS
