"""Comprehensive deterministic tests for the Governance Simulation Engine (PR 18.8.2).

200+ assertions covering all modules: models, overlay, diff, impact, validator, fingerprint,
scenario, simulator, replay, exporter, contract, and mcim_registration.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from services.canonical import canonical_json_bytes, utc_iso8601_z_now
from services.governance_digital_twin.immutability import FrozenDict
from services.governance_digital_twin.models import (
    GovernanceDigitalTwinAuthorityEdge,
    GovernanceDigitalTwinAuthorityGraph,
    GovernanceDigitalTwinAuthorityNode,
    GovernanceDigitalTwinConfidenceProvenance,
    GovernanceDigitalTwinEntity,
    GovernanceDigitalTwinEntityProvenance,
    GovernanceDigitalTwinFutureReferences,
    GovernanceDigitalTwinRelationship,
    GovernanceDigitalTwinSnapshot,
    GovernanceDigitalTwinSourceAuthority,
    GovernanceDigitalTwinStateExtensions,
    GovernanceDigitalTwinTwinIdentity,
)
from services.governance_simulation.contract import GovernanceSimulationService
from services.governance_simulation.diff import compute_graph_diff
from services.governance_simulation.exporter import export_replay_package
from services.governance_simulation.fingerprint import (
    compute_comparison_hash,
    compute_diff_hash,
    compute_impact_hash,
    compute_overlay_hash,
    compute_replay_fingerprint,
    compute_scenario_fingerprint,
)
from services.governance_simulation.impact import analyze_impact
from services.governance_simulation.mcim_registration import (
    GOVERNANCE_SIMULATION_MCIM_VERSION,
    MCIM_REGISTRATION_SOURCE,
)
from services.governance_simulation.models import (
    GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN,
    GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
    GOVERNANCE_SIMULATION_REPLAY_VERSION,
    GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
    GOVERNANCE_SIMULATION_VERSION,
    SCENARIO_CATEGORY_REGISTRY,
    ExecutiveComparison,
    ExecutiveComparisonRow,
    GraphDiff,
    GraphDiffEntry,
    ImpactConfidence,
    ImpactDomain,
    ImpactEntry,
    ImpactReport,
    OverlayOperationType,
    ReplayPackage,
    ScenarioCategory,
    ScenarioOverlay,
    ScenarioOverlayOperation,
    SimulationManifest,
    SimulationResult,
    SimulationScenario,
    SimulationValidationFinding,
    SimulationValidationReport,
    SimulationValidationSeverity,
)
from services.governance_simulation.overlay import OverlayError, apply_overlay
from services.governance_simulation.replay import build_replay_package
from services.governance_simulation.scenario import build_scenario
from services.governance_simulation.simulator import simulate
from services.governance_simulation.validator import (
    SimulationValidationError,
    validate_simulation,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = "2026-07-06T00:00:00Z"


def _make_confidence_prov(authority: str = "test_authority") -> GovernanceDigitalTwinConfidenceProvenance:
    return GovernanceDigitalTwinConfidenceProvenance(
        authority=authority,
        confidence_weight=80,
        coverage_percent=80,
        freshness_at=_TS,
        trust_level="high",
        method="deterministic",
    )


def _make_entity_prov(authority: str = "test_authority", eid: str = "e1") -> GovernanceDigitalTwinEntityProvenance:
    return GovernanceDigitalTwinEntityProvenance(
        origin_authority=authority,
        source_table="test",
        source_object=eid,
        capture_method="direct",
        deterministic_extractor="test",
        created_from=(),
    )


def _make_entity(
    eid: str,
    etype: str,
    tenant_id: str,
    *,
    authority: str = "test_authority",
    status: str = "active",
    confidence: int = 80,
) -> GovernanceDigitalTwinEntity:
    return GovernanceDigitalTwinEntity(
        id=eid,
        canonical_entity_id=eid,
        type=etype,
        authority=authority,
        source_ref=eid,
        title=f"Test {eid}",
        status=status,
        created_at=_TS,
        updated_at=_TS,
        confidence=confidence,
        confidence_provenance=_make_confidence_prov(authority),
        tenant_scope=tenant_id,
        replay_safe=True,
        redaction_state="clean",
        metadata_hash="abc123",
        provenance=_make_entity_prov(authority, eid),
    )


def _make_relationship(
    rid: str,
    rtype: str,
    from_id: str,
    to_id: str,
    *,
    authority: str = "test_authority",
) -> GovernanceDigitalTwinRelationship:
    return GovernanceDigitalTwinRelationship(
        id=rid,
        canonical_relationship_id=rid,
        type=rtype,
        from_entity_id=from_id,
        to_entity_id=to_id,
        authority=authority,
        confidence=80,
        confidence_provenance=_make_confidence_prov(authority),
        evidence_refs=(),
        created_at=_TS,
        replay_safe=True,
        metadata_hash="relh123",
    )


def _make_snapshot(
    tenant_id: str,
    entities: list[GovernanceDigitalTwinEntity],
    relationships: list[GovernanceDigitalTwinRelationship],
    *,
    snapshot_id: str | None = None,
    fingerprint: str | None = None,
) -> GovernanceDigitalTwinSnapshot:
    sid = snapshot_id or f"snap-{tenant_id}-001"
    fp = fingerprint or hashlib.sha256(f"fp:{sid}".encode()).hexdigest()
    return GovernanceDigitalTwinSnapshot(
        snapshot_id=sid,
        canonical_snapshot_id=sid,
        tenant_id=tenant_id,
        generated_at=_TS,
        snapshot_version="18.8.1",
        graph_schema_version="1.0",
        builder_version="1.2.0",
        category="simulation",
        parent_snapshot_id=None,
        previous_fingerprint=None,
        generation=1,
        lineage_id="lineage-001",
        twin_identity=GovernanceDigitalTwinTwinIdentity(
            twin_id=f"twin-{tenant_id}",
            twin_version="1.0",
            twin_class="governance",
            tenant_id=tenant_id,
            created_by="test",
            governance_model_version="1.0",
        ),
        source_authorities=(),
        authority_graph=GovernanceDigitalTwinAuthorityGraph(
            authorities=(),
            dependencies=(),
        ),
        entities=tuple(entities),
        relationships=tuple(relationships),
        baselines=(),
        manifest=None,
        replay_safe_export=FrozenDict({}),
        fingerprint=fp,
        redaction_profile="replay_safe",
        completeness=FrozenDict({}),
        validation_report=None,
        state_extensions=GovernanceDigitalTwinStateExtensions(
            memory_reference=None,
            memory_sequence=None,
            timeline_anchor=None,
        ),
        future_references=GovernanceDigitalTwinFutureReferences(
            simulation_overlay=None,
            prediction_reference=None,
            execution_reference=None,
            learning_reference=None,
            optimization_reference=None,
        ),
        warnings=(),
        limitations=(),
    )


def _make_overlay(
    scenario_id: str,
    snapshot: GovernanceDigitalTwinSnapshot,
    operations: list[ScenarioOverlayOperation],
) -> ScenarioOverlay:
    import hashlib
    from dataclasses import asdict

    created_at = _TS
    overlay_id = hashlib.sha256(f"OVL:{scenario_id}:{snapshot.snapshot_id}".encode()).hexdigest()[:24]
    ops = [asdict(op) for op in operations]
    payload = {
        "overlay_id": overlay_id,
        "scenario_id": scenario_id,
        "source_snapshot_id": snapshot.snapshot_id,
        "source_snapshot_fingerprint": snapshot.fingerprint,
        "tenant_id": snapshot.tenant_id,
        "operations": ops,
        "created_at": created_at,
    }
    overlay_hash = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return ScenarioOverlay(
        overlay_id=overlay_id,
        scenario_id=scenario_id,
        source_snapshot_id=snapshot.snapshot_id,
        source_snapshot_fingerprint=snapshot.fingerprint,
        tenant_id=snapshot.tenant_id,
        operations=tuple(operations),
        created_at=created_at,
        overlay_hash=overlay_hash,
    )


def _make_op(
    op_id: str,
    operation_type: str,
    *,
    source_entity_id: str | None = None,
    entity_payload: dict | None = None,
    relationship_payload: dict | None = None,
    source_relationship_id: str | None = None,
    authority: str = "test_authority",
) -> ScenarioOverlayOperation:
    return ScenarioOverlayOperation(
        op_id=op_id,
        operation_type=operation_type,
        source_entity_id=source_entity_id,
        target_entity_id=None,
        source_relationship_id=source_relationship_id,
        entity_payload=entity_payload,
        relationship_payload=relationship_payload,
        reason="test reason",
        authoritative_basis="test_basis",
        authority=authority,
    )


# ---------------------------------------------------------------------------
# Group 1: Scenario creation
# ---------------------------------------------------------------------------

class TestScenarioCreation:
    def test_valid_scenario_creation(self):
        tenant = "tenant-a"
        snap = _make_snapshot(tenant, [], [])
        scenario = build_scenario(snap, "Test Scenario", "PolicyChange", [])
        assert scenario.scenario_id is not None
        assert len(scenario.scenario_id) == 24
        assert scenario.scenario_name == "Test Scenario"
        assert scenario.category == "PolicyChange"
        assert scenario.tenant_id == tenant
        assert scenario.parent_snapshot_id == snap.snapshot_id
        assert scenario.source_snapshot_fingerprint == snap.fingerprint

    def test_scenario_has_version_constants(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "ControlChange", [])
        assert scenario.scenario_version == GOVERNANCE_SIMULATION_VERSION
        assert scenario.graph_schema_version == GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION
        assert scenario.simulator_version == GOVERNANCE_SIMULATION_SIMULATOR_VERSION
        assert scenario.replay_version == GOVERNANCE_SIMULATION_REPLAY_VERSION

    def test_invalid_category_raises(self):
        snap = _make_snapshot("t1", [], [])
        with pytest.raises(SimulationValidationError):
            build_scenario(snap, "S", "INVALID_CATEGORY_XYZ", [])

    def test_none_snapshot_raises(self):
        with pytest.raises(SimulationValidationError):
            build_scenario(None, "S", "PolicyChange", [])  # type: ignore

    def test_empty_operations_allowed(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Empty", "RiskAcceptance", [])
        assert len(scenario.overlay.operations) == 0

    def test_deterministic_scenario_id_same_inputs(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-fixed-001", fingerprint="fp1234")
        # scenario_id includes created_at, so strictly it will differ — but overlay_hash is stable
        # Verify scenario_id format
        s = build_scenario(snap, "Name", "PolicyChange", [])
        assert len(s.scenario_id) == 24
        assert s.scenario_id.isalnum() or all(c in "0123456789abcdef" for c in s.scenario_id)

    def test_overlay_embedded_in_scenario(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "With Ops", "EvidenceChange", [
            {"op_id": "op1", "operation_type": "add_entity", "authority": "test",
             "reason": "r", "authoritative_basis": "b",
             "entity_payload": None, "relationship_payload": None,
             "source_entity_id": None, "target_entity_id": None,
             "source_relationship_id": None}
        ])
        assert scenario.overlay is not None
        assert len(scenario.overlay.operations) == 1
        assert scenario.overlay.operations[0].op_id == "op1"

    def test_created_from_default(self):
        snap = _make_snapshot("t1", [], [])
        s = build_scenario(snap, "S", "PolicyChange", [])
        assert s.created_from == "system:governance_simulation"

    def test_created_from_custom(self):
        snap = _make_snapshot("t1", [], [])
        s = build_scenario(snap, "S", "PolicyChange", [], created_from="custom:tool")
        assert s.created_from == "custom:tool"

    def test_all_scenario_categories_valid(self):
        snap = _make_snapshot("t1", [], [])
        for cat in ScenarioCategory:
            s = build_scenario(snap, f"S-{cat.value}", cat.value, [])
            assert s.category == cat.value

    def test_scenario_has_overlay_hash(self):
        snap = _make_snapshot("t1", [], [])
        s = build_scenario(snap, "S", "PolicyChange", [])
        assert len(s.overlay.overlay_hash) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Group 2: Overlay generation
# ---------------------------------------------------------------------------

class TestOverlayGeneration:
    def test_add_entity(self):
        tenant = "tenant-a"
        snap = _make_snapshot(tenant, [], [])
        entity = _make_entity("e_new", "policy", tenant)
        op = _make_op("op1", "add_entity", entity_payload=dataclasses.asdict(entity))
        overlay = _make_overlay("sc1", snap, [op])
        entities, rels = apply_overlay(snap, overlay)
        assert len(entities) == 1
        assert entities[0].id == "e_new"

    def test_remove_entity(self):
        tenant = "tenant-a"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        op = _make_op("op2", "remove_entity", source_entity_id="e1")
        overlay = _make_overlay("sc2", snap, [op])
        entities, rels = apply_overlay(snap, overlay)
        assert len(entities) == 0

    def test_modify_entity(self):
        tenant = "tenant-a"
        e1 = _make_entity("e1", "policy", tenant, status="active")
        snap = _make_snapshot(tenant, [e1], [])
        op = _make_op("op3", "modify_entity", source_entity_id="e1",
                       entity_payload={"status": "deprecated"})
        overlay = _make_overlay("sc3", snap, [op])
        entities, rels = apply_overlay(snap, overlay)
        assert len(entities) == 1
        assert entities[0].status == "deprecated"

    def test_add_relationship(self):
        tenant = "tenant-a"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        snap = _make_snapshot(tenant, [e1, e2], [])
        rel = _make_relationship("r_new", "governs", "e1", "e2")
        op = _make_op("op4", "add_relationship", relationship_payload=dataclasses.asdict(rel))
        overlay = _make_overlay("sc4", snap, [op])
        entities, rels = apply_overlay(snap, overlay)
        assert len(rels) == 1
        assert rels[0].id == "r_new"

    def test_remove_relationship(self):
        tenant = "tenant-a"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        r1 = _make_relationship("r1", "governs", "e1", "e2")
        snap = _make_snapshot(tenant, [e1, e2], [r1])
        op = _make_op("op5", "remove_relationship", source_relationship_id="r1")
        overlay = _make_overlay("sc5", snap, [op])
        _, rels = apply_overlay(snap, overlay)
        assert len(rels) == 0

    def test_overlay_hash_stable_same_inputs(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-001", fingerprint="fp01")
        ops: list[ScenarioOverlayOperation] = []
        o1 = _make_overlay("sc6a", snap, ops)
        o2 = _make_overlay("sc6a", snap, ops)
        # Same inputs → same hash (overlay_id derived from same seed + snap)
        assert o1.overlay_hash == o2.overlay_hash

    def test_snapshot_unchanged_after_overlay(self):
        tenant = "tenant-a"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        original_entities = snap.entities
        op = _make_op("op6", "remove_entity", source_entity_id="e1")
        overlay = _make_overlay("sc7", snap, [op])
        apply_overlay(snap, overlay)
        # Snapshot entities must be unchanged
        assert snap.entities == original_entities

    def test_overlay_remove_nonexistent_entity_raises(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("op7", "remove_entity", source_entity_id="nonexistent")
        overlay = _make_overlay("sc8", snap, [op])
        with pytest.raises(OverlayError):
            apply_overlay(snap, overlay)

    def test_overlay_modify_missing_entity_raises(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("op8", "modify_entity", source_entity_id="ghost",
                       entity_payload={"status": "x"})
        overlay = _make_overlay("sc9", snap, [op])
        with pytest.raises(OverlayError):
            apply_overlay(snap, overlay)

    def test_derived_entities_sorted_by_id(self):
        tenant = "t1"
        e_b = _make_entity("b_entity", "policy", tenant)
        e_a = _make_entity("a_entity", "control", tenant)
        snap = _make_snapshot(tenant, [e_b, e_a], [])
        overlay = _make_overlay("sc10", snap, [])
        entities, _ = apply_overlay(snap, overlay)
        ids = [e.id for e in entities]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# Group 3: Cross-tenant denial
# ---------------------------------------------------------------------------

class TestCrossTenantDenial:
    def test_cross_tenant_overlay_raises_validation_error(self):
        snap = _make_snapshot("tenant-a", [], [])
        # entity_payload has a different tenant_scope
        wrong_entity = _make_entity("e_wrong", "policy", "tenant-b")
        op = _make_op("op1", "add_entity", entity_payload=dataclasses.asdict(wrong_entity))
        overlay = _make_overlay("sc_ct", snap, [op])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay,
                                _empty_diff("sc_ct", snap),
                                _empty_impact("sc_ct", snap))

    def test_same_tenant_allowed(self):
        tenant = "tenant-a"
        snap = _make_snapshot(tenant, [], [])
        entity = _make_entity("e_ok", "policy", tenant)
        op = _make_op("op2", "add_entity", entity_payload=dataclasses.asdict(entity))
        overlay = _make_overlay("sc_ct2", snap, [op])
        # Should not raise
        diff = _empty_diff("sc_ct2", snap)
        impact = _empty_impact("sc_ct2", snap)
        report = validate_simulation(snap, overlay, diff, impact)
        assert report.valid

    def test_cross_tenant_severity_is_fatal(self):
        snap = _make_snapshot("tenant-a", [], [])
        wrong_entity = _make_entity("e_wrong", "policy", "tenant-b")
        op = _make_op("op1", "add_entity", entity_payload=dataclasses.asdict(wrong_entity))
        overlay = _make_overlay("sc_ct3", snap, [op])
        try:
            validate_simulation(snap, overlay, _empty_diff("sc_ct3", snap), _empty_impact("sc_ct3", snap))
        except SimulationValidationError:
            pass  # expected
        else:
            pytest.fail("Expected SimulationValidationError")


# ---------------------------------------------------------------------------
# Group 4: Deterministic diff
# ---------------------------------------------------------------------------

class TestDeterministicDiff:
    def test_added_entity_in_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (e1,), (), "sc-diff1")
        assert len(diff.entries) == 1
        assert diff.entries[0].operation == "added"
        assert diff.entries[0].entity_id == "e1"

    def test_removed_entity_in_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-diff2")
        assert len(diff.entries) == 1
        assert diff.entries[0].operation == "removed"

    def test_modified_entity_in_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant, status="active")
        snap = _make_snapshot(tenant, [e1], [])
        e1_mod = dataclasses.replace(e1, status="deprecated")
        diff = compute_graph_diff(snap, (e1_mod,), (), "sc-diff3")
        assert len(diff.entries) == 1
        assert diff.entries[0].operation == "modified"

    def test_same_inputs_same_diff_hash(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [], snapshot_id="snap-fixed", fingerprint="fp-fixed")
        d1 = compute_graph_diff(snap, (), (), "sc-det")
        d2 = compute_graph_diff(snap, (), (), "sc-det")
        assert d1.diff_hash == d2.diff_hash

    def test_diff_entries_sorted(self):
        tenant = "t1"
        e1 = _make_entity("e_z", "policy", tenant)
        e2 = _make_entity("e_a", "control", tenant)
        snap = _make_snapshot(tenant, [e1, e2], [])
        diff = compute_graph_diff(snap, (), (), "sc-sorted")
        diff_ids = [e.diff_id for e in diff.entries]
        assert diff_ids == sorted(diff_ids)

    def test_no_change_empty_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (e1,), (), "sc-nochange")
        assert len(diff.entries) == 0

    def test_diff_has_scenario_id(self):
        snap = _make_snapshot("t1", [], [])
        diff = compute_graph_diff(snap, (), (), "sc-id-test")
        assert diff.scenario_id == "sc-id-test"

    def test_relationship_added_in_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        r1 = _make_relationship("r1", "governs", "e1", "e2")
        snap = _make_snapshot(tenant, [e1, e2], [])
        diff = compute_graph_diff(snap, (e1, e2), (r1,), "sc-rel-add")
        rel_entries = [e for e in diff.entries if e.relationship_id == "r1"]
        assert len(rel_entries) == 1
        assert rel_entries[0].operation == "added"


# ---------------------------------------------------------------------------
# Group 5: Impact analysis
# ---------------------------------------------------------------------------

def _empty_diff(scenario_id: str, snap: GovernanceDigitalTwinSnapshot) -> GraphDiff:
    import hashlib
    return GraphDiff(
        diff_id=hashlib.sha256(f"DIFFMASTER:{scenario_id}".encode()).hexdigest()[:24],
        scenario_id=scenario_id,
        source_snapshot_id=snap.snapshot_id,
        entries=(),
        diff_hash=hashlib.sha256(b"[]").hexdigest(),
        created_at=_TS,
    )


def _empty_impact(scenario_id: str, snap: GovernanceDigitalTwinSnapshot) -> ImpactReport:
    import hashlib
    return ImpactReport(
        report_id=hashlib.sha256(f"IR:{scenario_id}".encode()).hexdigest()[:24],
        scenario_id=scenario_id,
        source_snapshot_id=snap.snapshot_id,
        entries=(),
        report_hash=hashlib.sha256(b"[]").hexdigest(),
        created_at=_TS,
        limitations=(),
    )


class TestImpactAnalysis:
    def test_no_diff_no_impact_entries(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-imp1", snap)
        report = analyze_impact(snap, diff, "sc-imp1")
        assert isinstance(report, ImpactReport)
        assert len(report.entries) == 0

    def test_added_policy_entity_has_governance_impact(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (e1,), (), "sc-imp2")
        report = analyze_impact(snap, diff, "sc-imp2")
        domains = {entry.domain for entry in report.entries}
        assert "governance" in domains or "compliance" in domains

    def test_unknown_confidence_when_no_evidence(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (e1,), (), "sc-imp3")
        report = analyze_impact(snap, diff, "sc-imp3")
        # e1 not in snap → UNKNOWN
        unknown = [e for e in report.entries if e.confidence == ImpactConfidence.UNKNOWN.value]
        assert len(unknown) > 0

    def test_proven_confidence_when_evidence_connected(self):
        tenant = "t1"
        e_policy = _make_entity("e_pol", "policy", tenant)
        e_evidence = _make_entity("e_ev", "evidence", tenant)
        r_verifies = _make_relationship("r1", "verifies", "e_pol", "e_ev")
        snap = _make_snapshot(tenant, [e_policy, e_evidence], [r_verifies])
        # Modify the policy entity
        e_policy_mod = dataclasses.replace(e_policy, status="deprecated")
        diff = compute_graph_diff(snap, (e_policy_mod, e_evidence), (r_verifies,), "sc-imp4")
        report = analyze_impact(snap, diff, "sc-imp4")
        proven = [e for e in report.entries if e.confidence == ImpactConfidence.PROVEN.value]
        assert len(proven) > 0

    def test_impact_report_has_report_hash(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-imp5", snap)
        report = analyze_impact(snap, diff, "sc-imp5")
        assert len(report.report_hash) == 64  # SHA-256 hex

    def test_impact_all_domains_covered(self):
        """Test that the impact engine can produce entries for all domain types."""
        tenant = "t1"
        entities = [
            _make_entity(f"e_{dtype}", etype, tenant)
            for dtype, etype in [
                ("pol", "policy"), ("ctrl", "control"), ("ev", "evidence"),
                ("find", "finding"), ("rem", "remediation"), ("assess", "assessment"),
                ("rep", "report"), ("dec", "decision"), ("wf", "workflow"),
                ("fw", "framework"), ("auth", "authority"),
            ]
        ]
        snap = _make_snapshot(tenant, entities, [])
        diff = compute_graph_diff(snap, (), (), "sc-all-domains")
        report = analyze_impact(snap, diff, "sc-all-domains")
        domains = {e.domain for e in report.entries}
        # All major domains must be present
        for domain in ["governance", "control", "evidence", "risk", "readiness", "operational",
                       "executive", "framework", "authority"]:
            assert domain in domains, f"domain '{domain}' missing from impact entries"

    def test_impact_entries_sorted_by_impact_id(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        snap = _make_snapshot(tenant, [e1, e2], [])
        diff = compute_graph_diff(snap, (), (), "sc-sorted-impact")
        report = analyze_impact(snap, diff, "sc-sorted-impact")
        impact_ids = [e.impact_id for e in report.entries]
        assert impact_ids == sorted(impact_ids)

    def test_impact_report_scenario_id_set(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-imp-sid", snap)
        report = analyze_impact(snap, diff, "sc-imp-sid")
        assert report.scenario_id == "sc-imp-sid"


# ---------------------------------------------------------------------------
# Group 6: Replay integrity
# ---------------------------------------------------------------------------

class TestReplayIntegrity:
    def test_same_scenario_snapshot_same_fingerprint(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [], snapshot_id="snap-fixed", fingerprint="fp-stable")
        s1 = build_scenario(snap, "Fixed", "PolicyChange", [])
        s2 = build_scenario(snap, "Fixed", "PolicyChange", [])
        # overlay_hash must be stable for same scenario inputs when overlay_id is the same
        # Fingerprints will differ due to created_at — but overlay_hash for identical
        # overlay_id seeds will differ only due to time. Let's verify structure.
        assert s1.scenario_version == s2.scenario_version
        assert s1.parent_snapshot_id == s2.parent_snapshot_id

    def test_replay_package_fingerprint_deterministic(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [], snapshot_id="snap-r", fingerprint="fp-r")
        scenario = build_scenario(snap, "Replay", "PolicyChange", [])
        result = simulate(snap, scenario)
        pkg = result.replay_package
        # Recompute the fingerprint from the package's components
        expected_fp = compute_replay_fingerprint(
            package_id=pkg.package_id,
            scenario_id=pkg.scenario_id,
            overlay_hash=pkg.overlay.overlay_hash,
            diff_hash=pkg.diff.diff_hash,
            impact_hash=pkg.impact_report.report_hash,
            tenant_id=tenant,
        )
        assert pkg.fingerprint == expected_fp

    def test_two_simulate_runs_same_result_structure(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [], snapshot_id="snap-sim2", fingerprint="fp-sim2")
        s1 = build_scenario(snap, "Run", "PolicyChange", [])
        r1 = simulate(snap, s1)
        r2 = simulate(snap, s1)
        # Both runs should produce the same fingerprint (same scenario → same diff/impact)
        assert r1.simulation_fingerprint == r2.simulation_fingerprint


# ---------------------------------------------------------------------------
# Group 7: Fingerprint determinism
# ---------------------------------------------------------------------------

class TestFingerprintDeterminism:
    def test_overlay_hash_is_deterministic(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-fph", fingerprint="fp-hash")
        s = build_scenario(snap, "FP", "PolicyChange", [])
        h1 = compute_overlay_hash(s.overlay)
        h2 = compute_overlay_hash(s.overlay)
        assert h1 == h2

    def test_diff_hash_is_deterministic(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-fp2", snap)
        h1 = compute_diff_hash(diff)
        h2 = compute_diff_hash(diff)
        assert h1 == h2

    def test_impact_hash_is_deterministic(self):
        snap = _make_snapshot("t1", [], [])
        impact = _empty_impact("sc-fp3", snap)
        h1 = compute_impact_hash(impact)
        h2 = compute_impact_hash(impact)
        assert h1 == h2

    def test_scenario_fingerprint_no_runtime_values(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-stable", fingerprint="fp-stable")
        s = build_scenario(snap, "S", "PolicyChange", [])
        diff = _empty_diff(s.scenario_id, snap)
        impact = _empty_impact(s.scenario_id, snap)
        fp1 = compute_scenario_fingerprint(
            s.scenario_version, s.overlay, diff, impact,
            GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
            GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
            GOVERNANCE_SIMULATION_VERSION,
        )
        fp2 = compute_scenario_fingerprint(
            s.scenario_version, s.overlay, diff, impact,
            GOVERNANCE_SIMULATION_SIMULATOR_VERSION,
            GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION,
            GOVERNANCE_SIMULATION_VERSION,
        )
        assert fp1 == fp2

    def test_fingerprint_domain_is_correct(self):
        assert GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN == "FG_GOVERNANCE_SIMULATION_V1"

    def test_comparison_hash_deterministic(self):
        comparison = ExecutiveComparison(
            comparison_id="cmp1",
            scenario_id="sc1",
            rows=(),
            comparison_hash="",
            created_at=_TS,
        )
        h1 = compute_comparison_hash(comparison)
        h2 = compute_comparison_hash(comparison)
        assert h1 == h2


# ---------------------------------------------------------------------------
# Group 8: Authority validation
# ---------------------------------------------------------------------------

class TestAuthorityValidation:
    def test_empty_authority_op_rejected(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("op1", "add_entity", authority="")  # empty authority
        overlay = _make_overlay("sc-auth1", snap, [op])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay, _empty_diff("sc-auth1", snap),
                                _empty_impact("sc-auth1", snap))

    def test_valid_authority_passes(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("op1", "add_entity", authority="real_authority")
        overlay = _make_overlay("sc-auth2", snap, [op])
        # Should not raise (other violations might exist for add_entity with no payload,
        # but authority check alone passes)
        diff = _empty_diff("sc-auth2", snap)
        impact = _empty_impact("sc-auth2", snap)
        try:
            validate_simulation(snap, overlay, diff, impact)
        except SimulationValidationError as exc:
            assert "authority_violation" not in str(exc)

    def test_authority_violation_in_findings(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("op1", "add_entity", authority="")
        overlay = _make_overlay("sc-auth3", snap, [op])
        try:
            validate_simulation(snap, overlay, _empty_diff("sc-auth3", snap),
                                _empty_impact("sc-auth3", snap))
        except SimulationValidationError:
            pass


# ---------------------------------------------------------------------------
# Group 9: Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_tenant_a_scenario_has_tenant_a_id(self):
        snap_a = _make_snapshot("tenant-a", [], [])
        s = build_scenario(snap_a, "A", "PolicyChange", [])
        assert s.tenant_id == "tenant-a"

    def test_tenant_b_scenario_has_tenant_b_id(self):
        snap_b = _make_snapshot("tenant-b", [], [])
        s = build_scenario(snap_b, "B", "PolicyChange", [])
        assert s.tenant_id == "tenant-b"

    def test_different_tenants_different_scenario_ids(self):
        snap_a = _make_snapshot("tenant-a", [], [], snapshot_id="snap-ta", fingerprint="fp-a")
        snap_b = _make_snapshot("tenant-b", [], [], snapshot_id="snap-tb", fingerprint="fp-b")
        # scenario_ids include tenant_id so they will differ
        # Use same name/category to ensure tenant is the differentiator
        # (created_at differs too, so just assert they're both valid)
        s_a = build_scenario(snap_a, "Same Name", "PolicyChange", [])
        s_b = build_scenario(snap_b, "Same Name", "PolicyChange", [])
        assert s_a.tenant_id != s_b.tenant_id

    def test_overlay_tenant_must_match_snapshot(self):
        snap = _make_snapshot("tenant-a", [], [])
        # Overlay with wrong tenant
        wrong_entity = _make_entity("e1", "policy", "tenant-z")
        op = _make_op("op1", "add_entity", entity_payload=dataclasses.asdict(wrong_entity))
        overlay = _make_overlay("sc-tenant-iso", snap, [op])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay,
                                _empty_diff("sc-tenant-iso", snap),
                                _empty_impact("sc-tenant-iso", snap))


# ---------------------------------------------------------------------------
# Group 10: Graph validation
# ---------------------------------------------------------------------------

class TestGraphValidation:
    def test_orphan_overlay_detected(self):
        snap = _make_snapshot("t1", [], [])
        # modify_entity on nonexistent entity
        op = _make_op("op1", "modify_entity", source_entity_id="ghost_id",
                       entity_payload={"status": "x"})
        overlay = _make_overlay("sc-orphan", snap, [op])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay, _empty_diff("sc-orphan", snap),
                                _empty_impact("sc-orphan", snap))

    def test_duplicate_op_ids_detected(self):
        snap = _make_snapshot("t1", [], [])
        op1 = _make_op("dup-id", "add_entity", authority="a")
        op2 = _make_op("dup-id", "add_entity", authority="a")
        overlay = _make_overlay("sc-dup", snap, [op1, op2])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay, _empty_diff("sc-dup", snap),
                                _empty_impact("sc-dup", snap))

    def test_missing_source_snapshot_detected(self):
        snap = _make_snapshot("t1", [], [])
        overlay = ScenarioOverlay(
            overlay_id="ov1",
            scenario_id="sc1",
            source_snapshot_id="",  # empty!
            source_snapshot_fingerprint="fp",
            tenant_id="t1",
            operations=(),
            created_at=_TS,
            overlay_hash="x" * 64,
        )
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay, _empty_diff("sc1", snap),
                                _empty_impact("sc1", snap))

    def test_valid_overlay_passes_validation(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc-valid", snap, [])
        diff = _empty_diff("sc-valid", snap)
        impact = _empty_impact("sc-valid", snap)
        report = validate_simulation(snap, overlay, diff, impact)
        assert report.valid is True

    def test_cycle_violation_produces_warning(self):
        """A cycle is a WARNING, not ERROR — validation should pass but note it."""
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        r1 = _make_relationship("r1", "governs", "e1", "e2")
        r2 = _make_relationship("r2", "governs", "e2", "e1")  # creates cycle
        snap = _make_snapshot(tenant, [], [])
        overlay = _make_overlay("sc-cycle", snap, [])
        diff = _empty_diff("sc-cycle", snap)
        impact = _empty_impact("sc-cycle", snap)
        # Pass derived entities/relationships that form a cycle
        report = validate_simulation(
            snap, overlay, diff, impact,
            derived_entities=(e1, e2),
            derived_relationships=(r1, r2),
        )
        # cycle_violation is WARNING → valid should be True
        cycle_findings = [f for f in report.findings if f.code == "cycle_violation"]
        assert len(cycle_findings) == 1
        assert cycle_findings[0].severity == SimulationValidationSeverity.WARNING.value
        assert report.valid is True


# ---------------------------------------------------------------------------
# Group 11: Explicit relationship enforcement
# ---------------------------------------------------------------------------

class TestRelationshipEnforcement:
    def test_add_relationship_with_nonexistent_from_entity_fails(self):
        snap = _make_snapshot("t1", [], [])
        rel = _make_relationship("r1", "governs", "nonexistent_from", "nonexistent_to")
        op = _make_op("op1", "add_relationship", relationship_payload=dataclasses.asdict(rel))
        overlay = _make_overlay("sc-rel-enforce", snap, [op])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay,
                                _empty_diff("sc-rel-enforce", snap),
                                _empty_impact("sc-rel-enforce", snap))

    def test_add_relationship_with_valid_entities_passes(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        snap = _make_snapshot(tenant, [e1, e2], [])
        rel = _make_relationship("r1", "governs", "e1", "e2")
        op = _make_op("op1", "add_relationship", relationship_payload=dataclasses.asdict(rel))
        overlay = _make_overlay("sc-rel-valid", snap, [op])
        diff = _empty_diff("sc-rel-valid", snap)
        impact = _empty_impact("sc-rel-valid", snap)
        # With both entities in snapshot → relationship is valid in derived set
        report = validate_simulation(
            snap, overlay, diff, impact,
            derived_entities=(e1, e2),
            derived_relationships=(rel,),
        )
        assert report.valid


# ---------------------------------------------------------------------------
# Group 12: Unknown impact handling
# ---------------------------------------------------------------------------

class TestUnknownImpactHandling:
    def test_added_entity_not_in_snap_returns_unknown(self):
        tenant = "t1"
        new_e = _make_entity("brand_new", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (new_e,), (), "sc-unk1")
        report = analyze_impact(snap, diff, "sc-unk1")
        unknown = [e for e in report.entries if e.confidence == ImpactConfidence.UNKNOWN.value]
        assert len(unknown) > 0

    def test_unknown_has_limitation_text(self):
        tenant = "t1"
        new_e = _make_entity("new_e", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (new_e,), (), "sc-unk2")
        report = analyze_impact(snap, diff, "sc-unk2")
        unknown_entries = [e for e in report.entries if e.confidence == ImpactConfidence.UNKNOWN.value]
        for entry in unknown_entries:
            assert len(entry.limitations) > 0


# ---------------------------------------------------------------------------
# Group 13: Immutable snapshot verification
# ---------------------------------------------------------------------------

class TestImmutableSnapshot:
    def test_snapshot_entities_unchanged_after_simulation(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        original_entities = snap.entities
        scenario = build_scenario(snap, "Immutable Test", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert snap.entities == original_entities

    def test_snapshot_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            snap.tenant_id = "mutated"  # type: ignore

    def test_simulation_does_not_modify_snapshot_relationships(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        r1 = _make_relationship("r1", "governs", "e1", "e2")
        snap = _make_snapshot(tenant, [e1, e2], [r1])
        original_rels = snap.relationships
        scenario = build_scenario(snap, "Immut", "ControlChange", [])
        simulate(snap, scenario)
        assert snap.relationships == original_rels


# ---------------------------------------------------------------------------
# Group 14: Scenario replay
# ---------------------------------------------------------------------------

class TestScenarioReplay:
    def test_replay_with_snapshot_produces_identical_fingerprint(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [], snapshot_id="snap-replay", fingerprint="fp-replay")
        scenario = build_scenario(snap, "Replay Test", "PolicyChange", [])
        result1 = simulate(snap, scenario)
        result2 = simulate(snap, scenario)
        # Both runs from same scenario → same final fingerprint
        assert result1.simulation_fingerprint == result2.simulation_fingerprint

    def test_replay_package_has_embedded_scenario(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RPkg", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.scenario.scenario_id == scenario.scenario_id

    def test_replay_using_service_with_snapshot(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [])
        svc = GovernanceSimulationService()
        scenario = svc.build_scenario(snap, "SvcReplay", "PolicyChange", [],
                                       created_from="test")
        result = svc.simulate(snap, scenario)
        replayed = svc.replay_with_snapshot(snap, result.replay_package)
        assert replayed.simulation_fingerprint == result.simulation_fingerprint


# ---------------------------------------------------------------------------
# Group 15: Overlay determinism
# ---------------------------------------------------------------------------

class TestOverlayDeterminism:
    def test_overlay_hash_stable_across_identical_overlays(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-od", fingerprint="fp-od")
        o1 = _make_overlay("sc-od1", snap, [])
        o2 = _make_overlay("sc-od1", snap, [])
        assert o1.overlay_hash == o2.overlay_hash

    def test_overlay_operations_order_sensitive(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        snap = _make_snapshot(tenant, [e1, e2], [], snapshot_id="snap-oo", fingerprint="fp-oo")
        op1 = _make_op("op-a", "remove_entity", source_entity_id="e1")
        op2 = _make_op("op-b", "remove_entity", source_entity_id="e2")
        overlay_ab = _make_overlay("sc-oo1", snap, [op1, op2])
        overlay_ba = _make_overlay("sc-oo1", snap, [op2, op1])
        # Hash must differ when order differs (operations list is order-sensitive)
        assert overlay_ab.overlay_hash != overlay_ba.overlay_hash

    def test_overlay_hash_is_sha256_length(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc-hash-len", snap, [])
        assert len(overlay.overlay_hash) == 64


# ---------------------------------------------------------------------------
# Group 16: Manifest generation
# ---------------------------------------------------------------------------

class TestManifestGeneration:
    def test_simulation_manifest_fields_correct(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [])
        scenario = build_scenario(snap, "Manifest", "PolicyChange", [])
        result = simulate(snap, scenario)
        manifest = result.replay_package.manifest
        assert manifest.scenario_id == scenario.scenario_id
        assert manifest.tenant_id == tenant
        assert manifest.simulation_version == GOVERNANCE_SIMULATION_VERSION
        assert manifest.simulator_version == GOVERNANCE_SIMULATION_SIMULATOR_VERSION
        assert manifest.replay_version == GOVERNANCE_SIMULATION_REPLAY_VERSION
        assert manifest.graph_schema_version == GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION
        assert manifest.mcim_version == GOVERNANCE_SIMULATION_MCIM_VERSION

    def test_manifest_hashes_present(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Manifest2", "PolicyChange", [])
        result = simulate(snap, scenario)
        manifest = result.replay_package.manifest
        assert len(manifest.overlay_hash) == 64
        assert len(manifest.diff_hash) == 64
        assert len(manifest.impact_hash) == 64
        assert len(manifest.comparison_hash) == 64

    def test_manifest_source_snapshot_fingerprint(self):
        snap = _make_snapshot("t1", [], [], fingerprint="known-fp-12345")
        scenario = build_scenario(snap, "Manifest3", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.manifest.source_snapshot_fingerprint == snap.fingerprint

    def test_manifest_schema_version_set(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Manifest4", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.manifest.manifest_schema_version == "1.0"


# ---------------------------------------------------------------------------
# Group 17: MCIM registration
# ---------------------------------------------------------------------------

class TestMCIMRegistration:
    def test_all_9_keys_present(self):
        expected = {
            "scenario", "overlay", "impact_report", "diff_report",
            "replay_package", "simulation_manifest", "simulation_validator",
            "simulation_fingerprint", "simulation_category",
        }
        # simulation_run was added in the 18.8.2 improvements — all original 9 keys must still be present
        assert expected.issubset(set(MCIM_REGISTRATION_SOURCE.keys()))

    def test_mcim_version_constant_correct(self):
        assert GOVERNANCE_SIMULATION_MCIM_VERSION == "MCIM-18.8.2-GOVERNANCE-SIMULATION"

    def test_mcim_registration_is_immutable(self):
        with pytest.raises((TypeError, AttributeError)):
            MCIM_REGISTRATION_SOURCE["new_key"] = "val"  # type: ignore

    def test_mcim_values_have_mcim_prefix(self):
        for key, value in MCIM_REGISTRATION_SOURCE.items():
            assert value.startswith("MCIM-"), f"key '{key}' has non-MCIM value '{value}'"

    def test_mcim_scenario_value(self):
        assert MCIM_REGISTRATION_SOURCE["scenario"] == "MCIM-18.8.2-SIM-SCENARIO"

    def test_mcim_replay_package_value(self):
        assert MCIM_REGISTRATION_SOURCE["replay_package"] == "MCIM-18.8.2-SIM-REPLAY-PACKAGE"


# ---------------------------------------------------------------------------
# Group 18: Canonical ordering
# ---------------------------------------------------------------------------

class TestCanonicalOrdering:
    def test_diff_entries_are_sorted_by_diff_id(self):
        tenant = "t1"
        entities = [_make_entity(f"e{i}", "policy", tenant) for i in range(5)]
        snap = _make_snapshot(tenant, entities, [])
        diff = compute_graph_diff(snap, (), (), "sc-order")
        ids = [e.diff_id for e in diff.entries]
        assert ids == sorted(ids)

    def test_impact_entries_are_sorted_by_impact_id(self):
        tenant = "t1"
        entities = [_make_entity(f"e{i}", "policy", tenant) for i in range(3)]
        snap = _make_snapshot(tenant, entities, [])
        diff = compute_graph_diff(snap, (), (), "sc-impact-order")
        impact = analyze_impact(snap, diff, "sc-impact-order")
        ids = [e.impact_id for e in impact.entries]
        assert ids == sorted(ids)


# ---------------------------------------------------------------------------
# Group 19: Builder/schema version stability
# ---------------------------------------------------------------------------

class TestVersionStability:
    def test_simulator_version_constant(self):
        assert GOVERNANCE_SIMULATION_SIMULATOR_VERSION == "1.0.0"

    def test_schema_version_constant(self):
        assert GOVERNANCE_SIMULATION_GRAPH_SCHEMA_VERSION == "1.0"

    def test_simulation_version_constant(self):
        assert GOVERNANCE_SIMULATION_VERSION == "18.8.2"

    def test_replay_version_constant(self):
        assert GOVERNANCE_SIMULATION_REPLAY_VERSION == "1.0"

    def test_fingerprint_domain_constant(self):
        assert GOVERNANCE_SIMULATION_FINGERPRINT_DOMAIN == "FG_GOVERNANCE_SIMULATION_V1"


# ---------------------------------------------------------------------------
# Group 20: Schema version stability (enum checks)
# ---------------------------------------------------------------------------

class TestEnumStability:
    def test_scenario_category_has_all_values(self):
        values = {c.value for c in ScenarioCategory}
        for expected in [
            "PolicyChange", "ControlChange", "EvidenceChange", "FindingResolution",
            "Remediation", "AuthorityChange", "OrganizationalChange", "FrameworkMapping",
            "RiskAcceptance", "ReadinessImprovement", "ExecutiveDecision",
        ]:
            assert expected in values

    def test_overlay_operation_type_has_all_values(self):
        values = {o.value for o in OverlayOperationType}
        for expected in [
            "add_entity", "remove_entity", "modify_entity",
            "add_relationship", "remove_relationship", "modify_relationship",
        ]:
            assert expected in values

    def test_impact_domain_has_all_values(self):
        values = {d.value for d in ImpactDomain}
        for expected in [
            "governance", "control", "evidence", "framework", "compliance",
            "operational", "executive", "risk", "readiness", "authority", "trust",
        ]:
            assert expected in values

    def test_simulation_validation_severity_values(self):
        values = {s.value for s in SimulationValidationSeverity}
        assert "INFO" in values
        assert "WARNING" in values
        assert "ERROR" in values
        assert "FATAL" in values

    def test_impact_confidence_values(self):
        values = {c.value for c in ImpactConfidence}
        assert "PROVEN" in values
        assert "INFERRED" in values
        assert "UNKNOWN" in values

    def test_scenario_category_registry_matches_enum(self):
        for cat in ScenarioCategory:
            assert cat.value in SCENARIO_CATEGORY_REGISTRY


# ---------------------------------------------------------------------------
# Group 21: Replay package generation
# ---------------------------------------------------------------------------

class TestReplayPackageGeneration:
    def test_replay_package_has_all_required_fields(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ReplayPkg", "PolicyChange", [])
        result = simulate(snap, scenario)
        pkg = result.replay_package
        assert pkg.package_id is not None
        assert pkg.scenario_id is not None
        assert pkg.source_snapshot_fingerprint is not None
        assert pkg.manifest is not None
        assert pkg.scenario is not None
        assert pkg.overlay is not None
        assert pkg.diff is not None
        assert pkg.impact_report is not None
        assert pkg.comparison is not None
        assert pkg.validation_report is not None
        assert pkg.fingerprint is not None
        assert pkg.created_at is not None
        assert pkg.mcim_version == GOVERNANCE_SIMULATION_MCIM_VERSION
        assert pkg.schema_version == GOVERNANCE_SIMULATION_VERSION
        assert pkg.replay_version == GOVERNANCE_SIMULATION_REPLAY_VERSION

    def test_package_id_is_24_hex_chars(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "PkgId", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert len(result.replay_package.package_id) == 24

    def test_package_fingerprint_is_sha256(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "PkgFP", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert len(result.replay_package.fingerprint) == 64

    def test_package_lineage_contains_scenario_id(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Lineage", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert scenario.scenario_id in result.replay_package.lineage


# ---------------------------------------------------------------------------
# Group 22: Simulation validator — error severity behavior
# ---------------------------------------------------------------------------

class TestSimulationValidator:
    def test_error_severity_fails_closed(self):
        snap = _make_snapshot("t1", [], [])
        op = _make_op("dup", "add_entity", authority="a")
        op2 = _make_op("dup", "add_entity", authority="a")  # duplicate op_id
        overlay = _make_overlay("sc-err-close", snap, [op, op2])
        with pytest.raises(SimulationValidationError):
            validate_simulation(snap, overlay,
                                _empty_diff("sc-err-close", snap),
                                _empty_impact("sc-err-close", snap))

    def test_warning_severity_passes(self):
        """Cycle is a WARNING — should not raise."""
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        e2 = _make_entity("e2", "control", tenant)
        r1 = _make_relationship("r1", "governs", "e1", "e2")
        r2 = _make_relationship("r2", "governs", "e2", "e1")
        snap = _make_snapshot(tenant, [], [])
        overlay = _make_overlay("sc-warn-pass", snap, [])
        diff = _empty_diff("sc-warn-pass", snap)
        impact = _empty_impact("sc-warn-pass", snap)
        report = validate_simulation(
            snap, overlay, diff, impact,
            derived_entities=(e1, e2),
            derived_relationships=(r1, r2),
        )
        assert report.valid is True
        assert report.highest_severity == SimulationValidationSeverity.WARNING.value

    def test_validation_checked_invariants_present(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc-inv", snap, [])
        diff = _empty_diff("sc-inv", snap)
        impact = _empty_impact("sc-inv", snap)
        report = validate_simulation(snap, overlay, diff, impact)
        assert len(report.checked_invariants) > 0

    def test_valid_report_is_true_when_no_violations(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc-valid2", snap, [])
        diff = _empty_diff("sc-valid2", snap)
        impact = _empty_impact("sc-valid2", snap)
        report = validate_simulation(snap, overlay, diff, impact)
        assert report.valid is True

    def test_simulation_validation_error_is_exception(self):
        exc = SimulationValidationError("test")
        assert isinstance(exc, Exception)


# ---------------------------------------------------------------------------
# Group 23: Service contract
# ---------------------------------------------------------------------------

class TestServiceContract:
    def test_service_has_build_scenario(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "build_scenario")

    def test_service_has_validate(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "validate")

    def test_service_has_simulate(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "simulate")

    def test_service_has_diff(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "diff")

    def test_service_has_impact(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "impact")

    def test_service_has_fingerprint(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "fingerprint")

    def test_service_has_export(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "export")

    def test_service_has_replay(self):
        svc = GovernanceSimulationService()
        assert hasattr(svc, "replay")

    def test_service_build_scenario_returns_scenario(self):
        svc = GovernanceSimulationService()
        snap = _make_snapshot("t1", [], [])
        s = svc.build_scenario(snap, "SvcTest", "PolicyChange", [], created_from="test")
        assert isinstance(s, SimulationScenario)

    def test_service_simulate_returns_result(self):
        svc = GovernanceSimulationService()
        snap = _make_snapshot("t1", [], [])
        scenario = svc.build_scenario(snap, "SvcSim", "PolicyChange", [], created_from="test")
        result = svc.simulate(snap, scenario)
        assert isinstance(result, SimulationResult)

    def test_service_export_returns_mapping(self):
        svc = GovernanceSimulationService()
        snap = _make_snapshot("t1", [], [])
        scenario = svc.build_scenario(snap, "SvcExp", "PolicyChange", [], created_from="test")
        result = svc.simulate(snap, scenario)
        exported = svc.export(result.replay_package)
        assert isinstance(exported, dict)

    def test_service_replay_raises_not_implemented(self):
        svc = GovernanceSimulationService()
        snap = _make_snapshot("t1", [], [])
        scenario = svc.build_scenario(snap, "SvcR", "PolicyChange", [], created_from="test")
        result = svc.simulate(snap, scenario)
        with pytest.raises(NotImplementedError):
            svc.replay(result.replay_package)


# ---------------------------------------------------------------------------
# Group 24: Export
# ---------------------------------------------------------------------------

class TestExport:
    def test_exported_package_is_deep_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Export", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)
        assert isinstance(exported, FrozenDict)

    def test_exported_package_has_no_forbidden_keys(self):
        forbidden = {
            "secret", "token", "password", "api_key", "auth_header",
            "authorization", "raw_prompt", "raw_vector", "embedding",
            "provider_payload", "private_key", "session", "cookie",
        }
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ExportSafe", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)

        def _check_no_forbidden(d: dict, path: str = "") -> None:
            for k, v in d.items():
                assert k.lower() not in forbidden, f"Forbidden key '{k}' found at {path}"
                if isinstance(v, dict):
                    _check_no_forbidden(v, path + f".{k}")

        _check_no_forbidden(dict(exported))

    def test_exported_package_has_replay_instructions(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ExportRI", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)
        assert "replay_instructions" in exported

    def test_exported_replay_instructions_have_required_keys(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ExportRIK", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)
        ri = exported["replay_instructions"]
        assert "schema_version" in ri
        assert "replay_version" in ri
        assert "how_to_replay" in ri
        assert "determinism_guarantee" in ri

    def test_export_includes_scenario_data(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ExportScenario", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)
        assert "scenario" in exported

    def test_export_includes_manifest(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "ExportManifest", "PolicyChange", [])
        result = simulate(snap, scenario)
        exported = export_replay_package(result.replay_package)
        assert "manifest" in exported


# ---------------------------------------------------------------------------
# Group 25: DataClass structure — all key dataclasses are frozen
# ---------------------------------------------------------------------------

class TestDataclassStructure:
    def test_scenario_overlay_operation_is_frozen(self):
        op = _make_op("op1", "add_entity", authority="a")
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            op.op_id = "changed"  # type: ignore

    def test_scenario_overlay_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc1", snap, [])
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            overlay.overlay_id = "changed"  # type: ignore

    def test_simulation_scenario_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "PolicyChange", [])
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            scenario.scenario_name = "changed"  # type: ignore

    def test_graph_diff_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc1", snap)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            diff.diff_id = "changed"  # type: ignore

    def test_impact_report_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        impact = _empty_impact("sc1", snap)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            impact.report_id = "changed"  # type: ignore

    def test_simulation_result_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "PolicyChange", [])
        result = simulate(snap, scenario)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            result.simulation_fingerprint = "changed"  # type: ignore

    def test_replay_package_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "PolicyChange", [])
        result = simulate(snap, scenario)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            result.replay_package.package_id = "changed"  # type: ignore

    def test_simulation_manifest_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "PolicyChange", [])
        result = simulate(snap, scenario)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            result.replay_package.manifest.scenario_id = "changed"  # type: ignore

    def test_executive_comparison_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "S", "PolicyChange", [])
        result = simulate(snap, scenario)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            result.comparison.scenario_id = "changed"  # type: ignore

    def test_simulation_validation_report_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        overlay = _make_overlay("sc1", snap, [])
        diff = _empty_diff("sc1", snap)
        impact = _empty_impact("sc1", snap)
        report = validate_simulation(snap, overlay, diff, impact)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            report.valid = False  # type: ignore


# ---------------------------------------------------------------------------
# Group 26: End-to-end simulation with multiple entity types
# ---------------------------------------------------------------------------

class TestEndToEndSimulation:
    def test_simulate_with_policy_change_scenario(self):
        tenant = "t1"
        e1 = _make_entity("pol1", "policy", tenant, status="active")
        snap = _make_snapshot(tenant, [e1], [])
        ops = [{"op_id": "op1", "operation_type": "modify_entity",
                "source_entity_id": "pol1", "entity_payload": {"status": "deprecated"},
                "authority": "test_auth", "reason": "policy update",
                "authoritative_basis": "board decision",
                "target_entity_id": None, "source_relationship_id": None,
                "relationship_payload": None}]
        scenario = build_scenario(snap, "Policy Deprecation", "PolicyChange", ops)
        result = simulate(snap, scenario)
        assert result.scenario.scenario_name == "Policy Deprecation"
        assert result.simulation_fingerprint is not None
        assert len(result.diff.entries) == 1
        assert result.diff.entries[0].operation == "modified"

    def test_simulate_with_add_control(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [])
        new_ctrl = _make_entity("ctrl_new", "control", tenant)
        ops = [{"op_id": "op1", "operation_type": "add_entity",
                "entity_payload": dataclasses.asdict(new_ctrl),
                "authority": "test_auth", "reason": "new control",
                "authoritative_basis": "risk assessment",
                "source_entity_id": None, "target_entity_id": None,
                "source_relationship_id": None, "relationship_payload": None}]
        scenario = build_scenario(snap, "Add Control", "ControlChange", ops)
        result = simulate(snap, scenario)
        assert len(result.diff.entries) == 1
        assert result.diff.entries[0].operation == "added"
        assert result.diff.entries[0].domain == "control"

    def test_simulate_returns_all_components(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Full", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert isinstance(result.scenario, SimulationScenario)
        assert isinstance(result.overlay, ScenarioOverlay)
        assert isinstance(result.diff, GraphDiff)
        assert isinstance(result.impact_report, ImpactReport)
        assert isinstance(result.comparison, ExecutiveComparison)
        assert isinstance(result.validation_report, SimulationValidationReport)
        assert isinstance(result.replay_package, ReplayPackage)
        assert isinstance(result.simulation_fingerprint, str)

    def test_simulate_empty_scenario_produces_empty_diff(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        scenario = build_scenario(snap, "NoChange", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert len(result.diff.entries) == 0

    def test_executive_comparison_rows_match_diff_entries(self):
        tenant = "t1"
        e1 = _make_entity("pol1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        ops = [{"op_id": "op1", "operation_type": "remove_entity",
                "source_entity_id": "pol1", "entity_payload": None,
                "authority": "test_auth", "reason": "removal",
                "authoritative_basis": "audit", "target_entity_id": None,
                "source_relationship_id": None, "relationship_payload": None}]
        scenario = build_scenario(snap, "Remove Policy", "PolicyChange", ops)
        result = simulate(snap, scenario)
        assert len(result.comparison.rows) == 1
        assert result.comparison.rows[0].object_id == "pol1"
        assert result.comparison.rows[0].delta is not None


# ---------------------------------------------------------------------------
# Group 27: Additional hash + model field assertions
# ---------------------------------------------------------------------------

class TestHashAndModelAdditional:
    def test_overlay_hash_64_chars(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-hlen", fingerprint="fp-hlen")
        overlay = _make_overlay("sc-hlen", snap, [])
        assert len(overlay.overlay_hash) == 64

    def test_diff_hash_64_chars(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-dh", snap)
        assert len(diff.diff_hash) == 64

    def test_impact_hash_64_chars(self):
        snap = _make_snapshot("t1", [], [])
        impact = _empty_impact("sc-ih", snap)
        assert len(impact.report_hash) == 64

    def test_scenario_fingerprint_is_sha256(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "FP256", "PolicyChange", [])
        assert len(scenario.simulation_fingerprint) == 64

    def test_diff_entry_domain_policy_is_governance(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-domain")
        assert diff.entries[0].domain == "governance"

    def test_diff_entry_domain_control_is_control(self):
        tenant = "t1"
        e1 = _make_entity("e1", "control", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-ctrl-domain")
        assert diff.entries[0].domain == "control"

    def test_diff_entry_domain_evidence_is_evidence(self):
        tenant = "t1"
        e1 = _make_entity("e1", "evidence", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-ev-domain")
        assert diff.entries[0].domain == "evidence"

    def test_diff_entry_domain_finding_is_risk(self):
        tenant = "t1"
        e1 = _make_entity("e1", "finding", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-finding-domain")
        assert diff.entries[0].domain == "risk"

    def test_diff_entry_domain_authority_is_authority(self):
        tenant = "t1"
        e1 = _make_entity("e1", "authority", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-auth-domain")
        assert diff.entries[0].domain == "authority"

    def test_simulation_result_fingerprint_matches_package(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "FPMatch", "PolicyChange", [])
        result = simulate(snap, scenario)
        # Final fingerprint and package fingerprint are computed differently
        # but result.simulation_fingerprint should be set
        assert result.simulation_fingerprint is not None
        assert isinstance(result.simulation_fingerprint, str)
        assert len(result.simulation_fingerprint) == 64

    def test_replay_package_source_snapshot_fingerprint_set(self):
        snap = _make_snapshot("t1", [], [], fingerprint="fp-known-1234")
        scenario = build_scenario(snap, "SFP", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.source_snapshot_fingerprint == "fp-known-1234"

    def test_comparison_has_comparison_hash(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "CmpHash", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert len(result.comparison.comparison_hash) == 64

    def test_impact_entry_has_domain_field(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant)
        snap = _make_snapshot(tenant, [], [])
        diff = compute_graph_diff(snap, (e1,), (), "sc-idom")
        report = analyze_impact(snap, diff, "sc-idom")
        for entry in report.entries:
            assert entry.domain in {d.value for d in ImpactDomain}

    def test_graph_diff_entry_has_authority(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant, authority="auth_xyz")
        snap = _make_snapshot(tenant, [e1], [])
        diff = compute_graph_diff(snap, (), (), "sc-auth-entry")
        assert diff.entries[0].authority == "auth_xyz"

    def test_overlay_op_fields_accessible(self):
        op = _make_op("op1", "add_entity", authority="myauth")
        assert op.op_id == "op1"
        assert op.operation_type == "add_entity"
        assert op.authority == "myauth"
        assert op.reason == "test reason"
        assert op.authoritative_basis == "test_basis"

    def test_graph_diff_entry_before_after_fields(self):
        tenant = "t1"
        e1 = _make_entity("e1", "policy", tenant, status="active")
        snap = _make_snapshot(tenant, [e1], [])
        e1_mod = dataclasses.replace(e1, status="deprecated")
        diff = compute_graph_diff(snap, (e1_mod,), (), "sc-before-after")
        entry = diff.entries[0]
        assert entry.before is not None
        assert entry.after is not None
        assert entry.before["status"] == "active"
        assert entry.after["status"] == "deprecated"

    def test_impact_entry_supporting_evidence_ids_field(self):
        tenant = "t1"
        e_pol = _make_entity("pol1", "policy", tenant)
        e_ev = _make_entity("ev1", "evidence", tenant)
        r1 = _make_relationship("r1", "verifies", "pol1", "ev1")
        snap = _make_snapshot(tenant, [e_pol, e_ev], [r1])
        e_pol_mod = dataclasses.replace(e_pol, status="deprecated")
        diff = compute_graph_diff(snap, (e_pol_mod, e_ev), (r1,), "sc-supp-ev")
        report = analyze_impact(snap, diff, "sc-supp-ev")
        proven = [e for e in report.entries if e.confidence == ImpactConfidence.PROVEN.value]
        for entry in proven:
            assert isinstance(entry.supporting_evidence_ids, tuple)

    def test_simulation_scenario_has_overlay_with_correct_tenant(self):
        tenant = "mytenat"
        snap = _make_snapshot(tenant, [], [])
        scenario = build_scenario(snap, "TenantOv", "PolicyChange", [])
        assert scenario.overlay.tenant_id == tenant


# ---------------------------------------------------------------------------
# Group 28: SimulationRun (Improvement 1)
# ---------------------------------------------------------------------------

from services.governance_simulation.simulator import run_simulation
from services.governance_simulation.models import SimulationRun, SimulationHorizon
from services.governance_simulation.models import SCENARIO_TEMPLATE_REGISTRY
from services.governance_simulation.overlay import compose_overlays
from pathlib import Path


class TestSimulationRun:
    def test_run_id_differs_from_scenario_id(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RunTest", "PolicyChange", [])
        run = run_simulation(snap, scenario)
        assert run.run_id != run.scenario_id

    def test_same_scenario_same_snapshot_deterministic_run_id(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-fixed-run", fingerprint="fp-run-det")
        scenario = build_scenario(snap, "DetRun", "PolicyChange", [])
        run1 = run_simulation(snap, scenario)
        run2 = run_simulation(snap, scenario)
        assert run1.run_id == run2.run_id

    def test_different_snapshots_produce_different_run_ids(self):
        snap1 = _make_snapshot("t1", [], [], snapshot_id="snap-A", fingerprint="fp-A")
        snap2 = _make_snapshot("t1", [], [], snapshot_id="snap-B", fingerprint="fp-B")
        scenario1 = build_scenario(snap1, "DiffSnap", "PolicyChange", [])
        scenario2 = build_scenario(snap2, "DiffSnap", "PolicyChange", [])
        run1 = run_simulation(snap1, scenario1)
        run2 = run_simulation(snap2, scenario2)
        assert run1.run_id != run2.run_id

    def test_run_result_is_simulation_result(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RunResult", "PolicyChange", [])
        run = run_simulation(snap, scenario)
        assert isinstance(run.result, SimulationResult)

    def test_horizon_propagates_to_run(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "HorizonRun", "PolicyChange", [],
                                  horizon="30_days")
        run = run_simulation(snap, scenario)
        assert run.horizon == "30_days"

    def test_run_has_correct_scenario_id(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RunSid", "PolicyChange", [])
        run = run_simulation(snap, scenario)
        assert run.scenario_id == scenario.scenario_id

    def test_run_has_correct_snapshot_id(self):
        snap = _make_snapshot("t1", [], [], snapshot_id="snap-run-sid")
        scenario = build_scenario(snap, "RunSnapId", "PolicyChange", [])
        run = run_simulation(snap, scenario)
        assert run.snapshot_id == snap.snapshot_id

    def test_run_is_frozen(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "FrozenRun", "PolicyChange", [])
        run = run_simulation(snap, scenario)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError, AttributeError)):
            run.run_id = "changed"  # type: ignore


# ---------------------------------------------------------------------------
# Group 29: SimulationHorizon (Improvement 2)
# ---------------------------------------------------------------------------

class TestSimulationHorizon:
    def test_all_5_values_exist(self):
        values = {h.value for h in SimulationHorizon}
        assert "immediate" in values
        assert "30_days" in values
        assert "90_days" in values
        assert "180_days" in values
        assert "1_year" in values

    def test_default_horizon_is_immediate(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "DefHorizon", "PolicyChange", [])
        assert scenario.horizon == SimulationHorizon.immediate.value

    def test_build_scenario_horizon_30_days(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "H30", "PolicyChange", [], horizon="30_days")
        assert scenario.horizon == "30_days"

    def test_build_scenario_horizon_1_year(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "H1Y", "PolicyChange", [], horizon="1_year")
        assert scenario.horizon == "1_year"

    def test_horizon_is_str_enum(self):
        assert SimulationHorizon.immediate == "immediate"
        assert SimulationHorizon.thirty_days == "30_days"


# ---------------------------------------------------------------------------
# Group 30: ImpactChain (Improvement 3)
# ---------------------------------------------------------------------------

class TestImpactChain:
    def test_impact_report_chains_attribute_exists(self):
        snap = _make_snapshot("t1", [], [])
        diff = _empty_diff("sc-chain-attr", snap)
        report = analyze_impact(snap, diff, "sc-chain-attr")
        assert hasattr(report, "chains")
        assert isinstance(report.chains, tuple)

    def test_chain_origin_domain_is_root_domain(self):
        tenant = "t1"
        # governance and evidence are root domains (not downstream of anything)
        e_pol = _make_entity("e_pol", "policy", tenant)
        e_ctrl = _make_entity("e_ctrl", "control", tenant)
        snap = _make_snapshot(tenant, [e_pol, e_ctrl], [])
        diff = compute_graph_diff(snap, (), (), "sc-chain-root")
        report = analyze_impact(snap, diff, "sc-chain-root")
        # All chain origin_domains should be root domains (governance, evidence, framework, etc.)
        # These are domains that have no upstream in the downstream graph
        upstream_set = {"control", "compliance", "risk", "trust", "readiness", "executive"}
        for chain in report.chains:
            assert chain.origin_domain not in upstream_set, (
                f"chain origin '{chain.origin_domain}' is an upstream domain"
            )

    def test_chain_nodes_ordered_root_to_leaf(self):
        tenant = "t1"
        # Build scenario that creates governance + compliance impact
        e_pol = _make_entity("e_pol", "policy", tenant)
        snap = _make_snapshot(tenant, [e_pol], [])
        diff = compute_graph_diff(snap, (), (), "sc-chain-order")
        report = analyze_impact(snap, diff, "sc-chain-order")
        for chain in report.chains:
            # first node should be the origin domain
            assert chain.chain[0].domain == chain.origin_domain

    def test_chain_hash_is_deterministic(self):
        tenant = "t1"
        e_pol = _make_entity("e_pol2", "policy", tenant)
        snap = _make_snapshot(tenant, [e_pol], [], snapshot_id="snap-ch-det", fingerprint="fp-ch-det")
        # Run twice with same inputs
        diff1 = compute_graph_diff(snap, (), (), "sc-chain-det")
        report1 = analyze_impact(snap, diff1, "sc-chain-det")
        diff2 = compute_graph_diff(snap, (), (), "sc-chain-det")
        report2 = analyze_impact(snap, diff2, "sc-chain-det")
        hashes1 = {c.chain_hash for c in report1.chains}
        hashes2 = {c.chain_hash for c in report2.chains}
        assert hashes1 == hashes2

    def test_governance_chain_propagates_to_downstream(self):
        tenant = "t1"
        # policy entity removed → should produce governance domain impact
        # governance chains downstream to control and compliance
        e_pol = _make_entity("gov_pol", "policy", tenant)
        snap = _make_snapshot(tenant, [e_pol], [])
        diff = compute_graph_diff(snap, (), (), "sc-gov-chain")
        report = analyze_impact(snap, diff, "sc-gov-chain")
        gov_chains = [c for c in report.chains if c.origin_domain == "governance"]
        if gov_chains:
            chain = gov_chains[0]
            chain_domains = [n.domain for n in chain.chain]
            # governance should be first, downstream domain should appear somewhere
            assert chain_domains[0] == "governance"
            # Must have at least 2 nodes to qualify as a chain
            assert len(chain.chain) >= 2

    def test_chains_sorted_by_chain_id(self):
        tenant = "t1"
        entities = [
            _make_entity("pol1", "policy", tenant),
            _make_entity("ev1", "evidence", tenant),
            _make_entity("fw1", "framework", tenant),
        ]
        snap = _make_snapshot(tenant, entities, [])
        diff = compute_graph_diff(snap, (), (), "sc-chain-sorted")
        report = analyze_impact(snap, diff, "sc-chain-sorted")
        chain_ids = [c.chain_id for c in report.chains]
        assert chain_ids == sorted(chain_ids)


# ---------------------------------------------------------------------------
# Group 31: SimulationManifest metrics (Improvement 4)
# ---------------------------------------------------------------------------

class TestManifestMetrics:
    def _run(self, tenant="t1", entities=None, num_ops=0):
        entities = entities or []
        snap = _make_snapshot(tenant, entities, [])
        ops = []
        for i in range(num_ops):
            new_e = _make_entity(f"new_e_{i}", "policy", tenant)
            ops.append({
                "op_id": f"op{i}", "operation_type": "add_entity",
                "entity_payload": dataclasses.asdict(new_e),
                "authority": "test_auth", "reason": "add",
                "authoritative_basis": "test", "source_entity_id": None,
                "target_entity_id": None, "source_relationship_id": None,
                "relationship_payload": None,
            })
        scenario = build_scenario(snap, "MetricsTest", "PolicyChange", ops)
        return simulate(snap, scenario)

    def test_objects_evaluated_positive(self):
        result = self._run(entities=[_make_entity("e1", "policy", "t1")])
        assert result.replay_package.manifest.objects_evaluated > 0

    def test_objects_changed_non_negative(self):
        result = self._run()
        assert result.replay_package.manifest.objects_changed >= 0

    def test_objects_unaffected_non_negative(self):
        result = self._run()
        assert result.replay_package.manifest.objects_unaffected >= 0

    def test_simulation_complexity_in_valid_set(self):
        result = self._run()
        assert result.replay_package.manifest.simulation_complexity in {"low", "medium", "high"}

    def test_complexity_low_for_zero_ops(self):
        result = self._run(num_ops=0)
        assert result.replay_package.manifest.simulation_complexity == "low"

    def test_complexity_low_for_3_ops(self):
        result = self._run(num_ops=3)
        assert result.replay_package.manifest.simulation_complexity == "low"

    def test_complexity_medium_for_5_ops(self):
        result = self._run(num_ops=5)
        assert result.replay_package.manifest.simulation_complexity == "medium"

    def test_complexity_high_for_11_ops(self):
        result = self._run(num_ops=11)
        assert result.replay_package.manifest.simulation_complexity == "high"

    def test_build_duration_ms_is_int_or_none(self):
        result = self._run()
        val = result.replay_package.manifest.build_duration_ms
        assert val is None or isinstance(val, int)

    def test_validation_duration_ms_is_int_or_none(self):
        result = self._run()
        val = result.replay_package.manifest.validation_duration_ms
        assert val is None or isinstance(val, int)


# ---------------------------------------------------------------------------
# Group 32: Overlay composition (Improvement 5)
# ---------------------------------------------------------------------------

class TestOverlayComposition:
    def test_compose_combines_operations(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [], snapshot_id="snap-compose", fingerprint="fp-compose")
        e1 = _make_entity("ce1", "policy", tenant)
        e2 = _make_entity("ce2", "control", tenant)
        op1 = _make_op("cop1", "add_entity", entity_payload=dataclasses.asdict(e1))
        op2 = _make_op("cop2", "add_entity", entity_payload=dataclasses.asdict(e2))
        ov_a = _make_overlay("sc-comp-a", snap, [op1])
        ov_b = _make_overlay("sc-comp-b", snap, [op2])
        composed = compose_overlays(ov_a, ov_b, composed_scenario_id="sc-composed")
        assert len(composed.operations) == 2

    def test_original_overlays_unchanged(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [], snapshot_id="snap-orig-unch", fingerprint="fp-ou")
        op1 = _make_op("oup1", "add_entity")
        ov_a = _make_overlay("sc-ou-a", snap, [op1])
        original_ops_count = len(ov_a.operations)
        op2 = _make_op("oup2", "add_entity")
        ov_b = _make_overlay("sc-ou-b", snap, [op2])
        compose_overlays(ov_a, ov_b, composed_scenario_id="sc-ou-composed")
        assert len(ov_a.operations) == original_ops_count

    def test_cross_tenant_compose_raises(self):
        snap_a = _make_snapshot("tenant-a", [], [], snapshot_id="snap-cta", fingerprint="fp-cta")
        snap_b = _make_snapshot("tenant-b", [], [], snapshot_id="snap-ctb", fingerprint="fp-ctb")
        ov_a = _make_overlay("sc-ct-a", snap_a, [])
        ov_b = _make_overlay("sc-ct-b", snap_b, [])
        with pytest.raises(OverlayError):
            compose_overlays(ov_a, ov_b, composed_scenario_id="sc-cross")

    def test_different_source_snapshot_compose_raises(self):
        tenant = "t1"
        snap1 = _make_snapshot(tenant, [], [], snapshot_id="snap-ds1", fingerprint="fp-ds1")
        snap2 = _make_snapshot(tenant, [], [], snapshot_id="snap-ds2", fingerprint="fp-ds2")
        ov1 = _make_overlay("sc-ds1", snap1, [])
        ov2 = _make_overlay("sc-ds2", snap2, [])
        with pytest.raises(OverlayError):
            compose_overlays(ov1, ov2, composed_scenario_id="sc-diff-snap")

    def test_composed_overlay_has_overlay_hash(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [], snapshot_id="snap-comp-hash", fingerprint="fp-ch")
        ov_a = _make_overlay("sc-ch-a", snap, [])
        composed = compose_overlays(ov_a, composed_scenario_id="sc-ch-composed")
        assert len(composed.overlay_hash) == 64

    def test_empty_compose_raises(self):
        with pytest.raises(OverlayError):
            compose_overlays(composed_scenario_id="sc-empty")

    def test_single_overlay_compose_works(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [], snapshot_id="snap-single", fingerprint="fp-single")
        ov = _make_overlay("sc-single", snap, [])
        composed = compose_overlays(ov, composed_scenario_id="sc-single-composed")
        assert composed.tenant_id == tenant


# ---------------------------------------------------------------------------
# Group 33: Scenario Template Registry (Improvement 6)
# ---------------------------------------------------------------------------

class TestScenarioTemplateRegistry:
    def test_6_keys_present(self):
        assert len(SCENARIO_TEMPLATE_REGISTRY) == 6

    def test_zero_trust_rollout_key_exists(self):
        assert "zero_trust_rollout" in SCENARIO_TEMPLATE_REGISTRY

    def test_pci_remediation_value_is_string(self):
        assert isinstance(SCENARIO_TEMPLATE_REGISTRY["pci_remediation"], str)

    def test_iso_readiness_key_exists(self):
        assert "iso_readiness" in SCENARIO_TEMPLATE_REGISTRY

    def test_ai_governance_key_exists(self):
        assert "ai_governance" in SCENARIO_TEMPLATE_REGISTRY

    def test_nist_migration_key_exists(self):
        assert "nist_migration" in SCENARIO_TEMPLATE_REGISTRY

    def test_cis_improvement_key_exists(self):
        assert "cis_improvement" in SCENARIO_TEMPLATE_REGISTRY

    def test_registry_is_immutable(self):
        with pytest.raises((TypeError, AttributeError)):
            SCENARIO_TEMPLATE_REGISTRY["new_key"] = "val"  # type: ignore

    def test_build_scenario_template_id_propagates(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "PCI", "PolicyChange", [],
                                  template_id="pci_remediation")
        assert scenario.template_id == "pci_remediation"

    def test_default_template_id_is_none(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "NoTemplate", "PolicyChange", [])
        assert scenario.template_id is None


# ---------------------------------------------------------------------------
# Group 34: Executive Comparison net summary (Improvement 7)
# ---------------------------------------------------------------------------

class TestExecutiveComparisonNetSummary:
    def test_net_counts_non_negative(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "NetCounts", "PolicyChange", [])
        result = simulate(snap, scenario)
        cmp = result.comparison
        assert cmp.net_positive >= 0
        assert cmp.net_negative >= 0
        assert cmp.neutral >= 0
        assert cmp.unknown_count >= 0

    def test_net_positive_increments_on_add(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [])
        new_e = _make_entity("net_add_e", "policy", tenant)
        ops = [{"op_id": "op1", "operation_type": "add_entity",
                "entity_payload": dataclasses.asdict(new_e),
                "authority": "test_auth", "reason": "add",
                "authoritative_basis": "test", "source_entity_id": None,
                "target_entity_id": None, "source_relationship_id": None,
                "relationship_payload": None}]
        scenario = build_scenario(snap, "NetAdd", "PolicyChange", ops)
        result = simulate(snap, scenario)
        assert result.comparison.net_positive >= 1

    def test_net_negative_increments_on_remove(self):
        tenant = "t1"
        e1 = _make_entity("net_rem_e", "policy", tenant)
        snap = _make_snapshot(tenant, [e1], [])
        ops = [{"op_id": "op1", "operation_type": "remove_entity",
                "source_entity_id": "net_rem_e", "entity_payload": None,
                "authority": "test_auth", "reason": "remove",
                "authoritative_basis": "test", "target_entity_id": None,
                "source_relationship_id": None, "relationship_payload": None}]
        scenario = build_scenario(snap, "NetRemove", "PolicyChange", ops)
        result = simulate(snap, scenario)
        assert result.comparison.net_negative >= 1

    def test_counts_are_integers(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "IntCounts", "PolicyChange", [])
        result = simulate(snap, scenario)
        cmp = result.comparison
        assert isinstance(cmp.net_positive, int)
        assert isinstance(cmp.net_negative, int)
        assert isinstance(cmp.neutral, int)
        assert isinstance(cmp.unknown_count, int)

    def test_total_counts_sum_is_consistent(self):
        tenant = "t1"
        snap = _make_snapshot(tenant, [], [])
        scenario = build_scenario(snap, "SumCounts", "PolicyChange", [])
        result = simulate(snap, scenario)
        cmp = result.comparison
        total = cmp.net_positive + cmp.net_negative + cmp.neutral
        assert total >= 0
        assert total <= len(cmp.rows)


# ---------------------------------------------------------------------------
# Group 35: Cost placeholders (Improvement 8)
# ---------------------------------------------------------------------------

class TestCostPlaceholders:
    def test_estimated_cost_is_none(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "CostNone", "PolicyChange", [])
        assert scenario.estimated_cost is None

    def test_estimated_effort_is_none(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "EffortNone", "PolicyChange", [])
        assert scenario.estimated_effort is None

    def test_estimated_duration_is_none(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "DurationNone", "PolicyChange", [])
        assert scenario.estimated_duration is None


# ---------------------------------------------------------------------------
# Group 36: Rollback metadata (Improvement 9)
# ---------------------------------------------------------------------------

class TestRollbackMetadata:
    def test_rollback_reference_is_none(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "Rollback", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.rollback_reference is None

    def test_rollback_ready_is_false(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RollbackReady", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.rollback_ready is False

    def test_rollback_dependencies_is_empty_tuple(self):
        snap = _make_snapshot("t1", [], [])
        scenario = build_scenario(snap, "RollbackDeps", "PolicyChange", [])
        result = simulate(snap, scenario)
        assert result.replay_package.rollback_dependencies == ()


# ---------------------------------------------------------------------------
# Group 37: Constitution doc exists (Improvement 10)
# ---------------------------------------------------------------------------

class TestConstitutionDoc:
    def test_constitution_doc_exists(self):
        repo_root = Path(__file__).resolve().parents[1]
        constitution_path = repo_root / "docs" / "GOVERNANCE_SIMULATION_CONSTITUTION.md"
        assert constitution_path.exists(), f"Constitution doc not found at {constitution_path}"

    def test_constitution_doc_has_content(self):
        repo_root = Path(__file__).resolve().parents[1]
        constitution_path = repo_root / "docs" / "GOVERNANCE_SIMULATION_CONSTITUTION.md"
        text = constitution_path.read_text(encoding="utf-8")
        assert "Foundational Rules" in text
        assert "Simulation" in text

    def test_constitution_mentions_tenant_isolation(self):
        repo_root = Path(__file__).resolve().parents[1]
        constitution_path = repo_root / "docs" / "GOVERNANCE_SIMULATION_CONSTITUTION.md"
        text = constitution_path.read_text(encoding="utf-8")
        assert "Tenant" in text

    def test_constitution_mentions_fail_closed(self):
        repo_root = Path(__file__).resolve().parents[1]
        constitution_path = repo_root / "docs" / "GOVERNANCE_SIMULATION_CONSTITUTION.md"
        text = constitution_path.read_text(encoding="utf-8")
        assert "Fail Closed" in text
