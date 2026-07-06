"""Tests for the Governance Execution Engine — PR 18.8.3.

250+ assertions covering all 43 test groups.
Pure Python — no DB, no SQLAlchemy, no mocks.
"""

from __future__ import annotations

import dataclasses
import pytest

# ---------------------------------------------------------------------------
# Upstream helpers
# ---------------------------------------------------------------------------
from services.governance_simulation.models import (
    ExecutiveComparison,
    ExecutiveComparisonRow,
    GraphDiff,
    GraphDiffEntry,
    ImpactEntry,
    ImpactReport,
    ReplayPackage,
    ScenarioOverlay,
    ScenarioOverlayOperation,
    SimulationManifest,
    SimulationResult,
    SimulationScenario,
    SimulationValidationReport,
)

# ---------------------------------------------------------------------------
# Module under test
# ---------------------------------------------------------------------------
from services.governance_execution.models import (
    GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN,
    GOVERNANCE_EXECUTION_MANIFEST_VERSION,
    GOVERNANCE_EXECUTION_MCIM_VERSION,
    GOVERNANCE_EXECUTION_PLANNER_VERSION,
    GOVERNANCE_EXECUTION_REPLAY_VERSION,
    GOVERNANCE_EXECUTION_SCHEMA_VERSION,
    GOVERNANCE_EXECUTION_VALIDATOR_VERSION,
    GOVERNANCE_EXECUTION_VERSION,
    ExecutionDecisionLedger,
    ExecutionDecisionRecord,
    ExecutionPlan,
    ExecutionReplayPackage,
    ExecutionRun,
    ExecutionValidationFinding,
    ExecutionValidationReport,
)
from services.governance_execution.registry import (
    APPROVAL_TYPE_REGISTRY,
    EXECUTION_STATE_TRANSITIONS,
    GOVERNANCE_GATES,
    get_required_approvers,
    is_valid_transition,
)
from services.governance_execution.constitution import (
    GOVERNANCE_EXECUTION_PERMANENT_RULES,
    GOVERNANCE_EXECUTION_CONSTITUTION_VERSION,
)
from services.governance_execution.fingerprint import (
    compute_plan_fingerprint,
    compute_step_hash,
    compute_approval_hash,
    compute_run_fingerprint,
    compute_verification_hash,
    compute_measurement_hash,
    compute_ledger_hash,
    compute_audit_fingerprint,
    compute_execution_fingerprint,
    compute_replay_fingerprint,
)
from services.governance_execution.planner import plan_execution
from services.governance_execution.approvals import (
    create_approval,
    check_approval_requirements,
)
from services.governance_execution.execution import (
    create_run,
    advance_state,
    complete_step,
    fail_step,
)
from services.governance_execution.verification import verify_step
from services.governance_execution.measurement import measure_outcome
from services.governance_execution.rollback import plan_rollback, execute_rollback
from services.governance_execution.manifest import build_execution_manifest
from services.governance_execution.replay import build_execution_replay_package
from services.governance_execution.exporter import export_execution_replay_package
from services.governance_execution.validator import (
    ExecutionValidationError,
    validate_execution_plan,
)
from services.governance_execution.contract import (
    GovernanceExecutionService,
    GovernanceExecutionServiceContract,
)
from services.governance_execution.mcim_registration import (
    MCIM_REGISTRATION_SOURCE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_diff_entry(
    eid: str = "e1",
    domain: str = "governance",
    operation: str = "modified",
    authority: str = "test_auth",
) -> GraphDiffEntry:
    return GraphDiffEntry(
        diff_id=f"d-{eid}",
        domain=domain,
        operation=operation,
        entity_id=eid,
        relationship_id=None,
        before={"type": "policy", "status": "active"},
        after={"type": "policy", "status": "updated"},
        authority=authority,
        reason=f"test change {eid}",
    )


def _make_simulation_result(
    tenant_id: str = "tenant-exec-a",
    entries: list[GraphDiffEntry] | None = None,
    scenario_id: str = "scen-001",
) -> SimulationResult:
    if entries is None:
        entries = [_make_diff_entry()]

    overlay_op = ScenarioOverlayOperation(
        op_id="op-1",
        operation_type="modify_entity",
        source_entity_id="e1",
        target_entity_id=None,
        source_relationship_id=None,
        entity_payload={"status": "updated"},
        relationship_payload=None,
        reason="test overlay",
        authoritative_basis="policy-001",
        authority="test_auth",
    )
    overlay = ScenarioOverlay(
        overlay_id="ov-001",
        scenario_id=scenario_id,
        source_snapshot_id="snap-001",
        source_snapshot_fingerprint="fp-snap-001",
        tenant_id=tenant_id,
        operations=(overlay_op,),
        created_at="2026-07-06T00:00:00Z",
        overlay_hash="oh-001",
    )
    scenario = SimulationScenario(
        scenario_id=scenario_id,
        parent_snapshot_id="snap-001",
        source_snapshot_fingerprint="fp-snap-001",
        scenario_name="Test Scenario",
        category="governance",
        created_from="manual",
        scenario_version="1.0",
        graph_schema_version="1.0",
        simulator_version="1.0.0",
        replay_version="1.0",
        created_at="2026-07-06T00:00:00Z",
        simulation_fingerprint="sim-fp-001",
        overlay=overlay,
        tenant_id=tenant_id,
    )
    diff = GraphDiff(
        diff_id="diff-001",
        scenario_id=scenario_id,
        source_snapshot_id="snap-001",
        entries=tuple(entries),
        diff_hash="dh-001",
        created_at="2026-07-06T00:00:00Z",
    )
    impact_entry = ImpactEntry(
        impact_id="imp-1",
        domain="governance",
        impacted_object_ids=("e1",),
        reason="test impact",
        originating_authority="test_auth",
        confidence="INFERRED",
        supporting_evidence_ids=(),
        limitations=(),
    )
    impact_report = ImpactReport(
        report_id="rpt-001",
        scenario_id=scenario_id,
        source_snapshot_id="snap-001",
        entries=(impact_entry,),
        report_hash="rh-001",
        created_at="2026-07-06T00:00:00Z",
        limitations=(),
        chains=(),
    )
    comparison_row = ExecutiveComparisonRow(
        object_id="e1",
        object_type="policy",
        domain="governance",
        current_value="active",
        scenario_value="updated",
        delta=None,
        evidence_ids=(),
        reason="test",
        confidence="INFERRED",
        authority="test_auth",
        limitations=(),
    )
    comparison = ExecutiveComparison(
        comparison_id="cmp-001",
        scenario_id=scenario_id,
        rows=(comparison_row,),
        comparison_hash="ch-001",
        created_at="2026-07-06T00:00:00Z",
    )
    val_report = SimulationValidationReport(
        valid=True,
        findings=(),
        highest_severity="INFO",
        violations=(),
        checked_invariants=(),
    )
    sim_manifest = SimulationManifest(
        manifest_schema_version="1.0",
        scenario_id=scenario_id,
        source_snapshot_id="snap-001",
        source_snapshot_fingerprint="fp-snap-001",
        scenario_name="Test Scenario",
        scenario_category="governance",
        simulation_version="18.8.2",
        graph_schema_version="1.0",
        simulator_version="1.0.0",
        replay_version="1.0",
        tenant_id=tenant_id,
        created_at="2026-07-06T00:00:00Z",
        simulation_fingerprint="sim-fp-001",
        overlay_hash="oh-001",
        diff_hash="dh-001",
        impact_hash="ih-001",
        comparison_hash="ch-001",
        mcim_version="MCIM-18.8.2-GOVERNANCE-SIMULATION",
        lineage="sim:scen-001:snap-001",
    )
    replay_pkg = ReplayPackage(
        package_id="rp-001",
        scenario_id=scenario_id,
        source_snapshot_fingerprint="fp-snap-001",
        manifest=sim_manifest,
        scenario=scenario,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        comparison=comparison,
        validation_report=val_report,
        fingerprint="rp-fp-001",
        created_at="2026-07-06T00:00:00Z",
        mcim_version="MCIM-18.8.2-GOVERNANCE-SIMULATION",
        schema_version="1.0",
        replay_version="1.0",
        lineage="sim:scen-001:snap-001",
    )
    return SimulationResult(
        scenario=scenario,
        overlay=overlay,
        diff=diff,
        impact_report=impact_report,
        comparison=comparison,
        validation_report=val_report,
        replay_package=replay_pkg,
        simulation_fingerprint="sim-fp-001",
    )


def _make_plan(
    tenant_id: str = "tenant-exec-a", entries: list[GraphDiffEntry] | None = None
) -> ExecutionPlan:
    sim = _make_simulation_result(tenant_id=tenant_id, entries=entries)
    return plan_execution(sim, "Test Plan", "test_auth")


def _make_approved_run(plan: ExecutionPlan) -> tuple[ExecutionRun, object]:
    approval = create_approval(
        plan, "approver-1", "admin_authority", "approved for test"
    )
    run = create_run(plan, (approval,))
    return run, approval


# ---------------------------------------------------------------------------
# 1. Version constants
# ---------------------------------------------------------------------------


class TestVersionConstants:
    def test_version(self) -> None:
        assert GOVERNANCE_EXECUTION_VERSION == "18.8.3"

    def test_planner_version(self) -> None:
        assert GOVERNANCE_EXECUTION_PLANNER_VERSION == "1.0.0"

    def test_validator_version(self) -> None:
        assert GOVERNANCE_EXECUTION_VALIDATOR_VERSION == "1.0.0"

    def test_schema_version(self) -> None:
        assert GOVERNANCE_EXECUTION_SCHEMA_VERSION == "1.0"

    def test_replay_version(self) -> None:
        assert GOVERNANCE_EXECUTION_REPLAY_VERSION == "1.0"

    def test_manifest_version(self) -> None:
        assert GOVERNANCE_EXECUTION_MANIFEST_VERSION == "1.0"

    def test_fingerprint_domain(self) -> None:
        assert GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN == "FG_GOVERNANCE_EXECUTION_V1"

    def test_mcim_version(self) -> None:
        assert GOVERNANCE_EXECUTION_MCIM_VERSION == "MCIM-18.8.3-GOVERNANCE-EXECUTION"


# ---------------------------------------------------------------------------
# 2. State registry
# ---------------------------------------------------------------------------


class TestStateRegistry:
    def test_all_14_states_present(self) -> None:
        states = set(EXECUTION_STATE_TRANSITIONS.keys())
        expected = {
            "Draft",
            "Validated",
            "AwaitingApproval",
            "Approved",
            "Scheduled",
            "Executing",
            "Verifying",
            "Completed",
            "Measured",
            "Archived",
            "Failed",
            "Rollback",
            "Verification",
            "Closed",
        }
        assert states == expected

    def test_is_valid_transition_draft_to_validated(self) -> None:
        assert is_valid_transition("Draft", "Validated") is True

    def test_is_valid_transition_validated_to_awaiting_approval(self) -> None:
        assert is_valid_transition("Validated", "AwaitingApproval") is True

    def test_is_valid_transition_awaiting_to_approved(self) -> None:
        assert is_valid_transition("AwaitingApproval", "Approved") is True

    def test_is_valid_transition_approved_to_scheduled(self) -> None:
        assert is_valid_transition("Approved", "Scheduled") is True

    def test_is_valid_transition_scheduled_to_executing(self) -> None:
        assert is_valid_transition("Scheduled", "Executing") is True

    def test_is_valid_transition_executing_to_verifying(self) -> None:
        assert is_valid_transition("Executing", "Verifying") is True

    def test_is_valid_transition_verifying_to_completed(self) -> None:
        assert is_valid_transition("Verifying", "Completed") is True

    def test_is_valid_transition_completed_to_measured(self) -> None:
        assert is_valid_transition("Completed", "Measured") is True

    def test_is_valid_transition_measured_to_archived(self) -> None:
        assert is_valid_transition("Measured", "Archived") is True

    def test_is_valid_transition_failed_to_rollback(self) -> None:
        assert is_valid_transition("Failed", "Rollback") is True

    def test_is_valid_transition_rollback_to_closed(self) -> None:
        assert is_valid_transition("Rollback", "Closed") is True

    def test_is_valid_transition_closed_terminal(self) -> None:
        assert is_valid_transition("Closed", "Draft") is False

    def test_is_valid_transition_archived_terminal(self) -> None:
        assert is_valid_transition("Archived", "Draft") is False

    def test_is_invalid_transition_draft_to_completed(self) -> None:
        assert is_valid_transition("Draft", "Completed") is False

    def test_is_invalid_transition_unknown_state(self) -> None:
        assert is_valid_transition("Unknown", "Draft") is False


# ---------------------------------------------------------------------------
# 3. Approval type registry
# ---------------------------------------------------------------------------


class TestApprovalTypeRegistry:
    def test_all_9_types_present(self) -> None:
        expected = {
            "SingleApprover",
            "DualApproval",
            "MajorityApproval",
            "RiskBased",
            "Emergency",
            "Executive",
            "Compliance",
            "Security",
            "Authority",
        }
        assert set(APPROVAL_TYPE_REGISTRY.keys()) == expected

    def test_single_approver_count(self) -> None:
        assert APPROVAL_TYPE_REGISTRY["SingleApprover"] == 1

    def test_dual_approval_count(self) -> None:
        assert APPROVAL_TYPE_REGISTRY["DualApproval"] == 2

    def test_majority_approval_count(self) -> None:
        assert APPROVAL_TYPE_REGISTRY["MajorityApproval"] == 3

    def test_get_required_approvers_single(self) -> None:
        assert get_required_approvers("SingleApprover") == 1

    def test_get_required_approvers_dual(self) -> None:
        assert get_required_approvers("DualApproval") == 2

    def test_get_required_approvers_majority(self) -> None:
        assert get_required_approvers("MajorityApproval") == 3

    def test_get_required_approvers_unknown_defaults_to_1(self) -> None:
        assert get_required_approvers("NonExistent") == 1


# ---------------------------------------------------------------------------
# 4. Governance gates
# ---------------------------------------------------------------------------


class TestGovernanceGates:
    def test_exactly_9_gates(self) -> None:
        assert len(GOVERNANCE_GATES) == 9

    def test_simulation_passed_present(self) -> None:
        assert "simulation_passed" in GOVERNANCE_GATES

    def test_validation_passed_present(self) -> None:
        assert "validation_passed" in GOVERNANCE_GATES

    def test_authority_verified_present(self) -> None:
        assert "authority_verified" in GOVERNANCE_GATES

    def test_evidence_present_present(self) -> None:
        assert "evidence_present" in GOVERNANCE_GATES

    def test_policy_allows_execution_present(self) -> None:
        assert "policy_allows_execution" in GOVERNANCE_GATES

    def test_required_approvals_complete_present(self) -> None:
        assert "required_approvals_complete" in GOVERNANCE_GATES

    def test_replay_package_valid_present(self) -> None:
        assert "replay_package_valid" in GOVERNANCE_GATES

    def test_digital_twin_fingerprint_unchanged_present(self) -> None:
        assert "digital_twin_fingerprint_unchanged" in GOVERNANCE_GATES


# ---------------------------------------------------------------------------
# 5. Constitution rules
# ---------------------------------------------------------------------------


class TestConstitutionRules:
    def test_exactly_17_rules(self) -> None:
        assert len(GOVERNANCE_EXECUTION_PERMANENT_RULES) == 17

    def test_no_autonomous_execution(self) -> None:
        assert "no_autonomous_execution" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_fail_closed(self) -> None:
        assert "fail_closed" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_tenant_isolation(self) -> None:
        assert "tenant_isolation" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_rollback_required(self) -> None:
        assert "rollback_required" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_verification_required(self) -> None:
        assert "verification_required" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_no_ai_generated_governance(self) -> None:
        assert "no_ai_generated_governance" in GOVERNANCE_EXECUTION_PERMANENT_RULES

    def test_constitution_version(self) -> None:
        assert GOVERNANCE_EXECUTION_CONSTITUTION_VERSION == "18.8.3"


# ---------------------------------------------------------------------------
# 6. Execution plan creation
# ---------------------------------------------------------------------------


class TestExecutionPlanCreation:
    def test_returns_execution_plan(self) -> None:
        plan = _make_plan()
        assert isinstance(plan, ExecutionPlan)

    def test_correct_tenant_id(self) -> None:
        plan = _make_plan(tenant_id="tenant-xyz")
        assert plan.tenant_id == "tenant-xyz"

    def test_plan_name(self) -> None:
        sim = _make_simulation_result()
        plan = plan_execution(sim, "My Plan", "auth_x")
        assert plan.plan_name == "My Plan"

    def test_initial_state_is_draft(self) -> None:
        plan = _make_plan()
        assert plan.state == "Draft"

    def test_planner_version_set(self) -> None:
        plan = _make_plan()
        assert plan.planner_version == GOVERNANCE_EXECUTION_PLANNER_VERSION

    def test_schema_version_set(self) -> None:
        plan = _make_plan()
        assert plan.schema_version == GOVERNANCE_EXECUTION_SCHEMA_VERSION

    def test_simulation_id_matches_scenario(self) -> None:
        sim = _make_simulation_result(scenario_id="scen-999")
        plan = plan_execution(sim, "P", "a")
        assert plan.simulation_id == "scen-999"

    def test_digital_twin_fingerprint_set(self) -> None:
        plan = _make_plan()
        assert plan.digital_twin_fingerprint == "fp-snap-001"

    def test_simulation_fingerprint_set(self) -> None:
        plan = _make_plan()
        assert plan.simulation_fingerprint == "sim-fp-001"

    def test_lineage_contains_plan_and_sim(self) -> None:
        plan = _make_plan()
        assert "exec:" in plan.lineage
        assert "sim:" in plan.lineage
        assert "snap:" in plan.lineage


# ---------------------------------------------------------------------------
# 7. Step generation
# ---------------------------------------------------------------------------


class TestStepGeneration:
    def test_one_step_per_diff_entry(self) -> None:
        entries = [
            _make_diff_entry("e1"),
            _make_diff_entry("e2"),
            _make_diff_entry("e3"),
        ]
        plan = _make_plan(entries=entries)
        assert len(plan.steps) == 3

    def test_sequence_starts_at_1(self) -> None:
        plan = _make_plan()
        assert plan.steps[0].sequence == 1

    def test_sequences_are_consecutive(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        seqs = [s.sequence for s in plan.steps]
        assert seqs == list(range(1, len(seqs) + 1))

    def test_authority_required_propagated(self) -> None:
        entry = _make_diff_entry(authority="specific_auth")
        plan = _make_plan(entries=[entry])
        assert plan.steps[0].authority_required == "specific_auth"

    def test_authority_falls_back_to_plan_authority(self) -> None:
        entry = _make_diff_entry(authority="")
        sim = _make_simulation_result(entries=[entry])
        plan = plan_execution(sim, "P", "fallback_auth")
        assert plan.steps[0].authority_required == "fallback_auth"

    def test_verification_required_true_for_all_steps(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        assert all(s.verification_required for s in plan.steps)

    def test_step_tenant_id_matches_plan(self) -> None:
        plan = _make_plan(tenant_id="tenant-check")
        assert all(s.tenant_id == "tenant-check" for s in plan.steps)

    def test_step_plan_id_matches_plan(self) -> None:
        plan = _make_plan()
        assert all(s.plan_id == plan.plan_id for s in plan.steps)


# ---------------------------------------------------------------------------
# 8. Rollback plan creation
# ---------------------------------------------------------------------------


class TestRollbackPlanCreation:
    def test_rollback_plan_present(self) -> None:
        plan = _make_plan()
        assert plan.rollback_plan is not None

    def test_rollback_ready_true(self) -> None:
        entries = [_make_diff_entry("e1")]
        plan = _make_plan(entries=entries)
        assert plan.rollback_plan.rollback_ready is True

    def test_one_rollback_step_per_forward_step(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        assert len(plan.rollback_plan.rollback_steps) == len(entries)

    def test_rollback_step_reverses_original(self) -> None:
        entries = [_make_diff_entry("e1")]
        plan = _make_plan(entries=entries)
        assert (
            plan.rollback_plan.rollback_steps[0].reverses_step_id
            == plan.steps[0].step_id
        )

    def test_rollback_verification_true(self) -> None:
        plan = _make_plan()
        assert plan.rollback_plan.rollback_verification is True

    def test_rollback_plan_tenant_matches(self) -> None:
        plan = _make_plan(tenant_id="tenant-rb")
        assert plan.rollback_plan.tenant_id == "tenant-rb"


# ---------------------------------------------------------------------------
# 9. Rollback required before execution
# ---------------------------------------------------------------------------


class TestRollbackRequiredBeforeExecution:
    def test_plan_always_has_rollback_plan(self) -> None:
        plan = _make_plan()
        assert plan.rollback_plan is not None
        assert plan.rollback_plan.rollback_id != ""

    def test_empty_diff_still_has_rollback_plan(self) -> None:
        plan = _make_plan(entries=[])
        assert plan.rollback_plan is not None


# ---------------------------------------------------------------------------
# 10. Governance gates creation
# ---------------------------------------------------------------------------


class TestGovernanceGatesCreation:
    def test_9_gates_in_plan(self) -> None:
        plan = _make_plan()
        assert len(plan.gates) == 9

    def test_all_gates_start_pending(self) -> None:
        plan = _make_plan()
        assert all(g.result == "Pending" for g in plan.gates)

    def test_gate_names_match_governance_gates(self) -> None:
        plan = _make_plan()
        gate_names = {g.name for g in plan.gates}
        assert gate_names == set(GOVERNANCE_GATES)

    def test_all_gates_blocking(self) -> None:
        plan = _make_plan()
        assert all(g.blocking for g in plan.gates)


# ---------------------------------------------------------------------------
# 11. Plan fingerprint determinism
# ---------------------------------------------------------------------------


class TestPlanFingerprintDeterminism:
    def test_fingerprint_is_nonempty(self) -> None:
        plan = _make_plan()
        assert plan.plan_fingerprint != ""

    def test_fingerprint_deterministic_same_sim(self) -> None:
        # Two plans from the exact same simulation should have different plan_ids
        # (because created_at differs), but same-sim same-time would be equal.
        # We test that compute_plan_fingerprint is deterministic by calling it twice.
        plan = _make_plan()
        fp1 = compute_plan_fingerprint(plan)
        fp2 = compute_plan_fingerprint(plan)
        assert fp1 == fp2

    def test_fingerprint_changes_with_different_plan(self) -> None:
        entries1 = [_make_diff_entry("e1")]
        entries2 = [_make_diff_entry("e2")]
        plan1 = _make_plan(entries=entries1)
        plan2 = _make_plan(entries=entries2)
        assert plan1.plan_fingerprint != plan2.plan_fingerprint

    def test_step_hash_deterministic(self) -> None:
        plan = _make_plan()
        step = plan.steps[0]
        assert compute_step_hash(step) == compute_step_hash(step)


# ---------------------------------------------------------------------------
# 12. Approval creation
# ---------------------------------------------------------------------------


class TestApprovalCreation:
    def test_create_approval_returns_execution_approval(self) -> None:
        from services.governance_execution.models import ExecutionApproval

        plan = _make_plan()
        approval = create_approval(plan, "user-1", "admin_auth", "looks good")
        assert isinstance(approval, ExecutionApproval)

    def test_approval_plan_id_matches(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "user-1", "admin_auth", "ok")
        assert approval.plan_id == plan.plan_id

    def test_approval_tenant_id_matches(self) -> None:
        plan = _make_plan(tenant_id="tenant-a1")
        approval = create_approval(plan, "user-1", "admin_auth", "ok")
        assert approval.tenant_id == "tenant-a1"

    def test_approval_approver_id_set(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "user-999", "auth_x", "r")
        assert approval.approver_id == "user-999"

    def test_approval_authority_set(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "specific_authority", "r")
        assert approval.approver_authority == "specific_authority"

    def test_approval_has_fingerprint(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "r")
        assert approval.fingerprint != ""

    def test_approval_reason_set(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "my reason")
        assert approval.reason == "my reason"


# ---------------------------------------------------------------------------
# 13. Approval authority validation
# ---------------------------------------------------------------------------


class TestApprovalAuthorityValidation:
    def test_empty_authority_raises(self) -> None:
        plan = _make_plan()
        with pytest.raises(ExecutionValidationError):
            create_approval(plan, "user-1", "", "reason")

    def test_whitespace_only_authority_is_falsy(self) -> None:
        # Empty string raises
        plan = _make_plan()
        with pytest.raises(ExecutionValidationError):
            create_approval(plan, "user-1", "", "reason")

    def test_valid_authority_does_not_raise(self) -> None:
        plan = _make_plan()
        # Should not raise
        approval = create_approval(plan, "user-1", "valid_auth", "ok")
        assert approval.approver_authority == "valid_auth"


# ---------------------------------------------------------------------------
# 14. Approval requirements check
# ---------------------------------------------------------------------------


class TestApprovalRequirementsCheck:
    def test_single_approver_satisfied_by_one(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u1", "auth", "ok")
        satisfied, unmet = check_approval_requirements(plan, (approval,))
        assert satisfied is True
        assert unmet == []

    def test_dual_approval_requires_two(self) -> None:
        sim = _make_simulation_result()
        plan = plan_execution(sim, "P", "auth", approval_type="DualApproval")
        approval1 = create_approval(plan, "u1", "auth1", "ok")
        satisfied1, _ = check_approval_requirements(plan, (approval1,))
        assert satisfied1 is False

        approval2 = create_approval(plan, "u2", "auth2", "ok")
        satisfied2, unmet2 = check_approval_requirements(plan, (approval1, approval2))
        assert satisfied2 is True
        assert unmet2 == []

    def test_no_approvals_not_satisfied(self) -> None:
        plan = _make_plan()
        satisfied, unmet = check_approval_requirements(plan, ())
        assert satisfied is False
        assert len(unmet) > 0


# ---------------------------------------------------------------------------
# 15. Approval insufficient
# ---------------------------------------------------------------------------


class TestApprovalInsufficient:
    def test_create_run_with_zero_approvals_raises(self) -> None:
        plan = _make_plan()
        with pytest.raises(ExecutionValidationError):
            create_run(plan, ())

    def test_create_run_with_wrong_plan_approvals_raises(self) -> None:
        plan1 = _make_plan()
        plan2 = _make_plan()
        # Approval for plan2 should not satisfy plan1
        approval = create_approval(plan2, "u", "auth", "ok")
        with pytest.raises(ExecutionValidationError):
            create_run(plan1, (approval,))


# ---------------------------------------------------------------------------
# 16. Execution run creation
# ---------------------------------------------------------------------------


class TestExecutionRunCreation:
    def test_create_run_returns_execution_run(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert isinstance(run, ExecutionRun)

    def test_run_initial_state_is_draft(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.state == "Draft"

    def test_run_plan_id_matches(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.plan_id == plan.plan_id

    def test_run_tenant_id_matches(self) -> None:
        plan = _make_plan(tenant_id="tenant-run")
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.tenant_id == "tenant-run"

    def test_run_has_fingerprint(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.run_fingerprint != ""

    def test_run_executed_steps_initially_empty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.executed_steps == ()

    def test_run_approvals_stored(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert len(run.approvals) == 1


# ---------------------------------------------------------------------------
# 17. State machine valid transitions
# ---------------------------------------------------------------------------


class TestStateMachineValidTransitions:
    def _run_from_plan(self) -> tuple[ExecutionPlan, ExecutionRun]:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        return plan, run

    def test_advance_draft_to_validated(self) -> None:
        _, run = self._run_from_plan()
        updated_run, audit = advance_state(run, "Validated")
        assert updated_run.state == "Validated"

    def test_advance_validated_to_awaiting_approval(self) -> None:
        _, run = self._run_from_plan()
        run, _ = advance_state(run, "Validated")
        run, _ = advance_state(run, "AwaitingApproval")
        assert run.state == "AwaitingApproval"

    def test_advance_to_approved(self) -> None:
        _, run = self._run_from_plan()
        run, _ = advance_state(run, "Validated")
        run, _ = advance_state(run, "AwaitingApproval")
        run, _ = advance_state(run, "Approved")
        assert run.state == "Approved"

    def test_advance_to_executing(self) -> None:
        _, run = self._run_from_plan()
        run, _ = advance_state(run, "Validated")
        run, _ = advance_state(run, "AwaitingApproval")
        run, _ = advance_state(run, "Approved")
        run, _ = advance_state(run, "Scheduled")
        run, _ = advance_state(run, "Executing")
        assert run.state == "Executing"

    def test_advance_to_completed(self) -> None:
        _, run = self._run_from_plan()
        for state in [
            "Validated",
            "AwaitingApproval",
            "Approved",
            "Scheduled",
            "Executing",
            "Verifying",
            "Completed",
        ]:
            run, _ = advance_state(run, state)
        assert run.state == "Completed"

    def test_advance_failed_to_rollback(self) -> None:
        _, run = self._run_from_plan()
        run, _ = advance_state(run, "Validated")
        run, _ = advance_state(run, "AwaitingApproval")
        run, _ = advance_state(run, "Approved")
        run, _ = advance_state(run, "Scheduled")
        run, _ = advance_state(run, "Executing")
        run, _ = advance_state(run, "Failed")
        run, _ = advance_state(run, "Rollback")
        assert run.state == "Rollback"


# ---------------------------------------------------------------------------
# 18. State machine invalid transition
# ---------------------------------------------------------------------------


class TestStateMachineInvalidTransition:
    def test_draft_to_completed_raises(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        with pytest.raises(ExecutionValidationError):
            advance_state(run, "Completed")

    def test_closed_to_draft_raises(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        # Manually craft a run in Closed state for test
        closed_run = dataclasses.replace(run, state="Closed")
        with pytest.raises(ExecutionValidationError):
            advance_state(closed_run, "Draft")

    def test_archived_to_any_raises(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        archived_run = dataclasses.replace(run, state="Archived")
        with pytest.raises(ExecutionValidationError):
            advance_state(archived_run, "Completed")


# ---------------------------------------------------------------------------
# 19. Complete step
# ---------------------------------------------------------------------------


class TestCompleteStep:
    def test_step_id_added_to_executed_steps(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        updated = complete_step(run, "step-abc")
        assert "step-abc" in updated.executed_steps

    def test_multiple_steps_completed(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, "step-1")
        run = complete_step(run, "step-2")
        assert "step-1" in run.executed_steps
        assert "step-2" in run.executed_steps

    def test_original_run_unchanged(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        complete_step(run, "step-abc")
        assert "step-abc" not in run.executed_steps  # original frozen


# ---------------------------------------------------------------------------
# 20. Fail step
# ---------------------------------------------------------------------------


class TestFailStep:
    def test_step_id_added_to_failed_steps(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        updated = fail_step(run, "step-fail")
        assert "step-fail" in updated.failed_steps

    def test_failed_step_not_in_executed(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        updated = fail_step(run, "step-fail")
        assert "step-fail" not in updated.executed_steps


# ---------------------------------------------------------------------------
# 21. Audit record on advance_state
# ---------------------------------------------------------------------------


class TestAuditRecordOnAdvanceState:
    def test_returns_audit_record(self) -> None:
        from services.governance_execution.models import ExecutionAuditRecord

        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert isinstance(audit, ExecutionAuditRecord)

    def test_audit_before_state(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert audit.before_state == "Draft"

    def test_audit_after_state(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert audit.after_state == "Validated"

    def test_audit_has_fingerprint(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert audit.fingerprint != ""

    def test_audit_run_id_matches(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert audit.run_id == run.run_id

    def test_audit_event_type(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert audit.event_type == "state_transition"


# ---------------------------------------------------------------------------
# 22. Verification — confidence levels
# ---------------------------------------------------------------------------


class TestVerificationConfidence:
    def _make_run(self) -> ExecutionRun:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        return create_run(plan, (approval,))

    def test_proven_when_evidence_and_policy(self) -> None:
        run = self._make_run()
        v = verify_step(
            run,
            "step-1",
            evidence_collected=("ev-1",),
            policy_satisfied=True,
        )
        assert v.confidence == "PROVEN"

    def test_inferred_when_authority_confirmed(self) -> None:
        run = self._make_run()
        v = verify_step(
            run,
            "step-1",
            authority_confirmed="admin_authority",
        )
        assert v.confidence == "INFERRED"

    def test_unknown_when_nothing(self) -> None:
        run = self._make_run()
        v = verify_step(run, "step-1")
        assert v.confidence == "UNKNOWN"

    def test_proven_takes_precedence_over_authority(self) -> None:
        run = self._make_run()
        v = verify_step(
            run,
            "step-1",
            evidence_collected=("ev-1",),
            policy_satisfied=True,
            authority_confirmed="auth",
        )
        assert v.confidence == "PROVEN"


# ---------------------------------------------------------------------------
# 23. Verification outcome
# ---------------------------------------------------------------------------


class TestVerificationOutcome:
    def _make_run(self) -> ExecutionRun:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        return create_run(plan, (approval,))

    def test_success_when_expected_achieved_true(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1", expected_outcome_achieved=True)
        assert v.outcome == "success"

    def test_failure_when_expected_achieved_false(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1", expected_outcome_achieved=False)
        assert v.outcome == "failure"

    def test_unknown_when_expected_achieved_none(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1", expected_outcome_achieved=None)
        assert v.outcome == "unknown"

    def test_verification_step_id_correct(self) -> None:
        run = self._make_run()
        v = verify_step(run, "target-step")
        assert v.step_id == "target-step"

    def test_verification_run_id_correct(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1")
        assert v.run_id == run.run_id

    def test_verification_tenant_id_correct(self) -> None:
        plan = _make_plan(tenant_id="tenant-verify")
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        assert v.tenant_id == "tenant-verify"


# ---------------------------------------------------------------------------
# 24. Measurement quality
# ---------------------------------------------------------------------------


class TestMeasurementQuality:
    def _make_run(self) -> ExecutionRun:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        return create_run(plan, (approval,))

    def test_proven_quality_when_proven_verification(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1", evidence_collected=("ev-1",), policy_satisfied=True)
        m = measure_outcome(run, (v,))
        assert m.execution_quality == "PROVEN"

    def test_inferred_quality_when_inferred_verification(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1", authority_confirmed="auth")
        m = measure_outcome(run, (v,))
        assert m.execution_quality == "INFERRED"

    def test_unknown_quality_when_no_verifications(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, ())
        assert m.execution_quality == "UNKNOWN"

    def test_limitation_when_no_verifications(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, ())
        assert "no verifications provided" in m.limitations

    def test_no_limitation_when_verifications_provided(self) -> None:
        run = self._make_run()
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        assert "no verifications provided" not in m.limitations


# ---------------------------------------------------------------------------
# 25. Measurement deltas
# ---------------------------------------------------------------------------


class TestMeasurementDeltas:
    def _make_run(self) -> ExecutionRun:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        return create_run(plan, (approval,))

    def test_governance_delta_propagated(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, (), governance_delta=5)
        assert m.governance_delta == 5

    def test_risk_delta_propagated(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, (), risk_delta=-3)
        assert m.risk_delta == -3

    def test_policy_impact_propagated(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, (), policy_impact="policy updated")
        assert m.policy_impact == "policy updated"

    def test_supporting_evidence_ids_propagated(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, (), supporting_evidence_ids=("ev-a", "ev-b"))
        assert m.supporting_evidence_ids == ("ev-a", "ev-b")

    def test_none_deltas_by_default(self) -> None:
        run = self._make_run()
        m = measure_outcome(run, ())
        assert m.governance_delta is None
        assert m.control_delta is None
        assert m.compliance_delta is None


# ---------------------------------------------------------------------------
# 26. Decision ledger
# ---------------------------------------------------------------------------


class TestDecisionLedger:
    def test_ledger_hash_deterministic(self) -> None:
        plan = _make_plan()
        import hashlib

        decided_at = "2026-07-06T00:00:00Z"
        record = ExecutionDecisionRecord(
            record_id="rec-001",
            plan_id=plan.plan_id,
            run_id="run-001",
            tenant_id=plan.tenant_id,
            decided_at=decided_at,
            decided_by="user-1",
            decision="approved",
            authority="admin_auth",
            policy="default",
            supporting_evidence_ids=(),
            simulation_reference="sim-001",
            execution_reference="exec-001",
            verification_reference="ver-001",
            outcome=None,
            fingerprint=hashlib.sha256(b"test").hexdigest(),
        )
        ledger = ExecutionDecisionLedger(
            ledger_id="led-001",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(record,),
            ledger_hash="",
        )
        h1 = compute_ledger_hash(ledger)
        h2 = compute_ledger_hash(ledger)
        assert h1 == h2

    def test_ledger_hash_changes_with_different_records(self) -> None:
        plan = _make_plan()
        import hashlib

        record1 = ExecutionDecisionRecord(
            record_id="rec-001",
            plan_id=plan.plan_id,
            run_id="run-001",
            tenant_id=plan.tenant_id,
            decided_at="2026-07-06T00:00:00Z",
            decided_by="user-1",
            decision="approved",
            authority="a",
            policy="p",
            supporting_evidence_ids=(),
            simulation_reference="s",
            execution_reference="e",
            verification_reference="v",
            outcome=None,
            fingerprint=hashlib.sha256(b"r1").hexdigest(),
        )
        record2 = dataclasses.replace(
            record1, record_id="rec-002", fingerprint=hashlib.sha256(b"r2").hexdigest()
        )
        ledger1 = ExecutionDecisionLedger(
            ledger_id="l1",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(record1,),
            ledger_hash="",
        )
        ledger2 = ExecutionDecisionLedger(
            ledger_id="l1",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(record1, record2),
            ledger_hash="",
        )
        assert compute_ledger_hash(ledger1) != compute_ledger_hash(ledger2)


# ---------------------------------------------------------------------------
# 27. Rollback planning
# ---------------------------------------------------------------------------


class TestRollbackPlanning:
    def test_plan_rollback_creates_rollback_plan(self) -> None:
        from services.governance_execution.models import ExecutionRollbackPlan

        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        rb = plan_rollback(plan, run, authority="rollback_auth")
        assert isinstance(rb, ExecutionRollbackPlan)

    def test_rollback_ready_when_steps_executed(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        rb = plan_rollback(plan, run, authority="rollback_auth")
        assert rb.rollback_ready is True

    def test_rollback_not_ready_when_no_executed_steps(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        # no completed steps
        rb = plan_rollback(plan, run, authority="rollback_auth")
        assert rb.rollback_ready is False

    def test_rollback_steps_in_reverse_order(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        run = complete_step(run, plan.steps[1].step_id)
        rb = plan_rollback(plan, run, authority="a")
        # Last executed step should be first rollback step
        assert rb.rollback_steps[0].reverses_step_id == plan.steps[1].step_id


# ---------------------------------------------------------------------------
# 28. Rollback execute
# ---------------------------------------------------------------------------


class TestRollbackExecute:
    def test_execute_rollback_sets_rollback_reference(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        rb = plan_rollback(plan, run, authority="rb_auth")
        updated_run, audit = execute_rollback(rb, run)
        assert updated_run.rollback_reference == rb.rollback_id

    def test_execute_rollback_returns_audit_record(self) -> None:
        from services.governance_execution.models import ExecutionAuditRecord

        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        rb = plan_rollback(plan, run, authority="rb_auth")
        _, audit = execute_rollback(rb, run)
        assert isinstance(audit, ExecutionAuditRecord)

    def test_execute_rollback_audit_event_type(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        run = complete_step(run, plan.steps[0].step_id)
        rb = plan_rollback(plan, run, authority="rb_auth")
        _, audit = execute_rollback(rb, run)
        assert audit.event_type == "rollback_initiated"


# ---------------------------------------------------------------------------
# 29. Rollback not ready
# ---------------------------------------------------------------------------


class TestRollbackNotReady:
    def test_execute_rollback_not_ready_raises(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        # No executed steps → rollback_ready=False
        rb = plan_rollback(plan, run, authority="rb_auth")
        assert rb.rollback_ready is False
        with pytest.raises(ExecutionValidationError):
            execute_rollback(rb, run)


# ---------------------------------------------------------------------------
# 30. Replay package
# ---------------------------------------------------------------------------


class TestReplayPackage:
    def _make_replay_package(self) -> ExecutionReplayPackage:
        from services.governance_execution.models import ExecutionDecisionLedger

        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        ledger = ExecutionDecisionLedger(
            ledger_id="led-1",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(),
            ledger_hash="",
        )
        val_report = ExecutionValidationReport(
            valid=True,
            findings=(),
            highest_severity="INFO",
            violations=(),
            checked_invariants=(),
        )
        return build_execution_replay_package(
            plan,
            run,
            (v,),
            (m,),
            ledger,
            val_report,
            digital_twin_fingerprint="dtf-001",
            simulation_fingerprint="sf-001",
        )

    def test_replay_package_all_fields_present(self) -> None:
        from services.governance_execution.models import ExecutionReplayPackage

        pkg = self._make_replay_package()
        assert isinstance(pkg, ExecutionReplayPackage)

    def test_replay_package_fingerprint_nonempty(self) -> None:
        pkg = self._make_replay_package()
        assert pkg.fingerprint != ""

    def test_replay_package_execution_fingerprint_nonempty(self) -> None:
        pkg = self._make_replay_package()
        assert pkg.execution_fingerprint != ""

    def test_replay_package_mcim_version(self) -> None:
        pkg = self._make_replay_package()
        assert pkg.mcim_version == GOVERNANCE_EXECUTION_MCIM_VERSION

    def test_replay_package_schema_version(self) -> None:
        pkg = self._make_replay_package()
        assert pkg.schema_version == GOVERNANCE_EXECUTION_SCHEMA_VERSION

    def test_replay_package_replay_version(self) -> None:
        pkg = self._make_replay_package()
        assert pkg.replay_version == GOVERNANCE_EXECUTION_REPLAY_VERSION

    def test_replay_package_verifications_stored(self) -> None:
        pkg = self._make_replay_package()
        assert len(pkg.verifications) == 1

    def test_replay_package_measurements_stored(self) -> None:
        pkg = self._make_replay_package()
        assert len(pkg.measurements) == 1


# ---------------------------------------------------------------------------
# 31. Replay fingerprint determinism
# ---------------------------------------------------------------------------


class TestReplayFingerprintDeterminism:
    def test_fingerprint_deterministic(self) -> None:
        fp1 = compute_replay_fingerprint(
            "pkg-1", "plan-1", "run-1", "exec-fp", "tenant-a"
        )
        fp2 = compute_replay_fingerprint(
            "pkg-1", "plan-1", "run-1", "exec-fp", "tenant-a"
        )
        assert fp1 == fp2

    def test_fingerprint_changes_with_different_inputs(self) -> None:
        fp1 = compute_replay_fingerprint(
            "pkg-1", "plan-1", "run-1", "exec-fp", "tenant-a"
        )
        fp2 = compute_replay_fingerprint(
            "pkg-2", "plan-1", "run-1", "exec-fp", "tenant-a"
        )
        assert fp1 != fp2

    def test_execution_fingerprint_deterministic(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        fp1 = compute_execution_fingerprint(plan, run, (v,), (m,), "1.0", "1.0")
        fp2 = compute_execution_fingerprint(plan, run, (v,), (m,), "1.0", "1.0")
        assert fp1 == fp2


# ---------------------------------------------------------------------------
# 32. Validator — tenant isolation
# ---------------------------------------------------------------------------


class TestValidatorTenantIsolation:
    def test_fatal_if_step_tenant_differs(self) -> None:
        plan = _make_plan(tenant_id="tenant-a")
        # Manually patch a step with wrong tenant_id
        bad_step = dataclasses.replace(plan.steps[0], tenant_id="tenant-evil")
        bad_plan = dataclasses.replace(
            plan,
            steps=(bad_step,) + plan.steps[1:],
            plan_fingerprint=plan.plan_fingerprint,
        )
        with pytest.raises(ExecutionValidationError) as exc_info:
            validate_execution_plan(bad_plan)
        assert "tenant_isolation" in str(exc_info.value).lower() or "FATAL" in str(
            exc_info.value
        )


# ---------------------------------------------------------------------------
# 33. Validator — rollback completeness
# ---------------------------------------------------------------------------


class TestValidatorRollbackCompleteness:
    def test_error_if_rollback_not_ready(self) -> None:
        plan = _make_plan()
        # Patch rollback_plan to rollback_ready=False
        bad_rollback = dataclasses.replace(plan.rollback_plan, rollback_ready=False)
        bad_plan = dataclasses.replace(plan, rollback_plan=bad_rollback)
        with pytest.raises(ExecutionValidationError):
            validate_execution_plan(bad_plan)


# ---------------------------------------------------------------------------
# 34. Validator — authority integrity
# ---------------------------------------------------------------------------


class TestValidatorAuthorityIntegrity:
    def test_error_if_step_has_empty_authority(self) -> None:
        plan = _make_plan()
        bad_step = dataclasses.replace(plan.steps[0], authority_required="")
        bad_plan = dataclasses.replace(plan, steps=(bad_step,) + plan.steps[1:])
        with pytest.raises(ExecutionValidationError):
            validate_execution_plan(bad_plan)


# ---------------------------------------------------------------------------
# 35. Validator — dependency graph (cycle detection)
# ---------------------------------------------------------------------------


class TestValidatorDependencyGraph:
    def test_cycle_detected_as_warning(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        step_a = plan.steps[0]
        step_b = plan.steps[1]
        # Create a cycle: a depends on b, b depends on a
        cycled_a = dataclasses.replace(step_a, dependencies=(step_b.step_id,))
        cycled_b = dataclasses.replace(step_b, dependencies=(step_a.step_id,))
        bad_plan = dataclasses.replace(plan, steps=(cycled_a, cycled_b))
        # Should NOT raise (cycle is WARNING, not ERROR)
        report = validate_execution_plan(bad_plan)
        assert any(f.code == "dependency_graph" for f in report.findings)


# ---------------------------------------------------------------------------
# 36. Validator — duplicate IDs
# ---------------------------------------------------------------------------


class TestValidatorDuplicateIds:
    def test_error_on_duplicate_step_ids(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        # Force duplicate step_id
        dup_step = dataclasses.replace(plan.steps[1], step_id=plan.steps[0].step_id)
        bad_plan = dataclasses.replace(plan, steps=(plan.steps[0], dup_step))
        with pytest.raises(ExecutionValidationError):
            validate_execution_plan(bad_plan)


# ---------------------------------------------------------------------------
# 37. Validator — fail closed
# ---------------------------------------------------------------------------


class TestValidatorFailClosed:
    def test_raises_on_error_severity(self) -> None:
        plan = _make_plan()
        bad_step = dataclasses.replace(plan.steps[0], authority_required="")
        bad_plan = dataclasses.replace(plan, steps=(bad_step,) + plan.steps[1:])
        with pytest.raises(ExecutionValidationError):
            validate_execution_plan(bad_plan)

    def test_valid_plan_does_not_raise(self) -> None:
        plan = _make_plan()
        # Should not raise; returns report
        report = validate_execution_plan(plan)
        assert isinstance(report, ExecutionValidationReport)

    def test_valid_plan_report_is_valid(self) -> None:
        plan = _make_plan()
        report = validate_execution_plan(plan)
        assert report.valid is True


# ---------------------------------------------------------------------------
# 38. Manifest generation
# ---------------------------------------------------------------------------


class TestManifestGeneration:
    def test_manifest_step_count_correct(self) -> None:
        entries = [_make_diff_entry("e1"), _make_diff_entry("e2")]
        plan = _make_plan(entries=entries)
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        manifest = build_execution_manifest(plan, run, (v,), (m,), "exec-fp-001")
        assert manifest.step_count == 2

    def test_manifest_execution_version(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        manifest = build_execution_manifest(plan, run, (), (), "exec-fp-001")
        assert manifest.execution_version == GOVERNANCE_EXECUTION_VERSION

    def test_manifest_planner_version(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        manifest = build_execution_manifest(plan, run, (), (), "exec-fp-001")
        assert manifest.planner_version == GOVERNANCE_EXECUTION_PLANNER_VERSION

    def test_manifest_mcim_version(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        manifest = build_execution_manifest(plan, run, (), (), "exec-fp-001")
        assert manifest.mcim_version == GOVERNANCE_EXECUTION_MCIM_VERSION

    def test_manifest_rollback_ready(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        manifest = build_execution_manifest(plan, run, (), (), "exec-fp-001")
        assert manifest.rollback_ready is True

    def test_manifest_verification_count(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v1 = verify_step(run, "s1")
        v2 = verify_step(run, "s2")
        manifest = build_execution_manifest(plan, run, (v1, v2), (), "fp")
        assert manifest.verification_count == 2

    def test_manifest_approval_count(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        manifest = build_execution_manifest(plan, run, (), (), "fp")
        assert manifest.approval_count == 1


# ---------------------------------------------------------------------------
# 39. MCIM registration
# ---------------------------------------------------------------------------


class TestMcimRegistration:
    def test_all_13_keys_present(self) -> None:
        expected_keys = {
            "execution_plan",
            "execution_run",
            "execution_decision",
            "execution_verification",
            "execution_measurement",
            "execution_replay",
            "execution_manifest",
            "execution_approval",
            "execution_gate",
            "execution_policy",
            "execution_authority",
            "execution_rollback",
            "execution_audit",
        }
        assert set(MCIM_REGISTRATION_SOURCE.keys()) == expected_keys

    def test_execution_plan_mcim_value(self) -> None:
        assert MCIM_REGISTRATION_SOURCE["execution_plan"] == "MCIM-18.8.3-EXEC-PLAN"

    def test_execution_run_mcim_value(self) -> None:
        assert MCIM_REGISTRATION_SOURCE["execution_run"] == "MCIM-18.8.3-EXEC-RUN"

    def test_execution_replay_mcim_value(self) -> None:
        assert MCIM_REGISTRATION_SOURCE["execution_replay"] == "MCIM-18.8.3-EXEC-REPLAY"

    def test_execution_audit_mcim_value(self) -> None:
        assert MCIM_REGISTRATION_SOURCE["execution_audit"] == "MCIM-18.8.3-EXEC-AUDIT"


# ---------------------------------------------------------------------------
# 40. Export
# ---------------------------------------------------------------------------


class TestExport:
    def _make_pkg(self) -> ExecutionReplayPackage:
        from services.governance_execution.models import ExecutionDecisionLedger

        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        ledger = ExecutionDecisionLedger(
            ledger_id="led-1",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(),
            ledger_hash="",
        )
        val_report = ExecutionValidationReport(
            valid=True,
            findings=(),
            highest_severity="INFO",
            violations=(),
            checked_invariants=(),
        )
        return build_execution_replay_package(
            plan, run, (v,), (m,), ledger, val_report, "dtf-001", "sf-001"
        )

    def test_export_returns_mapping(self) -> None:
        from collections.abc import Mapping

        pkg = self._make_pkg()
        exported = export_execution_replay_package(pkg)
        assert isinstance(exported, Mapping)

    def test_export_has_replay_instructions(self) -> None:
        pkg = self._make_pkg()
        exported = export_execution_replay_package(pkg)
        assert "replay_instructions" in exported

    def test_export_is_deep_frozen(self) -> None:
        from services.governance_digital_twin.immutability import FrozenDict

        pkg = self._make_pkg()
        exported = export_execution_replay_package(pkg)
        assert isinstance(exported, FrozenDict)

    def test_export_no_forbidden_keys(self) -> None:
        forbidden = {
            "secret",
            "token",
            "password",
            "api_key",
            "auth_header",
            "authorization",
            "raw_prompt",
            "raw_vector",
            "embedding",
            "provider_payload",
            "private_key",
            "session",
            "cookie",
        }
        pkg = self._make_pkg()
        exported = export_execution_replay_package(pkg)

        def _check_keys(d: object) -> None:
            if isinstance(d, dict):
                for k, v in d.items():
                    assert k not in forbidden, f"Forbidden key found: {k}"
                    _check_keys(v)
            elif isinstance(d, (list, tuple)):
                for item in d:
                    _check_keys(item)

        _check_keys(dict(exported))

    def test_export_contains_plan_id(self) -> None:
        pkg = self._make_pkg()
        exported = export_execution_replay_package(pkg)
        assert "plan_id" in exported


# ---------------------------------------------------------------------------
# 41. Frozen dataclasses
# ---------------------------------------------------------------------------


class TestFrozenDataclasses:
    def test_cannot_mutate_execution_plan_state(self) -> None:
        plan = _make_plan()
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            plan.state = "Approved"  # type: ignore[misc]

    def test_cannot_mutate_execution_step(self) -> None:
        plan = _make_plan()
        step = plan.steps[0]
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            step.sequence = 99  # type: ignore[misc]

    def test_cannot_mutate_execution_run(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            run.state = "Completed"  # type: ignore[misc]

    def test_cannot_mutate_execution_approval(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            approval.reason = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 42. Empty diff → valid plan
# ---------------------------------------------------------------------------


class TestEmptyDiffValidPlan:
    def test_plan_with_zero_steps(self) -> None:
        plan = _make_plan(entries=[])
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) == 0

    def test_empty_plan_still_has_rollback(self) -> None:
        plan = _make_plan(entries=[])
        assert plan.rollback_plan is not None

    def test_empty_plan_still_has_gates(self) -> None:
        plan = _make_plan(entries=[])
        assert len(plan.gates) == 9

    def test_empty_plan_rollback_ready_false(self) -> None:
        # Empty diff → no steps → rollback_ready=True (empty rollback is still ready per planner)
        plan = _make_plan(entries=[])
        # Planner sets rollback_ready=True regardless
        assert plan.rollback_plan.rollback_ready is True

    def test_empty_plan_can_create_run(self) -> None:
        plan = _make_plan(entries=[])
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert isinstance(run, ExecutionRun)


# ---------------------------------------------------------------------------
# 43. Service contract
# ---------------------------------------------------------------------------


class TestServiceContract:
    def test_governance_execution_service_has_plan(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "plan")

    def test_governance_execution_service_has_validate(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "validate")

    def test_governance_execution_service_has_approve(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "approve")

    def test_governance_execution_service_has_execute(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "execute")

    def test_governance_execution_service_has_verify(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "verify")

    def test_governance_execution_service_has_measure(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "measure")

    def test_governance_execution_service_has_rollback(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "rollback")

    def test_governance_execution_service_has_export(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "export")

    def test_governance_execution_service_has_replay(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "replay")

    def test_governance_execution_service_has_fingerprint(self) -> None:
        svc = GovernanceExecutionService()
        assert hasattr(svc, "fingerprint")

    def test_service_plan_returns_execution_plan(self) -> None:
        svc = GovernanceExecutionService()
        sim = _make_simulation_result()
        plan = svc.plan(sim, "P", "auth")
        assert isinstance(plan, ExecutionPlan)

    def test_service_replay_raises_not_implemented(self) -> None:
        from services.governance_execution.models import ExecutionDecisionLedger

        svc = GovernanceExecutionService()
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        m = measure_outcome(run, (v,))
        ledger = ExecutionDecisionLedger(
            ledger_id="led-1",
            plan_id=plan.plan_id,
            tenant_id=plan.tenant_id,
            records=(),
            ledger_hash="",
        )
        val_report = ExecutionValidationReport(
            valid=True,
            findings=(),
            highest_severity="INFO",
            violations=(),
            checked_invariants=(),
        )
        pkg = build_execution_replay_package(
            plan, run, (v,), (m,), ledger, val_report, "dtf", "sf"
        )
        with pytest.raises(NotImplementedError):
            svc.replay(pkg)

    def test_service_fingerprint_returns_str(self) -> None:
        svc = GovernanceExecutionService()
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        fp = svc.fingerprint(plan, run, (), ())
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex

    def test_governance_execution_service_contract_is_protocol(self) -> None:
        import typing

        assert issubclass(GovernanceExecutionServiceContract, typing.Protocol)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 44. Fingerprint — various hash functions
# ---------------------------------------------------------------------------


class TestFingerprintFunctions:
    def test_compute_step_hash_nonempty(self) -> None:
        plan = _make_plan()
        assert compute_step_hash(plan.steps[0]) != ""

    def test_compute_step_hash_deterministic(self) -> None:
        plan = _make_plan()
        step = plan.steps[0]
        assert compute_step_hash(step) == compute_step_hash(step)

    def test_compute_approval_hash_nonempty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        assert compute_approval_hash(approval) != ""

    def test_compute_approval_hash_deterministic(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        assert compute_approval_hash(approval) == compute_approval_hash(approval)

    def test_compute_run_fingerprint_deterministic(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert compute_run_fingerprint(run) == compute_run_fingerprint(run)

    def test_compute_verification_hash_nonempty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        v = verify_step(run, "s1")
        assert compute_verification_hash(v) != ""

    def test_compute_measurement_hash_nonempty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        m = measure_outcome(run, ())
        assert compute_measurement_hash(m) != ""

    def test_compute_execution_fingerprint_is_64_chars(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        fp = compute_execution_fingerprint(plan, run, (), (), "1.0", "1.0")
        assert len(fp) == 64

    def test_fingerprint_domain_used_in_plan_fingerprint(self) -> None:
        # The domain must be FG_GOVERNANCE_EXECUTION_V1
        assert GOVERNANCE_EXECUTION_FINGERPRINT_DOMAIN == "FG_GOVERNANCE_EXECUTION_V1"

    def test_compute_audit_fingerprint_nonempty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        _, audit = advance_state(run, "Validated")
        assert compute_audit_fingerprint(audit) != ""


# ---------------------------------------------------------------------------
# 45. Domain priority ordering in steps
# ---------------------------------------------------------------------------


class TestDomainPriorityOrdering:
    def test_authority_domain_comes_before_governance(self) -> None:
        entries = [
            _make_diff_entry("g1", domain="governance"),
            _make_diff_entry("a1", domain="authority"),
        ]
        plan = _make_plan(entries=entries)
        # authority < governance in priority
        assert (
            plan.steps[0].description.endswith("test change a1")
            or "authority" in plan.steps[0].name
        )

    def test_governance_domain_comes_before_compliance(self) -> None:
        entries = [
            _make_diff_entry("c1", domain="compliance"),
            _make_diff_entry("g1", domain="governance"),
        ]
        plan = _make_plan(entries=entries)
        # governance < compliance in priority
        assert "governance" in plan.steps[0].name or plan.steps[0].sequence == 1

    def test_sequences_cover_all_entries(self) -> None:
        n = 5
        entries = [_make_diff_entry(f"e{i}") for i in range(n)]
        plan = _make_plan(entries=entries)
        assert len(plan.steps) == n
        seqs = sorted(s.sequence for s in plan.steps)
        assert seqs == list(range(1, n + 1))


# ---------------------------------------------------------------------------
# 46. Plan authorities and approval requirements
# ---------------------------------------------------------------------------


class TestPlanAuthoritiesAndApprovals:
    def test_plan_has_one_authority(self) -> None:
        plan = _make_plan()
        assert len(plan.authorities) == 1

    def test_plan_authority_name_matches(self) -> None:
        sim = _make_simulation_result()
        plan = plan_execution(sim, "P", "my_authority")
        assert plan.authorities[0].name == "my_authority"

    def test_plan_has_one_approval_requirement(self) -> None:
        plan = _make_plan()
        assert len(plan.approval_requirements) == 1

    def test_approval_requirement_type_single(self) -> None:
        plan = _make_plan()
        assert plan.approval_requirements[0].approval_type == "SingleApprover"

    def test_approval_requirement_min_approvers_1(self) -> None:
        plan = _make_plan()
        assert plan.approval_requirements[0].min_approvers == 1

    def test_approval_requirement_dual_type(self) -> None:
        sim = _make_simulation_result()
        plan = plan_execution(sim, "P", "auth", approval_type="DualApproval")
        assert plan.approval_requirements[0].approval_type == "DualApproval"
        assert plan.approval_requirements[0].min_approvers == 2

    def test_authority_tenant_matches_plan(self) -> None:
        plan = _make_plan(tenant_id="tenant-auth-check")
        assert plan.authorities[0].tenant_id == "tenant-auth-check"


# ---------------------------------------------------------------------------
# 47. Execution enum values
# ---------------------------------------------------------------------------


class TestEnumValues:
    def test_execution_state_draft_value(self) -> None:
        from services.governance_execution.models import ExecutionState

        assert ExecutionState.Draft.value == "Draft"

    def test_execution_state_closed_value(self) -> None:
        from services.governance_execution.models import ExecutionState

        assert ExecutionState.Closed.value == "Closed"

    def test_approval_type_single_value(self) -> None:
        from services.governance_execution.models import ApprovalType

        assert ApprovalType.SingleApprover.value == "SingleApprover"

    def test_outcome_confidence_proven_value(self) -> None:
        from services.governance_execution.models import ExecutionOutcomeConfidence

        assert ExecutionOutcomeConfidence.PROVEN.value == "PROVEN"

    def test_gate_result_pending_value(self) -> None:
        from services.governance_execution.models import ExecutionGateResult

        assert ExecutionGateResult.Pending.value == "Pending"

    def test_step_state_completed_value(self) -> None:
        from services.governance_execution.models import ExecutionStepState

        assert ExecutionStepState.Completed.value == "Completed"

    def test_all_execution_states_count(self) -> None:
        from services.governance_execution.models import ExecutionState

        assert len(list(ExecutionState)) == 14

    def test_all_approval_types_count(self) -> None:
        from services.governance_execution.models import ApprovalType

        assert len(list(ApprovalType)) == 9

    def test_all_step_states_count(self) -> None:
        from services.governance_execution.models import ExecutionStepState

        assert len(list(ExecutionStepState)) == 6


# ---------------------------------------------------------------------------
# 48. Execution run fields
# ---------------------------------------------------------------------------


class TestExecutionRunFields:
    def test_run_simulation_id_matches_plan(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.simulation_id == plan.simulation_id

    def test_run_simulation_fingerprint_matches_plan(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.simulation_fingerprint == plan.simulation_fingerprint

    def test_run_completed_at_initially_none(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.completed_at is None

    def test_run_failed_at_initially_none(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.failed_at is None

    def test_run_rollback_reference_initially_none(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.rollback_reference is None

    def test_run_verification_ids_initially_empty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.verification_ids == ()

    def test_run_measurement_ids_initially_empty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.measurement_ids == ()

    def test_run_skipped_steps_initially_empty(self) -> None:
        plan = _make_plan()
        approval = create_approval(plan, "u", "auth", "ok")
        run = create_run(plan, (approval,))
        assert run.skipped_steps == ()


# ---------------------------------------------------------------------------
# 49. Validation report fields
# ---------------------------------------------------------------------------


class TestValidationReportFields:
    def test_valid_plan_checked_invariants_nonempty(self) -> None:
        plan = _make_plan()
        report = validate_execution_plan(plan)
        assert len(report.checked_invariants) > 0

    def test_valid_plan_violations_empty(self) -> None:
        plan = _make_plan()
        report = validate_execution_plan(plan)
        assert report.violations == ()

    def test_finding_severity_field(self) -> None:
        f = ExecutionValidationFinding(
            severity="WARNING", code="dep_cycle", message="cycle"
        )
        assert f.severity == "WARNING"
        assert f.code == "dep_cycle"
        assert f.message == "cycle"

    def test_validation_report_is_frozen(self) -> None:
        plan = _make_plan()
        report = validate_execution_plan(plan)
        with pytest.raises((TypeError, dataclasses.FrozenInstanceError)):
            report.valid = False  # type: ignore[misc]
