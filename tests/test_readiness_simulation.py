"""Tests for Enterprise Governance Simulation, Readiness Impact Projection
& Autonomous Systems Governance Modeling Engine.

Covers:
- Pure unit: derive_simulation_id determinism, tenant isolation, scenario scope
- Pure unit: derive_simulation_snapshot_id, derive_impact_id
- Pure unit: each scenario evaluator — correct projections and warnings
- Pure unit: SimulationEngine — dispatch, fail-closed, version pins
- Pure unit: serialization round-trip
- API: POST /control-plane/readiness/simulation/runs (success, idempotency, errors)
- API: GET /control-plane/readiness/simulation/runs (list, filter, tenant isolation)
- API: GET /control-plane/readiness/simulation/runs/{run_id} (get, 404, isolation)
- Security: no secrets / vectors / prompts; projection_json not in responses

All API tests run offline against an in-memory SQLite DB.
"""

from __future__ import annotations

import os

os.environ.setdefault("FG_ENV", "dev")
os.environ.setdefault("FG_AUTH_ENABLED", "0")
os.environ.setdefault("FG_SQLITE_PATH", "state/test_readiness_simulation.db")
os.environ.setdefault("FG_RL_ENABLED", "0")

import json
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_input(
    scenario_type: str = "provider_change",
    params: dict | None = None,
    tenant_id: str = "tenant-sim-1",
    assessment_id: str | None = None,
    framework_id: str | None = None,
    contract_version: str = "1.0",
):
    from services.readiness.simulation.models import (
        SimulationInput,
        SimulationScenarioType,
    )

    if params is None:
        params = {}
    sorted_params = tuple(sorted(params.items()))
    return SimulationInput(
        scenario_type=SimulationScenarioType(scenario_type),
        scenario_parameters=sorted_params,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        framework_id=framework_id,
        simulation_contract_version=contract_version,
        simulation_engine_version="1.0",
        requested_at_iso=datetime.now(timezone.utc).isoformat(),
    )


# ---------------------------------------------------------------------------
# TestDeriveSimulationId (5 tests)
# ---------------------------------------------------------------------------


class TestDeriveSimulationId:
    def test_determinism(self):
        from services.readiness.simulation.identity import derive_simulation_id

        a = derive_simulation_id("t1", "a1", "fw1", "provider_change", "{}", "1.0")
        b = derive_simulation_id("t1", "a1", "fw1", "provider_change", "{}", "1.0")
        assert a == b

    def test_tenant_isolation(self):
        from services.readiness.simulation.identity import derive_simulation_id

        a = derive_simulation_id(
            "tenant-A", "a1", "fw1", "provider_change", "{}", "1.0"
        )
        b = derive_simulation_id(
            "tenant-B", "a1", "fw1", "provider_change", "{}", "1.0"
        )
        assert a != b

    def test_scenario_type_in_key(self):
        from services.readiness.simulation.identity import derive_simulation_id

        a = derive_simulation_id("t1", "a1", "fw1", "provider_change", "{}", "1.0")
        b = derive_simulation_id("t1", "a1", "fw1", "policy_change", "{}", "1.0")
        assert a != b

    def test_assessment_id_scope(self):
        from services.readiness.simulation.identity import derive_simulation_id

        a = derive_simulation_id(
            "t1", "assessment-1", "fw1", "policy_change", "{}", "1.0"
        )
        b = derive_simulation_id(
            "t1", "assessment-2", "fw1", "policy_change", "{}", "1.0"
        )
        assert a != b

    def test_contract_version_in_key(self):
        from services.readiness.simulation.identity import derive_simulation_id

        a = derive_simulation_id("t1", "a1", "fw1", "policy_change", "{}", "1.0")
        b = derive_simulation_id("t1", "a1", "fw1", "policy_change", "{}", "2.0")
        assert a != b


# ---------------------------------------------------------------------------
# TestDeriveSimulationSnapshotId (3 tests)
# ---------------------------------------------------------------------------


class TestDeriveSimulationSnapshotId:
    def test_determinism(self):
        from services.readiness.simulation.identity import derive_simulation_snapshot_id

        a = derive_simulation_snapshot_id("sim-abc", "2026-05-18T10:00:00+00:00")
        b = derive_simulation_snapshot_id("sim-abc", "2026-05-18T10:00:00+00:00")
        assert a == b

    def test_uniqueness_per_timestamp(self):
        from services.readiness.simulation.identity import derive_simulation_snapshot_id

        a = derive_simulation_snapshot_id("sim-abc", "2026-05-18T10:00:00+00:00")
        b = derive_simulation_snapshot_id("sim-abc", "2026-05-18T11:00:00+00:00")
        assert a != b

    def test_returns_32_char_hex(self):
        from services.readiness.simulation.identity import derive_simulation_snapshot_id

        sid = derive_simulation_snapshot_id("sim-x", "2026-01-01T00:00:00+00:00")
        assert len(sid) == 32
        assert all(c in "0123456789abcdef" for c in sid)


# ---------------------------------------------------------------------------
# TestDeriveImpactId (3 tests)
# ---------------------------------------------------------------------------


class TestDeriveImpactId:
    def test_determinism(self):
        from services.readiness.simulation.identity import derive_impact_id

        a = derive_impact_id("sim-1", "provider_governance", "provider:p1")
        b = derive_impact_id("sim-1", "provider_governance", "provider:p1")
        assert a == b

    def test_domain_isolation(self):
        from services.readiness.simulation.identity import derive_impact_id

        a = derive_impact_id("sim-1", "provider_governance", "scope")
        b = derive_impact_id("sim-1", "policy_governance", "scope")
        assert a != b

    def test_returns_24_char_hex(self):
        from services.readiness.simulation.identity import derive_impact_id

        iid = derive_impact_id("sim-1", "domain", "scope")
        assert len(iid) == 24
        assert all(c in "0123456789abcdef" for c in iid)


# ---------------------------------------------------------------------------
# TestProviderChangeScenario (5 tests)
# ---------------------------------------------------------------------------


class TestProviderChangeScenario:
    def test_blocked_provider_risk_degraded(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_provider_change

        params = (("new_status", "blocked"), ("provider_id", "p1"))
        _, risk, _, _, _, _, _ = evaluate_provider_change("sim-1", params)
        assert risk.direction == SimulationRiskDirection.DEGRADED
        assert risk.projected_risk_score > risk.baseline_risk_score

    def test_allowed_provider_risk_improved(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_provider_change

        params = (("new_status", "allowed"), ("provider_id", "p1"))
        _, risk, _, _, _, _, _ = evaluate_provider_change("sim-1", params)
        assert risk.direction == SimulationRiskDirection.IMPROVED

    def test_missing_params_unsupported_boundary(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import evaluate_provider_change

        readiness, _, _, _, _, _, _ = evaluate_provider_change("sim-1", ())
        assert readiness.uncertainty == SimulationUncertainty.UNSUPPORTED_BOUNDARY

    def test_blocked_provider_generates_warnings(self):
        from services.readiness.simulation.scenarios import evaluate_provider_change

        params = (("new_status", "blocked"), ("provider_id", "p-x"))
        _, _, _, _, _, warnings, _ = evaluate_provider_change("sim-1", params)
        assert len(warnings) > 0
        severities = {w.severity.value for w in warnings}
        assert any(s in severities for s in ("critical", "blocking", "high"))

    def test_blocked_provider_generates_impact_records(self):
        from services.readiness.simulation.scenarios import evaluate_provider_change

        params = (("new_status", "blocked"), ("provider_id", "p-y"))
        _, _, _, impacts, _, _, _ = evaluate_provider_change("sim-1", params)
        assert len(impacts) > 0
        assert impacts[0].impact_domain == "provider_governance"


# ---------------------------------------------------------------------------
# TestPolicyChangeScenario (5 tests)
# ---------------------------------------------------------------------------


class TestPolicyChangeScenario:
    def test_disabled_policy_readiness_regression(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_policy_change

        params = (
            ("new_enabled", "false"),
            ("new_enforcement_mode", "disabled"),
            ("policy_id", "policy-basic"),
        )
        readiness, _, _, _, _, _, _ = evaluate_policy_change("sim-1", params)
        assert readiness.direction == SimulationRiskDirection.DEGRADED
        assert readiness.projected_completion_pct < readiness.baseline_completion_pct

    def test_provenance_disabled_critical_warning(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import evaluate_policy_change

        params = (
            ("new_enabled", "false"),
            ("new_enforcement_mode", "disabled"),
            ("policy_id", "provenance-enforcement-policy"),
        )
        _, _, _, _, _, warnings, _ = evaluate_policy_change("sim-1", params)
        assert any(w.severity == SimulationSeverity.CRITICAL for w in warnings)

    def test_audit_disabled_blocking_warning(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import evaluate_policy_change

        params = (
            ("new_enabled", "false"),
            ("new_enforcement_mode", "disabled"),
            ("policy_id", "audit-chain-policy"),
        )
        _, _, _, _, _, warnings, _ = evaluate_policy_change("sim-1", params)
        assert any(w.severity == SimulationSeverity.BLOCKING for w in warnings)

    def test_enabled_strict_policy_improvement(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_policy_change

        params = (
            ("new_enabled", "true"),
            ("new_enforcement_mode", "strict"),
            ("policy_id", "policy-x"),
        )
        readiness, _, _, _, _, _, _ = evaluate_policy_change("sim-1", params)
        assert readiness.direction == SimulationRiskDirection.IMPROVED

    def test_unknown_enforcement_mode_unsupported_boundary(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import evaluate_policy_change

        params = (
            ("new_enabled", "true"),
            ("new_enforcement_mode", "quantum-enforcement"),
            ("policy_id", "policy-q"),
        )
        readiness, _, _, _, _, warnings, _ = evaluate_policy_change("sim-1", params)
        assert readiness.uncertainty == SimulationUncertainty.UNSUPPORTED_BOUNDARY
        assert len(warnings) > 0


# ---------------------------------------------------------------------------
# TestRetrievalStrategyScenario (4 tests)
# ---------------------------------------------------------------------------


class TestRetrievalStrategyScenario:
    def test_disabled_retrieval_degraded(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import (
            evaluate_retrieval_strategy_change,
        )

        params = (("new_enabled", "false"), ("policy_id", "retrieval-pol-1"))
        readiness, _, _, _, _, _, _ = evaluate_retrieval_strategy_change(
            "sim-1", params
        )
        assert readiness.direction == SimulationRiskDirection.DEGRADED

    def test_reranker_disabled_moderate_warning(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import (
            evaluate_retrieval_strategy_change,
        )

        params = (
            ("new_enabled", "true"),
            ("new_reranker_state", "disabled"),
            ("policy_id", "retrieval-pol-2"),
        )
        _, _, _, _, _, warnings, _ = evaluate_retrieval_strategy_change("sim-1", params)
        assert any(
            w.severity in (SimulationSeverity.MODERATE, SimulationSeverity.HIGH)
            for w in warnings
        )

    def test_enabled_active_reranker_improved(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import (
            evaluate_retrieval_strategy_change,
        )

        params = (
            ("new_enabled", "true"),
            ("new_reranker_state", "active"),
            ("policy_id", "retrieval-pol-3"),
        )
        readiness, _, _, _, _, _, _ = evaluate_retrieval_strategy_change(
            "sim-1", params
        )
        assert readiness.direction == SimulationRiskDirection.IMPROVED

    def test_missing_policy_id_unsupported_boundary(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import (
            evaluate_retrieval_strategy_change,
        )

        readiness, _, _, _, _, _, _ = evaluate_retrieval_strategy_change("sim-1", ())
        assert readiness.uncertainty == SimulationUncertainty.UNSUPPORTED_BOUNDARY


# ---------------------------------------------------------------------------
# TestTenantPolicyRelaxationScenario (4 tests)
# ---------------------------------------------------------------------------


class TestTenantPolicyRelaxationScenario:
    def test_always_generates_high_or_critical_warning(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import (
            evaluate_tenant_policy_relaxation,
        )

        params = (("new_threshold", "50"), ("relaxation_type", "evidence"))
        _, _, _, _, _, warnings, _ = evaluate_tenant_policy_relaxation("sim-1", params)
        assert len(warnings) > 0
        assert all(
            w.severity in (SimulationSeverity.HIGH, SimulationSeverity.CRITICAL)
            for w in warnings
        )

    def test_evidence_relaxation(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import (
            evaluate_tenant_policy_relaxation,
        )

        params = (("new_threshold", "10"), ("relaxation_type", "evidence"))
        readiness, risk, _, _, _, warnings, _ = evaluate_tenant_policy_relaxation(
            "sim-1", params
        )
        assert risk.direction == SimulationRiskDirection.DEGRADED
        assert len(warnings) > 0

    def test_provenance_relaxation(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import (
            evaluate_tenant_policy_relaxation,
        )

        params = (("new_threshold", "5"), ("relaxation_type", "provenance"))
        _, _, _, _, _, warnings, _ = evaluate_tenant_policy_relaxation("sim-1", params)
        assert any(w.severity == SimulationSeverity.CRITICAL for w in warnings)

    def test_returns_non_optimistic_uncertainty(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import (
            evaluate_tenant_policy_relaxation,
        )

        params = (("new_threshold", "5"), ("relaxation_type", "audit"))
        readiness, _, _, _, _, _, _ = evaluate_tenant_policy_relaxation("sim-1", params)
        assert readiness.uncertainty != SimulationUncertainty.CONFIRMED


# ---------------------------------------------------------------------------
# TestFrameworkUpgradeScenario (5 tests)
# ---------------------------------------------------------------------------


class TestFrameworkUpgradeScenario:
    def test_added_controls_readiness_regression(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_framework_upgrade

        params = (
            ("added_control_count", "10"),
            ("removed_control_count", "0"),
            ("target_framework_version_tag", "v2.0"),
        )
        readiness, _, _, _, _, _, _ = evaluate_framework_upgrade("sim-1", params)
        assert readiness.direction == SimulationRiskDirection.DEGRADED
        assert readiness.projected_completion_pct < readiness.baseline_completion_pct

    def test_removed_controls_no_regression(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_framework_upgrade

        params = (
            ("added_control_count", "0"),
            ("removed_control_count", "5"),
            ("target_framework_version_tag", "v1.5"),
        )
        readiness, _, _, _, _, _, _ = evaluate_framework_upgrade("sim-1", params)
        assert readiness.direction in (
            SimulationRiskDirection.IMPROVED,
            SimulationRiskDirection.UNCHANGED,
        )

    def test_zero_delta_unchanged(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import evaluate_framework_upgrade

        params = (
            ("added_control_count", "0"),
            ("removed_control_count", "0"),
            ("target_framework_version_tag", "v1.1"),
        )
        readiness, _, _, _, _, _, _ = evaluate_framework_upgrade("sim-1", params)
        assert readiness.direction == SimulationRiskDirection.UNCHANGED

    def test_newly_missing_required_populated(self):
        from services.readiness.simulation.scenarios import evaluate_framework_upgrade

        params = (
            ("added_control_count", "5"),
            ("removed_control_count", "0"),
            ("target_framework_version_tag", "v3.0"),
        )
        readiness, _, compliance, _, _, _, _ = evaluate_framework_upgrade(
            "sim-1", params
        )
        assert len(readiness.newly_failing_control_ids) > 0
        assert len(compliance.newly_missing_required_controls) > 0

    def test_compliance_drops_with_added_controls(self):
        from services.readiness.simulation.scenarios import evaluate_framework_upgrade

        params = (
            ("added_control_count", "8"),
            ("removed_control_count", "0"),
            ("target_framework_version_tag", "v4.0"),
        )
        _, _, compliance, _, _, _, _ = evaluate_framework_upgrade("sim-1", params)
        assert (
            compliance.projected_framework_coverage
            < compliance.baseline_framework_coverage
        )
        assert compliance.compliance_risk_increase is True


# ---------------------------------------------------------------------------
# TestGovernanceEnforcementScenario (4 tests)
# ---------------------------------------------------------------------------


class TestGovernanceEnforcementScenario:
    def test_disabled_generates_blocking_warning_and_degraded(self):
        from services.readiness.simulation.models import (
            SimulationRiskDirection,
            SimulationSeverity,
        )
        from services.readiness.simulation.scenarios import (
            evaluate_governance_enforcement_change,
        )

        params = (("enforcement_mode", "disabled"),)
        readiness, risk, _, _, _, warnings, _ = evaluate_governance_enforcement_change(
            "sim-1", params
        )
        assert risk.direction == SimulationRiskDirection.DEGRADED
        assert any(w.severity == SimulationSeverity.BLOCKING for w in warnings)

    def test_permissive_generates_high_warning(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import (
            evaluate_governance_enforcement_change,
        )

        params = (("enforcement_mode", "permissive"),)
        _, _, _, _, _, warnings, _ = evaluate_governance_enforcement_change(
            "sim-1", params
        )
        assert any(
            w.severity in (SimulationSeverity.HIGH, SimulationSeverity.CRITICAL)
            for w in warnings
        )

    def test_strict_no_degradation(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import (
            evaluate_governance_enforcement_change,
        )

        params = (("enforcement_mode", "strict"),)
        _, risk, _, _, _, _, _ = evaluate_governance_enforcement_change("sim-1", params)
        assert risk.direction in (
            SimulationRiskDirection.IMPROVED,
            SimulationRiskDirection.UNCHANGED,
        )

    def test_unknown_enforcement_unsupported_boundary(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import (
            evaluate_governance_enforcement_change,
        )

        params = (("enforcement_mode", "hyper-strict"),)
        readiness, _, _, _, _, warnings, _ = evaluate_governance_enforcement_change(
            "sim-1", params
        )
        assert readiness.uncertainty == SimulationUncertainty.UNSUPPORTED_BOUNDARY
        assert len(warnings) > 0


# ---------------------------------------------------------------------------
# TestCapabilityGovernanceScenario (4 tests)
# ---------------------------------------------------------------------------


class TestCapabilityGovernanceScenario:
    def test_expand_critical_warning_and_authority_degradation(self):
        from services.readiness.simulation.models import SimulationSeverity
        from services.readiness.simulation.scenarios import (
            evaluate_capability_governance_change,
        )

        params = (
            ("authority_change", "expand"),
            ("capability_scope", "agent:tool-exec"),
        )
        _, _, _, _, _, warnings, _ = evaluate_capability_governance_change(
            "sim-1", params
        )
        assert any(w.severity == SimulationSeverity.CRITICAL for w in warnings)

    def test_restrict_no_degradation(self):
        from services.readiness.simulation.models import SimulationRiskDirection
        from services.readiness.simulation.scenarios import (
            evaluate_capability_governance_change,
        )

        params = (
            ("authority_change", "restrict"),
            ("capability_scope", "agent:file-write"),
        )
        _, risk, _, _, _, _, _ = evaluate_capability_governance_change("sim-1", params)
        assert risk.direction in (
            SimulationRiskDirection.IMPROVED,
            SimulationRiskDirection.UNCHANGED,
        )

    def test_unknown_authority_change_unsupported_boundary(self):
        from services.readiness.simulation.models import SimulationUncertainty
        from services.readiness.simulation.scenarios import (
            evaluate_capability_governance_change,
        )

        params = (
            ("authority_change", "teleport"),
            ("capability_scope", "agent:x"),
        )
        readiness, _, _, _, _, _, _ = evaluate_capability_governance_change(
            "sim-1", params
        )
        assert readiness.uncertainty == SimulationUncertainty.UNSUPPORTED_BOUNDARY

    def test_escalation_risk_increase_when_expanded(self):
        from services.readiness.simulation.scenarios import (
            evaluate_capability_governance_change,
        )

        params = (
            ("authority_change", "expand"),
            ("capability_scope", "agent:network-access"),
        )
        _, risk, _, impacts, _, _, _ = evaluate_capability_governance_change(
            "sim-1", params
        )
        # Risk should show escalation factor
        risk_factor_keys = {k for k, _ in risk.risk_factors}
        assert any("escalation" in k for k in risk_factor_keys)


# ---------------------------------------------------------------------------
# TestSimulationEngine (6 tests)
# ---------------------------------------------------------------------------


class TestSimulationEngine:
    def test_empty_params_valid_projection(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = _make_input("provider_change", {})
        proj = engine.simulate("sim-e1", inp)
        assert proj.simulation_id == "sim-e1"
        assert proj.uncertainty is not None

    def test_version_pins_in_replay_contract(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = _make_input("policy_change", {"policy_id": "p1", "new_enabled": "false"})
        proj = engine.simulate("sim-e2", inp)
        meta = dict(proj.replay_contract_metadata)
        assert "simulation_contract_version" in meta
        assert "simulation_engine_version" in meta
        assert "scenario_type" in meta

    def test_exception_produces_degraded_visibility(self):
        from unittest.mock import patch

        from services.readiness.simulation.engine import SimulationEngine
        from services.readiness.simulation.models import SimulationUncertainty

        engine = SimulationEngine()
        inp = _make_input(
            "provider_change", {"provider_id": "p1", "new_status": "blocked"}
        )

        with patch.object(
            engine, "_dispatch", side_effect=RuntimeError("forced error")
        ):
            proj = engine.simulate("sim-e3", inp)

        assert proj.uncertainty == SimulationUncertainty.DEGRADED_VISIBILITY

    def test_scenario_type_dispatches_correctly(self):
        from services.readiness.simulation.engine import SimulationEngine
        from services.readiness.simulation.models import SimulationScenarioType

        engine = SimulationEngine()
        for scenario_type in SimulationScenarioType:
            inp = _make_input(scenario_type.value, {})
            proj = engine.simulate(f"sim-dispatch-{scenario_type.value}", inp)
            assert proj.scenario_type == scenario_type

    def test_projection_is_immutable(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = _make_input(
            "policy_change",
            {
                "policy_id": "p1",
                "new_enabled": "true",
                "new_enforcement_mode": "strict",
            },
        )
        proj = engine.simulate("sim-e4", inp)
        # Frozen dataclass — should raise TypeError on mutation attempt
        import pytest as _pytest

        with _pytest.raises((TypeError, AttributeError)):
            proj.simulation_id = "mutated"  # type: ignore[misc]

    def test_simulation_id_deterministic(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp1 = _make_input("policy_change", {"policy_id": "p1"})
        inp2 = _make_input("policy_change", {"policy_id": "p1"})
        # simulation_id is passed in, not derived by engine
        proj1 = engine.simulate("fixed-sim-id", inp1)
        proj2 = engine.simulate("fixed-sim-id", inp2)
        assert proj1.simulation_id == proj2.simulation_id


# ---------------------------------------------------------------------------
# TestSerialization (4 tests)
# ---------------------------------------------------------------------------


class TestSerialization:
    def _make_projection(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = _make_input(
            "governance_enforcement_change",
            {"enforcement_mode": "strict"},
        )
        return engine.simulate("sim-ser-1", inp)

    def test_valid_json(self):
        from services.readiness.simulation.serialization import projection_to_json

        proj = self._make_projection()
        raw = projection_to_json(proj)
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert "simulation_id" in parsed

    def test_deterministic(self):
        from services.readiness.simulation.engine import SimulationEngine
        from services.readiness.simulation.serialization import projection_to_json

        engine = SimulationEngine()
        inp = _make_input(
            "governance_enforcement_change", {"enforcement_mode": "strict"}
        )
        proj1 = engine.simulate("sim-ser-det", inp)
        # Serialize the same object twice
        j1 = projection_to_json(proj1)
        j2 = projection_to_json(proj1)
        assert j1 == j2

    def test_no_forbidden_keys(self):
        from services.readiness.simulation.serialization import projection_to_json

        proj = self._make_projection()
        raw = projection_to_json(proj)
        # No secrets, vectors, embeddings, prompts, PHI
        forbidden_substrings = [
            "password",
            "secret",
            "vector",
            "embedding",
            "prompt",
            "phi",
        ]
        raw_lower = raw.lower()
        for forbidden in forbidden_substrings:
            assert forbidden not in raw_lower, f"Found forbidden key: {forbidden}"

    def test_projection_from_json_round_trip(self):
        from services.readiness.simulation.serialization import (
            projection_from_json,
            projection_to_json,
        )

        proj = self._make_projection()
        raw = projection_to_json(proj)
        result = projection_from_json(raw)
        assert isinstance(result, dict)
        assert result["simulation_id"] == proj.simulation_id
        assert result["uncertainty"] == proj.uncertainty.value
        assert "readiness_projection" in result
        assert "risk_projection" in result
        assert "compliance_projection" in result


# ---------------------------------------------------------------------------
# API fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "simulation_api_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", "control-plane:admin")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def tenant_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "simulation_tenant_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read",
        "control-plane:write",
        "control-plane:admin",
        tenant_id="tenant-sim-alpha",
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def other_tenant_client(tmp_path, monkeypatch, tenant_client):
    from api.auth_scopes import mint_key
    from api.main import build_app

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key(
        "control-plane:read",
        "control-plane:write",
        "control-plane:admin",
        tenant_id="tenant-sim-beta",
    )
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


@pytest.fixture()
def no_auth_client(tmp_path, monkeypatch):
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "simulation_noauth_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=False)
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def read_only_tenant_client(tmp_path, monkeypatch):
    from api.auth_scopes import mint_key
    from api.db import reset_engine_cache
    from api.main import build_app

    db_path = tmp_path / "simulation_readonly_test.db"
    monkeypatch.setenv("FG_SQLITE_PATH", str(db_path))
    monkeypatch.setenv("FG_ENV", "test")
    monkeypatch.setenv("FG_KEY_PEPPER", "ci-test-pepper")
    reset_engine_cache()

    from fastapi.testclient import TestClient

    app = build_app(auth_enabled=True)
    key = mint_key("control-plane:read", tenant_id="tenant-sim-readonly")
    return TestClient(app, raise_server_exceptions=False, headers={"X-API-Key": key})


_VALID_REQUEST = {
    "scenario_type": "provider_change",
    "scenario_parameters": {"provider_id": "p1", "new_status": "blocked"},
    "simulation_contract_version": "1.0",
}


# ---------------------------------------------------------------------------
# TestCreateSimulationRun (7 tests)
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestCreateSimulationRun:
    def test_valid_post_returns_201(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201, resp.text

    def test_idempotent_second_post_returns_stored(self, tenant_client):
        resp1 = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp1.status_code == 201
        run_id1 = resp1.json()["run_id"]

        resp2 = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp2.status_code == 201
        run_id2 = resp2.json()["run_id"]
        assert run_id1 == run_id2

    def test_403_when_no_tenant_context(self, api_client):
        resp = api_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 403

    def test_401_when_no_auth(self, no_auth_client):
        resp = no_auth_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        # no auth → 401 or 403
        assert resp.status_code in (401, 403)

    def test_400_invalid_scenario_type(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "not_a_real_scenario",
                "scenario_parameters": {},
            },
        )
        assert resp.status_code == 400

    def test_valid_response_shape(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        data = resp.json()
        required = {
            "run_id",
            "tenant_id",
            "scenario_type",
            "simulation_contract_version",
            "simulation_engine_version",
            "snapshot_id",
            "uncertainty",
            "total_warnings",
            "total_impacts",
            "total_critical_warnings",
            "simulated_at_iso",
            "projection",
        }
        assert required.issubset(data.keys()), f"Missing: {required - data.keys()}"

    def test_projection_in_response(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        data = resp.json()
        proj = data["projection"]
        assert isinstance(proj, dict)
        assert "readiness_projection" in proj
        assert "risk_projection" in proj
        assert "blast_radius" in proj

    def test_400_too_many_parameters(self, tenant_client):
        many_params = {f"key_{i}": "val" for i in range(21)}
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": many_params,
            },
        )
        assert resp.status_code == 400

    def test_400_parameter_key_too_long(self, tenant_client):
        long_key = "k" * 129
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": {long_key: "value"},
            },
        )
        assert resp.status_code == 400

    def test_400_parameter_value_too_long(self, tenant_client):
        long_val = "v" * 257
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": {"provider_id": long_val},
            },
        )
        assert resp.status_code == 400

    def test_write_scope_required(self, read_only_tenant_client):
        resp = read_only_tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# TestListSimulationRuns (4 tests)
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestListSimulationRuns:
    def test_pagination(self, tenant_client):
        # Create two distinct runs
        for status in ("blocked", "allowed"):
            tenant_client.post(
                "/control-plane/readiness/simulation/runs",
                json={
                    "scenario_type": "provider_change",
                    "scenario_parameters": {
                        "provider_id": f"p-{status}",
                        "new_status": status,
                    },
                },
            )
        resp = tenant_client.get(
            "/control-plane/readiness/simulation/runs",
            params={"limit": 10, "offset": 0},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_tenant_isolation_list(self, tenant_client, other_tenant_client):
        # tenant-sim-alpha creates a run
        tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        # tenant-sim-beta should see an empty list (their own tenant)
        resp = other_tenant_client.get("/control-plane/readiness/simulation/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_scenario_type_filter(self, tenant_client):
        tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "framework_upgrade",
                "scenario_parameters": {
                    "target_framework_version_tag": "v2",
                    "added_control_count": "3",
                    "removed_control_count": "0",
                },
            },
        )
        resp = tenant_client.get(
            "/control-plane/readiness/simulation/runs",
            params={"scenario_type": "framework_upgrade"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # All returned records should match the filter
        for item in data:
            assert item["scenario_type"] == "framework_upgrade"

    def test_empty_list_when_no_runs(self, tenant_client):
        resp = tenant_client.get(
            "/control-plane/readiness/simulation/runs",
            params={"assessment_id": "nonexistent-assessment-xyz"},
        )
        assert resp.status_code == 200
        assert resp.json() == []


# ---------------------------------------------------------------------------
# TestGetSimulationRun (4 tests)
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestGetSimulationRun:
    def test_found_returns_200(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        get_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}"
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["run_id"] == run_id

    def test_cross_tenant_returns_404(self, tenant_client, other_tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        get_resp = other_tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}"
        )
        assert get_resp.status_code == 404

    def test_missing_run_returns_404(self, tenant_client):
        resp = tenant_client.get(
            "/control-plane/readiness/simulation/runs/nonexistent-run-id-000"
        )
        assert resp.status_code == 404

    def test_response_shape(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "governance_enforcement_change",
                "scenario_parameters": {"enforcement_mode": "strict"},
            },
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        get_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}"
        )
        data = get_resp.json()
        assert "projection" in data
        assert isinstance(data["projection"], dict)
        assert "readiness_projection" in data["projection"]


# ---------------------------------------------------------------------------
# TestSecurityInvariants (4 tests)
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestSecurityInvariants:
    def _post_run(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        return resp

    def test_no_secrets_in_response(self, tenant_client):
        resp = self._post_run(tenant_client)
        text = resp.text.lower()
        for kw in ("password", "secret", "api_key", "token", "credential"):
            assert kw not in text, f"Forbidden keyword '{kw}' found in response"

    def test_no_vectors_in_response(self, tenant_client):
        resp = self._post_run(tenant_client)
        text = resp.text.lower()
        for kw in ("embedding", "vector", "chunk_id"):
            assert kw not in text, f"Forbidden keyword '{kw}' found in response"

    def test_no_prompts_in_response(self, tenant_client):
        resp = self._post_run(tenant_client)
        text = resp.text.lower()
        # Avoid injected prompt patterns
        for kw in ("ignore previous", "system prompt", "jailbreak"):
            assert kw not in text, f"Injected prompt keyword '{kw}' found in response"

    def test_projection_json_not_in_response(self, tenant_client):
        resp = self._post_run(tenant_client)
        data = resp.json()
        # projection_json should NOT be a top-level key — it's stored internally
        assert "projection_json" not in data, (
            "projection_json must not appear in API response"
        )
        # 'projection' should be a dict, not a raw JSON string
        assert isinstance(data.get("projection"), dict), (
            "projection must be a deserialized dict"
        )


# ---------------------------------------------------------------------------
# TestSimulationClassification (4 tests) — PR 96
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestSimulationClassification:
    def test_default_classification_is_internal(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["classification"] == "internal"

    def test_regulator_classification_stored(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "policy_change",
                "scenario_parameters": {"policy_id": "p-reg-1", "new_enabled": "true"},
                "classification": "regulator",
            },
        )
        assert resp.status_code == 201, resp.text
        assert resp.json()["classification"] == "regulator"

    def test_invalid_classification_rejected(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": {"provider_id": "p2", "new_status": "blocked"},
                "classification": "not_valid",
            },
        )
        assert resp.status_code == 422

    def test_classification_in_list_response(self, tenant_client):
        # Create run with legal classification
        tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "framework_upgrade",
                "scenario_parameters": {"framework_id": "fw-list-cls"},
                "classification": "legal",
            },
        )
        resp = tenant_client.get("/control-plane/readiness/simulation/runs")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) >= 1
        for item in items:
            assert "classification" in item


# ---------------------------------------------------------------------------
# TestGovernanceEventEmission (4 tests) — PR 96
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestGovernanceEventEmission:
    def test_simulation_created_event_exists(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": {
                    "provider_id": "p-evt-1",
                    "new_status": "blocked",
                },
            },
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        events_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/events"
        )
        assert events_resp.status_code == 200
        event_types = [e["event_type"] for e in events_resp.json()]
        assert "SIMULATION_CREATED" in event_types

    def test_simulation_replayed_event_on_idempotent_post(self, tenant_client):
        payload = {
            "scenario_type": "provider_change",
            "scenario_parameters": {
                "provider_id": "p-idempotent-replay",
                "new_status": "blocked",
            },
        }
        resp1 = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=payload,
        )
        assert resp1.status_code == 201
        run_id = resp1.json()["run_id"]

        # Second POST — idempotency hit
        resp2 = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=payload,
        )
        assert resp2.status_code == 201
        assert resp2.json()["run_id"] == run_id

        events_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/events"
        )
        assert events_resp.status_code == 200
        event_types = [e["event_type"] for e in events_resp.json()]
        assert "SIMULATION_CREATED" in event_types
        assert "SIMULATION_REPLAYED" in event_types

    def test_capability_expansion_emits_critical_event(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "capability_governance_change",
                "scenario_parameters": {
                    "capability_scope": "tool:network-access",
                    "authority_change": "expand",
                },
            },
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        events_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/events"
        )
        assert events_resp.status_code == 200
        event_types = [e["event_type"] for e in events_resp.json()]
        assert "CAPABILITY_BOUNDARY_EXPANSION_PROJECTED" in event_types

    def test_events_tenant_isolated(self, tenant_client, other_tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "provider_change",
                "scenario_parameters": {
                    "provider_id": "p-iso-evt",
                    "new_status": "blocked",
                },
            },
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        other_resp = other_tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/events"
        )
        assert other_resp.status_code == 404


# ---------------------------------------------------------------------------
# TestSimulationReplayEndpoint (4 tests) — PR 96
# ---------------------------------------------------------------------------


@pytest.mark.contract
class TestSimulationReplayEndpoint:
    def test_replay_returns_200(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        replay_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/replay"
        )
        assert replay_resp.status_code == 200

    def test_replay_has_hash_fields(self, tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json={
                "scenario_type": "governance_enforcement_change",
                "scenario_parameters": {"enforcement_mode": "permissive"},
            },
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        replay_resp = tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/replay"
        )
        assert replay_resp.status_code == 200
        data = replay_resp.json()
        assert "input_hash" in data
        assert "projection_hash" in data
        assert "contract_hash" in data
        assert data["input_hash"] != ""
        assert data["projection_hash"] != ""
        assert data["contract_hash"] != ""

    def test_replay_cross_tenant_returns_404(self, tenant_client, other_tenant_client):
        resp = tenant_client.post(
            "/control-plane/readiness/simulation/runs",
            json=_VALID_REQUEST,
        )
        assert resp.status_code == 201
        run_id = resp.json()["run_id"]

        other_resp = other_tenant_client.get(
            f"/control-plane/readiness/simulation/runs/{run_id}/replay"
        )
        assert other_resp.status_code == 404

    def test_replay_missing_run_returns_404(self, tenant_client):
        resp = tenant_client.get(
            "/control-plane/readiness/simulation/runs/nonexistent-id/replay"
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestCapabilityGovernanceConstraints (4 tests) — PR 96
# ---------------------------------------------------------------------------


class TestCapabilityGovernanceConstraints:
    def _make_cap_input(
        self, authority_change: str, capability_scope: str = "tool:file-read"
    ):
        from datetime import datetime, timezone

        from services.readiness.simulation.models import (
            SimulationInput,
            SimulationScenarioType,
        )

        return SimulationInput(
            scenario_type=SimulationScenarioType.CAPABILITY_GOVERNANCE_CHANGE,
            scenario_parameters=(
                ("authority_change", authority_change),
                ("capability_scope", capability_scope),
            ),
            tenant_id="tenant-cap-test",
            assessment_id=None,
            framework_id=None,
            simulation_contract_version="1.0",
            simulation_engine_version="1.0",
            requested_at_iso=datetime.now(timezone.utc).isoformat(),
        )

    def test_expand_populates_bounded_authority_model(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = self._make_cap_input("expand")
        proj = engine.simulate("cap-test-expand-1", inp)
        assert proj.capability_projection is not None
        assert proj.capability_projection.bounded_authority_model is not None

    def test_expand_bounded_authority_violation_true(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = self._make_cap_input("expand")
        proj = engine.simulate("cap-test-expand-2", inp)
        assert proj.capability_projection is not None
        bam = proj.capability_projection.bounded_authority_model
        assert bam is not None
        assert bam.authority_boundary_violated is True

    def test_restrict_containment_state_contained(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = self._make_cap_input("restrict")
        proj = engine.simulate("cap-test-restrict-1", inp)
        assert proj.capability_projection is not None
        bam = proj.capability_projection.bounded_authority_model
        assert bam is not None
        assert bam.containment_state == "contained"

    def test_agent_scope_populates_cascade_projection(self):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = self._make_cap_input("expand", capability_scope="agent:network-access")
        proj = engine.simulate("cap-test-agent-1", inp)
        assert proj.capability_projection is not None
        assert proj.capability_projection.multi_agent_cascade_projection is not None


# ---------------------------------------------------------------------------
# TestGovernanceTimeline (2 tests) — PR 96
# ---------------------------------------------------------------------------


class TestGovernanceTimeline:
    def _make_projection(self, scenario_type: str = "provider_change"):
        from services.readiness.simulation.engine import SimulationEngine

        engine = SimulationEngine()
        inp = _make_input(
            scenario_type, {"provider_id": "p-tl-1", "new_status": "blocked"}
        )
        return engine.simulate("tl-sim-1", inp)

    def test_timeline_entry_built_from_projection(self):
        from services.readiness.simulation.models import SimulationClassification
        from services.readiness.simulation.timeline import build_timeline_entry

        proj = self._make_projection()
        entry = build_timeline_entry(proj, SimulationClassification.INTERNAL)
        assert entry.simulation_id == proj.simulation_id
        assert entry.timeline_summary != ""
        assert len(entry.timeline_summary) > 0

    def test_timeline_entry_has_risk_direction(self):
        from services.readiness.simulation.models import SimulationClassification
        from services.readiness.simulation.timeline import build_timeline_entry

        proj = self._make_projection()
        entry = build_timeline_entry(proj, SimulationClassification.INTERNAL)
        assert entry.risk_direction == proj.readiness_projection.direction
