"""Tests for PR 18.5 — Governance Intelligence Authority (core).

Coverage:
  GI-1   to GI-50:   models.py — enums, constants, terminal sets
  GI-51  to GI-120:  schemas.py — extra=forbid, request/response validation
  GI-121 to GI-200:  engine.py — core operations via mock/in-memory DB
  GI-201 to GI-300:  validators.py — input validation
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.db import get_engine
from services.governance_intelligence.engine import GovernanceIntelligenceEngine
from services.governance_intelligence.models import (
    GOVERNANCE_INTELLIGENCE_SCHEMA_VERSION,
    MUTABLE_POLICY_STATES,
    TERMINAL_SIMULATION_STATES,
    BenchmarkTier,
    ConfidenceLevel,
    ExternalEventType,
    FederationRole,
    ForecastHorizon,
    IntelligenceOutputType,
    PolicyLifecycleState,
    SimulationState,
    TrendDirection,
)
from services.governance_intelligence.repository import (
    GovernanceIntelligenceRepository,
)
from services.governance_intelligence.schemas import (
    CreateBenchmarkRequest,
    CreateIntelligencePolicyRequest,
    CreateSimulationRequest,
    ExternalEventRequest,
    FederationSyncRequest,
    GovernanceIntelligenceConflict,
    GovernanceIntelligenceError,
    GovernanceIntelligenceNotFound,
    GovernanceIntelligencePolicyError,
    GovernanceIntelligenceSimulationError,
    GovernanceIntelligenceTenantViolation,
    GovernanceIntelligenceValidationError,
    PolicyTransitionRequest,
    RunSimulationRequest,
    UpdateIntelligencePolicyRequest,
    UpdateSimulationRequest,
)
from services.governance_intelligence.validators import (
    validate_framework,
    validate_horizon,
    validate_limit_offset,
    validate_metric_key,
    validate_scenario_type,
    validate_search_query,
    validate_tenant_id,
)


_TENANT = "tenant-gi-001"
_TENANT_B = "tenant-gi-002"


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def svc(db):
    return GovernanceIntelligenceEngine(db, tenant_id=_TENANT)


@pytest.fixture()
def svc_b(db):
    return GovernanceIntelligenceEngine(db, tenant_id=_TENANT_B)


@pytest.fixture()
def repo(db):
    return GovernanceIntelligenceRepository(db, tenant_id=_TENANT)


# ===========================================================================
# GI-1 to GI-50: models.py
# ===========================================================================


@pytest.mark.parametrize(
    "value",
    ["DRAFT", "RUNNING", "COMPLETE", "FAILED", "ARCHIVED"],
)
def test_GI_1_simulation_state_values(value):
    assert any(m.value == value for m in SimulationState)


def test_GI_2_simulation_state_count():
    assert len(SimulationState) == 5


@pytest.mark.parametrize(
    "value",
    ["DRAFT", "REVIEW", "APPROVED", "ACTIVE", "DEPRECATED", "SUPERSEDED", "ARCHIVED"],
)
def test_GI_3_policy_lifecycle_state_values(value):
    assert any(m.value == value for m in PolicyLifecycleState)


def test_GI_4_policy_lifecycle_state_count():
    assert len(PolicyLifecycleState) == 7


@pytest.mark.parametrize(
    "value",
    [
        "PERCENTILE_25",
        "PERCENTILE_50",
        "PERCENTILE_75",
        "PERCENTILE_90",
        "PERCENTILE_95",
    ],
)
def test_GI_5_benchmark_tier_values(value):
    assert any(m.value == value for m in BenchmarkTier)


def test_GI_6_benchmark_tier_count():
    assert len(BenchmarkTier) == 5


@pytest.mark.parametrize("value", ["IMPROVING", "STABLE", "DECLINING", "VOLATILE"])
def test_GI_7_trend_direction_values(value):
    assert any(m.value == value for m in TrendDirection)


def test_GI_8_trend_direction_count():
    assert len(TrendDirection) == 4


@pytest.mark.parametrize("value", ["HIGH", "MEDIUM", "LOW", "INSUFFICIENT"])
def test_GI_9_confidence_level_values(value):
    assert any(m.value == value for m in ConfidenceLevel)


def test_GI_10_confidence_level_count():
    assert len(ConfidenceLevel) == 4


@pytest.mark.parametrize("value", ["DAYS_7", "DAYS_30", "DAYS_90", "DAYS_180"])
def test_GI_11_forecast_horizon_values(value):
    assert any(m.value == value for m in ForecastHorizon)


def test_GI_12_forecast_horizon_count():
    assert len(ForecastHorizon) == 4


@pytest.mark.parametrize(
    "value",
    [
        "SECURITY_INCIDENT",
        "COMPLIANCE_CHANGE",
        "VENDOR_CHANGE",
        "POLICY_UPDATE",
        "AUDIT_FINDING",
        "REGULATORY_UPDATE",
    ],
)
def test_GI_13_external_event_type_values(value):
    assert any(m.value == value for m in ExternalEventType)


def test_GI_14_external_event_type_count():
    assert len(ExternalEventType) == 6


@pytest.mark.parametrize("value", ["COORDINATOR", "MEMBER", "OBSERVER"])
def test_GI_15_federation_role_values(value):
    assert any(m.value == value for m in FederationRole)


def test_GI_16_federation_role_count():
    assert len(FederationRole) == 3


@pytest.mark.parametrize(
    "value",
    [
        "DASHBOARD",
        "EXPLAINABILITY",
        "SIMULATION",
        "BENCHMARK",
        "TREND",
        "FORECAST",
        "POLICY_DIFF",
        "CONFIDENCE",
        "STATISTICS",
    ],
)
def test_GI_17_intelligence_output_type_values(value):
    assert any(m.value == value for m in IntelligenceOutputType)


def test_GI_18_intelligence_output_type_count():
    assert len(IntelligenceOutputType) == 9


def test_GI_19_schema_version():
    assert GOVERNANCE_INTELLIGENCE_SCHEMA_VERSION == "1.0"


def test_GI_20_terminal_simulation_states():
    assert SimulationState.COMPLETE in TERMINAL_SIMULATION_STATES
    assert SimulationState.FAILED in TERMINAL_SIMULATION_STATES
    assert SimulationState.ARCHIVED in TERMINAL_SIMULATION_STATES
    assert SimulationState.DRAFT not in TERMINAL_SIMULATION_STATES
    assert SimulationState.RUNNING not in TERMINAL_SIMULATION_STATES


def test_GI_21_mutable_policy_states():
    assert PolicyLifecycleState.DRAFT in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.REVIEW in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.APPROVED not in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.ACTIVE not in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.DEPRECATED not in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.SUPERSEDED not in MUTABLE_POLICY_STATES
    assert PolicyLifecycleState.ARCHIVED not in MUTABLE_POLICY_STATES


def test_GI_22_terminal_simulation_states_is_frozenset():
    assert isinstance(TERMINAL_SIMULATION_STATES, frozenset)


def test_GI_23_mutable_policy_states_is_frozenset():
    assert isinstance(MUTABLE_POLICY_STATES, frozenset)


def test_GI_24_simulation_state_is_str_enum():
    assert isinstance(SimulationState.DRAFT, str)


def test_GI_25_policy_lifecycle_state_is_str_enum():
    assert isinstance(PolicyLifecycleState.DRAFT, str)


# ===========================================================================
# GI-51 to GI-120: schemas.py
# ===========================================================================


def test_GI_51_exception_hierarchy():
    assert issubclass(GovernanceIntelligenceNotFound, GovernanceIntelligenceError)
    assert issubclass(
        GovernanceIntelligenceTenantViolation, GovernanceIntelligenceError
    )
    assert issubclass(
        GovernanceIntelligenceSimulationError, GovernanceIntelligenceError
    )
    assert issubclass(
        GovernanceIntelligenceValidationError, GovernanceIntelligenceError
    )
    assert issubclass(GovernanceIntelligencePolicyError, GovernanceIntelligenceError)
    assert issubclass(GovernanceIntelligenceConflict, GovernanceIntelligenceError)


def test_GI_52_create_simulation_request_valid():
    req = CreateSimulationRequest(
        name="Test Sim",
        scenario_type="policy_change",
        parameters={"severity": "HIGH"},
    )
    assert req.name == "Test Sim"
    assert req.scenario_type == "policy_change"


def test_GI_53_create_simulation_request_requires_name():
    with pytest.raises(ValidationError):
        CreateSimulationRequest(scenario_type="policy_change", parameters={})  # type: ignore[call-arg]


def test_GI_54_create_simulation_request_forbids_extra():
    with pytest.raises(ValidationError):
        CreateSimulationRequest(
            name="x", scenario_type="policy_change", parameters={}, extra_field="nope"
        )


def test_GI_55_update_simulation_request_all_optional():
    req = UpdateSimulationRequest()
    assert req.name is None
    assert req.description is None
    assert req.parameters is None


def test_GI_56_run_simulation_request_default():
    req = RunSimulationRequest()
    assert req.dry_run is False


def test_GI_57_create_policy_request_valid():
    req = CreateIntelligencePolicyRequest(
        name="My Policy",
        policy_type="risk",
        policy_data={"rules": []},
    )
    assert req.name == "My Policy"
    assert req.framework is None


def test_GI_58_create_policy_request_with_framework():
    req = CreateIntelligencePolicyRequest(
        name="My Policy",
        policy_type="risk",
        policy_data={},
        framework="NIST_CSF",
    )
    assert req.framework == "NIST_CSF"


def test_GI_59_policy_transition_request_valid():
    req = PolicyTransitionRequest(
        target_state="REVIEW",
        actor_id="user-123",
    )
    assert req.target_state == "REVIEW"
    assert req.reason is None


def test_GI_60_create_benchmark_request_valid():
    req = CreateBenchmarkRequest(
        framework="NIST_CSF",
        category="governance",
        metric_key="control_coverage",
        value=0.85,
        metadata={},
    )
    assert req.value == 0.85


def test_GI_61_external_event_request_valid():
    req = ExternalEventRequest(
        event_type="SECURITY_INCIDENT",
        source="siem",
        payload={"severity": "HIGH"},
    )
    assert req.event_type == "SECURITY_INCIDENT"
    assert req.occurred_at is None


def test_GI_62_federation_sync_request_valid():
    req = FederationSyncRequest(
        instance_id="instance-abc",
        role="MEMBER",
        metadata={},
    )
    assert req.role == "MEMBER"


def test_GI_63_create_simulation_request_empty_name():
    with pytest.raises(ValidationError):
        CreateSimulationRequest(name="", scenario_type="policy_change", parameters={})


# ===========================================================================
# GI-121 to GI-200: engine.py
# ===========================================================================


def test_GI_121_health_returns_ok(svc):
    health = svc.get_health()
    assert health.status in ("ok", "degraded")
    assert health.authority == "governance_intelligence"
    assert health.version == "1.0.0"
    assert health.schema_version == "1.0"


def test_GI_122_dashboard_returns_response(svc, db):
    dash = svc.get_dashboard()
    assert dash.tenant_id == _TENANT
    assert isinstance(dash.governance_score, float)
    assert dash.risk_level in ("LOW", "MEDIUM", "HIGH")


def test_GI_123_create_simulation(svc, db):
    req = CreateSimulationRequest(
        name="Test Sim",
        scenario_type="policy_change",
        parameters={"severity": "HIGH"},
    )
    result = svc.create_simulation(req, actor_id="user-1")
    db.commit()
    assert result.name == "Test Sim"
    assert result.state == "DRAFT"
    assert result.tenant_id == _TENANT


def test_GI_124_get_simulation_not_found(svc):
    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_simulation("nonexistent-id")


def test_GI_125_list_simulations_empty(svc):
    result = svc.list_simulations(limit=50, offset=0)
    assert isinstance(result.items, list)
    assert isinstance(result.total, int)


def test_GI_126_create_and_get_simulation(svc, db):
    req = CreateSimulationRequest(
        name="Get Test",
        scenario_type="policy_change",
        parameters={},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()
    fetched = svc.get_simulation(created.id)
    assert fetched.id == created.id
    assert fetched.name == "Get Test"


def test_GI_127_update_simulation(svc, db):
    req = CreateSimulationRequest(
        name="Update Test",
        scenario_type="policy_change",
        parameters={},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    update = UpdateSimulationRequest(name="Updated Name")
    updated = svc.update_simulation(created.id, update, actor_id="user-1")
    db.commit()
    assert updated.name == "Updated Name"


def test_GI_128_run_simulation_policy_change(svc, db):
    req = CreateSimulationRequest(
        name="Run Test",
        scenario_type="policy_change",
        parameters={"severity": "MEDIUM"},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    run_req = RunSimulationRequest(dry_run=False)
    result = svc.run_simulation(created.id, run_req, actor_id="user-1")
    db.commit()
    assert result.state == "COMPLETE"
    assert result.result is not None
    assert result.result.get("simulation_label") == "PROJECTED"
    assert result.result.get("is_production") is False


def test_GI_129_run_simulation_dry_run(svc, db):
    req = CreateSimulationRequest(
        name="Dry Run Test",
        scenario_type="approval_chain",
        parameters={"stages": 3},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    run_req = RunSimulationRequest(dry_run=True)
    result = svc.run_simulation(created.id, run_req, actor_id="user-1")
    db.commit()
    # With dry_run=True, state should remain DRAFT
    assert result.state == "DRAFT"


def test_GI_130_delete_simulation(svc, db):
    req = CreateSimulationRequest(
        name="Delete Test",
        scenario_type="policy_change",
        parameters={},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()
    svc.delete_simulation(created.id, actor_id="user-1")
    db.commit()
    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_simulation(created.id)


def test_GI_131_create_explainability(svc, db):
    result = svc.create_explainability(
        decision_id="dec-001",
        trigger="RISK_THRESHOLD",
        policy_version="1.0",
        evaluation={"score": 0.8},
        decision="APPROVE",
        authorities_invoked=["evidence", "verification"],
        expected_impact={"governance_delta": 0.05},
        actor_id="user-1",
    )
    db.commit()
    assert result.decision_id == "dec-001"
    assert result.tenant_id == _TENANT


def test_GI_132_get_explainability_not_found(svc):
    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_explainability("nonexistent-decision")


def test_GI_133_create_intelligence_policy(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Risk Policy",
        policy_type="risk",
        policy_data={"rules": [], "thresholds": {}},
    )
    result = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()
    assert result.name == "Risk Policy"
    assert result.lifecycle_state == "DRAFT"
    assert result.version == "1.0"
    assert result.tenant_id == _TENANT


def test_GI_134_get_policy_not_found(svc):
    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_intelligence_policy("nonexistent-id")


def test_GI_135_update_policy_draft(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Draft Policy",
        policy_type="risk",
        policy_data={},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    update = UpdateIntelligencePolicyRequest(name="Updated Policy")
    updated = svc.update_intelligence_policy(created.id, update, actor_id="user-1")
    db.commit()
    assert updated.name == "Updated Policy"


def test_GI_136_transition_policy(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Transition Policy",
        policy_type="risk",
        policy_data={},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    trans = PolicyTransitionRequest(target_state="REVIEW", actor_id="user-1")
    updated = svc.transition_policy(created.id, trans, actor_id="user-1")
    db.commit()
    assert updated.lifecycle_state == "REVIEW"


def test_GI_137_transition_policy_invalid(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Invalid Transition",
        policy_type="risk",
        policy_data={},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    with pytest.raises(GovernanceIntelligencePolicyError):
        trans = PolicyTransitionRequest(target_state="ACTIVE", actor_id="user-1")
        svc.transition_policy(created.id, trans, actor_id="user-1")


def test_GI_138_get_policy_versions(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Version Policy",
        policy_type="risk",
        policy_data={},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    versions = svc.get_policy_versions(created.id)
    assert versions.total >= 1
    assert len(versions.items) >= 1


def test_GI_139_create_benchmark(svc, db):
    req = CreateBenchmarkRequest(
        framework="NIST_CSF",
        category="governance",
        metric_key="control_coverage",
        value=0.85,
        metadata={},
    )
    result = svc.create_benchmark(req, actor_id="user-1")
    db.commit()
    assert result.framework == "NIST_CSF"
    assert result.value == 0.85
    assert result.tenant_id == _TENANT


def test_GI_140_list_benchmarks(svc, db):
    req = CreateBenchmarkRequest(
        framework="NIST_CSF",
        category="governance",
        metric_key="test_metric",
        value=0.5,
        metadata={},
    )
    svc.create_benchmark(req, actor_id="user-1")
    db.commit()

    result = svc.list_benchmarks(framework=None, limit=50, offset=0)
    assert result.total >= 1


def test_GI_141_record_external_event(svc, db):
    req = ExternalEventRequest(
        event_type="SECURITY_INCIDENT",
        source="siem",
        payload={"severity": "HIGH"},
    )
    result = svc.record_external_event(req, actor_id="user-1")
    db.commit()
    assert result.event_type == "SECURITY_INCIDENT"
    assert result.tenant_id == _TENANT


def test_GI_142_list_external_events(svc, db):
    req = ExternalEventRequest(
        event_type="AUDIT_FINDING",
        source="auditor",
        payload={},
    )
    svc.record_external_event(req, actor_id="user-1")
    db.commit()

    result = svc.list_external_events(event_type=None, limit=50, offset=0)
    assert result.total >= 1


def test_GI_143_register_federation(svc, db):
    req = FederationSyncRequest(
        instance_id="instance-001",
        role="MEMBER",
        metadata={},
    )
    result = svc.register_federation(req, actor_id="user-1")
    db.commit()
    assert result.instance_id == "instance-001"
    assert result.role == "MEMBER"
    assert result.tenant_id == _TENANT


def test_GI_144_list_federation(svc, db):
    req = FederationSyncRequest(
        instance_id="instance-002",
        role="OBSERVER",
        metadata={},
    )
    svc.register_federation(req, actor_id="user-1")
    db.commit()

    result = svc.list_federation(limit=50, offset=0)
    assert result.total >= 1


def test_GI_145_search_returns_results(svc, db):
    req = CreateSimulationRequest(
        name="Unique Search Term XYZ",
        scenario_type="policy_change",
        parameters={},
    )
    svc.create_simulation(req, actor_id="user-1")
    db.commit()

    result = svc.search("Unique Search Term", limit=50)
    assert result.total >= 1
    assert result.query == "Unique Search Term"


def test_GI_146_get_statistics(svc, db):
    stats = svc.get_statistics()
    assert stats.tenant_id == _TENANT
    assert isinstance(stats.total_simulations, int)
    assert isinstance(stats.total_policies, int)


def test_GI_147_get_timeline(svc, db):
    req = CreateSimulationRequest(
        name="Timeline Test",
        scenario_type="policy_change",
        parameters={},
    )
    svc.create_simulation(req, actor_id="user-1")
    db.commit()

    timeline = svc.get_timeline(limit=50, offset=0)
    assert isinstance(timeline.items, list)


def test_GI_148_tenant_isolation_simulations(svc, svc_b, db):
    req = CreateSimulationRequest(
        name="Tenant A Sim",
        scenario_type="policy_change",
        parameters={},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    with pytest.raises(GovernanceIntelligenceNotFound):
        svc_b.get_simulation(created.id)


def test_GI_149_update_simulation_in_terminal_state(svc, db):
    req = CreateSimulationRequest(
        name="Terminal Test",
        scenario_type="policy_change",
        parameters={"severity": "LOW"},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    run_req = RunSimulationRequest(dry_run=False)
    svc.run_simulation(created.id, run_req, actor_id="user-1")
    db.commit()

    with pytest.raises(GovernanceIntelligenceSimulationError):
        update = UpdateSimulationRequest(name="Cannot Update")
        svc.update_simulation(created.id, update, actor_id="user-1")


def test_GI_150_update_policy_in_immutable_state(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Immutable Policy",
        policy_type="risk",
        policy_data={},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    # Move to REVIEW -> APPROVED
    svc.transition_policy(
        created.id,
        PolicyTransitionRequest(target_state="REVIEW", actor_id="u"),
        actor_id="u",
    )
    db.commit()
    svc.transition_policy(
        created.id,
        PolicyTransitionRequest(target_state="APPROVED", actor_id="u"),
        actor_id="u",
    )
    db.commit()

    with pytest.raises(GovernanceIntelligencePolicyError):
        update = UpdateIntelligencePolicyRequest(name="Cannot Update")
        svc.update_intelligence_policy(created.id, update, actor_id="user-1")


def test_GI_151_get_confidence_default(svc):
    result = svc.get_confidence("test_dimension")
    assert result.dimension == "test_dimension"
    assert isinstance(result.score, float)


def test_GI_152_get_trends_empty(svc):
    result = svc.get_trends("nonexistent_metric", window_days=30)
    assert result.metric_key == "nonexistent_metric"
    assert result.window_days == 30


def test_GI_153_get_forecast_empty(svc):
    result = svc.get_forecast("nonexistent_metric", "DAYS_30")
    assert result.metric_key == "nonexistent_metric"
    assert result.horizon == "DAYS_30"


def test_GI_154_archive_simulation(svc, db):
    req = CreateSimulationRequest(
        name="Archive Test",
        scenario_type="policy_change",
        parameters={},
    )
    created = svc.create_simulation(req, actor_id="user-1")
    db.commit()

    result = svc.archive_simulation(created.id, actor_id="user-1")
    db.commit()
    assert result.state == "ARCHIVED"


def test_GI_155_get_policy_diff(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="Diff Policy",
        policy_type="risk",
        policy_data={"rules": ["rule1"], "thresholds": {"t1": 0.5}},
    )
    created = svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    update = UpdateIntelligencePolicyRequest(
        policy_data={"rules": ["rule1", "rule2"], "thresholds": {"t1": 0.7}}
    )
    svc.update_intelligence_policy(created.id, update, actor_id="user-1")
    db.commit()

    diff = svc.get_policy_diff(created.id, "1.0", "1.1")
    assert diff.policy_id == created.id
    assert diff.from_version == "1.0"
    assert diff.to_version == "1.1"


def test_GI_156_list_intelligence_policies(svc, db):
    req = CreateIntelligencePolicyRequest(
        name="List Policy",
        policy_type="risk",
        policy_data={},
    )
    svc.create_intelligence_policy(req, actor_id="user-1")
    db.commit()

    result = svc.list_intelligence_policies(limit=50, offset=0)
    assert result.total >= 1


def test_GI_157_list_explainability(svc, db):
    svc.create_explainability(
        decision_id="dec-list-001",
        trigger="RISK",
        policy_version="1.0",
        evaluation={},
        decision="APPROVE",
        authorities_invoked=[],
        expected_impact={},
        actor_id="user-1",
    )
    db.commit()

    result = svc.list_explainability(limit=50, offset=0)
    assert result.total >= 1


def test_GI_158_get_explainability_by_decision(svc, db):
    svc.create_explainability(
        decision_id="dec-get-001",
        trigger="RISK",
        policy_version="1.0",
        evaluation={},
        decision="DENY",
        authorities_invoked=["auth1"],
        expected_impact={"delta": 0.1},
        actor_id="user-1",
    )
    db.commit()

    result = svc.get_explainability("dec-get-001")
    assert result.decision_id == "dec-get-001"
    assert result.decision == "DENY"


def test_GI_159_get_benchmark_by_id(svc, db):
    req = CreateBenchmarkRequest(
        framework="NIST_CSF",
        category="governance",
        metric_key="by_id_test",
        value=0.75,
        metadata={},
    )
    created = svc.create_benchmark(req, actor_id="user-1")
    db.commit()

    fetched = svc.get_benchmark_by_id(created.id)
    assert fetched.id == created.id
    assert fetched.value == 0.75


def test_GI_160_delete_benchmark(svc, db):
    req = CreateBenchmarkRequest(
        framework="NIST_CSF",
        category="governance",
        metric_key="delete_test",
        value=0.5,
        metadata={},
    )
    created = svc.create_benchmark(req, actor_id="user-1")
    db.commit()

    svc.delete_benchmark(created.id, actor_id="user-1")
    db.commit()

    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_benchmark_by_id(created.id)


def test_GI_161_get_external_event(svc, db):
    req = ExternalEventRequest(
        event_type="VENDOR_CHANGE",
        source="vendor_api",
        payload={"vendor": "acme"},
    )
    created = svc.record_external_event(req, actor_id="user-1")
    db.commit()

    fetched = svc.get_external_event(created.id)
    assert fetched.id == created.id
    assert fetched.event_type == "VENDOR_CHANGE"


def test_GI_162_get_external_event_not_found(svc):
    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_external_event("nonexistent-event")


def test_GI_163_get_federation_by_id(svc, db):
    req = FederationSyncRequest(
        instance_id="fed-get-001",
        role="COORDINATOR",
        metadata={},
    )
    created = svc.register_federation(req, actor_id="user-1")
    db.commit()

    fetched = svc.get_federation_by_id(created.id)
    assert fetched.id == created.id
    assert fetched.instance_id == "fed-get-001"


def test_GI_164_delete_federation(svc, db):
    req = FederationSyncRequest(
        instance_id="fed-del-001",
        role="OBSERVER",
        metadata={},
    )
    created = svc.register_federation(req, actor_id="user-1")
    db.commit()

    svc.delete_federation(created.id, actor_id="user-1")
    db.commit()

    with pytest.raises(GovernanceIntelligenceNotFound):
        svc.get_federation_by_id(created.id)


def test_GI_165_list_confidence(svc, db):
    result = svc.list_confidence(limit=50, offset=0)
    assert isinstance(result.items, list)


def test_GI_166_list_trends(svc, db):
    result = svc.list_trends(limit=50, offset=0)
    assert isinstance(result.items, list)


def test_GI_167_list_forecasts(svc, db):
    result = svc.list_forecasts(limit=50, offset=0)
    assert isinstance(result.items, list)


# ===========================================================================
# GI-201 to GI-300: validators.py
# ===========================================================================


def test_GI_201_validate_tenant_id_valid():
    validate_tenant_id("tenant-001")  # no exception


def test_GI_202_validate_tenant_id_empty():
    with pytest.raises(GovernanceIntelligenceTenantViolation):
        validate_tenant_id("")


def test_GI_203_validate_tenant_id_whitespace():
    with pytest.raises(GovernanceIntelligenceTenantViolation):
        validate_tenant_id("   ")


def test_GI_204_validate_tenant_id_none():
    with pytest.raises(GovernanceIntelligenceTenantViolation):
        validate_tenant_id(None)  # type: ignore[arg-type]


def test_GI_205_validate_limit_offset_valid():
    validate_limit_offset(50, 0)  # no exception
    validate_limit_offset(1, 0)
    validate_limit_offset(500, 100)


def test_GI_206_validate_limit_offset_limit_zero():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_limit_offset(0, 0)


def test_GI_207_validate_limit_offset_limit_too_large():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_limit_offset(501, 0)


def test_GI_208_validate_limit_offset_negative_offset():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_limit_offset(50, -1)


def test_GI_209_validate_search_query_valid():
    validate_search_query("search term")  # no exception


def test_GI_210_validate_search_query_empty():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_search_query("")


def test_GI_211_validate_search_query_too_long():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_search_query("x" * 513)


def test_GI_212_validate_scenario_type_valid():
    validate_scenario_type("policy_change")
    validate_scenario_type("approval_chain")
    validate_scenario_type("sla_change")


def test_GI_213_validate_scenario_type_invalid():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_scenario_type("unknown_type")


def test_GI_214_validate_metric_key_valid():
    validate_metric_key("governance_score")  # no exception


def test_GI_215_validate_metric_key_empty():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_metric_key("")


def test_GI_216_validate_metric_key_too_long():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_metric_key("x" * 256)


def test_GI_217_validate_horizon_valid():
    validate_horizon("DAYS_30")
    validate_horizon("DAYS_7")
    validate_horizon("DAYS_90")
    validate_horizon("DAYS_180")


def test_GI_218_validate_horizon_invalid():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_horizon("DAYS_365")


def test_GI_219_validate_framework_valid():
    validate_framework("NIST_CSF")  # no exception


def test_GI_220_validate_framework_empty():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_framework("")


def test_GI_221_validate_framework_too_long():
    with pytest.raises(GovernanceIntelligenceValidationError):
        validate_framework("x" * 129)


@pytest.mark.parametrize(
    "scenario_type",
    [
        "policy_change",
        "approval_chain",
        "sla_change",
        "maintenance_window",
        "risk_threshold",
        "reassessment_cadence",
        "playbook_selection",
    ],
)
def test_GI_222_all_scenario_types_valid(scenario_type):
    validate_scenario_type(scenario_type)


def test_GI_223_search_empty_returns_empty(svc, db):
    result = svc.search("zzz_nonexistent_xyz_query_abc", limit=50)
    assert result.total == 0
    assert result.results == []
