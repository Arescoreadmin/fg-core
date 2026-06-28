"""Tests for PR 17.6D — Governance Optimization Engine.

Coverage:
  GOO-1  to GOO-20:  Model unit tests (enums, pure functions)
  GOO-21 to GOO-40:  DB model smoke tests (ORM instantiation, append-only guards)
  GOO-41 to GOO-70:  Ranking unit tests (rank_recommendations, rank_remediations,
                      rank_bridges, rank_strategies)
  GOO-71 to GOO-100: Engine tests (dashboard, list, CGIN, recalculate,
                      tenant isolation)
  GOO-101 to GOO-130: API route tests (auth, scope, tenant isolation)
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

os.environ.setdefault("FG_ENV", "test")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine, init_db
from api.db_models_governance_optimization import (
    FaGovernanceOptimizationAggregate,
    FaGovernanceOptimizationDecision,
    FaGovernanceOptimizationSnapshot,
)
from services.governance_optimization.engine import GovernanceOptimizationEngine
from services.governance_optimization.models import (
    GOVERNANCE_OPTIMIZATION_VERSION,
    OptimizationConfidence,
    OptimizationType,
    TargetType,
    classify_optimization_confidence,
    clamp,
    compute_priority_score,
)
from services.governance_optimization.optimization_rules import (
    apply_optimization_context,
    should_surface_as_optimization_target,
)
from services.governance_optimization.ranking import (
    RankedItem,
    rank_bridges,
    rank_recommendations,
    rank_remediations,
    rank_strategies,
)
from services.governance_optimization.schemas import (
    CGINOptimizationSnapshot,
    OptimizationDecisionResponse,
    RankRequest,
    RecalculateOptimizationRequest,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-go-001"
_TENANT_B = "t-go-002"


def _uid() -> str:
    return str(uuid.uuid4())


def _tid() -> str:
    return f"t-go-{uuid.uuid4().hex[:8]}"


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_decision_row(
    tenant_id: str = _TENANT,
    optimization_type: str = "RECOMMENDATION_RANKING",
    target_type: str = "RECOMMENDATION",
    target_id: str = "PRIORITIZE_BEST_CATEGORY",
    priority_score: float = 75.0,
    rank: int = 1,
) -> FaGovernanceOptimizationDecision:
    return FaGovernanceOptimizationDecision(
        id=_uid(),
        tenant_id=tenant_id,
        optimization_id=_uid(),
        optimization_type=optimization_type,
        target_type=target_type,
        target_id=target_id,
        priority_score=priority_score,
        rank=rank,
        reason="Test reason",
        evidence_summary="Test evidence",
        source_authorities=json.dumps(["governance_adaptive_intelligence"]),
        source_record_ids=json.dumps([_uid()]),
        confidence="HIGH",
        created_at=_now_str(),
    )


def _make_aggregate_row(
    tenant_id: str = _TENANT,
    target_type: str = "RECOMMENDATION",
    target_id: str = "PRIORITIZE_BEST_CATEGORY",
    optimization_type: str = "RECOMMENDATION_RANKING",
    times_ranked: int = 3,
    latest_priority_score: float = 75.0,
) -> FaGovernanceOptimizationAggregate:
    return FaGovernanceOptimizationAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        target_type=target_type,
        target_id=target_id,
        optimization_type=optimization_type,
        times_ranked=times_ranked,
        average_priority_score=latest_priority_score,
        latest_priority_score=latest_priority_score,
        highest_priority_score=latest_priority_score,
        lowest_priority_score=latest_priority_score,
        last_ranked_at=_now_str(),
    )


def _make_snapshot_row(
    tenant_id: str = _TENANT,
    snapshot_type: str = "RECOMMENDATION_RANKING",
) -> FaGovernanceOptimizationSnapshot:
    return FaGovernanceOptimizationSnapshot(
        id=_uid(),
        tenant_id=tenant_id,
        snapshot_type=snapshot_type,
        total_items_ranked=3,
        top_priority_target_id="PRIORITIZE_BEST_CATEGORY",
        top_priority_score=80.0,
        average_priority_score=60.0,
        optimization_confidence="MEDIUM",
        generated_at=_now_str(),
    )


# ---------------------------------------------------------------------------
# GOO-1 to GOO-10: Model unit tests
# ---------------------------------------------------------------------------


def test_goo_1_governance_optimization_version():
    assert GOVERNANCE_OPTIMIZATION_VERSION == "1.0"


def test_goo_2_optimization_type_enum():
    assert OptimizationType.RECOMMENDATION_RANKING.value == "RECOMMENDATION_RANKING"
    assert OptimizationType.CONTROL_PRIORITIZATION.value == "CONTROL_PRIORITIZATION"
    assert (
        OptimizationType.REMEDIATION_PRIORITIZATION.value
        == "REMEDIATION_PRIORITIZATION"
    )
    assert OptimizationType.BRIDGE_PRIORITIZATION.value == "BRIDGE_PRIORITIZATION"
    assert OptimizationType.STRATEGY_WEIGHTING.value == "STRATEGY_WEIGHTING"


def test_goo_3_target_type_enum():
    assert TargetType.RECOMMENDATION.value == "RECOMMENDATION"
    assert TargetType.CONTROL.value == "CONTROL"
    assert TargetType.REMEDIATION.value == "REMEDIATION"
    assert TargetType.BRIDGE.value == "BRIDGE"
    assert TargetType.STRATEGY.value == "STRATEGY"


def test_goo_4_optimization_confidence_enum():
    assert OptimizationConfidence.HIGH.value == "HIGH"
    assert OptimizationConfidence.MEDIUM.value == "MEDIUM"
    assert OptimizationConfidence.LOW.value == "LOW"
    assert OptimizationConfidence.INSUFFICIENT.value == "INSUFFICIENT"


def test_goo_5_clamp_basic():
    assert clamp(50.0, 0.0, 100.0) == 50.0
    assert clamp(-5.0, 0.0, 100.0) == 0.0
    assert clamp(110.0, 0.0, 100.0) == 100.0
    assert clamp(0.0, 0.0, 100.0) == 0.0
    assert clamp(100.0, 0.0, 100.0) == 100.0


def test_goo_6_compute_priority_score_basic():
    score = compute_priority_score(
        accuracy_score=1.0,
        avg_health_delta=10.0,
        avg_effectiveness_delta=5.0,
        failure_penalty=0.0,
        sample_size=10,
    )
    # base=60, health_bonus=clamp(20,-20,20)=20, eff_bonus=clamp(5,-10,10)=5
    # size_bonus=min(1.0, 10)=1.0, penalty=0, deprioritize=0
    # raw = 60+20+5+1-0-0 = 86
    assert score == pytest.approx(86.0, abs=0.01)


def test_goo_7_compute_priority_score_bounds():
    score_max = compute_priority_score(1.0, 100.0, 100.0, 0.0, 1000)
    assert score_max == 100.0

    score_min = compute_priority_score(0.0, -100.0, -100.0, 1.0, 0)
    assert score_min == 0.0


def test_goo_8_compute_priority_score_deprioritize():
    score_normal = compute_priority_score(0.5, None, None, 0.0, 5)
    score_dep = compute_priority_score(0.5, None, None, 0.0, 5, deprioritize=True)
    assert score_dep == pytest.approx(score_normal - 15.0, abs=0.01)


def test_goo_9_compute_priority_score_failure_penalty():
    score_no_penalty = compute_priority_score(0.5, None, None, 0.0, 5)
    score_with_penalty = compute_priority_score(0.5, None, None, 1.0, 5)
    assert score_with_penalty == pytest.approx(score_no_penalty - 20.0, abs=0.01)


def test_goo_10_compute_priority_score_size_bonus():
    score_small = compute_priority_score(0.5, None, None, 0.0, 1)
    score_large = compute_priority_score(0.5, None, None, 0.0, 100)
    # size_bonus for 100 = min(10.0, 10.0) = 10.0, for 1 = min(0.1, 10.0) = 0.1
    assert score_large > score_small


# ---------------------------------------------------------------------------
# GOO-11 to GOO-15: classify_optimization_confidence
# ---------------------------------------------------------------------------


def test_goo_11_confidence_insufficient():
    assert (
        classify_optimization_confidence(90.0, 0) == OptimizationConfidence.INSUFFICIENT
    )


def test_goo_12_confidence_high():
    assert classify_optimization_confidence(70.0, 5) == OptimizationConfidence.HIGH
    assert classify_optimization_confidence(100.0, 10) == OptimizationConfidence.HIGH


def test_goo_13_confidence_medium_by_samples():
    assert classify_optimization_confidence(40.0, 3) == OptimizationConfidence.MEDIUM


def test_goo_14_confidence_medium_by_score():
    assert classify_optimization_confidence(50.0, 1) == OptimizationConfidence.MEDIUM


def test_goo_15_confidence_low():
    assert classify_optimization_confidence(30.0, 2) == OptimizationConfidence.LOW


# ---------------------------------------------------------------------------
# GOO-16 to GOO-20: optimization_rules
# ---------------------------------------------------------------------------


def test_goo_16_should_surface_zero_sample():
    assert not should_surface_as_optimization_target("RECOMMENDATION", 80.0, 0)


def test_goo_17_should_surface_bridge_with_data():
    # All bridges with sample_size > 0 surface regardless of score (rank determines priority)
    assert should_surface_as_optimization_target("BRIDGE", 25.0, 5)


def test_goo_18_should_surface_bridge_above_threshold():
    assert should_surface_as_optimization_target("BRIDGE", 35.0, 5)


def test_goo_19_should_surface_recommendation():
    assert should_surface_as_optimization_target("RECOMMENDATION", 10.0, 1)


def test_goo_20_apply_optimization_context_ordering():
    items = [
        RankedItem("A", "RECOMMENDATION", "RECOMMENDATION_RANKING", 50.0, 0, "r", "e"),
        RankedItem("B", "RECOMMENDATION", "RECOMMENDATION_RANKING", 80.0, 0, "r", "e"),
        RankedItem("C", "RECOMMENDATION", "RECOMMENDATION_RANKING", 30.0, 0, "r", "e"),
    ]
    ranked = apply_optimization_context(items, "RECOMMENDATION_RANKING")
    assert ranked[0].target_id == "B"
    assert ranked[0].rank == 1
    assert ranked[1].target_id == "A"
    assert ranked[1].rank == 2
    assert ranked[2].target_id == "C"
    assert ranked[2].rank == 3


# ---------------------------------------------------------------------------
# GOO-21 to GOO-30: DB model smoke tests
# ---------------------------------------------------------------------------


def test_goo_21_decision_orm_instantiation():
    row = _make_decision_row()
    assert row.tenant_id == _TENANT
    assert row.optimization_type == "RECOMMENDATION_RANKING"


def test_goo_22_aggregate_orm_instantiation():
    row = _make_aggregate_row()
    assert row.tenant_id == _TENANT
    assert row.target_type == "RECOMMENDATION"


def test_goo_23_snapshot_orm_instantiation():
    row = _make_snapshot_row()
    assert row.tenant_id == _TENANT
    assert row.snapshot_type == "RECOMMENDATION_RANKING"


def test_goo_24_decision_append_only_update():
    import pytest

    row = _make_decision_row()
    with pytest.raises(RuntimeError, match="append-only"):
        # Simulate the before_update event
        from api.db_models_governance_optimization import _block_god_update

        _block_god_update(None, None, row)


def test_goo_25_decision_append_only_delete():
    import pytest

    row = _make_decision_row()
    with pytest.raises(RuntimeError, match="append-only"):
        from api.db_models_governance_optimization import _block_god_delete

        _block_god_delete(None, None, row)


def test_goo_26_snapshot_append_only_update():
    import pytest

    row = _make_snapshot_row()
    with pytest.raises(RuntimeError, match="append-only"):
        from api.db_models_governance_optimization import _block_gos_update

        _block_gos_update(None, None, row)


def test_goo_27_snapshot_append_only_delete():
    import pytest

    row = _make_snapshot_row()
    with pytest.raises(RuntimeError, match="append-only"):
        from api.db_models_governance_optimization import _block_gos_delete

        _block_gos_delete(None, None, row)


# ---------------------------------------------------------------------------
# GOO-31 to GOO-50: Ranking unit tests
# ---------------------------------------------------------------------------


def _make_accuracy_agg(
    rec_type: str,
    executed: int = 10,
    successful: int = 8,
    failed: int = 2,
    avg_health_delta: float = 5.0,
    avg_effectiveness_delta: float = 2.0,
    calibrated_confidence: str = "CALIBRATED_HIGH",
):
    agg = MagicMock()
    agg.id = _uid()
    agg.recommendation_type = rec_type
    agg.recommendations_executed = executed
    agg.recommendations_successful = successful
    agg.recommendations_failed = failed
    agg.avg_health_delta = avg_health_delta
    agg.avg_effectiveness_delta = avg_effectiveness_delta
    agg.calibrated_confidence = calibrated_confidence
    return agg


def _make_learning_agg(
    rem_cat: str,
    success: int = 8,
    failure: int = 2,
    partial: int = 0,
    no_change: int = 0,
    avg_health_delta: float = 3.0,
    avg_eff_delta: float = 1.0,
):
    agg = MagicMock()
    agg.id = _uid()
    agg.remediation_category = rem_cat
    agg.success_count = success
    agg.failure_count = failure
    agg.partial_success_count = partial
    agg.no_change_count = no_change
    agg.average_health_delta = avg_health_delta
    agg.average_effectiveness_delta = avg_eff_delta
    return agg


def _make_chain_execution(
    bridge_type: str,
    execution_result: str = "SUCCESS",
):
    ex = MagicMock()
    ex.id = _uid()
    ex.bridge_type = bridge_type
    ex.execution_result = execution_result
    return ex


def test_goo_31_rank_recommendations_empty():
    result = rank_recommendations([])
    assert result == []


def test_goo_32_rank_recommendations_single():
    agg = _make_accuracy_agg("TYPE_A", executed=10, successful=8, failed=2)
    result = rank_recommendations([agg])
    assert len(result) == 1
    assert result[0].target_id == "TYPE_A"
    assert result[0].target_type == "RECOMMENDATION"
    assert result[0].optimization_type == "RECOMMENDATION_RANKING"
    assert result[0].priority_score > 0


def test_goo_33_rank_recommendations_ordering():
    agg_high = _make_accuracy_agg("HIGH_TYPE", executed=20, successful=19, failed=1)
    agg_low = _make_accuracy_agg("LOW_TYPE", executed=10, successful=2, failed=8)
    result = rank_recommendations([agg_high, agg_low])
    assert len(result) == 2
    scores = {r.target_id: r.priority_score for r in result}
    assert scores["HIGH_TYPE"] > scores["LOW_TYPE"]


def test_goo_34_rank_recommendations_deprioritize():
    agg = _make_accuracy_agg(
        "BAD_TYPE",
        executed=10,
        successful=1,
        failed=9,
        calibrated_confidence="CALIBRATED_LOW",
    )
    result = rank_recommendations([agg])
    assert len(result) == 1
    assert "deprioritized" in result[0].reason.lower()


def test_goo_35_rank_remediations_empty():
    result = rank_remediations([])
    assert result == []


def test_goo_36_rank_remediations_single():
    agg = _make_learning_agg("POLICY", success=8, failure=2)
    result = rank_remediations([agg])
    assert len(result) == 1
    assert result[0].target_id == "POLICY"
    assert result[0].target_type == "REMEDIATION"
    assert result[0].optimization_type == "REMEDIATION_PRIORITIZATION"


def test_goo_37_rank_remediations_ordering():
    agg_high = _make_learning_agg("HIGH_CAT", success=9, failure=1)
    agg_low = _make_learning_agg("LOW_CAT", success=2, failure=8)
    result = rank_remediations([agg_high, agg_low])
    scores = {r.target_id: r.priority_score for r in result}
    assert scores["HIGH_CAT"] > scores["LOW_CAT"]


def test_goo_38_rank_bridges_empty():
    result = rank_bridges([])
    assert result == []


def test_goo_39_rank_bridges_high_failure_ranks_highest():
    execs = (
        [_make_chain_execution("BRIDGE_A", "FAILURE")] * 8
        + [_make_chain_execution("BRIDGE_A", "SUCCESS")] * 2
        + [_make_chain_execution("BRIDGE_B", "SUCCESS")] * 9
        + [_make_chain_execution("BRIDGE_B", "FAILURE")] * 1
    )
    result = rank_bridges(execs)
    scores = {r.target_id: r.priority_score for r in result}
    # BRIDGE_A has 80% failure → should have higher priority score
    assert scores["BRIDGE_A"] > scores["BRIDGE_B"]


def test_goo_40_rank_bridges_skip_rate_noted():
    execs = (
        [_make_chain_execution("BRIDGE_X", "SKIPPED_UNAVAILABLE")] * 5
        + [_make_chain_execution("BRIDGE_X", "SUCCESS")] * 2
        + [_make_chain_execution("BRIDGE_X", "FAILURE")] * 3
    )
    result = rank_bridges(execs)
    assert len(result) == 1
    assert "skip" in result[0].reason.lower() or "workflow" in result[0].reason.lower()


def test_goo_41_rank_bridges_skipped_unavailable_not_success():
    execs = [_make_chain_execution("BRIDGE_Z", "SKIPPED_UNAVAILABLE")] * 10
    result = rank_bridges(execs)
    assert len(result) == 1
    # All skipped — not counted as success, not as failure either
    # Score should still be computable
    assert result[0].priority_score >= 0.0


def test_goo_42_rank_strategies_empty_playbooks():
    from services.governance_adaptive_intelligence.strategy_profiles import (
        STRATEGY_PROFILES,
    )

    result = rank_strategies([], STRATEGY_PROFILES)
    # With no playbooks, fallback to all (empty list) — still produces items per profile
    assert len(result) == len(STRATEGY_PROFILES)
    for item in result:
        assert item.priority_score == 0.0


def test_goo_43_rank_strategies_with_playbooks():
    pb = MagicMock()
    pb.id = _uid()
    pb.playbook_type = "REMEDIATION"
    pb.success_rate = 0.9
    pb.avg_health_improvement = 5.0
    pb.sample_size = 10

    from services.governance_adaptive_intelligence.strategy_profiles import (
        STRATEGY_PROFILES,
    )

    result = rank_strategies([pb], STRATEGY_PROFILES)
    assert len(result) > 0
    for item in result:
        assert item.target_type == "STRATEGY"
        assert item.optimization_type == "STRATEGY_WEIGHTING"


# ---------------------------------------------------------------------------
# GOO-51 to GOO-70: Engine tests (using in-memory SQLite)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def test_db():
    """Initialize a fresh SQLite test DB and yield engine."""
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    os.environ["FG_ENV"] = "test"
    os.environ["FG_SQLITE_PATH"] = db_path

    from api.db import reset_engine_cache

    reset_engine_cache()
    init_db(sqlite_path=db_path)
    engine = get_engine()
    yield engine
    reset_engine_cache()
    try:
        os.unlink(db_path)
    except Exception:
        pass


@pytest.fixture()
def db_session(test_db):
    with Session(test_db) as session:
        yield session
        session.rollback()


def test_goo_51_engine_init(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    assert engine is not None


def test_goo_52_engine_dashboard_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    dashboard = engine.get_dashboard()
    assert dashboard.total_decisions == 0
    assert dashboard.total_aggregates == 0
    assert dashboard.overall_confidence == "INSUFFICIENT"


def test_goo_53_engine_list_decisions_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    decisions = engine.list_decisions()
    assert decisions == []


def test_goo_54_engine_list_aggregates_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    aggs = engine.list_aggregates()
    assert aggs == []


def test_goo_55_engine_list_snapshots_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    snaps = engine.list_snapshots()
    assert snaps == []


def test_goo_56_engine_rank_recommendations_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    result = engine.rank_recommendations(persist=False)
    assert result == []


def test_goo_57_engine_rank_remediations_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    result = engine.rank_remediations(persist=False)
    assert result == []


def test_goo_58_engine_rank_bridges_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    result = engine.rank_bridges(persist=False)
    assert result == []


def test_goo_59_engine_rank_strategies_empty_playbooks(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    result = engine.rank_strategies(persist=False)
    # Strategy profiles are static — result is per-profile even without playbooks
    assert isinstance(result, list)


def test_goo_60_engine_cgin_no_raw_tenant_id(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    snap = engine.get_cgin_snapshot()
    assert tenant_id not in snap.tenant_fingerprint
    assert snap.tenant_fingerprint != tenant_id


def test_goo_61_engine_cgin_fingerprint_format(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    snap = engine.get_cgin_snapshot()
    assert len(snap.tenant_fingerprint) == 32
    assert snap.bundle_id.startswith("cgin-go-")


def test_goo_62_engine_cgin_no_cross_tenant(db_session):
    t1 = _tid()
    t2 = _tid()
    e1 = GovernanceOptimizationEngine(db_session, t1)
    e2 = GovernanceOptimizationEngine(db_session, t2)
    snap1 = e1.get_cgin_snapshot()
    snap2 = e2.get_cgin_snapshot()
    assert snap1.tenant_fingerprint != snap2.tenant_fingerprint


def test_goo_63_engine_recalculate_empty(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    result = engine.recalculate()
    assert "recalculated_at" in result
    assert "results" in result


def test_goo_64_engine_list_decisions_filter_optimization_type(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    # Insert a decision row directly
    row = _make_decision_row(
        tenant_id=tenant_id,
        optimization_type="RECOMMENDATION_RANKING",
    )
    db_session.add(row)
    db_session.flush()

    decisions = engine.list_decisions(optimization_type="RECOMMENDATION_RANKING")
    assert len(decisions) >= 1
    for d in decisions:
        assert d.optimization_type == "RECOMMENDATION_RANKING"

    decisions_other = engine.list_decisions(optimization_type="BRIDGE_PRIORITIZATION")
    assert all(d.optimization_type == "BRIDGE_PRIORITIZATION" for d in decisions_other)


def test_goo_65_engine_list_decisions_filter_target_type(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    row = _make_decision_row(tenant_id=tenant_id, target_type="REMEDIATION")
    db_session.add(row)
    db_session.flush()

    decisions = engine.list_decisions(target_type="REMEDIATION")
    assert all(d.target_type == "REMEDIATION" for d in decisions)


def test_goo_66_engine_list_aggregates_filter_target_type(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    row = _make_aggregate_row(tenant_id=tenant_id, target_type="BRIDGE")
    db_session.add(row)
    db_session.flush()

    aggs = engine.list_aggregates(target_type="BRIDGE")
    assert all(a.target_type == "BRIDGE" for a in aggs)


def test_goo_67_engine_list_snapshots_filter_type(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    row = _make_snapshot_row(tenant_id=tenant_id, snapshot_type="BRIDGE_PRIORITIZATION")
    db_session.add(row)
    db_session.flush()

    snaps = engine.list_snapshots(snapshot_type="BRIDGE_PRIORITIZATION")
    assert all(s.snapshot_type == "BRIDGE_PRIORITIZATION" for s in snaps)


def test_goo_68_tenant_isolation_decisions(db_session):
    t1 = _tid()
    t2 = _tid()
    row1 = _make_decision_row(tenant_id=t1)
    row2 = _make_decision_row(tenant_id=t2)
    db_session.add(row1)
    db_session.add(row2)
    db_session.flush()

    e1 = GovernanceOptimizationEngine(db_session, t1)
    e2 = GovernanceOptimizationEngine(db_session, t2)

    d1 = e1.list_decisions()
    d2 = e2.list_decisions()

    assert all(d.tenant_id == t1 for d in d1)
    assert all(d.tenant_id == t2 for d in d2)


def test_goo_69_engine_dashboard_populated(db_session):
    tenant_id = _tid()
    # Insert decision + aggregate to populate dashboard
    row = _make_decision_row(tenant_id=tenant_id)
    agg = _make_aggregate_row(tenant_id=tenant_id)
    db_session.add(row)
    db_session.add(agg)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    dashboard = engine.get_dashboard()
    assert dashboard.total_decisions >= 1
    assert dashboard.total_aggregates >= 1


def test_goo_70_engine_cgin_version(db_session):
    engine = GovernanceOptimizationEngine(db_session, _tid())
    snap = engine.get_cgin_snapshot()
    assert snap.optimization_version == GOVERNANCE_OPTIMIZATION_VERSION


# ---------------------------------------------------------------------------
# GOO-71 to GOO-80: Schema validation tests
# ---------------------------------------------------------------------------


def test_goo_71_decision_response_extra_forbidden():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        OptimizationDecisionResponse(
            id="x",
            tenant_id="t",
            optimization_id="o",
            optimization_type="RECOMMENDATION_RANKING",
            target_type="RECOMMENDATION",
            target_id="T",
            priority_score=50.0,
            rank=1,
            reason="r",
            evidence_summary="e",
            source_authorities=["gai"],
            confidence="HIGH",
            created_at="now",
            extra_field="bad",  # type: ignore[call-arg]
        )


def test_goo_72_rank_request_extra_forbidden():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RankRequest(persist=True, extra_field="bad")  # type: ignore[call-arg]


def test_goo_73_recalculate_request_extra_forbidden():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RecalculateOptimizationRequest(optimization_type=None, extra_field="bad")  # type: ignore[call-arg]


def test_goo_74_decision_response_parses_source_authorities_json():
    resp = OptimizationDecisionResponse(
        id="x",
        tenant_id="t",
        optimization_id="o",
        optimization_type="RECOMMENDATION_RANKING",
        target_type="RECOMMENDATION",
        target_id="T",
        priority_score=50.0,
        rank=1,
        reason="r",
        evidence_summary="e",
        source_authorities='["gai", "learning"]',
        confidence="HIGH",
        created_at="now",
    )
    assert resp.source_authorities == ["gai", "learning"]


def test_goo_75_cgin_snapshot_no_tenant_id_field():
    # CGINOptimizationSnapshot must NOT have a tenant_id field
    fields = CGINOptimizationSnapshot.model_fields
    assert "tenant_id" not in fields


# ---------------------------------------------------------------------------
# GOO-81 to GOO-100: API Route tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def app_client(test_db):
    """Build FastAPI test client."""
    import os

    os.environ["FG_ENV"] = "test"
    from api.main import build_app

    app = build_app(auth_enabled=True)
    return TestClient(app, raise_server_exceptions=True)


def _mint_read_key(tenant_id: str) -> str:
    return mint_key("governance:read", tenant_id=tenant_id)


def _mint_write_key(tenant_id: str) -> str:
    return mint_key("governance:read", "governance:write", tenant_id=tenant_id)


def test_goo_81_dashboard_401_no_auth(app_client):
    resp = app_client.get(
        "/governance-optimization/dashboard",
        headers={"X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 401


def test_goo_82_dashboard_403_wrong_scope(app_client):
    wrong_key = mint_key("admin:read", tenant_id=_TENANT)
    resp = app_client.get(
        "/governance-optimization/dashboard",
        headers={"X-API-Key": wrong_key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 403


def test_goo_83_dashboard_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/dashboard",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "total_decisions" in data


def test_goo_84_decisions_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/decisions",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_goo_85_aggregates_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/aggregates",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_86_snapshots_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/snapshots",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_87_recommendation_rankings_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/recommendation-rankings",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_88_control_priorities_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/control-priorities",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_89_remediation_priorities_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/remediation-priorities",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_90_bridge_priorities_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/bridge-priorities",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_91_strategy_weights_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/strategy-weights",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_92_cgin_snapshot_200(app_client):
    key = _mint_read_key(_TENANT)
    resp = app_client.get(
        "/governance-optimization/cgin/snapshot",
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "tenant_fingerprint" in data
    assert _TENANT not in data["tenant_fingerprint"]


def test_goo_93_rank_recommendations_post_401(app_client):
    resp = app_client.post(
        "/governance-optimization/rank-recommendations",
        json={"persist": False},
        headers={"X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 401


def test_goo_94_rank_recommendations_post_403_read_scope(app_client):
    read_key = _mint_read_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/rank-recommendations",
        json={"persist": False},
        headers={"X-API-Key": read_key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 403


def test_goo_95_rank_recommendations_post_200(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/rank-recommendations",
        json={"persist": False},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_goo_96_rank_remediations_post_200(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/rank-remediations",
        json={"persist": False},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_97_rank_bridges_post_200(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/rank-bridges",
        json={"persist": False},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_98_rank_controls_post_200(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/rank-controls",
        json={"persist": False},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_goo_99_recalculate_post_200(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/recalculate",
        json={},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 200


def test_goo_100_recalculate_extra_field_rejected(app_client):
    key = _mint_write_key(_TENANT)
    resp = app_client.post(
        "/governance-optimization/recalculate",
        json={"tenant_id": "spoof", "optimization_type": None},
        headers={"X-API-Key": key, "X-Tenant-Id": _TENANT},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GOO-101 to GOO-120: Additional coverage
# ---------------------------------------------------------------------------


def test_goo_101_rank_recommendations_persist_creates_decisions(db_session):
    from api.db_models_governance_adaptive_intelligence import (
        FaGovernanceAccuracyAggregate,
    )

    tenant_id = _tid()
    # Insert accuracy aggregate
    agg = FaGovernanceAccuracyAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        recommendation_type="PRIORITIZE_BEST_CATEGORY",
        recommendations_generated=10,
        recommendations_accepted=8,
        recommendations_executed=7,
        recommendations_successful=6,
        recommendations_failed=1,
        avg_health_delta=4.0,
        avg_effectiveness_delta=2.0,
        calibrated_confidence="CALIBRATED_HIGH",
        last_updated_at=_now_str(),
    )
    db_session.add(agg)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.rank_recommendations(persist=True)
    assert len(result) == 1
    assert result[0].target_id == "PRIORITIZE_BEST_CATEGORY"

    # Decision should be persisted
    decisions = engine.list_decisions(optimization_type="RECOMMENDATION_RANKING")
    assert len(decisions) >= 1
    assert decisions[0].optimization_type == "RECOMMENDATION_RANKING"


def test_goo_102_rank_remediations_persist_creates_aggregate(db_session):
    from api.db_models_governance_learning import FaGovernanceLearningAggregate

    tenant_id = _tid()
    agg = FaGovernanceLearningAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        remediation_category="TECHNICAL",
        success_count=7,
        failure_count=3,
        partial_success_count=0,
        no_change_count=0,
        average_health_delta=2.0,
        average_effectiveness_delta=1.0,
        confidence="HIGH",
        last_updated_at=_now_str(),
    )
    db_session.add(agg)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.rank_remediations(persist=True)
    assert len(result) == 1

    # Aggregate should be updated
    aggs = engine.list_aggregates(target_type="REMEDIATION")
    assert len(aggs) >= 1
    assert aggs[0].times_ranked >= 1


def test_goo_103_bridge_ranking_high_failure_score(db_session):
    from api.db_models_governance_chain import FaGovernanceChainExecution

    tenant_id = _tid()
    # 9 failures, 1 success for bridge A
    for _ in range(9):
        ex = FaGovernanceChainExecution(
            id=_uid(),
            tenant_id=tenant_id,
            chain_execution_id=_uid(),
            source_authority="test",
            target_authority="test",
            bridge_type="BRIDGE_A",
            trigger_object_id=_uid(),
            trigger_object_type="test",
            execution_result="FAILURE",
            success=0,
            executed_at=_now_str(),
        )
        db_session.add(ex)
    ex_s = FaGovernanceChainExecution(
        id=_uid(),
        tenant_id=tenant_id,
        chain_execution_id=_uid(),
        source_authority="test",
        target_authority="test",
        bridge_type="BRIDGE_A",
        trigger_object_id=_uid(),
        trigger_object_type="test",
        execution_result="SUCCESS",
        success=1,
        executed_at=_now_str(),
    )
    db_session.add(ex_s)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.rank_bridges(persist=True)
    assert len(result) == 1
    assert result[0].target_id == "BRIDGE_A"
    # High failure rate → high priority score
    assert result[0].priority_score > 30.0


def test_goo_104_recalculate_all_types(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.recalculate(optimization_type=None)
    assert "results" in result
    assert "recalculated_at" in result


def test_goo_105_recalculate_specific_type(db_session):
    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.recalculate(optimization_type="RECOMMENDATION_RANKING")
    assert "RECOMMENDATION_RANKING" in result["results"]
    assert "REMEDIATION_PRIORITIZATION" not in result["results"]
