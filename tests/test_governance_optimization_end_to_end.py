"""End-to-end tests for PR 17.6D — Governance Optimization Engine.

Coverage:
  E2E-1: Full loop — ingest learning outcome → rank remediations → check decision
         stored → check aggregate updated → CGIN snapshot
  E2E-2: Recommendation ranking — ingest GAI tracking + outcome →
         rank recommendations → verify ordering by accuracy
  E2E-3: Bridge ranking — mock chain execution rows → rank bridges →
         high failure rate bridges rank highest
  E2E-4: Recalculate — rank → then recalculate → aggregates rebuilt
  E2E-5: CGIN no tenant_id in snapshot
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from api.db import get_engine, init_db

os.environ.setdefault("FG_ENV", "test")


def _uid() -> str:
    return str(uuid.uuid4())


def _tid() -> str:
    return f"t-goe2e-{uuid.uuid4().hex[:8]}"


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


@pytest.fixture(scope="module")
def test_db():
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


# ---------------------------------------------------------------------------
# E2E-1: Full loop — learning outcome → rank remediations → decision + aggregate + CGIN
# ---------------------------------------------------------------------------


def test_e2e_1_full_loop_remediation(db_session):
    from api.db_models_governance_learning import FaGovernanceLearningAggregate
    from services.governance_optimization.engine import GovernanceOptimizationEngine

    tenant_id = _tid()

    # Insert a learning aggregate for this tenant
    agg = FaGovernanceLearningAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        remediation_category="POLICY",
        success_count=8,
        failure_count=2,
        partial_success_count=0,
        no_change_count=0,
        average_health_delta=5.0,
        average_effectiveness_delta=3.0,
        confidence="HIGH",
        last_updated_at=_now_str(),
    )
    db_session.add(agg)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    # Rank remediations — persist=True
    result = engine.rank_remediations(persist=True)
    assert len(result) == 1
    assert result[0].target_id == "POLICY"
    assert result[0].priority_score > 0

    # Check decision is stored
    decisions = engine.list_decisions(optimization_type="REMEDIATION_PRIORITIZATION")
    assert len(decisions) >= 1
    assert decisions[0].target_id == "POLICY"

    # Check aggregate updated
    aggs = engine.list_aggregates(target_type="REMEDIATION")
    assert len(aggs) >= 1
    assert aggs[0].times_ranked >= 1
    assert aggs[0].latest_priority_score is not None

    # CGIN snapshot
    snap = engine.get_cgin_snapshot()
    assert snap.tenant_fingerprint != tenant_id
    assert snap.remediation_priority_stats["count"] >= 1


# ---------------------------------------------------------------------------
# E2E-2: Recommendation ranking ordering by accuracy
# ---------------------------------------------------------------------------


def test_e2e_2_recommendation_ranking_accuracy_ordering(db_session):
    from api.db_models_governance_adaptive_intelligence import (
        FaGovernanceAccuracyAggregate,
    )
    from services.governance_optimization.engine import GovernanceOptimizationEngine

    tenant_id = _tid()

    # High accuracy type
    agg_high = FaGovernanceAccuracyAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        recommendation_type="HIGH_ACCURACY_TYPE",
        recommendations_generated=20,
        recommendations_accepted=18,
        recommendations_executed=15,
        recommendations_successful=14,
        recommendations_failed=1,
        avg_health_delta=8.0,
        avg_effectiveness_delta=4.0,
        calibrated_confidence="CALIBRATED_HIGH",
        last_updated_at=_now_str(),
    )
    # Low accuracy type
    agg_low = FaGovernanceAccuracyAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        recommendation_type="LOW_ACCURACY_TYPE",
        recommendations_generated=10,
        recommendations_accepted=5,
        recommendations_executed=5,
        recommendations_successful=1,
        recommendations_failed=4,
        avg_health_delta=-2.0,
        avg_effectiveness_delta=-1.0,
        calibrated_confidence="CALIBRATED_LOW",
        last_updated_at=_now_str(),
    )
    db_session.add(agg_high)
    db_session.add(agg_low)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.rank_recommendations(persist=True)

    assert len(result) == 2
    scores = {r.target_id: r.priority_score for r in result}
    assert scores["HIGH_ACCURACY_TYPE"] > scores["LOW_ACCURACY_TYPE"]

    # Rank 1 should be the high accuracy type
    ranked = sorted(result, key=lambda r: r.rank)
    assert ranked[0].target_id == "HIGH_ACCURACY_TYPE"
    assert ranked[0].rank == 1


# ---------------------------------------------------------------------------
# E2E-3: Bridge ranking — high failure rate ranks highest
# ---------------------------------------------------------------------------


def test_e2e_3_bridge_ranking_failure_rate(db_session):
    from api.db_models_governance_chain import FaGovernanceChainExecution
    from services.governance_optimization.engine import GovernanceOptimizationEngine

    tenant_id = _tid()

    # Bridge A: 80% failure rate (needs most attention)
    for _ in range(8):
        db_session.add(
            FaGovernanceChainExecution(
                id=_uid(),
                tenant_id=tenant_id,
                chain_execution_id=_uid(),
                source_authority="test",
                target_authority="test",
                bridge_type="FAILING_BRIDGE",
                trigger_object_id=_uid(),
                trigger_object_type="test",
                execution_result="FAILURE",
                success=0,
                executed_at=_now_str(),
            )
        )
    for _ in range(2):
        db_session.add(
            FaGovernanceChainExecution(
                id=_uid(),
                tenant_id=tenant_id,
                chain_execution_id=_uid(),
                source_authority="test",
                target_authority="test",
                bridge_type="FAILING_BRIDGE",
                trigger_object_id=_uid(),
                trigger_object_type="test",
                execution_result="SUCCESS",
                success=1,
                executed_at=_now_str(),
            )
        )

    # Bridge B: 90% success rate (healthy bridge)
    for _ in range(9):
        db_session.add(
            FaGovernanceChainExecution(
                id=_uid(),
                tenant_id=tenant_id,
                chain_execution_id=_uid(),
                source_authority="test",
                target_authority="test",
                bridge_type="HEALTHY_BRIDGE",
                trigger_object_id=_uid(),
                trigger_object_type="test",
                execution_result="SUCCESS",
                success=1,
                executed_at=_now_str(),
            )
        )
    db_session.add(
        FaGovernanceChainExecution(
            id=_uid(),
            tenant_id=tenant_id,
            chain_execution_id=_uid(),
            source_authority="test",
            target_authority="test",
            bridge_type="HEALTHY_BRIDGE",
            trigger_object_id=_uid(),
            trigger_object_type="test",
            execution_result="FAILURE",
            success=0,
            executed_at=_now_str(),
        )
    )
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)
    result = engine.rank_bridges(persist=True)

    assert len(result) >= 2
    scores = {r.target_id: r.priority_score for r in result}
    # FAILING_BRIDGE (80% failure) should rank higher than HEALTHY_BRIDGE (10% failure)
    assert scores["FAILING_BRIDGE"] > scores["HEALTHY_BRIDGE"]

    # Rank 1 = most attention needed
    ranked = sorted(result, key=lambda r: r.rank)
    assert ranked[0].target_id == "FAILING_BRIDGE"


# ---------------------------------------------------------------------------
# E2E-4: Recalculate rebuilds aggregates
# ---------------------------------------------------------------------------


def test_e2e_4_recalculate_rebuilds_aggregates(db_session):
    from api.db_models_governance_learning import FaGovernanceLearningAggregate
    from services.governance_optimization.engine import GovernanceOptimizationEngine

    tenant_id = _tid()

    agg = FaGovernanceLearningAggregate(
        id=_uid(),
        tenant_id=tenant_id,
        remediation_category="PROCESS",
        success_count=6,
        failure_count=4,
        partial_success_count=0,
        no_change_count=0,
        average_health_delta=2.0,
        average_effectiveness_delta=1.0,
        confidence="MEDIUM",
        last_updated_at=_now_str(),
    )
    db_session.add(agg)
    db_session.flush()

    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    # Initial rank
    initial = engine.rank_remediations(persist=True)
    assert len(initial) == 1
    initial_times = engine.list_aggregates(target_type="REMEDIATION")[0].times_ranked

    # Recalculate
    recap = engine.recalculate(optimization_type="REMEDIATION_PRIORITIZATION")
    assert "REMEDIATION_PRIORITIZATION" in recap["results"]

    # Aggregate times_ranked should have increased
    updated_aggs = engine.list_aggregates(target_type="REMEDIATION")
    assert len(updated_aggs) >= 1
    assert updated_aggs[0].times_ranked >= initial_times


# ---------------------------------------------------------------------------
# E2E-5: CGIN snapshot has no raw tenant_id
# ---------------------------------------------------------------------------


def test_e2e_5_cgin_no_tenant_id(db_session):
    from services.governance_optimization.engine import GovernanceOptimizationEngine

    tenant_id = _tid()
    engine = GovernanceOptimizationEngine(db_session, tenant_id)

    snap = engine.get_cgin_snapshot()

    # tenant_id must not appear anywhere in the snapshot
    snap_dict = snap.model_dump()
    snap_str = str(snap_dict)
    assert tenant_id not in snap_str

    # Fingerprint should be a 32-char hex derived from sha256
    assert len(snap.tenant_fingerprint) == 32
    assert all(c in "0123456789abcdef" for c in snap.tenant_fingerprint)
