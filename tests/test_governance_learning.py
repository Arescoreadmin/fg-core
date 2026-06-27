"""Tests for PR 17.6B — Governance Learning Loop Authority.

Coverage:
  GL-1   to GL-30:   Model unit tests (enums, compute_success_score,
                      compute_confidence_score, classify_*, detect_signals)
  GL-31  to GL-50:   DB model smoke tests (ORM instantiation, append-only guards)
  GL-51  to GL-70:   Repository tests (create, list, filter, tenant isolation)
  GL-71  to GL-100:  Engine tests (ingest, idempotency, dashboard, aggregates,
                      recommendations, top-performers, failures, momentum, cgin,
                      recalculate)
  GL-101 to GL-130:  API route tests (all 10 routes, auth, tenant isolation)
  GL-131 to GL-145:  Authority integration (signals, success/failure rates)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_governance_learning import (
    FaGovernanceLearningAggregate,
    FaGovernanceLearningRecord,
)
from services.governance_learning.engine import GovernanceLearningEngine
from services.governance_learning.models import (
    GOVERNANCE_LEARNING_VERSION,
    ConfidenceLevel,
    LearningCategory,
    LearningSignal,
    MomentumClass,
    StabilityClass,
    classify_confidence,
    classify_momentum,
    classify_stability,
    compute_confidence_score,
    compute_success_score,
    detect_signals,
)
from services.governance_learning.schemas import (
    IngestOutcomeRequest,
    RecalculateRequest,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-gl-001"
_TENANT_B = "t-gl-002"


def _uid() -> str:
    return str(uuid.uuid4())


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _tid() -> str:
    """Generate an isolated tenant_id per test."""
    return f"t-gl-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_record_row(
    tenant_id: str = _TENANT,
    learning_category: str = "REMEDIATION",
    remediation_category: str = "VERIFICATION",
    outcome_type: str = "SUCCESS",
    success_score: float = 100.0,
    confidence_score: float = 20.0,
    health_delta: float | None = None,
    source_outcome_id: str | None = None,
) -> FaGovernanceLearningRecord:
    return FaGovernanceLearningRecord(
        id=_uid(),
        tenant_id=tenant_id,
        learning_category=learning_category,
        control_id="ctrl-001",
        remediation_category=remediation_category,
        outcome_type=outcome_type,
        effectiveness_before=60.0,
        effectiveness_after=75.0,
        effectiveness_delta=15.0,
        verification_before=50.0,
        verification_after=65.0,
        verification_delta=15.0,
        freshness_before=None,
        freshness_after=None,
        freshness_delta=None,
        forecast_before=None,
        forecast_after=None,
        forecast_delta=None,
        health_before=70.0,
        health_after=80.0 if health_delta is None else 70.0 + health_delta,
        health_delta=health_delta if health_delta is not None else 10.0,
        success_score=success_score,
        confidence_score=confidence_score,
        source_outcome_id=source_outcome_id or _uid(),
        created_at=_now_str(),
    )


def _ingest_req(
    tenant_id: str = _TENANT,
    remediation_category: str = "VERIFICATION",
    outcome_classification: str = "SUCCESS",
    score_delta: float = 15.0,
    source_outcome_id: str | None = None,
    control_id: str = "ctrl-001",
) -> IngestOutcomeRequest:
    return IngestOutcomeRequest(
        source_outcome_id=source_outcome_id or _uid(),
        control_id=control_id,
        outcome_classification=outcome_classification,
        score_delta=score_delta,
        remediation_category=remediation_category,
        effectiveness_before=60.0,
        effectiveness_after=75.0,
        verification_before=50.0,
        verification_after=65.0,
        freshness_before=None,
        freshness_after=None,
        forecast_before=None,
        forecast_after=None,
        health_before=70.0,
        health_after=80.0,
    )


# ===========================================================================
# GL-1 to GL-30: Model unit tests
# ===========================================================================


class TestModels:
    def test_GL_1_governance_learning_version(self):
        assert GOVERNANCE_LEARNING_VERSION == "1.0"

    def test_GL_2_learning_category_has_6_values(self):
        assert len(LearningCategory) == 6

    def test_GL_3_learning_category_remediation(self):
        assert LearningCategory.REMEDIATION == "REMEDIATION"

    def test_GL_4_learning_signal_has_11_values(self):
        assert len(LearningSignal) == 11

    def test_GL_5_compute_success_score_success(self):
        score = compute_success_score("SUCCESS", 0.0)
        assert score == 100.0

    def test_GL_6_compute_success_score_partial_success(self):
        score = compute_success_score("PARTIAL_SUCCESS", 0.0)
        assert score == 60.0

    def test_GL_7_compute_success_score_no_change(self):
        score = compute_success_score("NO_CHANGE", 0.0)
        assert score == 40.0

    def test_GL_8_compute_success_score_regression(self):
        score = compute_success_score("REGRESSION", 0.0)
        assert score == 20.0

    def test_GL_9_compute_success_score_failure(self):
        score = compute_success_score("FAILURE", 0.0)
        assert score == 0.0

    def test_GL_10_compute_success_score_bonus_capped_at_10(self):
        score = compute_success_score("SUCCESS", 100.0)
        assert score == 100.0  # 100 + 10 capped at 100

    def test_GL_11_compute_success_score_negative_delta(self):
        score = compute_success_score("FAILURE", -20.0)
        assert score == 0.0  # 0 + (-10) capped at 0

    def test_GL_12_compute_success_score_unknown_classification(self):
        score = compute_success_score("UNKNOWN", 0.0)
        assert score == 40.0  # defaults to NO_CHANGE base

    def test_GL_13_compute_confidence_score_high(self):
        assert compute_confidence_score(20) == 90.0

    def test_GL_14_compute_confidence_score_medium(self):
        assert compute_confidence_score(10) == 70.0

    def test_GL_15_compute_confidence_score_low(self):
        assert compute_confidence_score(3) == 50.0

    def test_GL_16_compute_confidence_score_unknown(self):
        assert compute_confidence_score(1) == 20.0

    def test_GL_17_classify_confidence_high(self):
        assert classify_confidence(20) == ConfidenceLevel.HIGH

    def test_GL_18_classify_confidence_medium(self):
        assert classify_confidence(10) == ConfidenceLevel.MEDIUM

    def test_GL_19_classify_confidence_low(self):
        assert classify_confidence(3) == ConfidenceLevel.LOW

    def test_GL_20_classify_confidence_unknown(self):
        assert classify_confidence(0) == ConfidenceLevel.UNKNOWN

    def test_GL_21_classify_momentum_accelerating(self):
        m = classify_momentum(10.0, 8.0)
        assert m == MomentumClass.ACCELERATING

    def test_GL_22_classify_momentum_stable(self):
        m = classify_momentum(2.0, 1.0)
        assert m == MomentumClass.STABLE

    def test_GL_23_classify_momentum_decelerating(self):
        m = classify_momentum(-2.0, -3.0)
        assert m == MomentumClass.DECELERATING

    def test_GL_24_classify_momentum_regressing(self):
        m = classify_momentum(-10.0, -8.0)
        assert m == MomentumClass.REGRESSING

    def test_GL_25_classify_momentum_none_inputs(self):
        m = classify_momentum(None, None)
        assert m == MomentumClass.STABLE

    def test_GL_26_classify_stability_very_stable(self):
        deltas = [5.0, 5.0, 5.0, 5.0]
        assert classify_stability(deltas) == StabilityClass.VERY_STABLE

    def test_GL_27_classify_stability_stable(self):
        # stddev ~2.5 → STABLE (>2 and <=5)
        deltas = [0.0, 5.0, 0.0, 5.0]
        assert classify_stability(deltas) == StabilityClass.STABLE

    def test_GL_28_classify_stability_variable(self):
        deltas = [0.0, 10.0, -5.0, 15.0]
        assert classify_stability(deltas) == StabilityClass.VARIABLE

    def test_GL_29_classify_stability_unstable(self):
        deltas = [-20.0, 30.0, -15.0, 25.0]
        assert classify_stability(deltas) == StabilityClass.UNSTABLE

    def test_GL_30_detect_signals_improves_health(self):
        sigs = detect_signals(
            avg_effectiveness_delta=None,
            avg_health_delta=10.0,
            avg_freshness_delta=None,
            avg_verification_delta=None,
            avg_forecast_delta=None,
            success_rate=0.5,
            failure_rate=0.2,
            total_count=5,
        )
        assert LearningSignal.IMPROVES_HEALTH.value in sigs

    def test_GL_30b_detect_signals_high_success_rate(self):
        sigs = detect_signals(
            avg_effectiveness_delta=None,
            avg_health_delta=None,
            avg_freshness_delta=None,
            avg_verification_delta=None,
            avg_forecast_delta=None,
            success_rate=0.85,
            failure_rate=0.1,
            total_count=10,
        )
        assert LearningSignal.HIGH_SUCCESS_RATE.value in sigs

    def test_GL_30c_detect_signals_repeated_failure(self):
        sigs = detect_signals(
            avg_effectiveness_delta=None,
            avg_health_delta=None,
            avg_freshness_delta=None,
            avg_verification_delta=None,
            avg_forecast_delta=None,
            success_rate=0.1,
            failure_rate=0.75,
            total_count=5,
        )
        assert LearningSignal.REPEATED_FAILURE.value in sigs


# ===========================================================================
# GL-31 to GL-50: DB model smoke tests
# ===========================================================================


class TestDBModels:
    def test_GL_31_record_has_tablename(self):
        assert (
            FaGovernanceLearningRecord.__tablename__ == "fa_governance_learning_records"
        )

    def test_GL_32_aggregate_has_tablename(self):
        assert (
            FaGovernanceLearningAggregate.__tablename__
            == "fa_governance_learning_aggregates"
        )

    def test_GL_33_record_can_instantiate(self):
        row = _make_record_row()
        assert row.tenant_id == _TENANT

    def test_GL_34_aggregate_can_instantiate(self):
        agg = FaGovernanceLearningAggregate(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_category="VERIFICATION",
            success_count=5,
            failure_count=1,
            partial_success_count=2,
            confidence="MEDIUM",
            last_updated_at=_now_str(),
        )
        assert agg.remediation_category == "VERIFICATION"

    def test_GL_35_record_append_only_update_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_record_row(tenant_id=_tid())
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                row.outcome_type = "MODIFIED"
                db.commit()
            db.rollback()

    def test_GL_36_record_append_only_delete_blocked(self, build_app):
        build_app(auth_enabled=False)
        with Session(get_engine()) as db:
            row = _make_record_row(tenant_id=_tid())
            db.add(row)
            db.commit()
            db.refresh(row)
            with pytest.raises(RuntimeError, match="append-only"):
                db.delete(row)
                db.commit()
            db.rollback()

    def test_GL_37_aggregate_is_mutable(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            agg = FaGovernanceLearningAggregate(
                id=_uid(),
                tenant_id=tenant,
                remediation_category="FRESHNESS",
                success_count=0,
                failure_count=0,
                partial_success_count=0,
                confidence="UNKNOWN",
                last_updated_at=_now_str(),
            )
            db.add(agg)
            db.commit()
            db.refresh(agg)
            agg.success_count = 5
            db.commit()
            db.refresh(agg)
            assert agg.success_count == 5

    def test_GL_38_record_learning_category_stored(self):
        row = _make_record_row(learning_category="EFFECTIVENESS")
        assert row.learning_category == "EFFECTIVENESS"

    def test_GL_39_record_source_outcome_id_stored(self):
        oid = _uid()
        row = _make_record_row(source_outcome_id=oid)
        assert row.source_outcome_id == oid

    def test_GL_40_record_control_id_nullable(self):
        row = FaGovernanceLearningRecord(
            id=_uid(),
            tenant_id=_TENANT,
            learning_category="REMEDIATION",
            control_id=None,
            remediation_category="OTHER",
            outcome_type="SUCCESS",
            success_score=100.0,
            confidence_score=20.0,
            created_at=_now_str(),
        )
        assert row.control_id is None


# ===========================================================================
# GL-51 to GL-70: Repository tests
# ===========================================================================


class TestRepository:
    def test_GL_51_create_and_get_record(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            row = _make_record_row(tenant_id=tenant)
            repo.create_record(row)
            db.commit()
            fetched = repo.get_record(row.id)
            assert fetched is not None
            assert fetched.id == row.id

    def test_GL_52_get_record_wrong_tenant_returns_none(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        tenant_b = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            row = _make_record_row(tenant_id=tenant)
            repo.create_record(row)
            db.commit()
            repo_b = GovernanceLearningRepository(db, tenant_b)
            assert repo_b.get_record(row.id) is None

    def test_GL_53_list_records_with_category_filter(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            repo.create_record(
                _make_record_row(tenant_id=tenant, remediation_category="VERIFICATION")
            )
            repo.create_record(
                _make_record_row(tenant_id=tenant, remediation_category="FRESHNESS")
            )
            db.commit()
            rows, total = repo.list_records(remediation_category="FRESHNESS")
            assert total == 1
            assert rows[0].remediation_category == "FRESHNESS"

    def test_GL_54_get_record_by_outcome_idempotency(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        oid = _uid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            row = _make_record_row(tenant_id=tenant, source_outcome_id=oid)
            repo.create_record(row)
            db.commit()
            found = repo.get_record_by_outcome(oid)
            assert found is not None
            assert found.source_outcome_id == oid

    def test_GL_55_get_record_by_outcome_not_found(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            result = repo.get_record_by_outcome("nonexistent-oid")
            assert result is None

    def test_GL_56_upsert_aggregate_creates_new(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            agg = repo.upsert_aggregate(
                tenant_id=tenant,
                remediation_category="VERIFICATION",
                updates={
                    "success_count": 3,
                    "failure_count": 1,
                    "partial_success_count": 0,
                    "confidence": "LOW",
                    "last_updated_at": _now_str(),
                },
            )
            db.commit()
            assert agg.success_count == 3
            assert agg.remediation_category == "VERIFICATION"

    def test_GL_57_upsert_aggregate_updates_existing(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            repo.upsert_aggregate(
                tenant_id=tenant,
                remediation_category="GOVERNANCE",
                updates={
                    "success_count": 2,
                    "failure_count": 0,
                    "partial_success_count": 0,
                    "confidence": "LOW",
                    "last_updated_at": _now_str(),
                },
            )
            db.commit()
            repo.upsert_aggregate(
                tenant_id=tenant,
                remediation_category="GOVERNANCE",
                updates={
                    "success_count": 5,
                    "failure_count": 1,
                    "partial_success_count": 1,
                    "confidence": "MEDIUM",
                    "last_updated_at": _now_str(),
                },
            )
            db.commit()
            agg = repo.get_aggregate("GOVERNANCE")
            assert agg is not None
            assert agg.success_count == 5

    def test_GL_58_list_aggregates_returns_all(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            for cat in ["VERIFICATION", "FRESHNESS", "COVERAGE"]:
                repo.upsert_aggregate(
                    tenant_id=tenant,
                    remediation_category=cat,
                    updates={
                        "success_count": 1,
                        "failure_count": 0,
                        "partial_success_count": 0,
                        "confidence": "LOW",
                        "last_updated_at": _now_str(),
                    },
                )
            db.commit()
            rows, total = repo.list_aggregates()
            assert total == 3

    def test_GL_59_list_recent_health_deltas(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            for delta in [5.0, 10.0, -2.0]:
                repo.create_record(
                    _make_record_row(tenant_id=tenant, health_delta=delta)
                )
            db.commit()
            deltas = repo.list_recent_health_deltas(n=10)
            assert len(deltas) == 3
            assert 5.0 in deltas

    def test_GL_60_count_records_by_outcome_type(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        from services.governance_learning.repository import GovernanceLearningRepository

        with Session(get_engine()) as db:
            repo = GovernanceLearningRepository(db, tenant)
            repo.create_record(
                _make_record_row(tenant_id=tenant, outcome_type="SUCCESS")
            )
            repo.create_record(
                _make_record_row(tenant_id=tenant, outcome_type="SUCCESS")
            )
            repo.create_record(
                _make_record_row(tenant_id=tenant, outcome_type="FAILURE")
            )
            db.commit()
            counts = repo.count_records_by_outcome_type()
            assert counts.get("SUCCESS", 0) == 2
            assert counts.get("FAILURE", 0) == 1


# ===========================================================================
# GL-71 to GL-100: Engine tests
# ===========================================================================


class TestEngine:
    def test_GL_71_ingest_outcome_creates_record(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            req = _ingest_req()
            resp = engine.ingest_outcome(req)
            assert resp.id is not None
            assert resp.tenant_id == tenant
            assert resp.outcome_type == "SUCCESS"

    def test_GL_72_ingest_outcome_idempotent(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        oid = _uid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            req = _ingest_req(source_outcome_id=oid)
            r1 = engine.ingest_outcome(req)
            r2 = engine.ingest_outcome(req)
            assert r1.id == r2.id

    def test_GL_73_ingest_updates_aggregate(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                _ingest_req(tenant_id=tenant, remediation_category="COVERAGE")
            )
            aggs = engine.list_aggregates()
            assert any(a.remediation_category == "COVERAGE" for a in aggs.aggregates)

    def test_GL_74_ingest_computes_success_score(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            resp = engine.ingest_outcome(
                _ingest_req(outcome_classification="SUCCESS", score_delta=0.0)
            )
            assert resp.success_score == 100.0

    def test_GL_75_ingest_failure_outcome(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            resp = engine.ingest_outcome(
                _ingest_req(outcome_classification="FAILURE", score_delta=-5.0)
            )
            assert resp.success_score == 0.0

    def test_GL_76_get_dashboard_empty(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            dash = engine.get_dashboard()
            assert dash.total_learning_records == 0
            assert dash.total_aggregates == 0
            assert dash.overall_success_rate == 0.0

    def test_GL_77_get_dashboard_populated(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            dash = engine.get_dashboard()
            assert dash.total_learning_records == 2
            assert dash.total_aggregates >= 1
            assert dash.overall_success_rate > 0.0

    def test_GL_78_list_records_empty(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            result = engine.list_records()
            assert result.total == 0
            assert result.records == []

    def test_GL_79_list_records_filtered(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            engine.ingest_outcome(_ingest_req(remediation_category="FRESHNESS"))
            result = engine.list_records(remediation_category="FRESHNESS")
            assert result.total == 1
            assert result.records[0].remediation_category == "FRESHNESS"

    def test_GL_80_list_aggregates_empty(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            result = engine.list_aggregates()
            assert result.total == 0

    def test_GL_81_list_aggregates_populated(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            result = engine.list_aggregates()
            assert result.total == 1
            assert result.aggregates[0].success_count == 2

    def test_GL_82_get_recommendations_no_data(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            result = engine.get_recommendations()
            assert result.total == 1
            assert (
                result.recommendations[0].recommended_next_action
                == "COLLECT_MORE_OUTCOME_DATA"
            )

    def test_GL_83_get_recommendations_with_data(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(4):
                engine.ingest_outcome(
                    _ingest_req(
                        outcome_classification="SUCCESS",
                        remediation_category="VERIFICATION",
                    )
                )
            result = engine.get_recommendations()
            assert result.total >= 1
            actions = [r.recommended_next_action for r in result.recommendations]
            assert "PRIORITIZE_REMEDIATION_CATEGORY" in actions

    def test_GL_84_get_top_performers(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                _ingest_req(
                    outcome_classification="SUCCESS",
                    remediation_category="VERIFICATION",
                )
            )
            engine.ingest_outcome(
                _ingest_req(
                    outcome_classification="FAILURE", remediation_category="FRESHNESS"
                )
            )
            result = engine.get_top_performers(limit=5)
            assert result.total >= 1
            if result.total > 1:
                # Top should have higher success rate
                assert (
                    result.aggregates[0].success_rate
                    >= result.aggregates[-1].success_rate
                )

    def test_GL_85_get_failures(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                _ingest_req(
                    outcome_classification="FAILURE", remediation_category="FORECAST"
                )
            )
            engine.ingest_outcome(
                _ingest_req(
                    outcome_classification="SUCCESS",
                    remediation_category="VERIFICATION",
                )
            )
            result = engine.get_failures(limit=5)
            assert result.total >= 1
            if result.total > 1:
                assert (
                    result.aggregates[0].failure_rate
                    >= result.aggregates[-1].failure_rate
                )

    def test_GL_86_get_momentum_empty(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            m = engine.get_momentum()
            assert m.tenant_id == tenant
            assert m.momentum_class in [mc.value for mc in MomentumClass]
            assert m.total_learning_records == 0

    def test_GL_87_get_momentum_accelerating(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            # Ingest 3 successful outcomes with high health deltas
            for _ in range(3):
                engine.ingest_outcome(
                    IngestOutcomeRequest(
                        source_outcome_id=_uid(),
                        control_id="ctrl-1",
                        outcome_classification="SUCCESS",
                        score_delta=20.0,
                        remediation_category="VERIFICATION",
                        health_before=50.0,
                        health_after=65.0,  # delta=15
                    )
                )
            m = engine.get_momentum()
            assert m.momentum_class in [
                MomentumClass.ACCELERATING.value,
                MomentumClass.STABLE.value,
            ]

    def test_GL_88_get_cgin_snapshot_no_raw_tenant_id(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            snap = engine.get_cgin_snapshot()
            # Must not include raw tenant_id in any field
            snap_dict = snap.model_dump()
            snap_str = str(snap_dict)
            assert tenant not in snap_str

    def test_GL_89_get_cgin_snapshot_has_fingerprint(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            snap = engine.get_cgin_snapshot()
            assert len(snap.tenant_fingerprint) == 32
            assert snap.bundle_version == GOVERNANCE_LEARNING_VERSION

    def test_GL_90_recalculate_empty(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            result = engine.recalculate(RecalculateRequest())
            assert result["categories_recalculated"] == 0

    def test_GL_91_recalculate_rebuilds_aggregate(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                _ingest_req(
                    outcome_classification="SUCCESS",
                    remediation_category="VERIFICATION",
                )
            )
            # Manually corrupt the aggregate
            from services.governance_learning.repository import (
                GovernanceLearningRepository,
            )

            repo = GovernanceLearningRepository(db, tenant)
            agg = repo.get_aggregate("VERIFICATION")
            agg.success_count = 999
            db.commit()
            # Recalculate
            result = engine.recalculate(RecalculateRequest())
            assert result["categories_recalculated"] >= 1
            agg2 = repo.get_aggregate("VERIFICATION")
            assert agg2.success_count == 1

    def test_GL_92_tenant_isolation_records(self, build_app):
        build_app(auth_enabled=False)
        tenant_a = _tid()
        tenant_b = _tid()
        with Session(get_engine()) as db:
            engine_a = GovernanceLearningEngine(db, tenant_a)
            engine_b = GovernanceLearningEngine(db, tenant_b)
            engine_a.ingest_outcome(_ingest_req())
            result_b = engine_b.list_records()
            assert result_b.total == 0

    def test_GL_93_ingest_partial_success(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            resp = engine.ingest_outcome(
                _ingest_req(outcome_classification="PARTIAL_SUCCESS", score_delta=5.0)
            )
            assert resp.success_score == pytest.approx(60.0 + 2.5, abs=0.1)

    def test_GL_94_aggregate_has_signals(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(5):
                engine.ingest_outcome(
                    IngestOutcomeRequest(
                        source_outcome_id=_uid(),
                        control_id="ctrl-1",
                        outcome_classification="SUCCESS",
                        score_delta=15.0,
                        remediation_category="VERIFICATION",
                        health_before=60.0,
                        health_after=75.0,
                        effectiveness_before=50.0,
                        effectiveness_after=70.0,
                    )
                )
            result = engine.list_aggregates()
            assert result.total >= 1
            agg = result.aggregates[0]
            # Should detect IMPROVES_HEALTH signal (delta=15 > 5)
            assert LearningSignal.IMPROVES_HEALTH.value in agg.signals

    def test_GL_95_list_records_pagination(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(5):
                engine.ingest_outcome(_ingest_req())
            page1 = engine.list_records(limit=3, offset=0)
            page2 = engine.list_records(limit=3, offset=3)
            assert len(page1.records) == 3
            assert len(page2.records) == 2
            assert page1.total == 5

    def test_GL_96_learning_category_is_remediation_on_ingest(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            resp = engine.ingest_outcome(_ingest_req())
            assert resp.learning_category == LearningCategory.REMEDIATION.value

    def test_GL_97_dashboard_momentum_is_valid(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            dash = engine.get_dashboard()
            assert dash.momentum in [mc.value for mc in MomentumClass]

    def test_GL_98_dashboard_stability_is_valid(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            dash = engine.get_dashboard()
            assert dash.stability in [sc.value for sc in StabilityClass]

    def test_GL_99_recalculate_with_control_id_filter(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                _ingest_req(control_id="ctrl-A", remediation_category="VERIFICATION")
            )
            engine.ingest_outcome(
                _ingest_req(control_id="ctrl-B", remediation_category="FRESHNESS")
            )
            result = engine.recalculate(RecalculateRequest(control_id="ctrl-A"))
            assert result["control_id_filter"] == "ctrl-A"
            assert result["categories_recalculated"] == 1  # Only VERIFICATION

    def test_GL_100_aggregate_confidence_updates_with_sample_count(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            # 1 record → UNKNOWN
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            result = engine.list_aggregates()
            agg = next(
                a for a in result.aggregates if a.remediation_category == "VERIFICATION"
            )
            assert agg.confidence == ConfidenceLevel.UNKNOWN.value
            # Add 2 more → LOW (total=3)
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            result2 = engine.list_aggregates()
            agg2 = next(
                a
                for a in result2.aggregates
                if a.remediation_category == "VERIFICATION"
            )
            assert agg2.confidence == ConfidenceLevel.LOW.value


# ===========================================================================
# GL-101 to GL-130: API route tests
# ===========================================================================


class TestAPIRoutes:
    @pytest.fixture()
    def rw_client(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        return TestClient(app, headers={"X-API-Key": key})

    @pytest.fixture()
    def ro_client(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=_TENANT)
        return TestClient(app, headers={"X-API-Key": key})

    @pytest.fixture()
    def rw_client_b(self, build_app):
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT_B)
        return TestClient(app, headers={"X-API-Key": key})

    def _ingest_body(self) -> dict:
        return {
            "source_outcome_id": _uid(),
            "control_id": "ctrl-001",
            "outcome_classification": "SUCCESS",
            "score_delta": 15.0,
            "remediation_category": "VERIFICATION",
            "effectiveness_before": 60.0,
            "effectiveness_after": 75.0,
            "health_before": 70.0,
            "health_after": 80.0,
        }

    def test_GL_101_dashboard_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_learning_records" in data

    def test_GL_102_dashboard_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-learning/dashboard")
        assert resp.status_code in (401, 403)

    def test_GL_103_learning_records_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/learning-records")
        assert resp.status_code == 200
        data = resp.json()
        assert "records" in data
        assert "total" in data

    def test_GL_104_learning_records_with_filters(self, rw_client):
        rw_client.post("/governance-learning/ingest-outcome", json=self._ingest_body())
        resp = rw_client.get(
            "/governance-learning/learning-records?remediation_category=VERIFICATION"
        )
        assert resp.status_code == 200

    def test_GL_105_aggregates_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/aggregates")
        assert resp.status_code == 200
        data = resp.json()
        assert "aggregates" in data

    def test_GL_106_recommendations_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/recommendations")
        assert resp.status_code == 200
        data = resp.json()
        assert "recommendations" in data
        assert "total" in data

    def test_GL_107_top_performers_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/top-performers")
        assert resp.status_code == 200
        data = resp.json()
        assert "aggregates" in data

    def test_GL_108_top_failures_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/top-failures")
        assert resp.status_code == 200
        data = resp.json()
        assert "aggregates" in data

    def test_GL_109_momentum_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/momentum")
        assert resp.status_code == 200
        data = resp.json()
        assert "momentum_class" in data
        assert "stability_class" in data

    def test_GL_110_cgin_snapshot_returns_200(self, rw_client):
        resp = rw_client.get("/governance-learning/cgin/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert "tenant_fingerprint" in data
        assert _TENANT not in str(data)

    def test_GL_111_ingest_outcome_returns_201(self, rw_client):
        resp = rw_client.post(
            "/governance-learning/ingest-outcome", json=self._ingest_body()
        )
        assert resp.status_code == 201

    def test_GL_112_ingest_outcome_requires_write_scope(self, ro_client):
        resp = ro_client.post(
            "/governance-learning/ingest-outcome", json=self._ingest_body()
        )
        assert resp.status_code in (401, 403)

    def test_GL_113_recalculate_returns_200(self, rw_client):
        resp = rw_client.post("/governance-learning/recalculate", json={})
        assert resp.status_code == 200

    def test_GL_114_recalculate_requires_write_scope(self, ro_client):
        resp = ro_client.post("/governance-learning/recalculate", json={})
        assert resp.status_code in (401, 403)

    def test_GL_115_tenant_isolation_ingest(self, rw_client, rw_client_b):
        rw_client.post("/governance-learning/ingest-outcome", json=self._ingest_body())
        resp_b = rw_client_b.get("/governance-learning/learning-records")
        data_b = resp_b.json()
        assert data_b["total"] == 0

    def test_GL_116_tenant_isolation_aggregates(self, rw_client, rw_client_b):
        rw_client.post("/governance-learning/ingest-outcome", json=self._ingest_body())
        resp_b = rw_client_b.get("/governance-learning/aggregates")
        data_b = resp_b.json()
        assert data_b["total"] == 0

    def test_GL_117_body_spoof_tenant_rejected(self, build_app):
        """tenant_id from body must NOT be accepted."""
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
        client = TestClient(app, headers={"X-API-Key": key})
        body = self._ingest_body()
        body["tenant_id"] = "spoofed-tenant"
        # Extra fields are rejected due to extra="forbid"
        resp = client.post("/governance-learning/ingest-outcome", json=body)
        assert resp.status_code == 422

    def test_GL_118_ingest_idempotent_via_api(self, rw_client):
        body = self._ingest_body()
        r1 = rw_client.post("/governance-learning/ingest-outcome", json=body)
        r2 = rw_client.post("/governance-learning/ingest-outcome", json=body)
        assert r1.status_code == 201
        assert r2.status_code == 201
        assert r1.json()["id"] == r2.json()["id"]

    def test_GL_119_learning_records_pagination(self, rw_client):
        for _ in range(3):
            rw_client.post(
                "/governance-learning/ingest-outcome", json=self._ingest_body()
            )
        resp = rw_client.get("/governance-learning/learning-records?limit=2&offset=0")
        data = resp.json()
        assert len(data["records"]) <= 2

    def test_GL_120_dashboard_top_performing_category_set(self, rw_client):
        rw_client.post("/governance-learning/ingest-outcome", json=self._ingest_body())
        resp = rw_client.get("/governance-learning/dashboard")
        data = resp.json()
        assert data["top_performing_category"] is not None

    def test_GL_121_momentum_endpoint_valid_classes(self, rw_client):
        resp = rw_client.get("/governance-learning/momentum")
        data = resp.json()
        assert data["momentum_class"] in [mc.value for mc in MomentumClass]
        assert data["stability_class"] in [sc.value for sc in StabilityClass]

    def test_GL_122_cgin_snapshot_no_tenant_id_field(self, rw_client):
        resp = rw_client.get("/governance-learning/cgin/snapshot")
        data = resp.json()
        assert "tenant_id" not in data

    def test_GL_123_recommendations_no_data_fallback(self, rw_client):
        resp = rw_client.get("/governance-learning/recommendations")
        data = resp.json()
        assert data["total"] >= 1
        assert data["recommendations"][0]["recommendation_confidence"] == "UNKNOWN"

    def test_GL_124_ingest_missing_required_field(self, rw_client):
        body = self._ingest_body()
        del body["source_outcome_id"]
        resp = rw_client.post("/governance-learning/ingest-outcome", json=body)
        assert resp.status_code == 422

    def test_GL_125_top_performers_limit_param(self, rw_client):
        for _ in range(3):
            body = self._ingest_body()
            body["remediation_category"] = "VERIFICATION"
            rw_client.post("/governance-learning/ingest-outcome", json=body)
        resp = rw_client.get("/governance-learning/top-performers?limit=1")
        data = resp.json()
        assert data["total"] <= 1

    def test_GL_126_top_failures_limit_param(self, rw_client):
        resp = rw_client.get("/governance-learning/top-failures?limit=2")
        assert resp.status_code == 200

    def test_GL_127_aggregates_pagination(self, rw_client):
        resp = rw_client.get("/governance-learning/aggregates?limit=10&offset=0")
        assert resp.status_code == 200

    def test_GL_128_recalculate_with_control_id(self, rw_client):
        rw_client.post("/governance-learning/ingest-outcome", json=self._ingest_body())
        resp = rw_client.post(
            "/governance-learning/recalculate", json={"control_id": "ctrl-001"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["control_id_filter"] == "ctrl-001"

    def test_GL_129_cgin_snapshot_has_bundle_version(self, rw_client):
        resp = rw_client.get("/governance-learning/cgin/snapshot")
        data = resp.json()
        assert data["bundle_version"] == "1.0"

    def test_GL_130_learning_records_control_id_filter(self, rw_client):
        body = self._ingest_body()
        body["control_id"] = "ctrl-xyz"
        rw_client.post("/governance-learning/ingest-outcome", json=body)
        resp = rw_client.get(
            "/governance-learning/learning-records?control_id=ctrl-xyz"
        )
        data = resp.json()
        assert data["total"] >= 1


# ===========================================================================
# GL-131 to GL-145: Authority integration
# ===========================================================================


class TestAuthorityIntegration:
    def test_GL_131_success_rate_computation_correct(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            # 2 success / 3 total = 0.667
            assert abs(agg.success_rate - 2.0 / 3.0) < 0.01

    def test_GL_132_failure_rate_computation_correct(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert abs(agg.failure_rate - 2.0 / 3.0) < 0.01

    def test_GL_133_partial_success_counted_in_aggregate(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="PARTIAL_SUCCESS"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert agg.partial_success_count == 1

    def test_GL_134_signals_detected_from_high_success_rate(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(5):
                engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert LearningSignal.HIGH_SUCCESS_RATE.value in agg.signals

    def test_GL_135_high_failure_signal_detected(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(3):
                engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert LearningSignal.HIGH_FAILURE_RATE.value in agg.signals

    def test_GL_136_repeated_failure_signal_detected(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(4):
                engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert LearningSignal.REPEATED_FAILURE.value in agg.signals

    def test_GL_137_recommendation_escalate_or_review_generated(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(4):
                engine.ingest_outcome(
                    _ingest_req(
                        outcome_classification="FAILURE",
                        remediation_category="FRESHNESS",
                    )
                )
            result = engine.get_recommendations()
            actions = [r.recommended_next_action for r in result.recommendations]
            assert "ESCALATE_OR_REVIEW" in actions

    def test_GL_138_cgin_fingerprint_deterministic(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        import hashlib

        expected = hashlib.sha256(f"cgin:v1:{tenant}".encode()).hexdigest()[:32]
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            snap = engine.get_cgin_snapshot()
            assert snap.tenant_fingerprint == expected

    def test_GL_139_aggregate_avg_health_delta_computed(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(
                IngestOutcomeRequest(
                    source_outcome_id=_uid(),
                    control_id="ctrl-1",
                    outcome_classification="SUCCESS",
                    score_delta=10.0,
                    remediation_category="VERIFICATION",
                    health_before=60.0,
                    health_after=70.0,
                )
            )
            engine.ingest_outcome(
                IngestOutcomeRequest(
                    source_outcome_id=_uid(),
                    control_id="ctrl-1",
                    outcome_classification="SUCCESS",
                    score_delta=10.0,
                    remediation_category="VERIFICATION",
                    health_before=70.0,
                    health_after=80.0,
                )
            )
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert agg.average_health_delta == pytest.approx(10.0, abs=0.1)

    def test_GL_140_total_count_in_aggregate_response(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            result = engine.list_aggregates()
            agg = result.aggregates[0]
            assert agg.total_count == 2

    def test_GL_141_multiple_categories_separate_aggregates(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            engine.ingest_outcome(_ingest_req(remediation_category="FRESHNESS"))
            engine.ingest_outcome(_ingest_req(remediation_category="FORECAST"))
            result = engine.list_aggregates()
            assert result.total == 3

    def test_GL_142_recalculate_all_categories(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(remediation_category="VERIFICATION"))
            engine.ingest_outcome(_ingest_req(remediation_category="FRESHNESS"))
            result = engine.recalculate(RecalculateRequest())
            assert result["categories_recalculated"] == 2

    def test_GL_143_dashboard_overall_success_rate_correct(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            engine.ingest_outcome(_ingest_req(outcome_classification="FAILURE"))
            dash = engine.get_dashboard()
            assert abs(dash.overall_success_rate - 2.0 / 3.0) < 0.01

    def test_GL_144_dashboard_active_signals_list(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(5):
                engine.ingest_outcome(_ingest_req(outcome_classification="SUCCESS"))
            dash = engine.get_dashboard()
            assert isinstance(dash.active_signals, list)
            assert LearningSignal.HIGH_SUCCESS_RATE.value in dash.active_signals

    def test_GL_145_momentum_from_positive_outcomes(self, build_app):
        build_app(auth_enabled=False)
        tenant = _tid()
        with Session(get_engine()) as db:
            engine = GovernanceLearningEngine(db, tenant)
            for _ in range(3):
                engine.ingest_outcome(
                    IngestOutcomeRequest(
                        source_outcome_id=_uid(),
                        control_id="ctrl-1",
                        outcome_classification="SUCCESS",
                        score_delta=20.0,
                        remediation_category="VERIFICATION",
                        health_before=50.0,
                        health_after=65.0,
                        effectiveness_before=40.0,
                        effectiveness_after=55.0,
                    )
                )
            m = engine.get_momentum()
            assert m.momentum_class in [
                MomentumClass.ACCELERATING.value,
                MomentumClass.STABLE.value,
            ]
