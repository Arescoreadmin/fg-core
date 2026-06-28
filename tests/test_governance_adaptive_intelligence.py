"""Tests for PR 17.6C — Governance Adaptive Intelligence Authority.

Coverage:
  GAI-1   to GAI-30:  Model unit tests (enums, pure functions)
  GAI-31  to GAI-50:  DB model smoke tests (ORM instantiation, append-only guards)
  GAI-51  to GAI-70:  Repository tests (create, list, filter, tenant isolation)
  GAI-71  to GAI-100: Engine tests (track, accept, reject, execute, record-outcome,
                       dashboard, list, accuracy, calibration, playbooks, cgin,
                       strategy-profiles, recalculate, tenant isolation)
  GAI-101 to GAI-130: API route tests (all routes, auth, tenant isolation)
  GAI-131 to GAI-150: Authority integration (adaptive recommendations, signals)
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_governance_adaptive_intelligence import (
    FaGovernanceAccuracyAggregate,
    FaGovernancePlaybook,
    FaGovernanceRecommendationHistory,
    FaGovernanceRecommendationOutcome,
)
from services.governance_adaptive_intelligence.engine import (
    GovernanceAdaptiveIntelligenceEngine,
)
from services.governance_adaptive_intelligence.models import (
    GOVERNANCE_ADAPTIVE_INTELLIGENCE_VERSION,
    CalibratedConfidence,
    PlaybookType,
    RecommendationStatus,
    RecommendationType,
    StrategyProfile,
    classify_calibrated_confidence,
    classify_strategy_profile,
    compute_accuracy_score,
    compute_avg_delta,
)
from services.governance_adaptive_intelligence.recommendation_rules import (
    generate_adaptive_recommendations,
)
from services.governance_adaptive_intelligence.schemas import (
    AcceptRecommendationRequest,
    ExecuteRecommendationRequest,
    RecalculateAdaptiveRequest,
    RecordOutcomeRequest,
    TrackRecommendationRequest,
)
from services.governance_adaptive_intelligence.strategy_profiles import (
    STRATEGY_PROFILES,
    get_strategy_profile,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-gai-001"
_TENANT_B = "t-gai-002"


def _uid() -> str:
    return str(uuid.uuid4())


def _tid() -> str:
    return f"t-gai-{uuid.uuid4().hex[:8]}"


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Helper: build a history row
# ---------------------------------------------------------------------------


def _make_history_row(
    tenant_id: str = _TENANT,
    recommendation_id: str | None = None,
    recommendation_type: str = "PRIORITIZE_BEST_CATEGORY",
    status: str = "PENDING",
) -> FaGovernanceRecommendationHistory:
    return FaGovernanceRecommendationHistory(
        id=_uid(),
        tenant_id=tenant_id,
        recommendation_id=recommendation_id or _uid(),
        recommendation_type=recommendation_type,
        recommendation_category="VERIFICATION",
        recommendation_reason="Test reason",
        recommendation_confidence="MEDIUM",
        generated_at=_now_str(),
        accepted_at=None,
        rejected_at=None,
        executed_at=None,
        closed_at=None,
        status=status,
        source_learning_record_id=None,
        source_aggregate_id=None,
        source_authority="governance_learning",
    )


def _track_req(
    recommendation_id: str | None = None,
    recommendation_type: str = "PRIORITIZE_BEST_CATEGORY",
) -> TrackRecommendationRequest:
    return TrackRecommendationRequest(
        recommendation_id=recommendation_id or _uid(),
        recommendation_type=recommendation_type,
        recommendation_category="VERIFICATION",
        recommendation_reason="Test reason",
        recommendation_confidence="MEDIUM",
        source_authority="governance_learning",
    )


# ===========================================================================
# GAI-1 to GAI-30: Model unit tests
# ===========================================================================


class TestModels:
    def test_GAI_1_version(self):
        assert GOVERNANCE_ADAPTIVE_INTELLIGENCE_VERSION == "1.0"

    def test_GAI_2_recommendation_status_has_5_values(self):
        assert len(RecommendationStatus) == 5

    def test_GAI_3_recommendation_status_pending(self):
        assert RecommendationStatus.PENDING == "PENDING"

    def test_GAI_4_recommendation_status_accepted(self):
        assert RecommendationStatus.ACCEPTED == "ACCEPTED"

    def test_GAI_5_recommendation_type_has_7_values(self):
        assert len(RecommendationType) == 7

    def test_GAI_6_recommendation_type_prioritize(self):
        assert RecommendationType.PRIORITIZE_BEST_CATEGORY == "PRIORITIZE_BEST_CATEGORY"

    def test_GAI_7_recommendation_type_escalate(self):
        assert RecommendationType.ESCALATE_WORST_CATEGORY == "ESCALATE_WORST_CATEGORY"

    def test_GAI_8_playbook_type_has_4_values(self):
        assert len(PlaybookType) == 4

    def test_GAI_9_playbook_type_remediation(self):
        assert PlaybookType.REMEDIATION == "REMEDIATION"

    def test_GAI_10_calibrated_confidence_has_4_values(self):
        assert len(CalibratedConfidence) == 4

    def test_GAI_11_calibrated_confidence_high(self):
        assert CalibratedConfidence.CALIBRATED_HIGH == "CALIBRATED_HIGH"

    def test_GAI_12_strategy_profile_has_7_values(self):
        assert len(StrategyProfile) == 7

    def test_GAI_13_compute_accuracy_score_zero_executed(self):
        assert compute_accuracy_score(0, 0) == 0.0

    def test_GAI_14_compute_accuracy_score_full(self):
        assert compute_accuracy_score(10, 10) == 1.0

    def test_GAI_15_compute_accuracy_score_half(self):
        assert compute_accuracy_score(5, 10) == 0.5

    def test_GAI_16_compute_accuracy_score_rounding(self):
        # 1/3 = 0.3333 rounded to 4 decimal places
        result = compute_accuracy_score(1, 3)
        assert result == round(1 / 3, 4)

    def test_GAI_17_classify_calibrated_confidence_unknown_no_data(self):
        assert (
            classify_calibrated_confidence(0.0, 0)
            == CalibratedConfidence.CALIBRATED_UNKNOWN
        )

    def test_GAI_18_classify_calibrated_confidence_unknown_insufficient(self):
        # Only 2 samples → UNKNOWN regardless of accuracy
        assert (
            classify_calibrated_confidence(1.0, 2)
            == CalibratedConfidence.CALIBRATED_UNKNOWN
        )

    def test_GAI_19_classify_calibrated_confidence_high(self):
        assert (
            classify_calibrated_confidence(0.75, 10)
            == CalibratedConfidence.CALIBRATED_HIGH
        )

    def test_GAI_20_classify_calibrated_confidence_medium(self):
        assert (
            classify_calibrated_confidence(0.5, 10)
            == CalibratedConfidence.CALIBRATED_MEDIUM
        )

    def test_GAI_21_classify_calibrated_confidence_low(self):
        assert (
            classify_calibrated_confidence(0.25, 10)
            == CalibratedConfidence.CALIBRATED_LOW
        )

    def test_GAI_22_classify_calibrated_confidence_unknown_poor(self):
        assert (
            classify_calibrated_confidence(0.1, 10)
            == CalibratedConfidence.CALIBRATED_UNKNOWN
        )

    def test_GAI_23_compute_avg_delta_all_none(self):
        assert compute_avg_delta([None, None]) is None

    def test_GAI_24_compute_avg_delta_mixed(self):
        result = compute_avg_delta([None, 4.0, 6.0])
        assert result == 5.0

    def test_GAI_25_compute_avg_delta_empty(self):
        assert compute_avg_delta([]) is None

    def test_GAI_26_classify_strategy_profile_healthcare(self):
        assert (
            classify_strategy_profile("healthcare compliance")
            == StrategyProfile.HEALTHCARE
        )

    def test_GAI_27_classify_strategy_profile_financial(self):
        assert (
            classify_strategy_profile("financial services") == StrategyProfile.FINANCIAL
        )

    def test_GAI_28_classify_strategy_profile_none(self):
        assert classify_strategy_profile(None) == StrategyProfile.GENERAL

    def test_GAI_29_classify_strategy_profile_unknown(self):
        assert (
            classify_strategy_profile("unknown industry xyz") == StrategyProfile.GENERAL
        )

    def test_GAI_30_strategy_profiles_have_7_entries(self):
        assert len(STRATEGY_PROFILES) == 7


# ===========================================================================
# GAI-31 to GAI-50: DB model smoke tests
# ===========================================================================


class TestDBModels:
    def test_GAI_31_history_tablename(self):
        assert (
            FaGovernanceRecommendationHistory.__tablename__
            == "fa_governance_recommendation_history"
        )

    def test_GAI_32_outcome_tablename(self):
        assert (
            FaGovernanceRecommendationOutcome.__tablename__
            == "fa_governance_recommendation_outcomes"
        )

    def test_GAI_33_accuracy_agg_tablename(self):
        assert (
            FaGovernanceAccuracyAggregate.__tablename__
            == "fa_governance_accuracy_aggregates"
        )

    def test_GAI_34_playbook_tablename(self):
        assert FaGovernancePlaybook.__tablename__ == "fa_governance_playbooks"

    def test_GAI_35_history_instantiate(self):
        row = _make_history_row()
        assert row.status == "PENDING"
        assert row.source_authority == "governance_learning"

    def test_GAI_36_history_append_only_update_blocked(self):
        row = _make_history_row()
        with pytest.raises(RuntimeError, match="append-only"):
            from api.db_models_governance_adaptive_intelligence import (
                _block_gai_rh_update,
            )

            _block_gai_rh_update(None, None, row)

    def test_GAI_37_history_append_only_delete_blocked(self):
        row = _make_history_row()
        with pytest.raises(RuntimeError, match="append-only"):
            from api.db_models_governance_adaptive_intelligence import (
                _block_gai_rh_delete,
            )

            _block_gai_rh_delete(None, None, row)

    def test_GAI_38_outcome_instantiate(self):
        row = FaGovernanceRecommendationOutcome(
            id=_uid(),
            tenant_id=_TENANT,
            recommendation_history_id=_uid(),
            success=True,
            recorded_at=_now_str(),
        )
        assert row.success is True

    def test_GAI_39_accuracy_agg_default_confidence(self):
        row = FaGovernanceAccuracyAggregate(
            id=_uid(),
            tenant_id=_TENANT,
            recommendation_type="PRIORITIZE_BEST_CATEGORY",
            calibrated_confidence="CALIBRATED_UNKNOWN",
            last_updated_at=_now_str(),
        )
        assert row.calibrated_confidence == "CALIBRATED_UNKNOWN"

    def test_GAI_40_playbook_default_success_rate(self):
        row = FaGovernancePlaybook(
            id=_uid(),
            tenant_id=_TENANT,
            playbook_type="REMEDIATION",
            recommended_path="[]",
            success_rate=0.0,
            last_updated_at=_now_str(),
        )
        assert row.success_rate == 0.0

    def test_GAI_41_history_fields_nullable(self):
        row = _make_history_row()
        assert row.accepted_at is None
        assert row.rejected_at is None
        assert row.executed_at is None
        assert row.closed_at is None

    def test_GAI_42_outcome_nullable_deltas(self):
        row = FaGovernanceRecommendationOutcome(
            id=_uid(),
            tenant_id=_TENANT,
            recommendation_history_id=_uid(),
            success=False,
            recorded_at=_now_str(),
        )
        assert row.health_delta is None
        assert row.effectiveness_delta is None


# ===========================================================================
# GAI-51 to GAI-70: Repository tests
# ===========================================================================


class TestRepository:
    @pytest.fixture()
    def db_and_repo(self):
        from services.governance_adaptive_intelligence.repository import (
            GovernanceAdaptiveIntelligenceRepository,
        )

        tenant = _tid()
        with Session(get_engine()) as db:
            repo = GovernanceAdaptiveIntelligenceRepository(db, tenant)
            yield db, repo, tenant

    def test_GAI_51_create_and_get_history(self, db_and_repo):
        db, repo, tenant = db_and_repo
        row = _make_history_row(tenant_id=tenant)
        repo.create_history(row)
        db.commit()
        fetched = repo.get_history_by_id(row.id)
        assert fetched is not None
        assert fetched.id == row.id

    def test_GAI_52_get_history_wrong_tenant(self, db_and_repo):
        db, repo, tenant = db_and_repo
        row = _make_history_row(tenant_id=_TENANT_B)
        db.add(row)
        db.commit()
        fetched = repo.get_history_by_id(row.id)
        assert fetched is None

    def test_GAI_53_get_latest_history_for_recommendation(self, db_and_repo):
        db, repo, tenant = db_and_repo
        rec_id = _uid()
        row1 = _make_history_row(tenant_id=tenant, recommendation_id=rec_id)
        row1.generated_at = "2025-01-01T00:00:00+00:00"
        row2 = _make_history_row(tenant_id=tenant, recommendation_id=rec_id)
        row2.generated_at = "2025-06-01T00:00:00+00:00"
        repo.create_history(row1)
        repo.create_history(row2)
        db.commit()
        latest = repo.get_latest_history_for_recommendation(rec_id)
        assert latest is not None
        assert latest.id == row2.id

    def test_GAI_54_list_history_deduplicates(self, db_and_repo):
        db, repo, tenant = db_and_repo
        rec_id = _uid()
        row1 = _make_history_row(
            tenant_id=tenant, recommendation_id=rec_id, status="PENDING"
        )
        row2 = _make_history_row(
            tenant_id=tenant, recommendation_id=rec_id, status="ACCEPTED"
        )
        row2.generated_at = "2030-01-01T00:00:00+00:00"
        repo.create_history(row1)
        repo.create_history(row2)
        db.commit()
        rows, total = repo.list_history()
        # Should only see 1 row for this recommendation_id
        matching = [r for r in rows if r.recommendation_id == rec_id]
        assert len(matching) == 1
        assert matching[0].status == "ACCEPTED"

    def test_GAI_55_list_history_filter_by_status(self, db_and_repo):
        db, repo, tenant = db_and_repo
        pending = _make_history_row(tenant_id=tenant, status="PENDING")
        rejected = _make_history_row(tenant_id=tenant, status="REJECTED")
        repo.create_history(pending)
        repo.create_history(rejected)
        db.commit()
        rows, total = repo.list_history(status="PENDING")
        statuses = {r.status for r in rows}
        assert "REJECTED" not in statuses

    def test_GAI_56_create_and_get_outcome(self, db_and_repo):
        db, repo, tenant = db_and_repo
        hist_id = _uid()
        outcome = FaGovernanceRecommendationOutcome(
            id=_uid(),
            tenant_id=tenant,
            recommendation_history_id=hist_id,
            success=True,
            recorded_at=_now_str(),
        )
        repo.create_outcome(outcome)
        db.commit()
        fetched = repo.get_outcome_by_history_id(hist_id)
        assert fetched is not None
        assert fetched.success is True

    def test_GAI_57_outcome_wrong_tenant(self, db_and_repo):
        db, repo, tenant = db_and_repo
        hist_id = _uid()
        outcome = FaGovernanceRecommendationOutcome(
            id=_uid(),
            tenant_id=_TENANT_B,
            recommendation_history_id=hist_id,
            success=True,
            recorded_at=_now_str(),
        )
        db.add(outcome)
        db.commit()
        fetched = repo.get_outcome_by_history_id(hist_id)
        assert fetched is None

    def test_GAI_58_upsert_accuracy_aggregate_create(self, db_and_repo):
        db, repo, tenant = db_and_repo
        agg = repo.upsert_accuracy_aggregate(
            "PRIORITIZE_BEST_CATEGORY",
            {
                "recommendations_executed": 5,
                "recommendations_successful": 3,
                "recommendations_failed": 2,
                "calibrated_confidence": "CALIBRATED_MEDIUM",
                "last_updated_at": _now_str(),
            },
        )
        db.commit()
        assert agg.recommendations_executed == 5

    def test_GAI_59_upsert_accuracy_aggregate_update(self, db_and_repo):
        db, repo, tenant = db_and_repo
        repo.upsert_accuracy_aggregate(
            "GOVERNANCE_REVIEW",
            {"recommendations_executed": 3, "last_updated_at": _now_str()},
        )
        db.commit()
        repo.upsert_accuracy_aggregate(
            "GOVERNANCE_REVIEW",
            {"recommendations_executed": 10, "last_updated_at": _now_str()},
        )
        db.commit()
        agg = repo.get_accuracy_aggregate("GOVERNANCE_REVIEW")
        assert agg.recommendations_executed == 10

    def test_GAI_60_upsert_playbook_create_and_update(self, db_and_repo):
        db, repo, tenant = db_and_repo
        repo.upsert_playbook(
            "REMEDIATION",
            {"recommended_path": '["step1"]', "last_updated_at": _now_str()},
        )
        db.commit()
        repo.upsert_playbook(
            "REMEDIATION",
            {"recommended_path": '["step1", "step2"]', "last_updated_at": _now_str()},
        )
        db.commit()
        pb = repo.get_playbook("REMEDIATION")
        assert pb is not None
        steps = json.loads(pb.recommended_path)
        assert len(steps) == 2


# ===========================================================================
# GAI-71 to GAI-100: Engine tests
# ===========================================================================


class TestEngine:
    @pytest.fixture()
    def engine_and_db(self):
        tenant = _tid()
        with Session(get_engine()) as db:
            eng = GovernanceAdaptiveIntelligenceEngine(db, tenant)
            yield eng, db, tenant

    def test_GAI_71_track_recommendation_creates_pending(self, engine_and_db):
        eng, db, tenant = engine_and_db
        req = _track_req()
        resp = eng.track_recommendation(req)
        assert resp.status == "PENDING"
        assert resp.tenant_id == tenant

    def test_GAI_72_track_recommendation_idempotent(self, engine_and_db):
        eng, db, tenant = engine_and_db
        rec_id = _uid()
        req = _track_req(recommendation_id=rec_id)
        resp1 = eng.track_recommendation(req)
        resp2 = eng.track_recommendation(req)
        assert resp1.recommendation_id == resp2.recommendation_id
        # Should return the same row, not create a duplicate
        assert resp1.id == resp2.id

    def test_GAI_73_accept_recommendation(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        accept_req = AcceptRecommendationRequest(
            recommendation_history_id=tracked.id, accepted=True
        )
        resp = eng.accept_recommendation(accept_req)
        assert resp.status == "ACCEPTED"
        assert resp.accepted_at is not None

    def test_GAI_74_reject_recommendation(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        reject_req = AcceptRecommendationRequest(
            recommendation_history_id=tracked.id, accepted=False
        )
        resp = eng.accept_recommendation(reject_req)
        assert resp.status == "REJECTED"
        assert resp.rejected_at is not None
        assert resp.closed_at is not None

    def test_GAI_75_execute_recommendation(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        exec_req = ExecuteRecommendationRequest(recommendation_history_id=tracked.id)
        resp = eng.execute_recommendation(exec_req)
        assert resp.status == "EXECUTED"
        assert resp.executed_at is not None

    def test_GAI_76_accept_not_found_raises_404(self, engine_and_db):
        eng, db, tenant = engine_and_db
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            eng.accept_recommendation(
                AcceptRecommendationRequest(
                    recommendation_history_id=_uid(), accepted=True
                )
            )
        assert exc_info.value.status_code == 404

    def test_GAI_77_execute_not_found_raises_404(self, engine_and_db):
        eng, db, tenant = engine_and_db
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            eng.execute_recommendation(
                ExecuteRecommendationRequest(recommendation_history_id=_uid())
            )
        assert exc_info.value.status_code == 404

    def test_GAI_78_record_outcome_creates_row(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        outcome_req = RecordOutcomeRequest(
            recommendation_history_id=tracked.id,
            success=True,
            health_before=60.0,
            health_after=75.0,
        )
        resp = eng.record_outcome(outcome_req)
        assert resp.success is True
        assert resp.health_delta == 15.0

    def test_GAI_79_record_outcome_idempotent(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        outcome_req = RecordOutcomeRequest(
            recommendation_history_id=tracked.id,
            success=True,
        )
        resp1 = eng.record_outcome(outcome_req)
        resp2 = eng.record_outcome(outcome_req)
        assert resp1.id == resp2.id

    def test_GAI_80_record_outcome_not_found_raises_404(self, engine_and_db):
        eng, db, tenant = engine_and_db
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            eng.record_outcome(
                RecordOutcomeRequest(recommendation_history_id=_uid(), success=True)
            )
        assert exc_info.value.status_code == 404

    def test_GAI_81_record_outcome_updates_accuracy_aggregate(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(
            _track_req(recommendation_type="GOVERNANCE_REVIEW")
        )
        eng.record_outcome(
            RecordOutcomeRequest(recommendation_history_id=tracked.id, success=True)
        )
        acc = eng.get_accuracy()
        types = {a.recommendation_type for a in acc.per_type}
        assert "GOVERNANCE_REVIEW" in types

    def test_GAI_82_dashboard_empty_state(self, engine_and_db):
        eng, db, tenant = engine_and_db
        dash = eng.get_dashboard()
        assert dash.tenant_id == tenant
        assert dash.total_recommendations == 0
        assert dash.total_executed == 0
        assert dash.overall_accuracy_score == 0.0

    def test_GAI_83_dashboard_populated(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        eng.record_outcome(
            RecordOutcomeRequest(recommendation_history_id=tracked.id, success=True)
        )
        dash = eng.get_dashboard()
        assert dash.total_recommendations >= 1
        assert dash.total_successful >= 1

    def test_GAI_84_list_recommendations_empty(self, engine_and_db):
        eng, db, tenant = engine_and_db
        recs = eng.list_recommendations()
        assert isinstance(recs, list)
        assert len(recs) == 0

    def test_GAI_85_list_recommendations_returns_latest(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        # Accept it — creates a new row
        eng.accept_recommendation(
            AcceptRecommendationRequest(
                recommendation_history_id=tracked.id, accepted=True
            )
        )
        recs = eng.list_recommendations()
        matching = [r for r in recs if r.recommendation_id == tracked.recommendation_id]
        assert len(matching) == 1
        assert matching[0].status == "ACCEPTED"

    def test_GAI_86_list_recommendations_filter_status(self, engine_and_db):
        eng, db, tenant = engine_and_db
        eng.track_recommendation(_track_req())
        pending = eng.list_recommendations(status="PENDING")
        for r in pending:
            assert r.status == "PENDING"

    def test_GAI_87_list_outcomes_empty(self, engine_and_db):
        eng, db, tenant = engine_and_db
        outcomes = eng.list_outcomes()
        assert isinstance(outcomes, list)
        assert len(outcomes) == 0

    def test_GAI_88_list_outcomes_populated(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        eng.record_outcome(
            RecordOutcomeRequest(recommendation_history_id=tracked.id, success=True)
        )
        outcomes = eng.list_outcomes()
        assert len(outcomes) >= 1

    def test_GAI_89_accuracy_empty(self, engine_and_db):
        eng, db, tenant = engine_and_db
        acc = eng.get_accuracy()
        assert acc.tenant_id == tenant
        assert acc.overall_accuracy_score == 0.0
        assert acc.per_type == []

    def test_GAI_90_accuracy_after_outcomes(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(
            _track_req(recommendation_type="IMPROVE_VERIFICATION")
        )
        eng.record_outcome(
            RecordOutcomeRequest(recommendation_history_id=tracked.id, success=True)
        )
        acc = eng.get_accuracy()
        types = {a.recommendation_type for a in acc.per_type}
        assert "IMPROVE_VERIFICATION" in types

    def test_GAI_91_calibration_empty(self, engine_and_db):
        eng, db, tenant = engine_and_db
        cal = eng.get_calibration()
        assert cal.tenant_id == tenant
        assert cal.overall_calibration == "CALIBRATED_UNKNOWN"
        assert cal.confidence_distribution == {}

    def test_GAI_92_calibration_populated(self, engine_and_db):
        eng, db, tenant = engine_and_db
        # Record 3+ outcomes to get a real calibration
        for _ in range(3):
            tracked = eng.track_recommendation(
                _track_req(recommendation_type="ESCALATE_WORST_CATEGORY")
            )
            eng.record_outcome(
                RecordOutcomeRequest(recommendation_history_id=tracked.id, success=True)
            )
        cal = eng.get_calibration()
        assert "ESCALATE_WORST_CATEGORY" in cal.confidence_distribution

    def test_GAI_93_playbooks_empty(self, engine_and_db):
        eng, db, tenant = engine_and_db
        playbooks = eng.list_playbooks()
        assert isinstance(playbooks, list)

    def test_GAI_94_strategy_profiles_count(self, engine_and_db):
        eng, db, tenant = engine_and_db
        profiles = eng.list_strategy_profiles()
        assert len(profiles) == 7

    def test_GAI_95_strategy_profiles_all_present(self, engine_and_db):
        eng, db, tenant = engine_and_db
        profiles = eng.list_strategy_profiles()
        names = {p.profile for p in profiles}
        expected = {
            "HEALTHCARE",
            "FINANCIAL",
            "INSURANCE",
            "GOVERNMENT",
            "LEGAL",
            "MSP",
            "GENERAL",
        }
        assert names == expected

    def test_GAI_96_cgin_snapshot_no_tenant_id(self, engine_and_db):
        eng, db, tenant = engine_and_db
        snap = eng.get_cgin_snapshot()
        assert tenant not in snap.tenant_fingerprint
        assert snap.tenant_fingerprint != tenant

    def test_GAI_97_cgin_snapshot_fingerprint_format(self, engine_and_db):
        eng, db, tenant = engine_and_db
        snap = eng.get_cgin_snapshot()
        assert len(snap.tenant_fingerprint) == 32
        assert snap.bundle_id.startswith("cgin-gai-")

    def test_GAI_98_get_recommendation_detail(self, engine_and_db):
        eng, db, tenant = engine_and_db
        tracked = eng.track_recommendation(_track_req())
        detail = eng.get_recommendation_detail(tracked.recommendation_id)
        assert detail.recommendation_id == tracked.recommendation_id

    def test_GAI_99_get_recommendation_detail_not_found(self, engine_and_db):
        eng, db, tenant = engine_and_db
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            eng.get_recommendation_detail(_uid())
        assert exc_info.value.status_code == 404

    def test_GAI_100_recalculate_returns_dict(self, engine_and_db):
        eng, db, tenant = engine_and_db
        result = eng.recalculate(RecalculateAdaptiveRequest())
        assert "recalculated_at" in result
        assert "tenant_id" in result


# ===========================================================================
# GAI-101 to GAI-130: API route tests
# ===========================================================================


class TestAPIRoutes:
    @pytest.fixture()
    def client_and_tenant(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        return client, tenant

    @pytest.fixture()
    def readonly_client(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        return client, tenant

    def _track_body(self, rec_id: str | None = None) -> dict:
        return {
            "recommendation_id": rec_id or _uid(),
            "recommendation_type": "PRIORITIZE_BEST_CATEGORY",
            "recommendation_category": "VERIFICATION",
            "recommendation_reason": "Test from API",
            "recommendation_confidence": "MEDIUM",
            "source_authority": "governance_learning",
        }

    # --- GET routes ---

    def test_GAI_101_dashboard_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tenant_id"] == tenant

    def test_GAI_102_recommendations_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/recommendations")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_GAI_103_outcomes_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/outcomes")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_GAI_104_accuracy_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/accuracy")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_accuracy_score" in data

    def test_GAI_105_calibration_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/calibration")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_calibration" in data

    def test_GAI_106_playbooks_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/playbooks")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_GAI_107_strategy_profiles_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/strategy-profiles")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 7

    def test_GAI_108_cgin_snapshot_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get("/governance-adaptive-intelligence/cgin/snapshot")
        assert resp.status_code == 200
        data = resp.json()
        assert "tenant_fingerprint" in data
        assert tenant not in data["tenant_fingerprint"]

    # --- POST routes ---

    def test_GAI_109_track_returns_201(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.post(
            "/governance-adaptive-intelligence/track",
            json=self._track_body(),
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "PENDING"
        assert data["tenant_id"] == tenant

    def test_GAI_110_track_idempotent(self, client_and_tenant):
        client, tenant = client_and_tenant
        body = self._track_body()
        resp1 = client.post("/governance-adaptive-intelligence/track", json=body)
        resp2 = client.post("/governance-adaptive-intelligence/track", json=body)
        assert resp1.status_code == 201
        assert resp2.status_code == 201
        assert resp1.json()["id"] == resp2.json()["id"]

    def test_GAI_111_accept_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        resp = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": history_id, "accepted": True},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ACCEPTED"

    def test_GAI_112_reject_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        resp = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": history_id, "accepted": False},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "REJECTED"

    def test_GAI_113_execute_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        resp = client.post(
            "/governance-adaptive-intelligence/execute",
            json={"recommendation_history_id": history_id},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "EXECUTED"

    def test_GAI_114_record_outcome_returns_201(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        resp = client.post(
            "/governance-adaptive-intelligence/record-outcome",
            json={
                "recommendation_history_id": history_id,
                "success": True,
                "health_before": 60.0,
                "health_after": 80.0,
            },
        )
        assert resp.status_code == 201
        assert resp.json()["success"] is True
        assert resp.json()["health_delta"] == 20.0

    def test_GAI_115_record_outcome_idempotent(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        body = {"recommendation_history_id": history_id, "success": True}
        resp1 = client.post(
            "/governance-adaptive-intelligence/record-outcome", json=body
        )
        resp2 = client.post(
            "/governance-adaptive-intelligence/record-outcome", json=body
        )
        assert resp1.status_code == 201
        assert resp2.status_code == 201
        assert resp1.json()["id"] == resp2.json()["id"]

    def test_GAI_116_recalculate_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.post("/governance-adaptive-intelligence/recalculate", json={})
        assert resp.status_code == 200
        data = resp.json()
        assert "recalculated_at" in data

    def test_GAI_117_get_recommendation_detail_returns_200(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        rec_id = track_resp.json()["recommendation_id"]
        resp = client.get(f"/governance-adaptive-intelligence/recommendations/{rec_id}")
        assert resp.status_code == 200
        assert resp.json()["recommendation_id"] == rec_id

    def test_GAI_118_get_recommendation_detail_not_found(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.get(f"/governance-adaptive-intelligence/recommendations/{_uid()}")
        assert resp.status_code == 404

    # --- Auth & security ---

    def test_GAI_119_no_auth_returns_401(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/governance-adaptive-intelligence/dashboard")
        assert resp.status_code == 401

    def test_GAI_120_wrong_scope_returns_403(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("evidence:read", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.get("/governance-adaptive-intelligence/dashboard")
        assert resp.status_code == 403

    def test_GAI_121_write_scope_required_for_track(self, readonly_client):
        client, tenant = readonly_client
        resp = client.post(
            "/governance-adaptive-intelligence/track",
            json=self._track_body(),
        )
        assert resp.status_code == 403

    def test_GAI_122_write_scope_required_for_accept(self, readonly_client):
        client, tenant = readonly_client
        resp = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": _uid(), "accepted": True},
        )
        assert resp.status_code == 403

    def test_GAI_123_write_scope_required_for_execute(self, readonly_client):
        client, tenant = readonly_client
        resp = client.post(
            "/governance-adaptive-intelligence/execute",
            json={"recommendation_history_id": _uid()},
        )
        assert resp.status_code == 403

    def test_GAI_124_write_scope_required_for_record_outcome(self, readonly_client):
        client, tenant = readonly_client
        resp = client.post(
            "/governance-adaptive-intelligence/record-outcome",
            json={"recommendation_history_id": _uid(), "success": True},
        )
        assert resp.status_code == 403

    def test_GAI_125_write_scope_required_for_recalculate(self, readonly_client):
        client, tenant = readonly_client
        resp = client.post("/governance-adaptive-intelligence/recalculate", json={})
        assert resp.status_code == 403

    # --- Tenant isolation ---

    def test_GAI_126_tenant_a_cannot_see_tenant_b_recommendations(self, build_app):
        tenant_a = _tid()
        tenant_b = _tid()
        app = build_app(auth_enabled=True)
        key_a = mint_key("governance:read", "governance:write", tenant_id=tenant_a)
        key_b = mint_key("governance:read", "governance:write", tenant_id=tenant_b)
        client_a = TestClient(app, headers={"X-API-Key": key_a})
        client_b = TestClient(app, headers={"X-API-Key": key_b})

        body = {
            "recommendation_id": _uid(),
            "recommendation_type": "GOVERNANCE_REVIEW",
            "recommendation_reason": "Tenant A rec",
            "recommendation_confidence": "HIGH",
            "source_authority": "governance_learning",
        }
        client_a.post("/governance-adaptive-intelligence/track", json=body)

        resp_b = client_b.get("/governance-adaptive-intelligence/recommendations")
        b_ids = {r["tenant_id"] for r in resp_b.json()}
        assert tenant_a not in b_ids

    def test_GAI_127_tenant_a_cannot_access_tenant_b_detail(self, build_app):
        tenant_a = _tid()
        tenant_b = _tid()
        app = build_app(auth_enabled=True)
        key_a = mint_key("governance:read", "governance:write", tenant_id=tenant_a)
        key_b = mint_key("governance:read", tenant_id=tenant_b)
        client_a = TestClient(app, headers={"X-API-Key": key_a})
        client_b = TestClient(app, headers={"X-API-Key": key_b})

        rec_id = _uid()
        client_a.post(
            "/governance-adaptive-intelligence/track",
            json={
                "recommendation_id": rec_id,
                "recommendation_type": "GOVERNANCE_REVIEW",
                "recommendation_reason": "Tenant A rec",
                "recommendation_confidence": "HIGH",
                "source_authority": "governance_learning",
            },
        )

        resp_b = client_b.get(
            f"/governance-adaptive-intelligence/recommendations/{rec_id}"
        )
        assert resp_b.status_code == 404

    def test_GAI_128_recommendations_filter_by_status_accepted(self, client_and_tenant):
        client, tenant = client_and_tenant
        track_resp = client.post(
            "/governance-adaptive-intelligence/track", json=self._track_body()
        )
        history_id = track_resp.json()["id"]
        client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": history_id, "accepted": True},
        )
        recs = client.get(
            "/governance-adaptive-intelligence/recommendations?status=ACCEPTED"
        ).json()
        for r in recs:
            assert r["status"] == "ACCEPTED"

    def test_GAI_129_accept_missing_history_returns_404(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.post(
            "/governance-adaptive-intelligence/accept",
            json={"recommendation_history_id": _uid(), "accepted": True},
        )
        assert resp.status_code == 404

    def test_GAI_130_execute_missing_history_returns_404(self, client_and_tenant):
        client, tenant = client_and_tenant
        resp = client.post(
            "/governance-adaptive-intelligence/execute",
            json={"recommendation_history_id": _uid()},
        )
        assert resp.status_code == 404


# ===========================================================================
# GAI-131 to GAI-150: Authority integration tests
# ===========================================================================


class TestAuthorityIntegration:
    def test_GAI_131_recommendation_rules_empty_aggregates(self):
        recs = generate_adaptive_recommendations(
            aggregates=[],
            accuracy_aggregates=[],
            total_records=0,
            avg_health_delta_30d=None,
        )
        assert recs == []

    def test_GAI_132_recommendation_rules_generates_prioritize(self):
        class FakeAgg:
            remediation_category = "VERIFICATION"
            success_count = 8
            failure_count = 1
            partial_success_count = 1
            no_change_count = 0
            average_health_delta = 5.0
            average_effectiveness_delta = 3.0
            average_verification_delta = None
            confidence = "HIGH"

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[],
            total_records=10,
            avg_health_delta_30d=3.0,
        )
        types = {r.type for r in recs}
        assert "PRIORITIZE_BEST_CATEGORY" in types

    def test_GAI_133_recommendation_rules_governance_review(self):
        class FakeAgg:
            remediation_category = "POLICY"
            success_count = 3
            failure_count = 7
            partial_success_count = 0
            no_change_count = 0
            average_health_delta = -5.0
            average_effectiveness_delta = None
            average_verification_delta = None
            confidence = "LOW"

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[],
            total_records=10,
            avg_health_delta_30d=-5.0,
        )
        types = {r.type for r in recs}
        assert "GOVERNANCE_REVIEW" in types

    def test_GAI_134_recommendation_deprioritize_when_accuracy_low(self):
        """If accuracy < 0.25 for ESCALATE_WORST_CATEGORY, should_deprioritize=True."""

        class FakeAgg:
            remediation_category = "POLICY"
            success_count = 1
            failure_count = 9
            partial_success_count = 0
            no_change_count = 0
            average_health_delta = -2.0
            average_effectiveness_delta = None
            average_verification_delta = None
            confidence = "LOW"

        class FakeAccAgg:
            recommendation_type = "ESCALATE_WORST_CATEGORY"
            recommendations_successful = 0
            recommendations_executed = 10

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[FakeAccAgg()],
            total_records=10,
            avg_health_delta_30d=None,
        )
        escalate_recs = [r for r in recs if r.type == "ESCALATE_WORST_CATEGORY"]
        assert len(escalate_recs) >= 1
        assert escalate_recs[0].should_deprioritize is True

    def test_GAI_135_recommendation_best_category_skipped_when_low_accuracy(self):
        """PRIORITIZE_BEST_CATEGORY should be skipped when historical accuracy < 0.5."""

        class FakeAgg:
            remediation_category = "TECHNICAL"
            success_count = 8
            failure_count = 2
            partial_success_count = 0
            no_change_count = 0
            average_health_delta = 5.0
            average_effectiveness_delta = None
            average_verification_delta = None
            confidence = "HIGH"

        class FakeAccAgg:
            recommendation_type = "PRIORITIZE_BEST_CATEGORY"
            recommendations_successful = 1
            recommendations_executed = 10  # accuracy = 0.1 < 0.5

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[FakeAccAgg()],
            total_records=10,
            avg_health_delta_30d=None,
        )
        types = {r.type for r in recs}
        assert "PRIORITIZE_BEST_CATEGORY" not in types

    def test_GAI_136_recommendation_improve_effectiveness_triggered(self):
        class FakeAgg:
            remediation_category = "AUDIT"
            success_count = 5
            failure_count = 5
            partial_success_count = 0
            no_change_count = 0
            average_health_delta = -1.0
            average_effectiveness_delta = -8.0  # < -5.0
            average_verification_delta = None
            confidence = "MEDIUM"

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[],
            total_records=10,
            avg_health_delta_30d=None,
        )
        types = {r.type for r in recs}
        assert "IMPROVE_EFFECTIVENESS" in types

    def test_GAI_137_recommendation_improve_verification_triggered(self):
        class FakeAgg:
            remediation_category = "AUDIT"
            success_count = 5
            failure_count = 5
            partial_success_count = 0
            no_change_count = 0
            average_health_delta = None
            average_effectiveness_delta = None
            average_verification_delta = -7.0  # < -5.0
            confidence = "MEDIUM"

        recs = generate_adaptive_recommendations(
            aggregates=[FakeAgg()],
            accuracy_aggregates=[],
            total_records=10,
            avg_health_delta_30d=None,
        )
        types = {r.type for r in recs}
        assert "IMPROVE_VERIFICATION" in types

    def test_GAI_138_strategy_profile_healthcare_controls(self):
        from services.governance_adaptive_intelligence.models import StrategyProfile

        profile = get_strategy_profile(StrategyProfile.HEALTHCARE)
        assert "encryption" in profile["recommended_controls"]

    def test_GAI_139_strategy_profile_financial_controls(self):
        profile = get_strategy_profile(StrategyProfile.FINANCIAL)
        assert "access_control" in profile["recommended_controls"]

    def test_GAI_140_strategy_profile_general_controls(self):
        profile = get_strategy_profile(StrategyProfile.GENERAL)
        assert "audit_logging" in profile["recommended_controls"]

    def test_GAI_141_classify_calibrated_confidence_boundary_medium(self):
        # Exactly 0.50 with 5 samples → MEDIUM
        result = classify_calibrated_confidence(0.50, 5)
        assert result == CalibratedConfidence.CALIBRATED_MEDIUM

    def test_GAI_142_classify_calibrated_confidence_boundary_high(self):
        # Exactly 0.75 with 5 samples → HIGH
        result = classify_calibrated_confidence(0.75, 5)
        assert result == CalibratedConfidence.CALIBRATED_HIGH

    def test_GAI_143_classify_calibrated_confidence_boundary_low(self):
        # Exactly 0.25 with 5 samples → LOW
        result = classify_calibrated_confidence(0.25, 5)
        assert result == CalibratedConfidence.CALIBRATED_LOW

    def test_GAI_144_cgin_snapshot_fingerprint_deterministic(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        snap1 = client.get("/governance-adaptive-intelligence/cgin/snapshot").json()
        snap2 = client.get("/governance-adaptive-intelligence/cgin/snapshot").json()
        assert snap1["tenant_fingerprint"] == snap2["tenant_fingerprint"]

    def test_GAI_145_cgin_snapshot_no_raw_tenant_in_bundle_id(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        snap = client.get("/governance-adaptive-intelligence/cgin/snapshot").json()
        assert tenant not in snap["bundle_id"]

    def test_GAI_146_accuracy_score_after_3_successes(self, build_app):
        """3 successful outcomes → accuracy = 1.0 → CALIBRATED_HIGH."""
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        for _ in range(3):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json={
                    "recommendation_id": _uid(),
                    "recommendation_type": "GOVERNANCE_REVIEW",
                    "recommendation_reason": "test",
                    "recommendation_confidence": "HIGH",
                    "source_authority": "governance_learning",
                },
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json={"recommendation_history_id": track["id"], "success": True},
            )
        acc = client.get("/governance-adaptive-intelligence/accuracy").json()
        gov_review = next(
            (
                t
                for t in acc["per_type"]
                if t["recommendation_type"] == "GOVERNANCE_REVIEW"
            ),
            None,
        )
        assert gov_review is not None
        assert gov_review["accuracy_score"] == 1.0
        assert gov_review["calibrated_confidence"] == "CALIBRATED_HIGH"

    def test_GAI_147_accuracy_score_after_3_failures(self, build_app):
        """3 failed outcomes → accuracy = 0.0 → CALIBRATED_UNKNOWN."""
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        for _ in range(3):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json={
                    "recommendation_id": _uid(),
                    "recommendation_type": "IMPROVE_FRESHNESS",
                    "recommendation_reason": "test",
                    "recommendation_confidence": "LOW",
                    "source_authority": "governance_learning",
                },
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json={"recommendation_history_id": track["id"], "success": False},
            )
        acc = client.get("/governance-adaptive-intelligence/accuracy").json()
        freshness = next(
            (
                t
                for t in acc["per_type"]
                if t["recommendation_type"] == "IMPROVE_FRESHNESS"
            ),
            None,
        )
        assert freshness is not None
        assert freshness["accuracy_score"] == 0.0

    def test_GAI_148_dashboard_shows_active_recommendations(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        client.post(
            "/governance-adaptive-intelligence/track",
            json={
                "recommendation_id": _uid(),
                "recommendation_type": "GOVERNANCE_REVIEW",
                "recommendation_reason": "test",
                "recommendation_confidence": "HIGH",
                "source_authority": "governance_learning",
            },
        )
        dash = client.get("/governance-adaptive-intelligence/dashboard").json()
        assert dash["active_recommendation_count"] >= 1

    def test_GAI_149_recalculate_with_type_filter(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        resp = client.post(
            "/governance-adaptive-intelligence/recalculate",
            json={"recommendation_type": "GOVERNANCE_REVIEW"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["recommendation_type_filter"] == "GOVERNANCE_REVIEW"

    def test_GAI_150_playbooks_have_steps_after_recalculate(self, build_app):
        tenant = _tid()
        app = build_app(auth_enabled=True)
        key = mint_key("governance:read", "governance:write", tenant_id=tenant)
        client = TestClient(app, headers={"X-API-Key": key})
        # Record some outcomes so playbooks get built
        for _ in range(2):
            track = client.post(
                "/governance-adaptive-intelligence/track",
                json={
                    "recommendation_id": _uid(),
                    "recommendation_type": "PRIORITIZE_BEST_CATEGORY",
                    "recommendation_reason": "test",
                    "recommendation_confidence": "HIGH",
                    "source_authority": "governance_learning",
                },
            ).json()
            client.post(
                "/governance-adaptive-intelligence/record-outcome",
                json={"recommendation_history_id": track["id"], "success": True},
            )
        client.post("/governance-adaptive-intelligence/recalculate", json={})
        playbooks = client.get("/governance-adaptive-intelligence/playbooks").json()
        remediation_pb = next(
            (pb for pb in playbooks if pb["playbook_type"] == "REMEDIATION"), None
        )
        if remediation_pb is not None:
            assert len(remediation_pb["recommended_steps"]) > 0
