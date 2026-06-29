"""Tests for PR 17.5 — Remediation Effectiveness Analytics Authority.

Coverage:
  REM-1   to REM-50:  Model unit tests (classify_outcome, compute_remediation_effectiveness_score,
                       classify_effectiveness_level, compute_roi_score, classify_roi,
                       classify_persistence, classify_category_from_string)
  REM-51  to REM-80:  DB model smoke tests (ORM instantiation, append-only enforcement)
  REM-81  to REM-120: Engine tests (record_outcome, get_outcome, list_outcomes, dashboard,
                       patterns, recalculate)
  REM-121 to REM-150: Route auth tests (wrong scope, no auth, correct scope)
  REM-151 to REM-200: POST /remediation-effectiveness tests
  REM-201 to REM-230: GET routes tests (dashboard, patterns, top-successes, failures, cgin)
  REM-231 to REM-260: Edge cases (404, invalid params, schema validation)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_remediation_effectiveness import (
    FaRemediationLearning,
    FaRemediationOutcome,
    FaRemediationPattern,
    FaRemediationPersistence,
)
from services.remediation_effectiveness.engine import RemediationEffectivenessEngine
from services.remediation_effectiveness.models import (
    OUTCOME_NO_CHANGE_FLOOR,
    OUTCOME_PARTIAL_THRESHOLD,
    OUTCOME_REGRESSION_FLOOR,
    OUTCOME_SUCCESS_THRESHOLD,
    REMEDIATION_EFFECTIVENESS_VERSION,
    OutcomeClassification,
    PatternType,
    PersistenceClassification,
    ROIClassification,
    RemediationCategory,
    RemediationEffectivenessLevel,
    RemediationStatus,
    classify_category_from_string,
    classify_effectiveness_level,
    classify_outcome,
    classify_persistence,
    classify_roi,
    compute_remediation_effectiveness_score,
    compute_roi_score,
)
from services.remediation_effectiveness.schemas import (
    CGINRemediationSnapshot,
    FailuresResponse,
    LearningItem,
    OutcomeListResponse,
    PatternItem,
    PatternsResponse,
    RecalculateResponse,
    RecordOutcomeRequest,
    RemediationDashboardResponse,
    RemediationOutcomeResponse,
    TopSuccessesResponse,
    UpdateOutcomeRequest,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-rem-001"
_TENANT_B = "t-rem-002"
_NOW = datetime.now(tz=timezone.utc)
_NOW_ISO = _NOW.isoformat()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_outcome_row(
    tenant_id: str = _TENANT,
    control_id: str | None = None,
    before_score: float = 60.0,
    after_score: float = 75.0,
    outcome_classification: str = "SUCCESS",
    remediation_category: str = "VERIFICATION",
    status: str = "COMPLETE",
    remediation_task_id: str | None = None,
) -> FaRemediationOutcome:
    score_delta = after_score - before_score
    res = compute_remediation_effectiveness_score(before_score, after_score)
    roi = compute_roi_score(before_score, score_delta)
    return FaRemediationOutcome(
        id=_uid(),
        tenant_id=tenant_id,
        remediation_task_id=remediation_task_id or _uid(),
        control_id=control_id or _uid(),
        before_score=before_score,
        after_score=after_score,
        score_delta=round(score_delta, 4),
        before_effectiveness_level="ADEQUATE",
        after_effectiveness_level="EFFECTIVE",
        outcome_classification=outcome_classification,
        remediation_effectiveness_score=round(res, 4),
        effectiveness_level=classify_effectiveness_level(res).value,
        roi_score=round(roi, 4),
        roi_classification=classify_roi(roi).value,
        remediation_category=remediation_category,
        status=status,
        measured_at=_now_str(),
        calculation_version=REMEDIATION_EFFECTIVENESS_VERSION,
    )


def _engine(db: Session, tenant_id: str = _TENANT) -> RemediationEffectivenessEngine:
    return RemediationEffectivenessEngine(db, tenant_id=tenant_id)


def _record_outcome(
    db: Session,
    tenant_id: str = _TENANT,
    control_id: str | None = None,
    before_score: float = 60.0,
    after_score: float = 75.0,
    remediation_category: str | None = "VERIFICATION",
) -> RemediationOutcomeResponse:
    req = RecordOutcomeRequest(
        remediation_task_id=_uid(),
        control_id=control_id or _uid(),
        before_score=before_score,
        after_score=after_score,
        before_effectiveness_level="ADEQUATE",
        after_effectiveness_level="EFFECTIVE",
        remediation_category=remediation_category,
    )
    return _engine(db, tenant_id).record_outcome(req)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db(build_app):
    build_app(auth_enabled=False)
    engine = get_engine()
    with Session(engine) as session:
        yield session


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", "governance:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def ro_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("governance:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


@pytest.fixture()
def wrong_scope_client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})


# ===========================================================================
# REM-1 to REM-50: Model unit tests
# ===========================================================================


class TestClassifyOutcome:
    """REM-1 through REM-15: classify_outcome pure function."""

    def test_REM_1_delta_10_is_success(self):
        assert classify_outcome(10.0) == OutcomeClassification.SUCCESS

    def test_REM_2_delta_above_10_is_success(self):
        assert classify_outcome(15.0) == OutcomeClassification.SUCCESS

    def test_REM_3_delta_3_is_partial_success(self):
        assert classify_outcome(3.0) == OutcomeClassification.PARTIAL_SUCCESS

    def test_REM_4_delta_5_is_partial_success(self):
        assert classify_outcome(5.0) == OutcomeClassification.PARTIAL_SUCCESS

    def test_REM_5_delta_9_9_is_partial_success(self):
        assert classify_outcome(9.9) == OutcomeClassification.PARTIAL_SUCCESS

    def test_REM_6_delta_0_is_no_change(self):
        assert classify_outcome(0.0) == OutcomeClassification.NO_CHANGE

    def test_REM_7_delta_minus_3_is_no_change(self):
        assert classify_outcome(-3.0) == OutcomeClassification.NO_CHANGE

    def test_REM_8_delta_minus_3_1_is_regression(self):
        assert classify_outcome(-3.1) == OutcomeClassification.REGRESSION

    def test_REM_9_delta_minus_10_is_regression(self):
        assert classify_outcome(-10.0) == OutcomeClassification.REGRESSION

    def test_REM_10_delta_minus_10_1_is_failure(self):
        assert classify_outcome(-10.1) == OutcomeClassification.FAILURE

    def test_REM_11_delta_minus_50_is_failure(self):
        assert classify_outcome(-50.0) == OutcomeClassification.FAILURE

    def test_REM_12_constants_correct(self):
        assert OUTCOME_SUCCESS_THRESHOLD == 10.0
        assert OUTCOME_PARTIAL_THRESHOLD == 3.0
        assert OUTCOME_NO_CHANGE_FLOOR == -3.0
        assert OUTCOME_REGRESSION_FLOOR == -10.0

    def test_REM_13_boundary_exactly_at_partial(self):
        result = classify_outcome(OUTCOME_PARTIAL_THRESHOLD)
        assert result == OutcomeClassification.PARTIAL_SUCCESS

    def test_REM_14_boundary_exactly_at_success(self):
        result = classify_outcome(OUTCOME_SUCCESS_THRESHOLD)
        assert result == OutcomeClassification.SUCCESS

    def test_REM_15_boundary_exactly_at_regression_floor(self):
        result = classify_outcome(OUTCOME_REGRESSION_FLOOR)
        assert result == OutcomeClassification.REGRESSION


class TestComputeRemediationEffectivenessScore:
    """REM-16 through REM-25: compute_remediation_effectiveness_score."""

    def test_REM_16_zero_delta_yields_50(self):
        score = compute_remediation_effectiveness_score(60.0, 60.0)
        assert abs(score - 50.0) < 1e-9

    def test_REM_17_plus_20_delta_yields_100(self):
        score = compute_remediation_effectiveness_score(50.0, 70.0)
        assert abs(score - 100.0) < 1e-9

    def test_REM_18_minus_20_delta_yields_0(self):
        score = compute_remediation_effectiveness_score(70.0, 50.0)
        assert abs(score - 0.0) < 1e-9

    def test_REM_19_score_clamped_at_100(self):
        score = compute_remediation_effectiveness_score(0.0, 100.0)
        assert score == 100.0

    def test_REM_20_score_clamped_at_0(self):
        score = compute_remediation_effectiveness_score(100.0, 0.0)
        assert score == 0.0

    def test_REM_21_positive_delta_above_50(self):
        score = compute_remediation_effectiveness_score(60.0, 70.0)
        assert score > 50.0

    def test_REM_22_negative_delta_below_50(self):
        score = compute_remediation_effectiveness_score(70.0, 60.0)
        assert score < 50.0

    def test_REM_23_delta_10_yields_75(self):
        score = compute_remediation_effectiveness_score(60.0, 70.0)
        assert abs(score - 75.0) < 1e-9

    def test_REM_24_formula_symmetry(self):
        up = compute_remediation_effectiveness_score(50.0, 60.0)
        down = compute_remediation_effectiveness_score(60.0, 50.0)
        assert abs((up - 50.0) + (down - 50.0)) < 1e-9

    def test_REM_25_version_constant_is_1_0(self):
        assert REMEDIATION_EFFECTIVENESS_VERSION == "1.0"


class TestClassifyEffectivenessLevel:
    """REM-26 through REM-32: classify_effectiveness_level."""

    def test_REM_26_75_is_highly_effective(self):
        assert (
            classify_effectiveness_level(75.0)
            == RemediationEffectivenessLevel.HIGHLY_EFFECTIVE
        )

    def test_REM_27_100_is_highly_effective(self):
        assert (
            classify_effectiveness_level(100.0)
            == RemediationEffectivenessLevel.HIGHLY_EFFECTIVE
        )

    def test_REM_28_60_is_effective(self):
        assert (
            classify_effectiveness_level(60.0)
            == RemediationEffectivenessLevel.EFFECTIVE
        )

    def test_REM_29_45_is_adequate(self):
        assert (
            classify_effectiveness_level(45.0) == RemediationEffectivenessLevel.ADEQUATE
        )

    def test_REM_30_30_is_weak(self):
        assert classify_effectiveness_level(30.0) == RemediationEffectivenessLevel.WEAK

    def test_REM_31_below_30_is_ineffective(self):
        assert (
            classify_effectiveness_level(29.9)
            == RemediationEffectivenessLevel.INEFFECTIVE
        )

    def test_REM_32_0_is_ineffective(self):
        assert (
            classify_effectiveness_level(0.0)
            == RemediationEffectivenessLevel.INEFFECTIVE
        )


class TestComputeROIScore:
    """REM-33 through REM-40: compute_roi_score."""

    def test_REM_33_zero_delta_yields_near_50(self):
        roi = compute_roi_score(50.0, 0.0)
        assert 45.0 <= roi <= 55.0

    def test_REM_34_positive_delta_yields_above_50(self):
        roi = compute_roi_score(50.0, 10.0)
        assert roi > 50.0

    def test_REM_35_negative_delta_yields_below_50(self):
        roi = compute_roi_score(50.0, -10.0)
        assert roi < 50.0

    def test_REM_36_roi_bounded_0_to_100(self):
        for before, delta in [(0.0, 100.0), (90.0, -100.0), (50.0, 50.0)]:
            roi = compute_roi_score(before, delta)
            assert 0.0 <= roi <= 100.0

    def test_REM_37_less_headroom_yields_higher_roi_fraction(self):
        roi_low_start = compute_roi_score(10.0, 10.0)
        roi_high_start = compute_roi_score(90.0, 10.0)
        # Formula rewards headroom efficiency: same delta from high base = larger fraction of remaining headroom
        assert roi_high_start > roi_low_start

    def test_REM_38_headroom_formula_correct(self):
        before = 60.0
        delta = 10.0
        headroom = 100.0 - before
        expected_roi = delta / (headroom + 1.0) * 100.0
        expected_normalized = (min(100.0, max(-100.0, expected_roi)) + 100.0) / 2.0
        result = compute_roi_score(before, delta)
        assert abs(result - expected_normalized) < 1e-6

    def test_REM_39_classify_roi_excellent_at_70(self):
        assert classify_roi(70.0) == ROIClassification.EXCELLENT

    def test_REM_40_classify_roi_negative_below_30(self):
        assert classify_roi(29.9) == ROIClassification.NEGATIVE


class TestClassifyROI:
    """REM-41 through REM-46: classify_roi thresholds."""

    def test_REM_41_excellent_at_and_above_70(self):
        assert classify_roi(70.0) == ROIClassification.EXCELLENT
        assert classify_roi(100.0) == ROIClassification.EXCELLENT

    def test_REM_42_good_at_55_to_69(self):
        assert classify_roi(55.0) == ROIClassification.GOOD
        assert classify_roi(69.9) == ROIClassification.GOOD

    def test_REM_43_acceptable_at_40_to_54(self):
        assert classify_roi(40.0) == ROIClassification.ACCEPTABLE
        assert classify_roi(54.9) == ROIClassification.ACCEPTABLE

    def test_REM_44_poor_at_30_to_39(self):
        assert classify_roi(30.0) == ROIClassification.POOR
        assert classify_roi(39.9) == ROIClassification.POOR

    def test_REM_45_negative_below_30(self):
        assert classify_roi(0.0) == ROIClassification.NEGATIVE
        assert classify_roi(29.9) == ROIClassification.NEGATIVE

    def test_REM_46_boundary_exactly_at_55(self):
        assert classify_roi(55.0) == ROIClassification.GOOD


class TestClassifyPersistence:
    """REM-47 through REM-50: classify_persistence."""

    def test_REM_47_delta_0_is_sustained(self):
        assert classify_persistence(70.0, 70.0) == PersistenceClassification.SUSTAINED

    def test_REM_48_delta_minus_2_is_sustained(self):
        assert classify_persistence(70.0, 68.0) == PersistenceClassification.SUSTAINED

    def test_REM_49_delta_minus_3_is_holding(self):
        assert classify_persistence(70.0, 67.0) == PersistenceClassification.HOLDING

    def test_REM_50_delta_minus_11_is_lost(self):
        assert classify_persistence(70.0, 59.0) == PersistenceClassification.LOST


# ===========================================================================
# Additional model tests (REM-51 to REM-80 begin with DB smoke tests below)
# ===========================================================================


class TestModelEnums:
    """Additional enum coverage."""

    def test_classify_category_verification(self):
        assert (
            classify_category_from_string("VERIFICATION")
            == RemediationCategory.VERIFICATION
        )

    def test_classify_category_case_insensitive(self):
        assert (
            classify_category_from_string("freshness") == RemediationCategory.FRESHNESS
        )

    def test_classify_category_none_returns_other(self):
        assert classify_category_from_string(None) == RemediationCategory.OTHER

    def test_classify_category_unknown_returns_other(self):
        assert classify_category_from_string("UNKNOWN_XYZ") == RemediationCategory.OTHER

    def test_remediation_status_values(self):
        assert RemediationStatus.PENDING == "PENDING"
        assert RemediationStatus.COMPLETE == "COMPLETE"

    def test_persistence_not_yet_measurable_exists(self):
        assert PersistenceClassification.NOT_YET_MEASURABLE == "NOT_YET_MEASURABLE"

    def test_pattern_types_all_present(self):
        types = {pt.value for pt in PatternType}
        assert "REPEATED_FAILURE" in types
        assert "CONSISTENT_IMPROVEMENT" in types
        assert "RAPID_REGRESSION" in types


# ===========================================================================
# REM-51 to REM-80: DB model smoke tests
# ===========================================================================


class TestOrmInstantiation:
    """REM-51 through REM-65: ORM model instantiation."""

    def test_REM_51_fa_remediation_outcome_instantiates(self, db):
        row = _make_outcome_row()
        db.add(row)
        db.flush()
        assert row.id is not None

    def test_REM_52_fa_remediation_outcome_has_correct_tenant(self, db):
        row = _make_outcome_row(tenant_id="t-smoke-1")
        db.add(row)
        db.flush()
        assert row.tenant_id == "t-smoke-1"

    def test_REM_53_fa_remediation_persistence_instantiates(self, db):
        outcome = _make_outcome_row()
        db.add(outcome)
        db.flush()
        p = FaRemediationPersistence(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_id=outcome.id,
            control_id=outcome.control_id,
            window_days=30,
            score_at_window=72.0,
            delta_from_close=-3.0,
            persistence_classification="HOLDING",
            measured_at=_now_str(),
        )
        db.add(p)
        db.flush()
        assert p.id is not None

    def test_REM_54_fa_remediation_learning_instantiates(self, db):
        row = FaRemediationLearning(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_category="VERIFICATION",
            total_remediations=5,
            success_count=3,
            partial_success_count=1,
            no_change_count=1,
            regression_count=0,
            failure_count=0,
            success_rate=0.6,
            average_score_delta=8.5,
            average_roi_score=62.0,
            last_updated_at=_now_str(),
        )
        db.add(row)
        db.flush()
        assert row.id is not None

    def test_REM_55_fa_remediation_pattern_instantiates(self, db):
        row = FaRemediationPattern(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=_uid(),
            pattern_type="REPEATED_FAILURE",
            severity="CRITICAL",
            occurrence_count=3,
            description="Test pattern description",
            detected_at=_now_str(),
            last_seen_at=_now_str(),
        )
        db.add(row)
        db.flush()
        assert row.id is not None

    def test_REM_56_outcome_default_status_is_complete(self, db):
        row = _make_outcome_row()
        db.add(row)
        db.flush()
        assert row.status == "COMPLETE"

    def test_REM_57_outcome_calculation_version_default(self, db):
        row = _make_outcome_row()
        db.add(row)
        db.flush()
        assert row.calculation_version == "1.0"

    def test_REM_58_multiple_outcomes_different_ids(self, db):
        row1 = _make_outcome_row()
        row2 = _make_outcome_row()
        db.add(row1)
        db.add(row2)
        db.flush()
        assert row1.id != row2.id

    def test_REM_59_outcome_score_delta_stored_correctly(self, db):
        row = _make_outcome_row(before_score=60.0, after_score=80.0)
        db.add(row)
        db.flush()
        assert abs(row.score_delta - 20.0) < 0.01

    def test_REM_60_outcome_roi_score_positive_for_positive_delta(self, db):
        row = _make_outcome_row(before_score=60.0, after_score=75.0)
        db.add(row)
        db.flush()
        assert row.roi_score > 50.0

    def test_REM_61_learning_unique_constraint_enforced(self, db):
        row1 = FaRemediationLearning(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_category="COVERAGE",
            total_remediations=1,
            success_count=1,
            partial_success_count=0,
            no_change_count=0,
            regression_count=0,
            failure_count=0,
            success_rate=1.0,
            average_score_delta=10.0,
            average_roi_score=65.0,
            last_updated_at=_now_str(),
        )
        row2 = FaRemediationLearning(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_category="COVERAGE",
            total_remediations=2,
            success_count=1,
            partial_success_count=0,
            no_change_count=0,
            regression_count=0,
            failure_count=1,
            success_rate=0.5,
            average_score_delta=5.0,
            average_roi_score=55.0,
            last_updated_at=_now_str(),
        )
        db.add(row1)
        db.flush()
        db.add(row2)
        with pytest.raises(Exception):
            db.flush()
        db.rollback()

    def test_REM_62_persistence_unique_constraint_on_tenant_remediation_window(
        self, db
    ):
        outcome = _make_outcome_row()
        db.add(outcome)
        db.flush()
        p1 = FaRemediationPersistence(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_id=outcome.id,
            control_id=outcome.control_id,
            window_days=30,
            score_at_window=72.0,
            delta_from_close=-3.0,
            persistence_classification="HOLDING",
            measured_at=_now_str(),
        )
        p2 = FaRemediationPersistence(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_id=outcome.id,
            control_id=outcome.control_id,
            window_days=30,
            score_at_window=70.0,
            delta_from_close=-5.0,
            persistence_classification="DECLINING",
            measured_at=_now_str(),
        )
        db.add(p1)
        db.flush()
        db.add(p2)
        with pytest.raises(Exception):
            db.flush()
        db.rollback()

    def test_REM_63_pattern_unique_constraint_on_tenant_control_type(self, db):
        cid = _uid()
        p1 = FaRemediationPattern(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=cid,
            pattern_type="REPEATED_FAILURE",
            severity="CRITICAL",
            occurrence_count=3,
            description="desc",
            detected_at=_now_str(),
            last_seen_at=_now_str(),
        )
        p2 = FaRemediationPattern(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=cid,
            pattern_type="REPEATED_FAILURE",
            severity="HIGH",
            occurrence_count=4,
            description="desc2",
            detected_at=_now_str(),
            last_seen_at=_now_str(),
        )
        db.add(p1)
        db.flush()
        db.add(p2)
        with pytest.raises(Exception):
            db.flush()
        db.rollback()

    def test_REM_64_outcome_tablename_correct(self):
        assert FaRemediationOutcome.__tablename__ == "fa_remediation_outcome"

    def test_REM_65_persistence_tablename_correct(self):
        assert FaRemediationPersistence.__tablename__ == "fa_remediation_persistence"


class TestAppendOnlyGuards:
    """REM-66 through REM-80: ORM-level append-only and delete protection."""

    def test_REM_66_outcome_delete_blocked(self, db):
        row = _make_outcome_row()
        db.add(row)
        db.flush()
        with pytest.raises(RuntimeError, match="cannot be deleted"):
            db.delete(row)
            db.flush()
        db.rollback()

    def test_REM_67_persistence_delete_blocked(self, db):
        outcome = _make_outcome_row()
        db.add(outcome)
        db.flush()
        p = FaRemediationPersistence(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_id=outcome.id,
            control_id=outcome.control_id,
            window_days=60,
            score_at_window=70.0,
            delta_from_close=-5.0,
            persistence_classification="HOLDING",
            measured_at=_now_str(),
        )
        db.add(p)
        db.flush()
        with pytest.raises(RuntimeError, match="append-only"):
            db.delete(p)
            db.flush()
        db.rollback()

    def test_REM_68_persistence_update_blocked(self, db):
        outcome = _make_outcome_row()
        db.add(outcome)
        db.flush()
        p = FaRemediationPersistence(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_id=outcome.id,
            control_id=outcome.control_id,
            window_days=90,
            score_at_window=68.0,
            delta_from_close=-7.0,
            persistence_classification="DECLINING",
            measured_at=_now_str(),
        )
        db.add(p)
        db.flush()
        with pytest.raises(RuntimeError, match="append-only"):
            p.score_at_window = 70.0
            db.flush()
        db.rollback()

    def test_REM_69_learning_can_be_updated(self, db):
        row = FaRemediationLearning(
            id=_uid(),
            tenant_id=_TENANT,
            remediation_category="TREND",
            total_remediations=1,
            success_count=1,
            partial_success_count=0,
            no_change_count=0,
            regression_count=0,
            failure_count=0,
            success_rate=1.0,
            average_score_delta=12.0,
            average_roi_score=70.0,
            last_updated_at=_now_str(),
        )
        db.add(row)
        db.flush()
        row.total_remediations = 2
        db.flush()
        assert row.total_remediations == 2

    def test_REM_70_pattern_can_be_updated(self, db):
        row = FaRemediationPattern(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=_uid(),
            pattern_type="ROLLBACK_PATTERN",
            severity="HIGH",
            occurrence_count=1,
            description="initial",
            detected_at=_now_str(),
            last_seen_at=_now_str(),
        )
        db.add(row)
        db.flush()
        row.occurrence_count = 2
        db.flush()
        assert row.occurrence_count == 2

    def test_REM_71_outcome_can_update_status(self, db):
        row = _make_outcome_row()
        db.add(row)
        db.flush()
        row.status = "INVALIDATED"
        db.flush()
        assert row.status == "INVALIDATED"

    def test_REM_72_learning_tablename_correct(self):
        assert FaRemediationLearning.__tablename__ == "fa_remediation_learning"

    def test_REM_73_pattern_tablename_correct(self):
        assert FaRemediationPattern.__tablename__ == "fa_remediation_pattern"

    def test_REM_74_outcome_has_correct_indexes(self):
        # Verify __table_args__ contains expected index definitions
        arg_names = [
            getattr(arg, "name", None) for arg in FaRemediationOutcome.__table_args__
        ]
        assert any("tenant" in (n or "") for n in arg_names)

    def test_REM_75_persistence_different_windows_on_same_remediation_allowed(self, db):
        outcome = _make_outcome_row()
        db.add(outcome)
        db.flush()
        for window in [7, 30, 90]:
            p = FaRemediationPersistence(
                id=_uid(),
                tenant_id=_TENANT,
                remediation_id=outcome.id,
                control_id=outcome.control_id,
                window_days=window,
                score_at_window=70.0,
                delta_from_close=-5.0,
                persistence_classification="HOLDING",
                measured_at=_now_str(),
            )
            db.add(p)
        db.flush()


# ===========================================================================
# REM-81 to REM-120: Engine tests
# ===========================================================================


class TestEngineRecordOutcome:
    """REM-81 through REM-95: record_outcome engine method."""

    def test_REM_81_record_outcome_returns_response(self, db):
        result = _record_outcome(db)
        assert isinstance(result, RemediationOutcomeResponse)

    def test_REM_82_record_outcome_tenant_id_correct(self, db):
        result = _record_outcome(db, tenant_id=_TENANT)
        assert result.tenant_id == _TENANT

    def test_REM_83_record_outcome_score_delta_computed(self, db):
        result = _record_outcome(db, before_score=60.0, after_score=75.0)
        assert abs(result.score_delta - 15.0) < 0.01

    def test_REM_84_record_outcome_classification_correct(self, db):
        result = _record_outcome(db, before_score=60.0, after_score=75.0)
        assert result.outcome_classification == "SUCCESS"

    def test_REM_85_record_outcome_partial_success(self, db):
        result = _record_outcome(db, before_score=60.0, after_score=64.0)
        assert result.outcome_classification == "PARTIAL_SUCCESS"

    def test_REM_86_record_outcome_no_change(self, db):
        result = _record_outcome(db, before_score=60.0, after_score=60.0)
        assert result.outcome_classification == "NO_CHANGE"

    def test_REM_87_record_outcome_regression(self, db):
        result = _record_outcome(db, before_score=70.0, after_score=64.0)
        assert result.outcome_classification == "REGRESSION"

    def test_REM_88_record_outcome_failure(self, db):
        result = _record_outcome(db, before_score=70.0, after_score=55.0)
        assert result.outcome_classification == "FAILURE"

    def test_REM_89_record_outcome_res_correct(self, db):
        result = _record_outcome(db, before_score=60.0, after_score=70.0)
        expected_res = compute_remediation_effectiveness_score(60.0, 70.0)
        assert abs(result.remediation_effectiveness_score - expected_res) < 0.01

    def test_REM_90_record_outcome_category_defaults_to_verification(self, db):
        result = _record_outcome(db, remediation_category="VERIFICATION")
        assert result.remediation_category == "VERIFICATION"

    def test_REM_91_record_outcome_none_category_defaults_to_other(self, db):
        result = _record_outcome(db, remediation_category=None)
        assert result.remediation_category == "OTHER"

    def test_REM_92_record_outcome_status_is_complete(self, db):
        result = _record_outcome(db)
        assert result.status == "COMPLETE"

    def test_REM_93_record_outcome_id_is_uuid(self, db):
        result = _record_outcome(db)
        assert len(result.id) > 0
        uuid.UUID(result.id)  # Should not raise

    def test_REM_94_record_outcome_roi_score_positive_for_success(self, db):
        result = _record_outcome(db, before_score=50.0, after_score=65.0)
        assert result.roi_score > 50.0

    def test_REM_95_record_two_outcomes_different_ids(self, db):
        r1 = _record_outcome(db)
        r2 = _record_outcome(db)
        assert r1.id != r2.id


class TestEngineGetOutcome:
    """REM-96 through REM-105: get_outcome engine method."""

    def test_REM_96_get_outcome_existing(self, db):
        r = _record_outcome(db)
        result = _engine(db).get_outcome(r.id)
        assert result is not None
        assert result.id == r.id

    def test_REM_97_get_outcome_missing_returns_none(self, db):
        result = _engine(db).get_outcome("nonexistent-id-xyz")
        assert result is None

    def test_REM_98_get_outcome_tenant_isolation(self, db):
        r = _record_outcome(db, tenant_id=_TENANT)
        result = _engine(db, _TENANT_B).get_outcome(r.id)
        assert result is None

    def test_REM_99_get_outcome_fields_correct(self, db):
        r = _record_outcome(db, before_score=55.0, after_score=70.0)
        result = _engine(db).get_outcome(r.id)
        assert result is not None
        assert abs(result.before_score - 55.0) < 0.01
        assert abs(result.after_score - 70.0) < 0.01

    def test_REM_100_get_outcome_has_generated_at(self, db):
        r = _record_outcome(db)
        result = _engine(db).get_outcome(r.id)
        assert result is not None
        assert result.generated_at is not None and len(result.generated_at) > 0


class TestEngineListOutcomes:
    """REM-101 through REM-110: list_outcomes engine method."""

    def test_REM_101_list_outcomes_empty(self, db):
        result = _engine(db).list_outcomes(limit=50, offset=0)
        assert isinstance(result, OutcomeListResponse)
        assert result.total == 0

    def test_REM_102_list_outcomes_counts_correct(self, db):
        for _ in range(3):
            _record_outcome(db, before_score=60.0, after_score=75.0)
        result = _engine(db).list_outcomes(limit=50, offset=0)
        assert result.total == 3
        assert len(result.items) == 3

    def test_REM_103_list_outcomes_pagination(self, db):
        for _ in range(5):
            _record_outcome(db)
        result = _engine(db).list_outcomes(limit=2, offset=0)
        assert len(result.items) == 2

    def test_REM_104_list_outcomes_offset(self, db):
        for _ in range(5):
            _record_outcome(db)
        r1 = _engine(db).list_outcomes(limit=50, offset=0)
        r2 = _engine(db).list_outcomes(limit=50, offset=2)
        assert len(r1.items) == 5
        assert len(r2.items) == 3

    def test_REM_105_list_outcomes_filter_by_classification(self, db):
        _record_outcome(db, before_score=60.0, after_score=75.0)  # SUCCESS
        _record_outcome(db, before_score=70.0, after_score=55.0)  # FAILURE
        result = _engine(db).list_outcomes(
            limit=50, offset=0, outcome_classification="SUCCESS"
        )
        assert all(i.outcome_classification == "SUCCESS" for i in result.items)

    def test_REM_106_list_outcomes_success_and_failure_counts(self, db):
        _record_outcome(db, before_score=60.0, after_score=75.0)  # SUCCESS
        _record_outcome(db, before_score=70.0, after_score=55.0)  # FAILURE
        result = _engine(db).list_outcomes(limit=50, offset=0)
        assert result.success_count == 1
        assert result.failure_count == 1

    def test_REM_107_list_outcomes_tenant_isolation(self, db):
        _record_outcome(db, tenant_id=_TENANT)
        _record_outcome(db, tenant_id=_TENANT_B)
        result = _engine(db, _TENANT).list_outcomes(limit=50, offset=0)
        assert result.total == 1

    def test_REM_108_list_outcomes_tenant_id_in_response(self, db):
        result = _engine(db).list_outcomes(limit=50, offset=0)
        assert result.tenant_id == _TENANT

    def test_REM_109_list_outcomes_has_generated_at(self, db):
        result = _engine(db).list_outcomes(limit=50, offset=0)
        assert result.generated_at is not None

    def test_REM_110_list_outcomes_items_are_outcome_responses(self, db):
        _record_outcome(db)
        result = _engine(db).list_outcomes(limit=50, offset=0)
        for item in result.items:
            assert isinstance(item, RemediationOutcomeResponse)


class TestEngineDashboard:
    """REM-111 through REM-120: get_dashboard engine method."""

    def test_REM_111_dashboard_empty(self, db):
        result = _engine(db).get_dashboard()
        assert isinstance(result, RemediationDashboardResponse)
        assert result.total_remediations == 0

    def test_REM_112_dashboard_counts_correct(self, db):
        _record_outcome(db, before_score=60.0, after_score=75.0)  # SUCCESS
        _record_outcome(db, before_score=70.0, after_score=55.0)  # FAILURE
        result = _engine(db).get_dashboard()
        assert result.total_remediations == 2
        assert result.success_count == 1
        assert result.failure_count == 1

    def test_REM_113_dashboard_success_rate(self, db):
        _record_outcome(db, before_score=60.0, after_score=75.0)  # SUCCESS
        _record_outcome(db, before_score=70.0, after_score=55.0)  # FAILURE
        result = _engine(db).get_dashboard()
        assert abs(result.success_rate - 0.5) < 0.01

    def test_REM_114_dashboard_tenant_id(self, db):
        result = _engine(db).get_dashboard()
        assert result.tenant_id == _TENANT

    def test_REM_115_dashboard_average_score_delta(self, db):
        _record_outcome(db, before_score=60.0, after_score=70.0)  # delta=10
        _record_outcome(db, before_score=60.0, after_score=70.0)  # delta=10
        result = _engine(db).get_dashboard()
        assert abs(result.average_score_delta - 10.0) < 0.01

    def test_REM_116_dashboard_tenant_isolation(self, db):
        _record_outcome(db, tenant_id=_TENANT)
        _record_outcome(db, tenant_id=_TENANT_B)
        result_a = _engine(db, _TENANT).get_dashboard()
        result_b = _engine(db, _TENANT_B).get_dashboard()
        assert result_a.total_remediations == 1
        assert result_b.total_remediations == 1

    def test_REM_117_dashboard_has_generated_at(self, db):
        result = _engine(db).get_dashboard()
        assert result.generated_at is not None

    def test_REM_118_dashboard_learning_empty_initially(self, db):
        result = _engine(db).get_dashboard()
        assert result.learning == []

    def test_REM_119_dashboard_patterns_count(self, db):
        result = _engine(db).get_dashboard()
        assert result.active_patterns == 0
        assert result.critical_patterns == 0

    def test_REM_120_dashboard_top_worst_category_none_when_no_learning(self, db):
        result = _engine(db).get_dashboard()
        assert result.top_performing_category is None
        assert result.worst_performing_category is None


# ===========================================================================
# REM-121 to REM-150: Route auth tests
# ===========================================================================


class TestRouteAuthWrongScope:
    """REM-121 through REM-135: wrong scope returns 403."""

    def test_REM_121_post_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.post(
            "/remediation-effectiveness",
            json={
                "remediation_task_id": _uid(),
                "control_id": _uid(),
                "before_score": 60.0,
                "after_score": 75.0,
                "before_effectiveness_level": "ADEQUATE",
                "after_effectiveness_level": "EFFECTIVE",
            },
        )
        assert resp.status_code == 403

    def test_REM_122_get_list_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness")
        assert resp.status_code == 403

    def test_REM_123_get_dashboard_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/dashboard")
        assert resp.status_code == 403

    def test_REM_124_get_patterns_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/patterns")
        assert resp.status_code == 403

    def test_REM_125_get_top_successes_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/top-successes")
        assert resp.status_code == 403

    def test_REM_126_get_failures_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/failures")
        assert resp.status_code == 403

    def test_REM_127_get_cgin_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/cgin/snapshot")
        assert resp.status_code == 403

    def test_REM_128_post_recalculate_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.post("/remediation-effectiveness/recalculate")
        assert resp.status_code == 403

    def test_REM_129_get_by_id_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.get("/remediation-effectiveness/nonexistent-id")
        assert resp.status_code == 403

    def test_REM_130_patch_wrong_scope(self, wrong_scope_client):
        resp = wrong_scope_client.patch(
            "/remediation-effectiveness/nonexistent-id",
            json={"status": "INVALIDATED"},
        )
        assert resp.status_code == 403


class TestRouteAuthNoAuth:
    """REM-131 through REM-140: no auth returns 401 or 403."""

    def test_REM_131_post_no_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.post(
            "/remediation-effectiveness",
            json={
                "remediation_task_id": _uid(),
                "control_id": _uid(),
                "before_score": 60.0,
                "after_score": 75.0,
                "before_effectiveness_level": "ADEQUATE",
                "after_effectiveness_level": "EFFECTIVE",
            },
        )
        assert resp.status_code in (401, 403)

    def test_REM_132_get_list_no_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/remediation-effectiveness")
        assert resp.status_code in (401, 403)

    def test_REM_133_get_dashboard_no_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/remediation-effectiveness/dashboard")
        assert resp.status_code in (401, 403)

    def test_REM_134_get_patterns_no_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/remediation-effectiveness/patterns")
        assert resp.status_code in (401, 403)

    def test_REM_135_get_by_id_no_auth(self, build_app):
        app = build_app(auth_enabled=True)
        client = TestClient(app)
        resp = client.get("/remediation-effectiveness/some-id")
        assert resp.status_code in (401, 403)


class TestRouteAuthROClient:
    """REM-136 through REM-150: ro_client (governance:read only)."""

    def test_REM_136_ro_can_get_list(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness")
        assert resp.status_code == 200

    def test_REM_137_ro_can_get_dashboard(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/dashboard")
        assert resp.status_code == 200

    def test_REM_138_ro_can_get_patterns(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/patterns")
        assert resp.status_code == 200

    def test_REM_139_ro_can_get_top_successes(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/top-successes")
        assert resp.status_code == 200

    def test_REM_140_ro_can_get_failures(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/failures")
        assert resp.status_code == 200

    def test_REM_141_ro_can_get_cgin_snapshot(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/cgin/snapshot")
        assert resp.status_code == 200

    def test_REM_142_ro_cannot_post(self, ro_client):
        resp = ro_client.post(
            "/remediation-effectiveness",
            json={
                "remediation_task_id": _uid(),
                "control_id": _uid(),
                "before_score": 60.0,
                "after_score": 75.0,
                "before_effectiveness_level": "ADEQUATE",
                "after_effectiveness_level": "EFFECTIVE",
            },
        )
        assert resp.status_code == 403

    def test_REM_143_ro_cannot_recalculate(self, ro_client):
        resp = ro_client.post("/remediation-effectiveness/recalculate")
        assert resp.status_code == 403

    def test_REM_144_ro_cannot_patch(self, ro_client):
        resp = ro_client.patch(
            "/remediation-effectiveness/nonexistent-id",
            json={"status": "INVALIDATED"},
        )
        assert resp.status_code == 403

    def test_REM_145_ro_get_by_id_404_for_missing(self, ro_client):
        resp = ro_client.get("/remediation-effectiveness/nonexistent-id")
        assert resp.status_code == 404


# ===========================================================================
# REM-151 to REM-200: POST /remediation-effectiveness tests
# ===========================================================================


class TestPostOutcome:
    """REM-151 through REM-200: POST /remediation-effectiveness via HTTP client."""

    def _valid_payload(self, **overrides) -> dict:
        base = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 60.0,
            "after_score": 75.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "remediation_category": "VERIFICATION",
        }
        base.update(overrides)
        return base

    def test_REM_151_post_returns_201(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        assert resp.status_code == 201

    def test_REM_152_post_response_has_id(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        data = resp.json()
        assert "id" in data
        assert len(data["id"]) > 0

    def test_REM_153_post_outcome_classification_success(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=60.0, after_score=75.0),
        )
        assert resp.json()["outcome_classification"] == "SUCCESS"

    def test_REM_154_post_outcome_classification_failure(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=70.0, after_score=55.0),
        )
        assert resp.json()["outcome_classification"] == "FAILURE"

    def test_REM_155_post_outcome_classification_regression(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=70.0, after_score=64.0),
        )
        assert resp.json()["outcome_classification"] == "REGRESSION"

    def test_REM_156_post_outcome_classification_no_change(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=60.0, after_score=60.0),
        )
        assert resp.json()["outcome_classification"] == "NO_CHANGE"

    def test_REM_157_post_outcome_classification_partial_success(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=60.0, after_score=64.0),
        )
        assert resp.json()["outcome_classification"] == "PARTIAL_SUCCESS"

    def test_REM_158_post_score_delta_correct(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=60.0, after_score=75.0),
        )
        assert abs(resp.json()["score_delta"] - 15.0) < 0.01

    def test_REM_159_post_remediation_effectiveness_score_in_range(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        res = resp.json()["remediation_effectiveness_score"]
        assert 0.0 <= res <= 100.0

    def test_REM_160_post_roi_score_in_range(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        roi = resp.json()["roi_score"]
        assert 0.0 <= roi <= 100.0

    def test_REM_161_post_tenant_id_from_auth_not_body(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        assert resp.json()["tenant_id"] == _TENANT

    def test_REM_162_post_status_is_complete(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        assert resp.json()["status"] == "COMPLETE"

    def test_REM_163_post_category_set_correctly(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_category="FRESHNESS"),
        )
        assert resp.json()["remediation_category"] == "FRESHNESS"

    def test_REM_164_post_category_none_defaults_to_other(self, client):
        payload = self._valid_payload()
        del payload["remediation_category"]
        resp = client.post("/remediation-effectiveness", json=payload)
        assert resp.json()["remediation_category"] == "OTHER"

    def test_REM_165_post_extra_field_rejected(self, client):
        payload = self._valid_payload()
        payload["extra_field"] = "unexpected"
        resp = client.post("/remediation-effectiveness", json=payload)
        assert resp.status_code == 422

    def test_REM_166_post_missing_required_field(self, client):
        payload = self._valid_payload()
        del payload["before_score"]
        resp = client.post("/remediation-effectiveness", json=payload)
        assert resp.status_code == 422

    def test_REM_167_post_before_score_zero(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=0.0, after_score=20.0),
        )
        assert resp.status_code == 201

    def test_REM_168_post_after_score_100(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=80.0, after_score=100.0),
        )
        assert resp.status_code == 201
        assert resp.json()["outcome_classification"] == "SUCCESS"

    def test_REM_169_post_returned_before_and_after_score(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=55.0, after_score=72.0),
        )
        data = resp.json()
        assert abs(data["before_score"] - 55.0) < 0.01
        assert abs(data["after_score"] - 72.0) < 0.01

    def test_REM_170_post_control_id_preserved(self, client):
        cid = _uid()
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(control_id=cid),
        )
        assert resp.json()["control_id"] == cid

    def test_REM_171_post_remediation_task_id_preserved(self, client):
        task_id = _uid()
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_task_id=task_id),
        )
        assert resp.json()["remediation_task_id"] == task_id

    def test_REM_172_post_effectiveness_level_correct_for_success(self, client):
        # delta=20, res=100, level=HIGHLY_EFFECTIVE
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=50.0, after_score=70.0),
        )
        assert resp.json()["effectiveness_level"] == "HIGHLY_EFFECTIVE"

    def test_REM_173_post_roi_classification_in_response(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        data = resp.json()
        assert "roi_classification" in data
        assert data["roi_classification"] in (
            "EXCELLENT",
            "GOOD",
            "ACCEPTABLE",
            "POOR",
            "NEGATIVE",
        )

    def test_REM_174_post_measured_at_in_response(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        assert "measured_at" in resp.json()

    def test_REM_175_post_generated_at_in_response(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        assert "generated_at" in resp.json()

    def test_REM_176_post_multiple_outcomes_different_ids(self, client):
        r1 = client.post(
            "/remediation-effectiveness", json=self._valid_payload()
        ).json()
        r2 = client.post(
            "/remediation-effectiveness", json=self._valid_payload()
        ).json()
        assert r1["id"] != r2["id"]

    def test_REM_177_post_coverage_category(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_category="COVERAGE"),
        )
        assert resp.json()["remediation_category"] == "COVERAGE"

    def test_REM_178_post_governance_category(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_category="GOVERNANCE"),
        )
        assert resp.json()["remediation_category"] == "GOVERNANCE"

    def test_REM_179_post_evidence_category(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_category="EVIDENCE"),
        )
        assert resp.json()["remediation_category"] == "EVIDENCE"

    def test_REM_180_post_before_effectiveness_level_preserved(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_effectiveness_level="WEAK"),
        )
        assert resp.json()["before_effectiveness_level"] == "WEAK"

    def test_REM_181_post_after_effectiveness_level_preserved(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(after_effectiveness_level="HIGHLY_EFFECTIVE"),
        )
        assert resp.json()["after_effectiveness_level"] == "HIGHLY_EFFECTIVE"

    def test_REM_182_post_unknown_category_maps_to_other(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(remediation_category="COMPLETELY_UNKNOWN"),
        )
        assert resp.json()["remediation_category"] == "OTHER"

    def test_REM_183_post_highly_negative_delta_is_failure(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=80.0, after_score=50.0),
        )
        assert resp.json()["outcome_classification"] == "FAILURE"

    def test_REM_184_post_all_required_fields_in_response(self, client):
        resp = client.post("/remediation-effectiveness", json=self._valid_payload())
        data = resp.json()
        required = [
            "id",
            "tenant_id",
            "remediation_task_id",
            "control_id",
            "before_score",
            "after_score",
            "score_delta",
            "before_effectiveness_level",
            "after_effectiveness_level",
            "outcome_classification",
            "remediation_effectiveness_score",
            "effectiveness_level",
            "roi_score",
            "roi_classification",
            "remediation_category",
            "status",
            "measured_at",
            "generated_at",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_REM_185_post_zero_delta_res_is_50(self, client):
        resp = client.post(
            "/remediation-effectiveness",
            json=self._valid_payload(before_score=60.0, after_score=60.0),
        )
        assert abs(resp.json()["remediation_effectiveness_score"] - 50.0) < 0.01


# ===========================================================================
# REM-201 to REM-230: GET routes tests
# ===========================================================================


class TestGetRoutes:
    """REM-201 through REM-230: GET routes via HTTP client."""

    def _post_outcome(
        self,
        client: TestClient,
        before: float = 60.0,
        after: float = 75.0,
        category: str = "VERIFICATION",
        control_id: str | None = None,
    ) -> dict:
        payload: dict[str, Any] = {
            "remediation_task_id": _uid(),
            "control_id": control_id or _uid(),
            "before_score": before,
            "after_score": after,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "remediation_category": category,
        }
        return client.post("/remediation-effectiveness", json=payload).json()

    def test_REM_201_get_list_returns_200(self, client):
        resp = client.get("/remediation-effectiveness")
        assert resp.status_code == 200

    def test_REM_202_get_list_empty(self, client):
        resp = client.get("/remediation-effectiveness")
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_REM_203_get_list_after_post(self, client):
        self._post_outcome(client)
        resp = client.get("/remediation-effectiveness")
        assert resp.json()["total"] == 1

    def test_REM_204_get_list_filter_by_classification(self, client):
        self._post_outcome(client, before=60.0, after=75.0)  # SUCCESS
        self._post_outcome(client, before=70.0, after=55.0)  # FAILURE
        resp = client.get(
            "/remediation-effectiveness", params={"outcome_classification": "SUCCESS"}
        )
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["outcome_classification"] == "SUCCESS"

    def test_REM_205_get_by_id_returns_200(self, client):
        outcome = self._post_outcome(client)
        resp = client.get(f"/remediation-effectiveness/{outcome['id']}")
        assert resp.status_code == 200

    def test_REM_206_get_by_id_data_matches(self, client):
        outcome = self._post_outcome(client)
        resp = client.get(f"/remediation-effectiveness/{outcome['id']}")
        data = resp.json()
        assert data["id"] == outcome["id"]
        assert data["tenant_id"] == _TENANT

    def test_REM_207_get_dashboard_returns_200(self, client):
        resp = client.get("/remediation-effectiveness/dashboard")
        assert resp.status_code == 200

    def test_REM_208_get_dashboard_has_required_fields(self, client):
        resp = client.get("/remediation-effectiveness/dashboard")
        data = resp.json()
        required = [
            "tenant_id",
            "total_remediations",
            "success_count",
            "failure_count",
            "success_rate",
            "average_score_delta",
            "average_roi_score",
            "average_effectiveness_score",
            "active_patterns",
            "critical_patterns",
            "learning",
            "generated_at",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_REM_209_get_patterns_returns_200(self, client):
        resp = client.get("/remediation-effectiveness/patterns")
        assert resp.status_code == 200

    def test_REM_210_get_patterns_empty_initially(self, client):
        resp = client.get("/remediation-effectiveness/patterns")
        data = resp.json()
        assert data["total"] == 0
        assert data["patterns"] == []

    def test_REM_211_get_top_successes_returns_200(self, client):
        resp = client.get("/remediation-effectiveness/top-successes")
        assert resp.status_code == 200

    def test_REM_212_get_top_successes_empty_initially(self, client):
        resp = client.get("/remediation-effectiveness/top-successes")
        data = resp.json()
        assert data["items"] == []

    def test_REM_213_get_top_successes_limit_param(self, client):
        for _ in range(5):
            self._post_outcome(client, before=60.0, after=75.0)
        resp = client.get(
            "/remediation-effectiveness/top-successes", params={"limit": 3}
        )
        data = resp.json()
        assert len(data["items"]) == 3

    def test_REM_214_get_failures_returns_200(self, client):
        resp = client.get("/remediation-effectiveness/failures")
        assert resp.status_code == 200

    def test_REM_215_get_failures_empty_initially(self, client):
        resp = client.get("/remediation-effectiveness/failures")
        data = resp.json()
        assert data["total_failures"] == 0
        assert data["total_regressions"] == 0

    def test_REM_216_get_failures_counts_correct(self, client):
        self._post_outcome(client, before=70.0, after=55.0)  # FAILURE
        self._post_outcome(client, before=70.0, after=64.0)  # REGRESSION
        resp = client.get("/remediation-effectiveness/failures")
        data = resp.json()
        assert data["total_failures"] == 1
        assert data["total_regressions"] == 1

    def test_REM_217_get_cgin_snapshot_returns_200(self, client):
        resp = client.get("/remediation-effectiveness/cgin/snapshot")
        assert resp.status_code == 200

    def test_REM_218_get_cgin_snapshot_has_required_fields(self, client):
        resp = client.get("/remediation-effectiveness/cgin/snapshot")
        data = resp.json()
        required = [
            "tenant_fingerprint",
            "total_remediations",
            "success_rate",
            "average_score_delta",
            "average_roi_score",
            "patterns_detected",
            "snapshot_at",
        ]
        for field in required:
            assert field in data, f"Missing field: {field}"
        assert "tenant_id" not in data

    def test_REM_219_recalculate_returns_200(self, client):
        resp = client.post("/remediation-effectiveness/recalculate")
        assert resp.status_code == 200

    def test_REM_220_recalculate_response_has_required_fields(self, client):
        resp = client.post("/remediation-effectiveness/recalculate")
        data = resp.json()
        assert "patterns_detected" in data
        assert "learning_categories_updated" in data
        assert "generated_at" in data

    def test_REM_221_recalculate_detects_patterns_after_failures(self, client):
        cid = _uid()
        # Create 3 FAILURE outcomes for same control
        for _ in range(3):
            client.post(
                "/remediation-effectiveness",
                json={
                    "remediation_task_id": _uid(),
                    "control_id": cid,
                    "before_score": 70.0,
                    "after_score": 55.0,
                    "before_effectiveness_level": "EFFECTIVE",
                    "after_effectiveness_level": "WEAK",
                    "remediation_category": "VERIFICATION",
                },
            )
        resp = client.post("/remediation-effectiveness/recalculate")
        data = resp.json()
        assert data["patterns_detected"] >= 1

    def test_REM_222_recalculate_updates_learning(self, client):
        self._post_outcome(client, category="COVERAGE")
        resp = client.post("/remediation-effectiveness/recalculate")
        data = resp.json()
        assert data["learning_categories_updated"] >= 1

    def test_REM_223_get_patterns_after_recalculate(self, client):
        cid = _uid()
        for _ in range(3):
            client.post(
                "/remediation-effectiveness",
                json={
                    "remediation_task_id": _uid(),
                    "control_id": cid,
                    "before_score": 70.0,
                    "after_score": 55.0,
                    "before_effectiveness_level": "EFFECTIVE",
                    "after_effectiveness_level": "WEAK",
                    "remediation_category": "VERIFICATION",
                },
            )
        client.post("/remediation-effectiveness/recalculate")
        resp = client.get("/remediation-effectiveness/patterns")
        data = resp.json()
        assert data["total"] >= 1

    def test_REM_224_dashboard_after_recalculate_has_learning(self, client):
        self._post_outcome(client, category="TREND")
        client.post("/remediation-effectiveness/recalculate")
        resp = client.get("/remediation-effectiveness/dashboard")
        data = resp.json()
        assert len(data["learning"]) >= 1

    def test_REM_225_patch_outcome_status(self, client):
        outcome = self._post_outcome(client)
        resp = client.patch(
            f"/remediation-effectiveness/{outcome['id']}",
            json={"status": "INVALIDATED"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "INVALIDATED"

    def test_REM_226_cgin_snapshot_total_after_posts(self, client):
        self._post_outcome(client)
        self._post_outcome(client)
        resp = client.get("/remediation-effectiveness/cgin/snapshot")
        assert resp.json()["total_remediations"] == 2

    def test_REM_227_get_list_has_tenant_id(self, client):
        resp = client.get("/remediation-effectiveness")
        assert resp.json()["tenant_id"] == _TENANT

    def test_REM_228_get_top_successes_ordered_by_res_desc(self, client):
        # Higher delta = higher RES
        self._post_outcome(client, before=60.0, after=65.0)  # delta=5
        self._post_outcome(client, before=60.0, after=80.0)  # delta=20
        resp = client.get("/remediation-effectiveness/top-successes")
        items = resp.json()["items"]
        if len(items) >= 2:
            assert (
                items[0]["remediation_effectiveness_score"]
                >= items[1]["remediation_effectiveness_score"]
            )

    def test_REM_229_recalculate_with_control_id_param(self, client):
        cid = _uid()
        self._post_outcome(client, control_id=cid)
        resp = client.post(
            "/remediation-effectiveness/recalculate",
            params={"control_id": cid},
        )
        assert resp.status_code == 200

    def test_REM_230_get_failures_has_items(self, client):
        self._post_outcome(client, before=70.0, after=55.0)  # FAILURE
        resp = client.get("/remediation-effectiveness/failures")
        data = resp.json()
        assert len(data["items"]) == 1


# ===========================================================================
# REM-231 to REM-260: Edge cases
# ===========================================================================


class TestEdgeCases:
    """REM-231 through REM-260: Edge cases, 404s, schema validation."""

    def test_REM_231_get_by_id_404_for_missing(self, client):
        resp = client.get("/remediation-effectiveness/does-not-exist")
        assert resp.status_code == 404

    def test_REM_232_patch_404_for_missing(self, client):
        resp = client.patch(
            "/remediation-effectiveness/does-not-exist",
            json={"status": "INVALIDATED"},
        )
        assert resp.status_code == 404

    def test_REM_233_list_limit_max_200(self, client):
        resp = client.get("/remediation-effectiveness", params={"limit": 201})
        assert resp.status_code == 422

    def test_REM_234_list_limit_min_1(self, client):
        resp = client.get("/remediation-effectiveness", params={"limit": 0})
        assert resp.status_code == 422

    def test_REM_235_list_offset_cannot_be_negative(self, client):
        resp = client.get("/remediation-effectiveness", params={"offset": -1})
        assert resp.status_code == 422

    def test_REM_236_top_successes_limit_min_1(self, client):
        resp = client.get(
            "/remediation-effectiveness/top-successes", params={"limit": 0}
        )
        assert resp.status_code == 422

    def test_REM_237_top_successes_limit_max_100(self, client):
        resp = client.get(
            "/remediation-effectiveness/top-successes", params={"limit": 101}
        )
        assert resp.status_code == 422

    def test_REM_238_schema_extra_field_forbidden(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id="t1",
                control_id="c1",
                before_score=60.0,
                after_score=75.0,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
                unexpected_extra="value",
            )

    def test_REM_239_update_outcome_schema_extra_forbidden(self):
        with pytest.raises(Exception):
            UpdateOutcomeRequest(status="COMPLETE", extra_field="bad")

    def test_REM_240_record_outcome_request_optional_category(self):
        req = RecordOutcomeRequest(
            remediation_task_id="t1",
            control_id="c1",
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        assert req.remediation_category is None

    def test_REM_241_classify_persistence_declining(self):
        # delta = -7 → DECLINING
        result = classify_persistence(70.0, 63.0)
        assert result == PersistenceClassification.DECLINING

    def test_REM_242_classify_persistence_holding(self):
        # delta = -4 → HOLDING
        result = classify_persistence(70.0, 66.0)
        assert result == PersistenceClassification.HOLDING

    def test_REM_243_classify_persistence_improvement_sustained(self):
        # delta = +5 → SUSTAINED (>= -2)
        result = classify_persistence(60.0, 65.0)
        assert result == PersistenceClassification.SUSTAINED

    def test_REM_244_pattern_detection_consistent_improvement(self, db):
        cid = _uid()
        for _ in range(3):
            _record_outcome(
                db,
                tenant_id=_TENANT,
                control_id=cid,
                before_score=60.0,
                after_score=75.0,
            )
        db.commit()
        result = _engine(db).recalculate()
        assert result.patterns_detected >= 1

    def test_REM_245_pattern_detection_rollback(self, db):
        cid = _uid()
        # SUCCESS then FAILURE
        _record_outcome(
            db, tenant_id=_TENANT, control_id=cid, before_score=60.0, after_score=75.0
        )
        _record_outcome(
            db, tenant_id=_TENANT, control_id=cid, before_score=70.0, after_score=55.0
        )
        db.commit()
        result = _engine(db).recalculate()
        assert result.patterns_detected >= 1

    def test_REM_246_cgin_snapshot_success_rate_zero_when_empty(self, db):
        result = _engine(db).cgin_snapshot()
        assert result.success_rate == 0.0
        assert result.total_remediations == 0

    def test_REM_247_cgin_snapshot_type(self, db):
        result = _engine(db).cgin_snapshot()
        assert isinstance(result, CGINRemediationSnapshot)

    def test_REM_248_patterns_response_type(self, db):
        result = _engine(db).get_patterns()
        assert isinstance(result, PatternsResponse)

    def test_REM_249_failures_response_type(self, db):
        result = _engine(db).get_failures()
        assert isinstance(result, FailuresResponse)

    def test_REM_250_top_successes_response_type(self, db):
        result = _engine(db).get_top_successes()
        assert isinstance(result, TopSuccessesResponse)

    def test_REM_251_update_status_none_returns_current(self, db):
        r = _record_outcome(db)
        result = _engine(db).update_outcome_status(r.id, "PENDING")
        assert result is not None
        assert result.status == "PENDING"

    def test_REM_252_update_status_nonexistent_returns_none(self, db):
        result = _engine(db).update_outcome_status("nonexistent-uuid", "INVALIDATED")
        assert result is None

    def test_REM_253_rebuild_learning_multiple_categories(self, db):
        _record_outcome(db, remediation_category="VERIFICATION")
        _record_outcome(db, remediation_category="FRESHNESS")
        _record_outcome(db, remediation_category="COVERAGE")
        db.commit()
        result = _engine(db).recalculate()
        assert result.learning_categories_updated == 3

    def test_REM_254_recalculate_response_type(self, db):
        result = _engine(db).recalculate()
        assert isinstance(result, RecalculateResponse)

    def test_REM_255_pattern_detection_no_improvement(self, db):
        cid = _uid()
        for _ in range(3):
            _record_outcome(
                db,
                tenant_id=_TENANT,
                control_id=cid,
                before_score=60.0,
                after_score=60.0,
            )
        db.commit()
        result = _engine(db).recalculate()
        assert result.patterns_detected >= 1

    def test_REM_256_pattern_repeated_failure_critical_severity(self, db):
        cid = _uid()
        for _ in range(3):
            _record_outcome(
                db,
                tenant_id=_TENANT,
                control_id=cid,
                before_score=70.0,
                after_score=55.0,
            )
        db.commit()
        _engine(db).recalculate()
        patterns_resp = _engine(db).get_patterns()
        critical = [
            p for p in patterns_resp.patterns if p.pattern_type == "REPEATED_FAILURE"
        ]
        assert len(critical) >= 1
        assert critical[0].severity == "CRITICAL"

    def test_REM_257_engine_tenant_isolation_recalculate(self, db):
        _record_outcome(db, tenant_id=_TENANT)
        _record_outcome(db, tenant_id=_TENANT_B)
        db.commit()
        result_a = _engine(db, _TENANT).recalculate()
        result_b = _engine(db, _TENANT_B).recalculate()
        # Each tenant only sees its own data
        assert result_a.learning_categories_updated >= 1
        assert result_b.learning_categories_updated >= 1

    def test_REM_258_schema_outcome_list_response_extra_forbidden(self):
        with pytest.raises(Exception):
            OutcomeListResponse(
                tenant_id="t1",
                items=[],
                total=0,
                success_count=0,
                failure_count=0,
                generated_at=_now_str(),
                unexpected="bad",
            )

    def test_REM_259_learning_item_schema_extra_forbidden(self):
        with pytest.raises(Exception):
            LearningItem(
                remediation_category="VERIFICATION",
                total_remediations=1,
                success_count=1,
                partial_success_count=0,
                no_change_count=0,
                regression_count=0,
                failure_count=0,
                success_rate=1.0,
                average_score_delta=10.0,
                average_roi_score=65.0,
                last_updated_at=_now_str(),
                extra="bad",
            )

    def test_REM_260_pattern_item_schema_extra_forbidden(self):
        with pytest.raises(Exception):
            PatternItem(
                control_id="c1",
                pattern_type="REPEATED_FAILURE",
                severity="CRITICAL",
                occurrence_count=3,
                description="test",
                detected_at=_now_str(),
                last_seen_at=_now_str(),
                bad_field="value",
            )


# ===========================================================================
# REM-261 to REM-274: Component score fields
# ===========================================================================


class TestComponentScoreFields:
    """REM-261 through REM-274: verification/freshness/forecast/governance_health fields."""

    def test_REM_261_record_outcome_request_accepts_component_scores(self):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=55.0,
            verification_after=70.0,
            freshness_before=60.0,
            freshness_after=78.0,
            forecast_before=50.0,
            forecast_after=65.0,
            governance_health_before=45.0,
            governance_health_after=62.0,
        )
        assert req.verification_before == 55.0
        assert req.verification_after == 70.0
        assert req.freshness_before == 60.0
        assert req.freshness_after == 78.0
        assert req.forecast_before == 50.0
        assert req.forecast_after == 65.0
        assert req.governance_health_before == 45.0
        assert req.governance_health_after == 62.0

    def test_REM_262_component_scores_default_to_none(self):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        assert req.verification_before is None
        assert req.verification_after is None
        assert req.freshness_before is None
        assert req.freshness_after is None
        assert req.forecast_before is None
        assert req.forecast_after is None
        assert req.governance_health_before is None
        assert req.governance_health_after is None

    def test_REM_263_engine_stores_and_returns_component_scores(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=78.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=55.0,
            verification_after=72.0,
            freshness_before=60.0,
            freshness_after=80.0,
            forecast_before=48.0,
            forecast_after=64.0,
            governance_health_before=42.0,
            governance_health_after=60.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.verification_before == 55.0
        assert result.verification_after == 72.0
        assert result.freshness_before == 60.0
        assert result.freshness_after == 80.0
        assert result.forecast_before == 48.0
        assert result.forecast_after == 64.0
        assert result.governance_health_before == 42.0
        assert result.governance_health_after == 60.0

    def test_REM_264_component_scores_null_when_not_provided(self, db):
        result = _record_outcome(db)
        assert result.verification_before is None
        assert result.verification_after is None
        assert result.freshness_before is None
        assert result.freshness_after is None
        assert result.forecast_before is None
        assert result.forecast_after is None
        assert result.governance_health_before is None
        assert result.governance_health_after is None

    def test_REM_265_component_scores_persisted_and_retrieved(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=55.0,
            after_score=70.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=50.0,
            verification_after=68.0,
        )
        created = _engine(db).record_outcome(req)
        fetched = _engine(db).get_outcome(created.id)
        assert fetched is not None
        assert fetched.verification_before == 50.0
        assert fetched.verification_after == 68.0
        assert fetched.freshness_before is None

    def test_REM_266_orm_outcome_has_component_score_columns(self, db):
        row = _make_outcome_row()
        row.verification_before = 55.0
        row.verification_after = 70.0
        row.freshness_before = 60.0
        row.freshness_after = 75.0
        row.forecast_before = 48.0
        row.forecast_after = 62.0
        row.governance_health_before = 40.0
        row.governance_health_after = 58.0
        db.add(row)
        db.flush()
        assert row.verification_before == 55.0
        assert row.governance_health_after == 58.0

    def test_REM_267_verification_delta_visible_via_before_after(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=40.0,
            verification_after=80.0,
        )
        result = _engine(db).record_outcome(req)
        delta = result.verification_after - result.verification_before
        assert delta == 40.0

    def test_REM_268_partial_component_scores_allowed(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=55.0,
            verification_after=70.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.verification_before == 55.0
        assert result.verification_after == 70.0
        assert result.freshness_before is None
        assert result.freshness_after is None

    def test_REM_269_http_post_accepts_component_scores(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 60.0,
            "after_score": 78.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "verification_before": 55.0,
            "verification_after": 72.0,
            "freshness_before": 60.0,
            "freshness_after": 80.0,
            "forecast_before": 48.0,
            "forecast_after": 64.0,
            "governance_health_before": 42.0,
            "governance_health_after": 60.0,
        }
        r = client.post("/remediation-effectiveness", json=payload)
        assert r.status_code == 201
        body = r.json()
        assert body["verification_before"] == 55.0
        assert body["verification_after"] == 72.0
        assert body["freshness_before"] == 60.0
        assert body["freshness_after"] == 80.0
        assert body["forecast_before"] == 48.0
        assert body["forecast_after"] == 64.0
        assert body["governance_health_before"] == 42.0
        assert body["governance_health_after"] == 60.0

    def test_REM_270_http_post_without_component_scores_returns_nulls(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 60.0,
            "after_score": 75.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
        }
        r = client.post("/remediation-effectiveness", json=payload)
        assert r.status_code == 201
        body = r.json()
        assert body["verification_before"] is None
        assert body["verification_after"] is None
        assert body["freshness_before"] is None
        assert body["freshness_after"] is None
        assert body["forecast_before"] is None
        assert body["forecast_after"] is None
        assert body["governance_health_before"] is None
        assert body["governance_health_after"] is None

    def test_REM_271_http_get_single_returns_component_scores(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 55.0,
            "after_score": 72.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "governance_health_before": 40.0,
            "governance_health_after": 58.0,
        }
        r = client.post("/remediation-effectiveness", json=payload)
        assert r.status_code == 201
        rid = r.json()["id"]
        r2 = client.get(f"/remediation-effectiveness/{rid}")
        assert r2.status_code == 200
        assert r2.json()["governance_health_before"] == 40.0
        assert r2.json()["governance_health_after"] == 58.0

    def test_REM_272_http_list_returns_component_scores(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 55.0,
            "after_score": 72.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "forecast_before": 48.0,
            "forecast_after": 63.0,
        }
        client.post("/remediation-effectiveness", json=payload)
        r = client.get("/remediation-effectiveness?limit=1")
        assert r.status_code == 200
        items = r.json()["items"]
        assert len(items) >= 1
        matching = [i for i in items if i.get("forecast_before") == 48.0]
        assert len(matching) >= 1

    def test_REM_273_outcome_response_schema_has_component_fields(self):
        fields = RemediationOutcomeResponse.model_fields
        for field in (
            "verification_before",
            "verification_after",
            "freshness_before",
            "freshness_after",
            "forecast_before",
            "forecast_after",
            "governance_health_before",
            "governance_health_after",
        ):
            assert field in fields, f"Missing field: {field}"

    def test_REM_274_record_request_schema_has_component_fields(self):
        fields = RecordOutcomeRequest.model_fields
        for field in (
            "verification_before",
            "verification_after",
            "freshness_before",
            "freshness_after",
            "forecast_before",
            "forecast_after",
            "governance_health_before",
            "governance_health_after",
        ):
            assert field in fields, f"Missing field: {field}"

    def test_REM_275_engine_computes_verification_delta(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=40.0,
            verification_after=65.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.verification_delta == 25.0

    def test_REM_276_engine_computes_freshness_delta(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            freshness_before=50.0,
            freshness_after=80.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.freshness_delta == 30.0

    def test_REM_277_engine_computes_forecast_delta(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            forecast_before=55.0,
            forecast_after=70.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.forecast_delta == 15.0

    def test_REM_278_engine_computes_governance_health_delta(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            governance_health_before=45.0,
            governance_health_after=62.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.governance_health_delta == 17.0

    def test_REM_279_delta_is_none_when_before_or_after_missing(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=50.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.verification_delta is None

    def test_REM_280_negative_delta_stored_correctly(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=75.0,
            after_score=60.0,
            before_effectiveness_level="EFFECTIVE",
            after_effectiveness_level="ADEQUATE",
            freshness_before=70.0,
            freshness_after=55.0,
        )
        result = _engine(db).record_outcome(req)
        assert result.freshness_delta == -15.0

    def test_REM_281_all_deltas_null_when_no_components_provided(self, db):
        result = _record_outcome(db)
        assert result.verification_delta is None
        assert result.freshness_delta is None
        assert result.forecast_delta is None
        assert result.governance_health_delta is None

    def test_REM_282_http_post_returns_all_deltas(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 60.0,
            "after_score": 78.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
            "verification_before": 50.0,
            "verification_after": 70.0,
            "freshness_before": 60.0,
            "freshness_after": 85.0,
            "forecast_before": 45.0,
            "forecast_after": 60.0,
            "governance_health_before": 40.0,
            "governance_health_after": 55.0,
        }
        r = client.post("/remediation-effectiveness", json=payload)
        assert r.status_code == 201
        body = r.json()
        assert body["verification_delta"] == 20.0
        assert body["freshness_delta"] == 25.0
        assert body["forecast_delta"] == 15.0
        assert body["governance_health_delta"] == 15.0

    def test_REM_283_outcome_response_schema_has_delta_fields(self):
        fields = RemediationOutcomeResponse.model_fields
        for field in (
            "verification_delta",
            "freshness_delta",
            "forecast_delta",
            "governance_health_delta",
        ):
            assert field in fields, f"Missing field: {field}"

    def test_REM_284_deltas_persisted_and_retrievable(self, db):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
            verification_before=50.0,
            verification_after=72.0,
            freshness_before=58.0,
            freshness_after=80.0,
        )
        created = _engine(db).record_outcome(req)
        fetched = _engine(db).get_outcome(created.id)
        assert fetched is not None
        assert fetched.verification_delta == 22.0
        assert fetched.freshness_delta == 22.0
        assert fetched.forecast_delta is None
        assert fetched.governance_health_delta is None


# ===========================================================================
# REM-285 to REM-300: P2 badge fixes
# ===========================================================================


class TestScoreValidation:
    """REM-285 through REM-292: before_score/after_score must be 0-100."""

    def test_REM_285_before_score_above_100_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=101.0,
                after_score=80.0,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
            )

    def test_REM_286_after_score_above_100_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=60.0,
                after_score=100.1,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
            )

    def test_REM_287_before_score_negative_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=-1.0,
                after_score=50.0,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
            )

    def test_REM_288_after_score_negative_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=60.0,
                after_score=-0.1,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
            )

    def test_REM_289_scores_at_boundary_accepted(self):
        req = RecordOutcomeRequest(
            remediation_task_id=_uid(),
            control_id=_uid(),
            before_score=0.0,
            after_score=100.0,
            before_effectiveness_level="INEFFECTIVE",
            after_effectiveness_level="HIGHLY_EFFECTIVE",
        )
        assert req.before_score == 0.0
        assert req.after_score == 100.0

    def test_REM_290_component_score_above_100_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=60.0,
                after_score=75.0,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
                verification_before=101.0,
            )

    def test_REM_291_component_score_negative_rejected(self):
        with pytest.raises(Exception):
            RecordOutcomeRequest(
                remediation_task_id=_uid(),
                control_id=_uid(),
                before_score=60.0,
                after_score=75.0,
                before_effectiveness_level="ADEQUATE",
                after_effectiveness_level="EFFECTIVE",
                freshness_after=-1.0,
            )

    def test_REM_292_http_post_101_score_returns_422(self, client):
        payload = {
            "remediation_task_id": _uid(),
            "control_id": _uid(),
            "before_score": 101.0,
            "after_score": 80.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
        }
        r = client.post("/remediation-effectiveness", json=payload)
        assert r.status_code == 422


class TestDuplicatePrevention:
    """REM-293 through REM-297: duplicate outcome prevention."""

    def test_REM_293_duplicate_task_control_raises_engine_error(self, db):
        from services.remediation_effectiveness.engine import (
            DuplicateRemediationOutcome,
        )

        task_id = _uid()
        ctrl_id = _uid()
        req = RecordOutcomeRequest(
            remediation_task_id=task_id,
            control_id=ctrl_id,
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        _engine(db).record_outcome(req)
        req2 = RecordOutcomeRequest(
            remediation_task_id=task_id,
            control_id=ctrl_id,
            before_score=65.0,
            after_score=80.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        with pytest.raises(DuplicateRemediationOutcome) as exc_info:
            _engine(db).record_outcome(req2)
        assert exc_info.value.outcome_id is not None

    def test_REM_294_different_control_same_task_allowed(self, db):
        task_id = _uid()
        req1 = RecordOutcomeRequest(
            remediation_task_id=task_id,
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        req2 = RecordOutcomeRequest(
            remediation_task_id=task_id,
            control_id=_uid(),
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        r1 = _engine(db).record_outcome(req1)
        r2 = _engine(db).record_outcome(req2)
        assert r1.id != r2.id

    def test_REM_295_same_task_different_tenant_allowed(self, db):
        task_id = _uid()
        ctrl_id = _uid()
        req = RecordOutcomeRequest(
            remediation_task_id=task_id,
            control_id=ctrl_id,
            before_score=60.0,
            after_score=75.0,
            before_effectiveness_level="ADEQUATE",
            after_effectiveness_level="EFFECTIVE",
        )
        r1 = _engine(db, tenant_id=_TENANT).record_outcome(req)
        r2 = _engine(db, tenant_id=_TENANT_B).record_outcome(req)
        assert r1.id != r2.id

    def test_REM_296_http_duplicate_returns_409(self, client):
        task_id = _uid()
        ctrl_id = _uid()
        payload = {
            "remediation_task_id": task_id,
            "control_id": ctrl_id,
            "before_score": 60.0,
            "after_score": 75.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
        }
        r1 = client.post("/remediation-effectiveness", json=payload)
        assert r1.status_code == 201
        r2 = client.post("/remediation-effectiveness", json=payload)
        assert r2.status_code == 409

    def test_REM_297_409_body_contains_existing_id(self, client):
        task_id = _uid()
        ctrl_id = _uid()
        payload = {
            "remediation_task_id": task_id,
            "control_id": ctrl_id,
            "before_score": 60.0,
            "after_score": 75.0,
            "before_effectiveness_level": "ADEQUATE",
            "after_effectiveness_level": "EFFECTIVE",
        }
        r1 = client.post("/remediation-effectiveness", json=payload)
        existing_id = r1.json()["id"]
        r2 = client.post("/remediation-effectiveness", json=payload)
        assert existing_id in r2.json()["detail"]


class TestFailureCounts:
    """REM-298 through REM-300: failure totals from DB counts, not limited list."""

    def test_REM_298_failure_totals_exceed_page_limit(self, db):
        ctrl_id = _uid()
        for _ in range(55):
            row = _make_outcome_row(
                control_id=ctrl_id,
                before_score=70.0,
                after_score=55.0,
                outcome_classification="FAILURE",
            )
            db.add(row)
        db.flush()
        result = _engine(db).get_failures()
        assert result.total_failures == 55
        assert len(result.items) == 50  # capped by default limit

    def test_REM_299_regression_totals_exceed_page_limit(self, db):
        ctrl_id = _uid()
        for _ in range(52):
            row = _make_outcome_row(
                control_id=ctrl_id,
                before_score=70.0,
                after_score=62.0,
                outcome_classification="REGRESSION",
            )
            db.add(row)
        db.flush()
        result = _engine(db).get_failures()
        assert result.total_regressions == 52
        assert len(result.items) == 50

    def test_REM_300_totals_count_across_pages_independently(self, db):
        ctrl_id = _uid()
        for _ in range(30):
            row = _make_outcome_row(
                control_id=ctrl_id,
                before_score=70.0,
                after_score=55.0,
                outcome_classification="FAILURE",
            )
            db.add(row)
        for _ in range(25):
            row = _make_outcome_row(
                control_id=ctrl_id,
                before_score=70.0,
                after_score=62.0,
                outcome_classification="REGRESSION",
            )
            db.add(row)
        db.flush()
        result = _engine(db).get_failures()
        assert result.total_failures == 30
        assert result.total_regressions == 25
        assert len(result.items) == 50  # combined, capped
