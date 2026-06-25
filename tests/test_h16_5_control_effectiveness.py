"""Tests for PR 16.5 — Control Effectiveness Engine.

Coverage:
  CE-1   to CE-20:  Pure function tests (scoring model)
  CE-21  to CE-40:  Coverage score component
  CE-41  to CE-60:  Verification score component
  CE-61  to CE-75:  Freshness score component
  CE-76  to CE-95:  Trend data component
  CE-96  to CE-110: Forecast score component
  CE-111 to CE-125: Evidence density + exception + governance health
  CE-126 to CE-150: Recalculate (single + all) + history
  CE-151 to CE-175: Dashboard + CGIN snapshot + list/get
  CE-176 to CE-200: API routes (scope, tenant isolation, route ordering)
  CE-201 to CE-220: ORM guards, timeline adapter, repository, edge cases
  CE-221+:          Adapter completeness
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from api.auth_scopes import mint_key
from api.db import get_engine
from api.db_models_control_effectiveness import (
    FaControlEffectiveness,
    FaControlEffectivenessHistory,
)
from api.db_models_evidence_authority import (
    FaEvidence,
    FaEvidenceControlLink,
    FaVerification,
)
from api.db_models_evidence_freshness_authority import (
    FaEvidenceFreshnessRecord,
    FaFreshnessException,
)
from api.db_models_freshness_score_history import FaFreshnessScoreSnapshot
from services.control_effectiveness.engine import ControlEffectivenessEngine
from services.control_effectiveness.models import (
    EffectivenessLevel,
    EffectivenessRisk,
    SCORING_MODEL_VERSION,
    classify_effectiveness,
    classify_risk,
    classify_trend,
    compute_effectiveness_score,
)
from services.control_effectiveness.schemas import ControlNotFound
from services.governance.timeline.models import SourceType

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TENANT = "t-ce-001"
_TENANT_B = "t-ce-002"
_NOW = datetime.now(tz=timezone.utc)
_NOW_ISO = _NOW.isoformat()
_FUTURE = (_NOW + timedelta(days=90)).isoformat()
_PAST_10D = (_NOW - timedelta(days=10)).strftime("%Y-%m-%d")
_PAST_35D = (_NOW - timedelta(days=35)).strftime("%Y-%m-%d")
_PAST_95D = (_NOW - timedelta(days=95)).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid.uuid4())[:16]


def _now_str() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _make_evidence(
    db: Session,
    tenant_id: str = _TENANT,
    lifecycle_state: str = "COLLECTED",
    trust_state: str = "UNVERIFIED",
    source_system: str = "JIRA",
    freshness_score: int | None = 80,
    verification_score: int | None = 70,
    completeness_score: int | None = 90,
) -> FaEvidence:
    now = _now_str()
    ev = FaEvidence(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_ref=f"ref-{_uid()}",
        lifecycle_state=lifecycle_state,
        classification="internal",
        classification_labels="[]",
        source_type="DOCUMENT",
        source_system=source_system,
        collection_method="MANUAL",
        title=f"Evidence {_uid()}",
        creator_id="test-actor",
        creator_type="human",
        trust_state=trust_state,
        collected_at=now,
        created_at=now,
        updated_at=now,
        freshness_score=freshness_score,
        verification_score=verification_score,
        completeness_score=completeness_score,
    )
    db.add(ev)
    db.flush()
    return ev


def _link_evidence(
    db: Session, evidence_id: str, control_id: str, tenant_id: str = _TENANT
) -> FaEvidenceControlLink:
    now = _now_str()
    link = FaEvidenceControlLink(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        control_id=control_id,
        linked_by="test",
        linked_at=now,
        created_at=now,
    )
    db.add(link)
    db.flush()
    return link


def _make_verification(
    db: Session,
    evidence_id: str,
    result: str = "PASS",
    tenant_id: str = _TENANT,
    created_at: str | None = None,
) -> FaVerification:
    now = created_at or _now_str()
    v = FaVerification(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        verification_type="MANUAL_REVIEW",
        verification_result=result,
        verified_by="test-actor",
        verified_actor_type="human",
        verified_at=now,
        created_at=now,
    )
    db.add(v)
    db.flush()
    return v


def _make_freshness_record(
    db: Session,
    evidence_id: str,
    freshness_score: int = 80,
    freshness_state: str = "CURRENT",
    tenant_id: str = _TENANT,
) -> FaEvidenceFreshnessRecord:
    now = _now_str()
    rec = FaEvidenceFreshnessRecord(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        freshness_score=freshness_score,
        freshness_state=freshness_state,
        created_at=now,
        updated_at=now,
    )
    db.add(rec)
    db.flush()
    return rec


def _make_exception(
    db: Session,
    evidence_id: str,
    status: str = "ACTIVE",
    expires_at: str | None = None,
    tenant_id: str = _TENANT,
) -> FaFreshnessException:
    now = _now_str()
    exc = FaFreshnessException(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        reason="test exception",
        approved_by="test-approver",
        expires_at=expires_at or _FUTURE,
        status=status,
        created_at=now,
    )
    db.add(exc)
    db.flush()
    return exc


def _make_snapshot(
    db: Session,
    evidence_id: str,
    capture_date: str,
    freshness_score: int = 80,
    tenant_id: str = _TENANT,
) -> FaFreshnessScoreSnapshot:
    snap = FaFreshnessScoreSnapshot(
        id=_uid(),
        tenant_id=tenant_id,
        evidence_id=evidence_id,
        freshness_score=freshness_score,
        capture_date=capture_date,
    )
    db.add(snap)
    db.flush()
    return snap


def _engine(db: Session, tenant_id: str = _TENANT) -> ControlEffectivenessEngine:
    return ControlEffectivenessEngine(db, tenant_id=tenant_id)


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
# CE-1 to CE-20: Pure function tests — scoring model
# ===========================================================================


class TestScoringModelPureFunctions:
    """CE-1 through CE-20: scoring model functions."""

    def test_CE_1_classify_highly_effective(self):
        assert classify_effectiveness(95.0) == EffectivenessLevel.HIGHLY_EFFECTIVE

    def test_CE_2_classify_effective(self):
        assert classify_effectiveness(80.0) == EffectivenessLevel.EFFECTIVE

    def test_CE_3_classify_adequate(self):
        assert classify_effectiveness(65.0) == EffectivenessLevel.ADEQUATE

    def test_CE_4_classify_weak(self):
        assert classify_effectiveness(50.0) == EffectivenessLevel.WEAK

    def test_CE_5_classify_ineffective(self):
        assert classify_effectiveness(30.0) == EffectivenessLevel.INEFFECTIVE

    def test_CE_6_classify_boundary_90(self):
        assert classify_effectiveness(90.0) == EffectivenessLevel.HIGHLY_EFFECTIVE

    def test_CE_7_classify_boundary_75(self):
        assert classify_effectiveness(75.0) == EffectivenessLevel.EFFECTIVE

    def test_CE_8_classify_boundary_60(self):
        assert classify_effectiveness(60.0) == EffectivenessLevel.ADEQUATE

    def test_CE_9_classify_boundary_40(self):
        assert classify_effectiveness(40.0) == EffectivenessLevel.WEAK

    def test_CE_10_classify_boundary_0(self):
        assert classify_effectiveness(0.0) == EffectivenessLevel.INEFFECTIVE

    def test_CE_11_risk_low_for_highly_effective(self):
        assert (
            classify_risk(EffectivenessLevel.HIGHLY_EFFECTIVE) == EffectivenessRisk.LOW
        )

    def test_CE_12_risk_low_for_effective(self):
        assert classify_risk(EffectivenessLevel.EFFECTIVE) == EffectivenessRisk.LOW

    def test_CE_13_risk_medium_for_adequate(self):
        assert classify_risk(EffectivenessLevel.ADEQUATE) == EffectivenessRisk.MEDIUM

    def test_CE_14_risk_high_for_weak(self):
        assert classify_risk(EffectivenessLevel.WEAK) == EffectivenessRisk.HIGH

    def test_CE_15_risk_critical_for_ineffective(self):
        assert (
            classify_risk(EffectivenessLevel.INEFFECTIVE) == EffectivenessRisk.CRITICAL
        )

    def test_CE_16_trend_improving(self):
        assert classify_trend(10.0).value == "IMPROVING"

    def test_CE_17_trend_stable(self):
        assert classify_trend(0.0).value == "STABLE"

    def test_CE_18_trend_degrading(self):
        assert classify_trend(-8.0).value == "DEGRADING"

    def test_CE_19_trend_critical(self):
        assert classify_trend(-20.0).value == "CRITICAL"

    def test_CE_20_compute_effectiveness_score_weighted(self):
        score = compute_effectiveness_score(100, 100, 100, 100, 100, 100, 100)
        assert score == 100.0

    def test_CE_20b_compute_effectiveness_score_zero(self):
        score = compute_effectiveness_score(0, 0, 0, 0, 0, 0, 0)
        assert score == 0.0

    def test_CE_20c_compute_effectiveness_score_partial(self):
        score = compute_effectiveness_score(50, 50, 50, 50, 50, 50, 50)
        assert score == 50.0

    def test_CE_20d_compute_effectiveness_score_clamped(self):
        score = compute_effectiveness_score(110, 110, 110, 110, 110, 110, 110)
        assert score == 100.0

    def test_CE_20e_scoring_model_version(self):
        assert SCORING_MODEL_VERSION == "1.0"


# ===========================================================================
# CE-21 to CE-40: Coverage score
# ===========================================================================


class TestCoverageScore:
    """CE-21 through CE-40: _compute_coverage_score."""

    def test_CE_21_no_evidence_returns_zero(self, db):
        eng = _engine(db)
        score = eng._compute_coverage_score("control-orphan")
        assert score == 0.0

    def test_CE_22_single_active_unverified_evidence(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, trust_state="UNVERIFIED")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert score > 0.0

    def test_CE_23_verified_evidence_boosts_score(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, trust_state="VERIFIED")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score_v = eng._compute_coverage_score(cid)
        cid2 = f"ctl-{_uid()}"
        ev2 = _make_evidence(db, trust_state="UNVERIFIED")
        _link_evidence(db, ev2.id, cid2)
        score_u = eng._compute_coverage_score(cid2)
        assert score_v > score_u

    def test_CE_24_high_confidence_treated_as_verified(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, trust_state="HIGH_CONFIDENCE")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert score > 0.0

    def test_CE_25_revoked_evidence_not_counted_as_active(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, lifecycle_state="REVOKED", trust_state="VERIFIED")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        # base score still > 0 (count×10), but verified_ratio = 0
        assert score < 60.0

    def test_CE_26_expired_evidence_not_counted_as_active(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, lifecycle_state="EXPIRED", trust_state="VERIFIED")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert score < 60.0

    def test_CE_27_archived_evidence_not_counted_as_active(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, lifecycle_state="ARCHIVED")
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert score < 60.0

    def test_CE_28_10_evidence_caps_base_at_100(self, db):
        cid = f"ctl-{_uid()}"
        for _ in range(12):
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert score <= 100.0

    def test_CE_29_tenant_isolation_in_coverage(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, tenant_id=_TENANT_B)
        _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
        eng = _engine(db, tenant_id=_TENANT)
        score = eng._compute_coverage_score(cid)
        assert score == 0.0

    def test_CE_30_score_is_float(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert isinstance(score, float)

    def test_CE_31_all_verified_full_ratio(self, db):
        cid = f"ctl-{_uid()}"
        for _ in range(5):
            ev = _make_evidence(db, trust_state="VERIFIED")
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        # base=50, verified_ratio=100 → 50×0.6 + 100×0.4 = 70.0
        assert abs(score - 70.0) < 1.0

    def test_CE_32_score_bounded_between_0_and_100(self, db):
        cid = f"ctl-{_uid()}"
        for _ in range(15):
            ev = _make_evidence(db, trust_state="VERIFIED")
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_coverage_score(cid)
        assert 0.0 <= score <= 100.0


# ===========================================================================
# CE-41 to CE-60: Verification score
# ===========================================================================


class TestVerificationScore:
    """CE-41 through CE-60: _compute_verification_score."""

    def test_CE_41_no_evidence_returns_zero(self, db):
        eng = _engine(db)
        assert eng._compute_verification_score("ctrl-orphan-v") == 0.0

    def test_CE_42_evidence_with_no_verifications_returns_zero(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        assert eng._compute_verification_score(cid) == 0.0

    def test_CE_43_all_pass_returns_high_score(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="PASS")
        _make_verification(db, ev.id, result="PASS")
        eng = _engine(db)
        score = eng._compute_verification_score(cid)
        assert score > 80.0

    def test_CE_44_mix_of_pass_fail_reduces_score(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="PASS")
        _make_verification(db, ev.id, result="FAIL")
        eng = _engine(db)
        score = eng._compute_verification_score(cid)
        cid2 = f"ctl-{_uid()}"
        ev2 = _make_evidence(db)
        _link_evidence(db, ev2.id, cid2)
        _make_verification(db, ev2.id, result="PASS")
        _make_verification(db, ev2.id, result="PASS")
        score2 = eng._compute_verification_score(cid2)
        assert score < score2

    def test_CE_45_approved_counts_as_passing(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="APPROVED")
        eng = _engine(db)
        score = eng._compute_verification_score(cid)
        assert score > 0.0

    def test_CE_46_verified_result_counts_as_passing(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="VERIFIED")
        eng = _engine(db)
        score = eng._compute_verification_score(cid)
        assert score > 0.0

    def test_CE_47_score_bounded_0_to_100(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="PASS")
        eng = _engine(db)
        assert 0.0 <= eng._compute_verification_score(cid) <= 100.0

    def test_CE_48_many_failures_penalized(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        for _ in range(7):
            _make_verification(db, ev.id, result="FAIL")
        eng = _engine(db)
        score = eng._compute_verification_score(cid)
        assert score == 0.0  # 30-point failure cap + 0% pass rate

    def test_CE_49_tenant_isolation_in_verification(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, tenant_id=_TENANT_B)
        _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
        _make_verification(db, ev.id, result="PASS", tenant_id=_TENANT_B)
        eng = _engine(db, tenant_id=_TENANT)
        assert eng._compute_verification_score(cid) == 0.0

    def test_CE_50_score_is_float(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_verification(db, ev.id, result="PASS")
        eng = _engine(db)
        assert isinstance(eng._compute_verification_score(cid), float)


# ===========================================================================
# CE-61 to CE-75: Freshness score
# ===========================================================================


class TestFreshnessScore:
    """CE-61 through CE-75."""

    def test_CE_61_no_evidence_returns_50(self, db):
        eng = _engine(db)
        assert eng._compute_freshness_score("ctrl-orphan-f") == 50.0

    def test_CE_62_no_freshness_records_returns_50(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        assert eng._compute_freshness_score(cid) == 50.0

    def test_CE_63_avg_freshness_from_records(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_score=80)
        eng = _engine(db)
        score = eng._compute_freshness_score(cid)
        assert abs(score - 80.0) < 2.0

    def test_CE_64_active_exception_adds_bonus(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_score=70)
        cid2 = f"ctl-{_uid()}"
        ev2 = _make_evidence(db)
        _link_evidence(db, ev2.id, cid2)
        _make_freshness_record(db, ev2.id, freshness_score=70)
        _make_exception(db, ev2.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        score_no_exc = eng._compute_freshness_score(cid)
        score_with_exc = eng._compute_freshness_score(cid2)
        assert score_with_exc > score_no_exc

    def test_CE_65_expired_exception_no_bonus(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_score=70)
        past = (_NOW - timedelta(days=5)).isoformat()
        _make_exception(db, ev.id, status="ACTIVE", expires_at=past)
        eng = _engine(db)
        score = eng._compute_freshness_score(cid)
        assert abs(score - 70.0) < 2.0  # no bonus from expired exception

    def test_CE_66_score_bounded_0_to_100(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_score=100)
        for _ in range(5):
            _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        assert eng._compute_freshness_score(cid) <= 100.0

    def test_CE_67_bonus_capped_at_10(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_score=50)
        for _ in range(10):
            _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        score = eng._compute_freshness_score(cid)
        assert score <= 60.0 + 0.1  # 50 + 10 max bonus


# ===========================================================================
# CE-76 to CE-95: Trend data
# ===========================================================================


class TestTrendData:
    """CE-76 through CE-95."""

    def test_CE_76_no_evidence_returns_stable(self, db):
        eng = _engine(db)
        score, direction, d7, d30, d90 = eng._compute_trend_data("ctrl-no-ev")
        assert direction == "STABLE"
        assert d7 is None and d30 is None and d90 is None

    def test_CE_77_single_snapshot_returns_stable(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_10D, 80)
        eng = _engine(db)
        score, direction, _, _, _ = eng._compute_trend_data(cid)
        assert direction == "STABLE"

    def test_CE_78_improving_trend_detected(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 50)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 80)
        eng = _engine(db)
        _, direction, _, d30, _ = eng._compute_trend_data(cid)
        assert direction == "IMPROVING"
        assert d30 is not None and d30 > 0

    def test_CE_79_degrading_trend_detected(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 80)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 65)
        eng = _engine(db)
        _, direction, _, d30, _ = eng._compute_trend_data(cid)
        assert direction in ("DEGRADING", "STABLE")

    def test_CE_80_critical_trend_detected(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 90)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 60)
        eng = _engine(db)
        _, direction, _, d30, _ = eng._compute_trend_data(cid)
        assert direction == "CRITICAL"

    def test_CE_81_trend_score_in_0_to_100(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 70)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 80)
        eng = _engine(db)
        score, _, _, _, _ = eng._compute_trend_data(cid)
        assert 0.0 <= score <= 100.0

    def test_CE_82_2x_window_constraint_no_baseline_too_old(self, db):
        # Snapshot at day -95 is beyond 2× window for 30d (must be >= day-60)
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_95D, 50)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 80)
        eng = _engine(db)
        _, _, _, d30, _ = eng._compute_trend_data(cid)
        assert d30 is None  # baseline too old; no delta

    def test_CE_83_delta_7d_computed(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_10D, 70)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 80)
        eng = _engine(db)
        _, _, d7, _, _ = eng._compute_trend_data(cid)
        assert d7 is not None

    def test_CE_84_tenant_isolation_trend(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, tenant_id=_TENANT_B)
        _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
        _make_snapshot(db, ev.id, _PAST_35D, 50, tenant_id=_TENANT_B)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 90, tenant_id=_TENANT_B)
        eng = _engine(db, tenant_id=_TENANT)
        score, direction, _, _, _ = eng._compute_trend_data(cid)
        # Should return default stable since no data for _TENANT
        assert direction == "STABLE"


# ===========================================================================
# CE-96 to CE-110: Forecast + density + exception + governance health
# ===========================================================================


class TestForecastAndOtherComponents:
    """CE-96 through CE-110."""

    def test_CE_96_forecast_no_evidence_returns_65(self, db):
        eng = _engine(db)
        assert eng._compute_forecast_score("ctrl-orphan-fc") == 65.0

    def test_CE_97_forecast_no_snapshots_returns_65(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        assert eng._compute_forecast_score(cid) == 65.0

    def test_CE_98_improving_velocity_raises_forecast(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 50)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 80)
        eng = _engine(db)
        score = eng._compute_forecast_score(cid)
        assert score > 65.0

    def test_CE_99_declining_velocity_lowers_forecast(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 90)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 60)
        eng = _engine(db)
        score = eng._compute_forecast_score(cid)
        assert score < 65.0

    def test_CE_100_forecast_bounded_10_to_90(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_snapshot(db, ev.id, _PAST_35D, 0)
        today = _NOW.strftime("%Y-%m-%d")
        _make_snapshot(db, ev.id, today, 0)
        eng = _engine(db)
        score = eng._compute_forecast_score(cid)
        assert 10.0 <= score <= 90.0

    def test_CE_101_density_no_evidence_returns_zero(self, db):
        eng = _engine(db)
        assert eng._compute_evidence_density_score("ctrl-orphan-d") == 0.0

    def test_CE_102_density_grows_with_evidence_count(self, db):
        cid = f"ctl-{_uid()}"
        for _ in range(5):
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_evidence_density_score(cid)
        assert score > 0.0

    def test_CE_103_density_diverse_sources_boost(self, db):
        cid = f"ctl-{_uid()}"
        for src in ["JIRA", "GITHUB", "CONFLUENCE", "SPLUNK"]:
            ev = _make_evidence(db, source_system=src)
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        score = eng._compute_evidence_density_score(cid)
        assert score > 0.0

    def test_CE_104_exception_no_evidence_returns_100(self, db):
        eng = _engine(db)
        assert eng._compute_exception_score("ctrl-orphan-e") == 100.0

    def test_CE_105_open_exception_penalizes_score(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        score = eng._compute_exception_score(cid)
        assert score < 100.0

    def test_CE_106_two_open_exceptions_greater_penalty(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        score2 = eng._compute_exception_score(cid)
        cid3 = f"ctl-{_uid()}"
        ev3 = _make_evidence(db)
        _link_evidence(db, ev3.id, cid3)
        _make_exception(db, ev3.id, status="ACTIVE", expires_at=_FUTURE)
        score1 = eng._compute_exception_score(cid3)
        assert score2 < score1

    def test_CE_107_exception_score_bounded_0_to_100(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        for _ in range(20):
            _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        assert eng._compute_exception_score(cid) == 0.0

    def test_CE_108_governance_health_no_evidence_returns_50(self, db):
        eng = _engine(db)
        assert eng._compute_governance_health_score("ctrl-orphan-g") == 50.0

    def test_CE_109_overdue_freshness_penalizes_health(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        _make_freshness_record(db, ev.id, freshness_state="EXPIRED")
        eng = _engine(db)
        score = eng._compute_governance_health_score(cid)
        assert score < 100.0

    def test_CE_110_health_score_bounded_0_to_100(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        for _ in range(20):
            _make_freshness_record(db, ev.id, freshness_state="EXPIRED")
            _make_exception(db, ev.id, status="ACTIVE", expires_at=_FUTURE)
        eng = _engine(db)
        score = eng._compute_governance_health_score(cid)
        assert 0.0 <= score <= 100.0


# ===========================================================================
# CE-126 to CE-155: Recalculate + history + repository
# ===========================================================================


class TestRecalculate:
    """CE-126 through CE-155: recalculate, recalculate_all, get_history."""

    def test_CE_126_recalculate_returns_response(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        result = eng.recalculate(cid)
        assert result.control_id == cid
        assert result.tenant_id == _TENANT

    def test_CE_127_effectiveness_score_in_range(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        result = _engine(db).recalculate(cid)
        assert 0.0 <= result.effectiveness_score <= 100.0

    def test_CE_128_level_is_valid_string(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        result = _engine(db).recalculate(cid)
        assert result.effectiveness_level in {
            "HIGHLY_EFFECTIVE",
            "EFFECTIVE",
            "ADEQUATE",
            "WEAK",
            "INEFFECTIVE",
        }

    def test_CE_129_risk_is_valid_string(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        result = _engine(db).recalculate(cid)
        assert result.effectiveness_risk in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    def test_CE_130_calculation_version_set(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        result = _engine(db).recalculate(cid)
        assert result.calculation_version == SCORING_MODEL_VERSION

    def test_CE_131_upsert_idempotent_second_call_updates(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        r1 = eng.recalculate(cid)
        r2 = eng.recalculate(cid)
        assert r2.id == r1.id  # same current record
        rows = (
            db.query(FaControlEffectiveness)
            .filter(
                FaControlEffectiveness.tenant_id == _TENANT,
                FaControlEffectiveness.control_id == cid,
            )
            .all()
        )
        assert len(rows) == 1

    def test_CE_132_history_appended_on_each_recalculate(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        eng.recalculate(cid)
        history_rows = (
            db.query(FaControlEffectivenessHistory)
            .filter(
                FaControlEffectivenessHistory.tenant_id == _TENANT,
                FaControlEffectivenessHistory.control_id == cid,
            )
            .all()
        )
        assert len(history_rows) == 2

    def test_CE_133_get_effectiveness_raises_not_found_for_unknown(self, db):
        eng = _engine(db)
        with pytest.raises(ControlNotFound):
            eng.get_effectiveness("ctrl-does-not-exist")

    def test_CE_134_get_effectiveness_returns_after_recalculate(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        result = eng.get_effectiveness(cid)
        assert result.control_id == cid

    def test_CE_135_recalculate_all_counts_correctly(self, db):
        cids = [f"ctl-{_uid()}" for _ in range(3)]
        for cid in cids:
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        result = eng.recalculate_all()
        assert result.controls_recalculated >= 3

    def test_CE_136_recalculate_all_returns_none_control_id(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        result = _engine(db).recalculate_all()
        assert result.control_id is None

    def test_CE_137_list_effectiveness_returns_items(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        result = eng.list_effectiveness(limit=10, offset=0)
        assert result.total >= 1
        assert any(r.control_id == cid for r in result.items)

    def test_CE_138_get_history_paginated(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        for _ in range(3):
            eng.recalculate(cid)
        result = eng.get_history(cid, limit=2, offset=0)
        assert len(result.items) == 2
        assert result.total == 3

    def test_CE_139_get_history_empty_for_unknown_control(self, db):
        eng = _engine(db)
        result = eng.get_history("ctrl-no-hist", limit=10, offset=0)
        assert result.total == 0
        assert result.items == []

    def test_CE_140_history_items_have_captured_at(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        result = eng.get_history(cid, limit=10, offset=0)
        assert result.items[0].captured_at is not None

    def test_CE_141_tenant_isolation_recalculate(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, tenant_id=_TENANT_B)
        _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
        eng = _engine(db, tenant_id=_TENANT_B)
        eng.recalculate(cid)
        eng_a = _engine(db, tenant_id=_TENANT)
        with pytest.raises(ControlNotFound):
            eng_a.get_effectiveness(cid)

    def test_CE_142_list_effectiveness_sorted_by_score_desc(self, db):
        cids = [f"ctl-{_uid()}" for _ in range(3)]
        for cid in cids:
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        for cid in cids:
            eng.recalculate(cid)
        result = eng.list_effectiveness(limit=100, offset=0)
        scores = [r.effectiveness_score for r in result.items]
        assert scores == sorted(scores, reverse=True)


# ===========================================================================
# CE-151 to CE-175: Dashboard + CGIN
# ===========================================================================


class TestDashboardAndCGIN:
    """CE-151 through CE-175."""

    def test_CE_151_dashboard_empty_returns_zeros(self, db):
        eng = ControlEffectivenessEngine(db, tenant_id=f"t-empty-{_uid()}")
        dash = eng.get_dashboard()
        assert dash.total_controls == 0
        assert dash.average_effectiveness_score == 0.0

    def test_CE_152_dashboard_counts_levels(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        dash = eng.get_dashboard()
        total = (
            dash.highly_effective_count
            + dash.effective_count
            + dash.adequate_count
            + dash.weak_count
            + dash.ineffective_count
        )
        assert total == dash.total_controls

    def test_CE_153_dashboard_has_generated_at(self, db):
        eng = _engine(db)
        dash = eng.get_dashboard()
        assert dash.generated_at is not None

    def test_CE_154_dashboard_top_controls_max_5(self, db):
        for _ in range(8):
            cid = f"ctl-{_uid()}"
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
            _engine(db).recalculate(cid)
        dash = _engine(db).get_dashboard()
        assert len(dash.top_controls) <= 5

    def test_CE_155_dashboard_weak_controls_max_5(self, db):
        dash = _engine(db).get_dashboard()
        assert len(dash.weak_controls) <= 5

    def test_CE_156_cgin_empty_returns_zeros(self, db):
        eng = ControlEffectivenessEngine(db, tenant_id=f"t-empty2-{_uid()}")
        snap = eng.get_cgin_snapshot()
        assert snap.total_controls == 0
        assert snap.average_effectiveness == 0.0

    def test_CE_157_cgin_distribution_sums_to_total(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        eng.recalculate(cid)
        snap = eng.get_cgin_snapshot()
        dist_total = sum(snap.effectiveness_distribution.values())
        assert dist_total == snap.total_controls

    def test_CE_158_cgin_has_generated_at(self, db):
        snap = _engine(db).get_cgin_snapshot()
        assert snap.generated_at is not None

    def test_CE_159_cgin_has_top_and_weak_controls(self, db):
        snap = _engine(db).get_cgin_snapshot()
        assert isinstance(snap.top_controls, list)
        assert isinstance(snap.weak_controls, list)

    def test_CE_160_cgin_high_risk_count_gte_zero(self, db):
        snap = _engine(db).get_cgin_snapshot()
        assert snap.high_risk_controls >= 0
        assert snap.critical_risk_controls >= 0


# ===========================================================================
# CE-176 to CE-200: API routes
# ===========================================================================


class TestAPIRoutes:
    """CE-176 through CE-200: HTTP endpoint tests."""

    def test_CE_176_get_dashboard_200(self, client):
        resp = client.get("/control-effectiveness/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_controls" in data

    def test_CE_177_get_cgin_snapshot_200(self, client):
        resp = client.get("/control-effectiveness/cgin/snapshot")
        assert resp.status_code == 200
        assert "average_effectiveness" in resp.json()

    def test_CE_178_list_effectiveness_200(self, client):
        resp = client.get("/control-effectiveness")
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_CE_179_post_recalculate_all_200(self, client):
        resp = client.post("/control-effectiveness/recalculate", json={})
        assert resp.status_code == 200
        assert "controls_recalculated" in resp.json()

    def test_CE_180_post_recalculate_single_not_found_404(self, client):
        resp = client.post(
            "/control-effectiveness/recalculate",
            json={"control_id": "ctrl-does-not-exist"},
        )
        assert resp.status_code == 404

    def test_CE_181_get_control_not_found_404(self, client):
        resp = client.get("/control-effectiveness/ctrl-does-not-exist")
        assert resp.status_code == 404

    def test_CE_182_get_history_unknown_control_returns_empty(self, client):
        resp = client.get("/control-effectiveness/history/ctrl-does-not-exist")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_CE_183_dashboard_route_not_captured_by_path_param(self, client):
        # Verifies /dashboard is not mistakenly served by /{control_id}
        resp = client.get("/control-effectiveness/dashboard")
        data = resp.json()
        assert "total_controls" in data  # proper dashboard response

    def test_CE_184_cgin_snapshot_route_not_captured_by_path_param(self, client):
        resp = client.get("/control-effectiveness/cgin/snapshot")
        data = resp.json()
        assert "average_effectiveness" in data

    def test_CE_185_list_pagination_limit_offset(self, client):
        resp = client.get("/control-effectiveness?limit=5&offset=0")
        assert resp.status_code == 200

    def test_CE_186_history_pagination_params(self, client):
        resp = client.get("/control-effectiveness/history/ctrl-xyz?limit=10&offset=0")
        assert resp.status_code == 200

    def test_CE_187_list_invalid_limit_422(self, client):
        resp = client.get("/control-effectiveness?limit=0")
        assert resp.status_code == 422

    def test_CE_188_list_invalid_offset_422(self, client):
        resp = client.get("/control-effectiveness?offset=-1")
        assert resp.status_code == 422

    def test_CE_189_list_limit_above_max_422(self, client):
        resp = client.get("/control-effectiveness?limit=999")
        assert resp.status_code == 422

    def test_CE_190_recalculate_bad_body_422(self, client):
        resp = client.post(
            "/control-effectiveness/recalculate", json={"unknown_field": "x"}
        )
        assert resp.status_code == 422

    def test_CE_191_recalculate_null_control_id_recalculates_all(self, client):
        resp = client.post(
            "/control-effectiveness/recalculate", json={"control_id": None}
        )
        assert resp.status_code == 200
        assert resp.json()["control_id"] is None

    def test_CE_192_response_schema_fields_present(self, build_app):
        build_app(auth_enabled=False)
        from api.db import get_engine

        with Session(get_engine()) as db:
            t = f"t-schema-{_uid()}"
            cid = f"ctl-{_uid()}"
            ev = _make_evidence(db, tenant_id=t)
            _link_evidence(db, ev.id, cid, tenant_id=t)
            eng = ControlEffectivenessEngine(db, tenant_id=t)
            eng.recalculate(cid)
            result = eng.get_effectiveness(cid)
        assert hasattr(result, "effectiveness_score")
        assert hasattr(result, "effectiveness_level")
        assert hasattr(result, "effectiveness_risk")
        assert hasattr(result, "last_calculated_at")
        assert hasattr(result, "calculation_version")


# ===========================================================================
# CE-201 to CE-220: Scope enforcement + tenant isolation
# ===========================================================================


class TestScopeAndTenantEnforcement:
    """CE-201 through CE-220."""

    def test_CE_201_wrong_scope_dashboard_403(self, wrong_scope_client):
        resp = wrong_scope_client.get("/control-effectiveness/dashboard")
        assert resp.status_code == 403

    def test_CE_202_wrong_scope_cgin_403(self, wrong_scope_client):
        resp = wrong_scope_client.get("/control-effectiveness/cgin/snapshot")
        assert resp.status_code == 403

    def test_CE_203_wrong_scope_list_403(self, wrong_scope_client):
        resp = wrong_scope_client.get("/control-effectiveness")
        assert resp.status_code == 403

    def test_CE_204_wrong_scope_get_control_403(self, wrong_scope_client):
        resp = wrong_scope_client.get("/control-effectiveness/ctrl-123")
        assert resp.status_code == 403

    def test_CE_205_wrong_scope_recalculate_403(self, wrong_scope_client):
        resp = wrong_scope_client.post("/control-effectiveness/recalculate", json={})
        assert resp.status_code == 403

    def test_CE_206_wrong_scope_history_403(self, wrong_scope_client):
        resp = wrong_scope_client.get("/control-effectiveness/history/ctrl-123")
        assert resp.status_code == 403

    def test_CE_207_read_only_scope_blocks_recalculate(self, ro_client):
        resp = ro_client.post("/control-effectiveness/recalculate", json={})
        assert resp.status_code == 403

    def test_CE_208_no_auth_header_401(self, build_app):
        app = build_app(auth_enabled=True)
        c = TestClient(app)
        resp = c.get("/control-effectiveness/dashboard")
        assert resp.status_code in (401, 403)

    def test_CE_209_tenant_isolation_get_returns_404(self, build_app):
        app = build_app(auth_enabled=True)
        # Create record under TENANT_B
        with Session(get_engine()) as db:
            cid = f"ctl-{_uid()}"
            ev = _make_evidence(db, tenant_id=_TENANT_B)
            _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
            ControlEffectivenessEngine(db, tenant_id=_TENANT_B).recalculate(cid)
        # Read with TENANT key should 404
        key = mint_key("governance:read", tenant_id=_TENANT)
        c = TestClient(app, headers={"X-API-Key": key, "X-Tenant-Id": _TENANT})
        resp = c.get(f"/control-effectiveness/{cid}")
        assert resp.status_code == 404

    def test_CE_210_tenant_b_list_does_not_include_tenant_a_records(self, build_app):
        app = build_app(auth_enabled=True)
        with Session(get_engine()) as db:
            cid = f"ctl-a-{_uid()}"
            ev = _make_evidence(db, tenant_id=_TENANT)
            _link_evidence(db, ev.id, cid, tenant_id=_TENANT)
            ControlEffectivenessEngine(db, tenant_id=_TENANT).recalculate(cid)
        key_b = mint_key("governance:read", tenant_id=_TENANT_B)
        c_b = TestClient(app, headers={"X-API-Key": key_b, "X-Tenant-Id": _TENANT_B})
        resp = c_b.get("/control-effectiveness")
        data = resp.json()
        assert all(r["tenant_id"] == _TENANT_B for r in data["items"])


# ===========================================================================
# CE-221+: ORM guards, timeline adapter, adapter completeness
# ===========================================================================


class TestOrmGuards:
    """CE-221 through CE-230: ORM immutability guards."""

    def test_CE_221_effectiveness_delete_blocked(self, db):
        row = FaControlEffectiveness(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=f"ctl-{_uid()}",
            effectiveness_score=75.0,
            effectiveness_level="EFFECTIVE",
            effectiveness_risk="LOW",
            last_calculated_at=_now_str(),
            calculation_version="1.0",
        )
        db.add(row)
        db.flush()
        with pytest.raises(Exception):
            db.delete(row)
            db.flush()
        db.rollback()

    def test_CE_222_history_update_blocked(self, db):
        row = FaControlEffectivenessHistory(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=f"ctl-{_uid()}",
            effectiveness_score=75.0,
            effectiveness_level="EFFECTIVE",
            effectiveness_risk="LOW",
            captured_at=_now_str(),
        )
        db.add(row)
        db.flush()
        with pytest.raises(Exception):
            row.effectiveness_score = 50.0
            db.flush()
        db.rollback()

    def test_CE_223_history_delete_blocked(self, db):
        row = FaControlEffectivenessHistory(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=f"ctl-{_uid()}",
            effectiveness_score=75.0,
            effectiveness_level="EFFECTIVE",
            effectiveness_risk="LOW",
            captured_at=_now_str(),
        )
        db.add(row)
        db.flush()
        with pytest.raises(Exception):
            db.delete(row)
            db.flush()
        db.rollback()

    def test_CE_224_effectiveness_update_allowed(self, db):
        # Update (recalculation) must NOT be blocked on fa_control_effectiveness
        row = FaControlEffectiveness(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=f"ctl-{_uid()}",
            effectiveness_score=75.0,
            effectiveness_level="EFFECTIVE",
            effectiveness_risk="LOW",
            last_calculated_at=_now_str(),
            calculation_version="1.0",
        )
        db.add(row)
        db.flush()
        row.effectiveness_score = 80.0  # should not raise
        db.flush()


class TestTimelineAdapter:
    """CE-231 through CE-240: timeline adapter."""

    def test_CE_231_control_effectiveness_source_type_exists(self):
        assert SourceType.CONTROL_EFFECTIVENESS == "CONTROL_EFFECTIVENESS"

    def test_CE_232_adapter_in_timeline_adapters(self):
        from services.governance.timeline.adapters import TIMELINE_ADAPTERS

        assert SourceType.CONTROL_EFFECTIVENESS in TIMELINE_ADAPTERS

    def test_CE_233_adapter_produces_timeline_event(self):
        from services.governance.timeline.adapters import (
            control_effectiveness_to_timeline_event,
        )

        event = control_effectiveness_to_timeline_event(
            tenant_id=_TENANT,
            source_id=_uid(),
            event_type="control_effectiveness.calculated",
            occurred_at=_NOW_ISO,
            payload={"effectiveness_score": 80.0},
        )
        assert event.tenant_id == _TENANT
        assert event.source_type == SourceType.CONTROL_EFFECTIVENESS
        assert event.event_type == "control_effectiveness.calculated"

    def test_CE_234_adapter_event_id_is_deterministic(self):
        from services.governance.timeline.adapters import (
            control_effectiveness_to_timeline_event,
        )

        sid = _uid()
        kwargs = dict(
            tenant_id=_TENANT,
            source_id=sid,
            event_type="control_effectiveness.calculated",
            occurred_at="2026-06-25T12:00:00Z",
        )
        e1 = control_effectiveness_to_timeline_event(**kwargs)
        e2 = control_effectiveness_to_timeline_event(**kwargs)
        assert e1.event_id == e2.event_id

    def test_CE_235_adapter_replay_eligible_default_false(self):
        from services.governance.timeline.adapters import (
            control_effectiveness_to_timeline_event,
        )

        event = control_effectiveness_to_timeline_event(
            tenant_id=_TENANT,
            source_id=_uid(),
            event_type="control_effectiveness.calculated",
            occurred_at=_NOW_ISO,
        )
        assert event.replay_eligible is False

    def test_CE_236_all_timeline_adapters_registered(self):
        from services.governance.timeline.adapters import TIMELINE_ADAPTERS

        for source_type in SourceType:
            assert source_type in TIMELINE_ADAPTERS, (
                f"SourceType.{source_type.name} missing from TIMELINE_ADAPTERS"
            )


class TestRepositoryMethods:
    """CE-241 through CE-250: repository boundary tests."""

    def test_CE_241_get_all_control_ids_returns_distinct(self, db):
        cid = f"ctl-{_uid()}"
        ev1 = _make_evidence(db)
        ev2 = _make_evidence(db)
        _link_evidence(db, ev1.id, cid)
        _link_evidence(db, ev2.id, cid)
        from services.control_effectiveness.repository import (
            ControlEffectivenessRepository,
        )

        repo = ControlEffectivenessRepository(db, _TENANT)
        ids = repo.get_all_control_ids()
        assert ids.count(cid) == 1

    def test_CE_242_list_effectiveness_pagination_offset(self, db):
        for _ in range(5):
            cid = f"ctl-{_uid()}"
            ev = _make_evidence(db)
            _link_evidence(db, ev.id, cid)
            _engine(db).recalculate(cid)
        eng = _engine(db)
        r1 = eng.list_effectiveness(limit=2, offset=0)
        r2 = eng.list_effectiveness(limit=2, offset=2)
        ids1 = {r.control_id for r in r1.items}
        ids2 = {r.control_id for r in r2.items}
        assert len(ids1.intersection(ids2)) == 0

    def test_CE_243_history_ordered_newest_first(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db)
        _link_evidence(db, ev.id, cid)
        eng = _engine(db)
        for _ in range(3):
            eng.recalculate(cid)
        result = eng.get_history(cid, limit=10, offset=0)
        dates = [r.captured_at for r in result.items]
        assert dates == sorted(dates, reverse=True)

    def test_CE_244_upsert_creates_new_record_when_none_exists(self, db):
        from services.control_effectiveness.repository import (
            ControlEffectivenessRepository,
        )

        cid = f"ctl-{_uid()}"
        repo = ControlEffectivenessRepository(db, _TENANT)
        assert repo.get_effectiveness(cid) is None
        row = FaControlEffectiveness(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=cid,
            effectiveness_score=75.0,
            effectiveness_level="EFFECTIVE",
            effectiveness_risk="LOW",
            last_calculated_at=_now_str(),
            calculation_version="1.0",
        )
        repo.upsert_effectiveness(row)
        assert repo.get_effectiveness(cid) is not None

    def test_CE_245_upsert_updates_existing_record(self, db):
        from services.control_effectiveness.repository import (
            ControlEffectivenessRepository,
        )

        cid = f"ctl-{_uid()}"
        repo = ControlEffectivenessRepository(db, _TENANT)
        row = FaControlEffectiveness(
            id=_uid(),
            tenant_id=_TENANT,
            control_id=cid,
            effectiveness_score=50.0,
            effectiveness_level="WEAK",
            effectiveness_risk="HIGH",
            last_calculated_at=_now_str(),
            calculation_version="1.0",
        )
        repo.upsert_effectiveness(row)
        row.effectiveness_score = 80.0
        row.effectiveness_level = "EFFECTIVE"
        row.effectiveness_risk = "LOW"
        repo.upsert_effectiveness(row)
        updated = repo.get_effectiveness(cid)
        assert updated.effectiveness_score == 80.0

    def test_CE_246_list_effectiveness_tenant_scoped(self, db):
        cid = f"ctl-{_uid()}"
        ev = _make_evidence(db, tenant_id=_TENANT_B)
        _link_evidence(db, ev.id, cid, tenant_id=_TENANT_B)
        ControlEffectivenessEngine(db, _TENANT_B).recalculate(cid)
        result = _engine(db, _TENANT).list_effectiveness(limit=100, offset=0)
        assert all(r.tenant_id == _TENANT for r in result.items)
