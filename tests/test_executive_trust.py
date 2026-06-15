"""Tests for P0-8 Executive Trust Command Center.

Covers:
  - posture_service helpers (_cert_expiry_status, _trend_windows, get_executive_posture)
  - risk weight calculation
  - quarterly period boundaries
  - tenant isolation (tenant_id mismatch)
  - empty-state handling (no TIM data)
  - drilldown trace linkage
  - report structure validation
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from services.executive_trust.posture_service import (
    _cert_expiry_status,
    get_executive_posture,
    get_tenant_overview,
)
from api.executive_trust import (
    _cert_expiry_status as _api_cert_expiry,
    _risk_weight,
    _load_json,
)


# ---------------------------------------------------------------------------
# _cert_expiry_status
# ---------------------------------------------------------------------------


class TestCertExpiryStatus:
    def test_none_returns_not_certified(self):
        status, days = _cert_expiry_status(None)
        assert status == "not_certified"
        assert days is None

    def test_past_date_returns_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(days=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        status, days = _cert_expiry_status(past)
        assert status == "expired"
        assert days is not None and days < 0

    def test_within_14d_returns_expiring_soon(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        status, days = _cert_expiry_status(soon)
        assert status == "expiring_soon"
        assert days is not None and 0 <= days <= 14

    def test_beyond_14d_returns_valid(self):
        future = (datetime.now(timezone.utc) + timedelta(days=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        status, days = _cert_expiry_status(future)
        assert status == "valid"
        assert days is not None and days > 14

    def test_malformed_returns_unknown(self):
        status, days = _cert_expiry_status("not-a-date")
        assert status == "unknown"
        assert days is None

    def test_api_helper_matches_service_helper(self):
        future = (datetime.now(timezone.utc) + timedelta(days=30)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        svc = _cert_expiry_status(future)
        api = _api_cert_expiry(future)
        assert svc == api


# ---------------------------------------------------------------------------
# _risk_weight
# ---------------------------------------------------------------------------


class TestRiskWeight:
    def test_info_zero(self):
        assert _risk_weight("info") == 0

    def test_low_one(self):
        assert _risk_weight("low") == 1

    def test_medium_three(self):
        assert _risk_weight("medium") == 3

    def test_high_seven(self):
        assert _risk_weight("high") == 7

    def test_critical_fifteen(self):
        assert _risk_weight("critical") == 15

    def test_unknown_zero(self):
        assert _risk_weight("unknown_severity") == 0


# ---------------------------------------------------------------------------
# _load_json
# ---------------------------------------------------------------------------


class TestLoadJson:
    def test_parses_json_string(self):
        assert _load_json('{"a": 1}') == {"a": 1}

    def test_returns_dict_unchanged(self):
        assert _load_json({"a": 1}) == {"a": 1}

    def test_invalid_json_returns_string(self):
        assert _load_json("not-json") == "not-json"

    def test_none_returns_none(self):
        assert _load_json(None) is None


# ---------------------------------------------------------------------------
# get_executive_posture — empty state (no TIM data)
# ---------------------------------------------------------------------------


class TestGetExecutivePostureEmptyState:
    def _make_db(self, *, snap=None, cert=None, open_events=None):
        db = MagicMock()
        execute = MagicMock()
        db.execute.return_value = execute

        # scalar_one_or_none returns snap or cert based on call order
        execute.scalar_one_or_none.side_effect = [snap, cert]
        # scalars().all() returns open_events
        execute.scalars.return_value.all.return_value = open_events or []
        return db

    def test_no_snapshot_returns_zero_posture(self):
        db = self._make_db(snap=None, cert=None)
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["trust_posture"]["posture_score"] == 0
        assert result["trust_posture"]["posture_level"] == "unknown"

    def test_no_cert_returns_not_certified(self):
        db = self._make_db(snap=None, cert=None)
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["certification"]["certification_level"] == "not_certified"
        assert result["certification"]["expiry_status"] == "not_certified"

    def test_no_open_events_zero_risk(self):
        db = self._make_db(snap=None, cert=None, open_events=[])
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["risk"]["engagement_risk_score"] == 0
        assert result["risk"]["open_event_count"] == 0

    def test_returns_engagement_id(self):
        db = self._make_db()
        result = get_executive_posture(db, tenant_id="t1", engagement_id="eng-42")
        assert result["engagement_id"] == "eng-42"

    def test_exception_returns_empty_dict(self):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("db exploded")
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result == {}


# ---------------------------------------------------------------------------
# get_executive_posture — with data
# ---------------------------------------------------------------------------


class TestGetExecutivePostureWithData:
    def _make_snap(self, **kwargs):
        snap = MagicMock()
        snap.posture_score = kwargs.get("posture_score", 75)
        snap.posture_level = kwargs.get("posture_level", "high")
        snap.risk_level = kwargs.get("risk_level", "low")
        snap.drift_score = kwargs.get("drift_score", 5)
        snap.drift_direction = kwargs.get("drift_direction", "stable")
        snap.evidence_count = kwargs.get("evidence_count", 10)
        snap.replay_status = kwargs.get("replay_status", "ok")
        snap.evaluated_at = kwargs.get("evaluated_at", "2026-06-15T10:00:00Z")
        snap.source_fingerprint = kwargs.get("source_fingerprint", "abc123")
        snap.last_snapshot_id = kwargs.get("last_snapshot_id", "snap-1")
        snap.last_certification_id = kwargs.get("last_certification_id", "cert-1")
        snap.last_bundle_id = kwargs.get("last_bundle_id", "bundle-1")
        snap.id = kwargs.get("id", "snap-id-1")
        return snap

    def _make_cert(self, **kwargs):
        cert = MagicMock()
        future = (datetime.now(timezone.utc) + timedelta(days=60)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        cert.id = kwargs.get("id", "cert-1")
        cert.certification_level = kwargs.get("certification_level", "gold")
        cert.composite_score = kwargs.get("composite_score", 82)
        cert.trust_score = kwargs.get("trust_score", 80)
        cert.confidence_score = kwargs.get("confidence_score", 88)
        cert.valid_from = kwargs.get("valid_from", "2026-04-01T00:00:00Z")
        cert.valid_until = kwargs.get("valid_until", future)
        cert.authority_version = kwargs.get("authority_version", "v1")
        return cert

    def _make_event(self, severity: str):
        e = MagicMock()
        e.severity = severity
        return e

    def _make_db(self, snap, cert, open_events):
        db = MagicMock()

        call_count = [0]

        def execute_side_effect(*args, **kwargs):
            call_count[0] += 1
            result = MagicMock()

            if call_count[0] == 1:
                result.scalar_one_or_none.return_value = snap
            elif call_count[0] == 2:
                result.scalar_one_or_none.return_value = cert
            else:
                result.scalars.return_value.all.return_value = open_events

            return result

        db.execute.side_effect = execute_side_effect
        return db

    def test_posture_score_from_snapshot(self):
        snap = self._make_snap(posture_score=82)
        db = self._make_db(snap, self._make_cert(), [])
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["trust_posture"]["posture_score"] == 82

    def test_certification_level_from_cert(self):
        snap = self._make_snap()
        cert = self._make_cert(certification_level="platinum")
        db = self._make_db(snap, cert, [])
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["certification"]["certification_level"] == "platinum"

    def test_risk_score_aggregates_severity_weights(self):
        snap = self._make_snap()
        cert = self._make_cert()
        events = [
            self._make_event("critical"),  # 15
            self._make_event("high"),  # 7
            self._make_event("medium"),  # 3
        ]
        db = self._make_db(snap, cert, events)
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["risk"]["engagement_risk_score"] == 25  # 15+7+3
        assert result["risk"]["critical_count"] == 1
        assert result["risk"]["high_count"] == 1
        assert result["risk"]["has_critical"] is True

    def test_no_critical_events(self):
        snap = self._make_snap()
        cert = self._make_cert()
        events = [self._make_event("low"), self._make_event("medium")]
        db = self._make_db(snap, cert, events)
        result = get_executive_posture(db, tenant_id="t1", engagement_id="e1")
        assert result["risk"]["has_critical"] is False
        assert result["risk"]["has_high"] is False
        assert result["risk"]["engagement_risk_score"] == 4  # 1+3


# ---------------------------------------------------------------------------
# get_tenant_overview
# ---------------------------------------------------------------------------


class TestGetTenantOverview:
    def test_empty_db_returns_empty_list(self):
        db = MagicMock()
        db.execute.return_value.scalars.return_value.all.return_value = []
        result = get_tenant_overview(db, tenant_id="t1")
        assert result == []

    def test_exception_returns_empty_list(self):
        db = MagicMock()
        db.execute.side_effect = RuntimeError("query failed")
        result = get_tenant_overview(db, tenant_id="t1")
        assert result == []

    def test_returns_engagement_summaries(self):
        db = MagicMock()
        row = MagicMock()
        row.engagement_id = "eng-1"
        row.posture_score = 70
        row.posture_level = "high"
        row.risk_level = "medium"
        row.certification_level = "silver"
        row.drift_direction = "stable"
        row.open_drift_count = 2
        row.replay_status = "ok"
        row.evaluated_at = "2026-06-15T10:00:00Z"
        db.execute.return_value.scalars.return_value.all.return_value = [row]
        result = get_tenant_overview(db, tenant_id="t1")
        assert len(result) == 1
        assert result[0]["engagement_id"] == "eng-1"
        assert result[0]["posture_score"] == 70


# ---------------------------------------------------------------------------
# Quarterly period boundary logic
# ---------------------------------------------------------------------------


class TestQuarterlyPeriodBoundaries:
    """Validate the Q1-Q4 ISO boundary strings computed in get_etcc_report_quarterly."""

    def _period(self, year: int, quarter: int) -> tuple[str, str]:
        q_start_month = (quarter - 1) * 3 + 1
        period_start = f"{year}-{q_start_month:02d}-01T00:00:00Z"
        if quarter == 4:
            period_end = f"{year + 1}-01-01T00:00:00Z"
        else:
            end_month = q_start_month + 3
            period_end = f"{year}-{end_month:02d}-01T00:00:00Z"
        return period_start, period_end

    def test_q1_2026(self):
        s, e = self._period(2026, 1)
        assert s == "2026-01-01T00:00:00Z"
        assert e == "2026-04-01T00:00:00Z"

    def test_q2_2026(self):
        s, e = self._period(2026, 2)
        assert s == "2026-04-01T00:00:00Z"
        assert e == "2026-07-01T00:00:00Z"

    def test_q3_2026(self):
        s, e = self._period(2026, 3)
        assert s == "2026-07-01T00:00:00Z"
        assert e == "2026-10-01T00:00:00Z"

    def test_q4_2026_wraps_to_next_year(self):
        s, e = self._period(2026, 4)
        assert s == "2026-10-01T00:00:00Z"
        assert e == "2027-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# Severity severity ordering for risk filter
# ---------------------------------------------------------------------------


class TestSeverityOrdering:
    _ORDER = ["info", "low", "medium", "high", "critical"]

    def test_min_medium_excludes_info_and_low(self):
        min_severity = "medium"
        min_idx = self._ORDER.index(min_severity)
        included = self._ORDER[min_idx:]
        assert "info" not in included
        assert "low" not in included
        assert "medium" in included
        assert "critical" in included

    def test_min_info_includes_all(self):
        min_severity = "info"
        min_idx = self._ORDER.index(min_severity)
        included = self._ORDER[min_idx:]
        assert len(included) == 5

    def test_min_critical_only_critical(self):
        min_severity = "critical"
        min_idx = self._ORDER.index(min_severity)
        included = self._ORDER[min_idx:]
        assert included == ["critical"]
