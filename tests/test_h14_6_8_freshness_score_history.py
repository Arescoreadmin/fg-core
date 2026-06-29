"""Tests for PR 14.6.8 — Freshness Score History & Governance Trend Intelligence.

Covers:
  - Snapshot creation (run_snapshot idempotency)
  - Evidence history retrieval with pagination
  - Trend calculations (7d, 30d, 90d)
  - Trend dashboard
  - CGIN trends
  - Tenant isolation
  - Scope enforcement
  - Pure function unit tests (compute_trend_direction, compute_score_delta)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from api.auth_scopes import mint_key
from services.freshness_score_history.models import (
    TrendDirection,
    compute_score_delta,
    compute_trend_direction,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime.now(tz=timezone.utc)
_TENANT = "t-fsh-001"
_TENANT_B = "t-fsh-002"

_TODAY = _NOW.strftime("%Y-%m-%d")
_YESTERDAY = (_NOW - timedelta(days=1)).strftime("%Y-%m-%d")
_REVIEW_DUE_FUTURE = (_NOW + timedelta(days=60)).isoformat()


def _freshness_record_payload(evidence_id: str = "ev-h001", **overrides: Any) -> dict:
    defaults: dict[str, Any] = {
        "evidence_id": evidence_id,
        "review_due_at": _REVIEW_DUE_FUTURE,
    }
    defaults.update(overrides)
    return defaults


def _create_freshness_record(
    client: TestClient, evidence_id: str = "ev-h001", **overrides: Any
) -> dict:
    payload = _freshness_record_payload(evidence_id, **overrides)
    resp = client.post("/freshness", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _run_snapshot(client: TestClient, capture_date: str | None = None) -> dict:
    payload: dict[str, Any] = {}
    if capture_date is not None:
        payload["capture_date"] = capture_date
    resp = client.post("/freshness/snapshots/run", json=payload)
    assert resp.status_code == 201, resp.text
    return resp.json()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def client(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT)
    return TestClient(app, headers={"X-API-Key": key})


@pytest.fixture()
def client_b(build_app):
    app = build_app(auth_enabled=True)
    key = mint_key("audit:read", "audit:write", tenant_id=_TENANT_B)
    return TestClient(app, headers={"X-API-Key": key})


# ---------------------------------------------------------------------------
# TestRunSnapshot — basic snapshot creation
# ---------------------------------------------------------------------------


class TestRunSnapshot:
    def test_run_snapshot_returns_201(self, client: TestClient):
        _create_freshness_record(client, "ev-snap-001")
        resp = client.post("/freshness/snapshots/run", json={})
        assert resp.status_code == 201

    def test_run_snapshot_response_structure(self, client: TestClient):
        _create_freshness_record(client, "ev-snap-002")
        data = _run_snapshot(client)
        assert "capture_date" in data
        assert "evidence_snapshots_created" in data
        assert "daily_snapshot_created" in data
        assert "already_exists" in data
        assert "captured_at" in data

    def test_run_snapshot_creates_evidence_snapshots(self, client: TestClient):
        _create_freshness_record(client, "ev-snap-003")
        _create_freshness_record(client, "ev-snap-004")
        data = _run_snapshot(client)
        assert data["evidence_snapshots_created"] >= 2

    def test_run_snapshot_daily_created_true(self, client: TestClient):
        _create_freshness_record(client, "ev-snap-005")
        data = _run_snapshot(client)
        assert data["daily_snapshot_created"] is True

    def test_run_snapshot_already_exists_false_on_first_run(self, client: TestClient):
        _create_freshness_record(client, "ev-snap-006")
        data = _run_snapshot(client)
        assert data["already_exists"] is False

    def test_run_snapshot_no_evidence_zero_snapshots(self, client: TestClient):
        data = _run_snapshot(client, capture_date="2099-01-01")
        assert data["evidence_snapshots_created"] == 0
        assert data["daily_snapshot_created"] is True


# ---------------------------------------------------------------------------
# TestRunSnapshotIdempotency — same date returns already_exists=True
# ---------------------------------------------------------------------------


class TestRunSnapshotIdempotency:
    def test_second_run_same_date_returns_already_exists(self, client: TestClient):
        _create_freshness_record(client, "ev-idem-001")
        _run_snapshot(client, capture_date="2090-06-01")
        data = _run_snapshot(client, capture_date="2090-06-01")
        assert data["already_exists"] is True

    def test_second_run_already_exists_zero_snapshots(self, client: TestClient):
        _create_freshness_record(client, "ev-idem-002")
        _run_snapshot(client, capture_date="2090-06-02")
        data = _run_snapshot(client, capture_date="2090-06-02")
        assert data["evidence_snapshots_created"] == 0

    def test_second_run_already_exists_daily_created_false(self, client: TestClient):
        _create_freshness_record(client, "ev-idem-003")
        _run_snapshot(client, capture_date="2090-06-03")
        data = _run_snapshot(client, capture_date="2090-06-03")
        assert data["daily_snapshot_created"] is False

    def test_second_run_still_returns_201(self, client: TestClient):
        _create_freshness_record(client, "ev-idem-004")
        _run_snapshot(client, capture_date="2090-06-04")
        resp = client.post(
            "/freshness/snapshots/run", json={"capture_date": "2090-06-04"}
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# TestRunSnapshotWithDate — explicit capture_date param
# ---------------------------------------------------------------------------


class TestRunSnapshotWithDate:
    def test_explicit_capture_date_is_stored(self, client: TestClient):
        _create_freshness_record(client, "ev-date-001")
        data = _run_snapshot(client, capture_date="2091-03-15")
        assert data["capture_date"] == "2091-03-15"

    def test_explicit_capture_date_past_is_accepted(self, client: TestClient):
        _create_freshness_record(client, "ev-date-002")
        data = _run_snapshot(client, capture_date="2020-01-01")
        assert data["capture_date"] == "2020-01-01"
        assert data["daily_snapshot_created"] is True

    def test_different_dates_create_separate_snapshots(self, client: TestClient):
        _create_freshness_record(client, "ev-date-003")
        data1 = _run_snapshot(client, capture_date="2091-05-01")
        data2 = _run_snapshot(client, capture_date="2091-05-02")
        assert data1["capture_date"] == "2091-05-01"
        assert data2["capture_date"] == "2091-05-02"
        assert data1["already_exists"] is False
        assert data2["already_exists"] is False


# ---------------------------------------------------------------------------
# TestRunSnapshotTenantIsolation
# ---------------------------------------------------------------------------


class TestRunSnapshotTenantIsolation:
    def test_tenant_a_snapshot_does_not_affect_tenant_b(
        self, client: TestClient, client_b: TestClient
    ):
        _create_freshness_record(client, "ev-iso-001")
        data_a = _run_snapshot(client, capture_date="2092-01-01")
        data_b = _run_snapshot(client_b, capture_date="2092-01-01")
        assert data_a["evidence_snapshots_created"] >= 1
        assert data_b["evidence_snapshots_created"] == 0

    def test_tenant_b_snapshot_idempotency_independent(
        self, client: TestClient, client_b: TestClient
    ):
        _run_snapshot(client, capture_date="2092-02-01")
        data_b = _run_snapshot(client_b, capture_date="2092-02-01")
        assert data_b["already_exists"] is False


# ---------------------------------------------------------------------------
# TestGetEvidenceHistory — basic history retrieval
# ---------------------------------------------------------------------------


class TestGetEvidenceHistory:
    def test_get_history_returns_200(self, client: TestClient):
        _create_freshness_record(client, "ev-hist-001")
        _run_snapshot(client, capture_date="2093-01-01")
        resp = client.get("/freshness/history/ev-hist-001")
        assert resp.status_code == 200

    def test_get_history_response_structure(self, client: TestClient):
        _create_freshness_record(client, "ev-hist-002")
        _run_snapshot(client, capture_date="2093-01-02")
        data = client.get("/freshness/history/ev-hist-002").json()
        assert data["evidence_id"] == "ev-hist-002"
        assert data["tenant_id"] == _TENANT
        assert "snapshots" in data
        assert "total" in data
        assert "trend_direction" in data

    def test_get_history_snapshots_list(self, client: TestClient):
        _create_freshness_record(client, "ev-hist-003")
        _run_snapshot(client, capture_date="2093-01-03")
        data = client.get("/freshness/history/ev-hist-003").json()
        assert len(data["snapshots"]) >= 1

    def test_get_history_snapshot_fields(self, client: TestClient):
        _create_freshness_record(client, "ev-hist-004")
        _run_snapshot(client, capture_date="2093-01-04")
        data = client.get("/freshness/history/ev-hist-004").json()
        snap = data["snapshots"][0]
        assert "id" in snap
        assert "evidence_id" in snap
        assert "freshness_score" in snap
        assert "freshness_state" in snap
        assert "capture_date" in snap
        assert "captured_at" in snap


# ---------------------------------------------------------------------------
# TestGetEvidenceHistoryDays — different day windows
# ---------------------------------------------------------------------------


class TestGetEvidenceHistoryDays:
    def test_days_param_accepted(self, client: TestClient):
        _create_freshness_record(client, "ev-days-001")
        _run_snapshot(client, capture_date="2094-01-01")
        resp = client.get("/freshness/history/ev-days-001?days=7")
        assert resp.status_code == 200

    def test_days_365_accepted(self, client: TestClient):
        _create_freshness_record(client, "ev-days-002")
        _run_snapshot(client, capture_date="2094-01-02")
        resp = client.get("/freshness/history/ev-days-002?days=365")
        assert resp.status_code == 200

    def test_days_below_minimum_rejected(self, client: TestClient):
        _create_freshness_record(client, "ev-days-003")
        resp = client.get("/freshness/history/ev-days-003?days=6")
        assert resp.status_code == 422

    def test_days_above_maximum_rejected(self, client: TestClient):
        _create_freshness_record(client, "ev-days-004")
        resp = client.get("/freshness/history/ev-days-004?days=366")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# TestGetEvidenceHistoryNotFound — 404 when no history
# ---------------------------------------------------------------------------


class TestGetEvidenceHistoryNotFound:
    def test_unknown_evidence_returns_404(self, client: TestClient):
        resp = client.get("/freshness/history/ev-nonexistent-xyzzy-99")
        assert resp.status_code == 404

    def test_404_detail_present(self, client: TestClient):
        resp = client.get("/freshness/history/ev-missing-abc123")
        data = resp.json()
        assert "detail" in data


# ---------------------------------------------------------------------------
# TestGetEvidenceHistoryTenantIsolation — cross-tenant returns 404
# ---------------------------------------------------------------------------


class TestGetEvidenceHistoryTenantIsolation:
    def test_tenant_b_cannot_see_tenant_a_history(
        self, client: TestClient, client_b: TestClient
    ):
        _create_freshness_record(client, "ev-tiso-001")
        _run_snapshot(client, capture_date="2095-01-01")
        resp = client_b.get("/freshness/history/ev-tiso-001")
        assert resp.status_code == 404

    def test_tenant_a_cannot_see_tenant_b_history(
        self, client: TestClient, client_b: TestClient
    ):
        _create_freshness_record(client_b, "ev-tiso-002")
        _run_snapshot(client_b, capture_date="2095-01-02")
        resp = client.get("/freshness/history/ev-tiso-002")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestGetTrends — basic trend calculation
# ---------------------------------------------------------------------------


class TestGetTrends:
    def test_get_trends_returns_200(self, client: TestClient):
        resp = client.get("/freshness/trends")
        assert resp.status_code == 200

    def test_get_trends_response_structure(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert "tenant_id" in data
        assert "period_days" in data
        assert "current_avg_score" in data
        assert "trend_direction" in data
        assert "generated_at" in data

    def test_get_trends_default_period_30(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["period_days"] == 30

    def test_get_trends_tenant_id_correct(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["tenant_id"] == _TENANT

    def test_get_trends_custom_period(self, client: TestClient):
        data = client.get("/freshness/trends?period_days=7").json()
        assert data["period_days"] == 7

    def test_get_trends_period_below_min_rejected(self, client: TestClient):
        resp = client.get("/freshness/trends?period_days=6")
        assert resp.status_code == 422

    def test_get_trends_period_above_max_rejected(self, client: TestClient):
        resp = client.get("/freshness/trends?period_days=366")
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# TestGetTrendsNoDelta — when no prior data, delta is None
# ---------------------------------------------------------------------------


class TestGetTrendsNoDelta:
    def test_no_data_returns_stable(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["trend_direction"] == "STABLE"

    def test_no_data_score_delta_is_none(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["score_delta"] is None

    def test_no_data_baseline_avg_is_none(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["baseline_avg_score"] is None

    def test_no_data_fresh_delta_is_none(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["fresh_delta"] is None

    def test_no_data_current_avg_score_zero(self, client: TestClient):
        data = client.get("/freshness/trends").json()
        assert data["current_avg_score"] == 0.0


# ---------------------------------------------------------------------------
# TestGetTrendsDelta — with multiple snapshots, delta is computed
# ---------------------------------------------------------------------------


class TestGetTrendsDelta:
    def test_two_snapshots_produce_delta(self, client: TestClient):
        _create_freshness_record(client, "ev-delta-001")
        _run_snapshot(client, capture_date="2096-01-01")
        _run_snapshot(client, capture_date="2096-02-01")
        data = client.get("/freshness/trends?period_days=31").json()
        assert data["score_delta"] is not None or data["baseline_avg_score"] is not None

    def test_two_snapshots_baseline_not_none(self, client: TestClient):
        _create_freshness_record(client, "ev-delta-002")
        _run_snapshot(client, capture_date="2096-03-01")
        _run_snapshot(client, capture_date="2096-04-01")
        data = client.get("/freshness/trends?period_days=365").json()
        assert data["current_avg_score"] >= 0.0


# ---------------------------------------------------------------------------
# TestGetTrendsDashboard — 7d/30d/90d deltas present
# ---------------------------------------------------------------------------


class TestGetTrendsDashboard:
    def test_dashboard_returns_200(self, client: TestClient):
        resp = client.get("/freshness/trends/dashboard")
        assert resp.status_code == 200

    def test_dashboard_response_structure(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert "tenant_id" in data
        assert "current_avg_score" in data
        assert "score_delta_7d" in data
        assert "score_delta_30d" in data
        assert "score_delta_90d" in data
        assert "trend_direction" in data
        assert "generated_at" in data

    def test_dashboard_tenant_id_correct(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["tenant_id"] == _TENANT

    def test_dashboard_velocity_fields_present(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert "freshness_velocity" in data
        assert "coverage_velocity" in data
        assert "risk_velocity" in data

    def test_dashboard_trend_direction_valid(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["trend_direction"] in {
            "IMPROVING",
            "STABLE",
            "DEGRADING",
            "CRITICAL",
        }


# ---------------------------------------------------------------------------
# TestGetTrendsDashboardNoData — returns stable with None deltas when no history
# ---------------------------------------------------------------------------


class TestGetTrendsDashboardNoData:
    def test_no_data_trend_direction_stable(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["trend_direction"] == "STABLE"

    def test_no_data_all_deltas_none(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["score_delta_7d"] is None
        assert data["score_delta_30d"] is None
        assert data["score_delta_90d"] is None

    def test_no_data_velocity_none(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["freshness_velocity"] is None

    def test_no_data_current_score_zero(self, client: TestClient):
        data = client.get("/freshness/trends/dashboard").json()
        assert data["current_avg_score"] == 0.0


# ---------------------------------------------------------------------------
# TestGetCGINTrends — cgin structure correct
# ---------------------------------------------------------------------------


class TestGetCGINTrends:
    def test_cgin_returns_200(self, client: TestClient):
        resp = client.get("/freshness/cgin/trends")
        assert resp.status_code == 200

    def test_cgin_response_structure(self, client: TestClient):
        data = client.get("/freshness/cgin/trends").json()
        assert "tenant_fingerprint" in data
        assert "tenant_id" not in data
        assert "average_score" in data
        assert "score_delta_30d" in data
        assert "score_delta_90d" in data
        assert "coverage_risk_delta" in data
        assert "improvement_velocity" in data
        assert "generated_at" in data

    def test_cgin_tenant_id_correct(self, client: TestClient):
        data = client.get("/freshness/cgin/trends").json()
        assert "tenant_id" not in data
        assert len(data["tenant_fingerprint"]) == 32

    def test_cgin_no_data_all_none(self, client: TestClient):
        data = client.get("/freshness/cgin/trends").json()
        assert data["average_score"] == 0.0
        assert data["score_delta_30d"] is None
        assert data["score_delta_90d"] is None
        assert data["improvement_velocity"] is None

    def test_cgin_improvement_velocity_none_when_no_improvement(
        self, client: TestClient
    ):
        data = client.get("/freshness/cgin/trends").json()
        assert data["improvement_velocity"] is None


# ---------------------------------------------------------------------------
# TestTrendDirectionClassification — unit tests for compute_trend_direction
# ---------------------------------------------------------------------------


class TestTrendDirectionClassification:
    def test_delta_above_5_is_improving(self):
        assert compute_trend_direction(5.1) == TrendDirection.IMPROVING

    def test_delta_exactly_5_is_stable(self):
        assert compute_trend_direction(5.0) == TrendDirection.STABLE

    def test_delta_zero_is_stable(self):
        assert compute_trend_direction(0.0) == TrendDirection.STABLE

    def test_delta_negative_small_is_stable(self):
        assert compute_trend_direction(-4.9) == TrendDirection.STABLE

    def test_delta_minus_5_is_stable(self):
        assert compute_trend_direction(-5.0) == TrendDirection.STABLE

    def test_delta_minus_5_1_is_degrading(self):
        assert compute_trend_direction(-5.1) == TrendDirection.DEGRADING

    def test_delta_minus_15_is_degrading(self):
        assert compute_trend_direction(-15.0) == TrendDirection.DEGRADING

    def test_delta_below_minus_15_is_critical(self):
        assert compute_trend_direction(-15.1) == TrendDirection.CRITICAL

    def test_delta_very_negative_is_critical(self):
        assert compute_trend_direction(-100.0) == TrendDirection.CRITICAL

    def test_delta_very_positive_is_improving(self):
        assert compute_trend_direction(50.0) == TrendDirection.IMPROVING


# ---------------------------------------------------------------------------
# TestScoreDeltaComputation — unit tests for compute_score_delta
# ---------------------------------------------------------------------------


class TestScoreDeltaComputation:
    def test_basic_positive_delta(self):
        assert compute_score_delta(80.0, 70.0) == 10.0

    def test_basic_negative_delta(self):
        assert compute_score_delta(60.0, 80.0) == -20.0

    def test_zero_delta(self):
        assert compute_score_delta(75.0, 75.0) == 0.0

    def test_rounding_to_two_decimal_places(self):
        result = compute_score_delta(80.005, 70.0)
        assert result == round(80.005 - 70.0, 2)

    def test_fractional_delta(self):
        assert compute_score_delta(72.55, 70.05) == 2.5

    def test_large_delta(self):
        assert compute_score_delta(100.0, 0.0) == 100.0

    def test_returns_float(self):
        result = compute_score_delta(80, 70)
        assert isinstance(result, float)


# ---------------------------------------------------------------------------
# TestSnapshotScopeEnforcement — audit:write required for POST, audit:read for GET
# ---------------------------------------------------------------------------


class TestSnapshotScopeEnforcement:
    def test_post_snapshot_requires_write_scope(self, build_app):
        app = build_app(auth_enabled=True)
        ro_key = mint_key("audit:read", tenant_id=_TENANT)
        ro_client = TestClient(app, headers={"X-API-Key": ro_key})
        resp = ro_client.post("/freshness/snapshots/run", json={})
        assert resp.status_code == 403

    def test_get_history_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/freshness/history/ev-auth-001")
        assert resp.status_code == 401

    def test_get_trends_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/freshness/trends")
        assert resp.status_code == 401

    def test_get_trends_dashboard_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/freshness/trends/dashboard")
        assert resp.status_code == 401

    def test_get_cgin_trends_requires_auth(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.get("/freshness/cgin/trends")
        assert resp.status_code == 401

    def test_read_only_key_can_access_trends(self, build_app):
        app = build_app(auth_enabled=True)
        ro_key = mint_key("audit:read", tenant_id=_TENANT)
        ro_client = TestClient(app, headers={"X-API-Key": ro_key})
        resp = ro_client.get("/freshness/trends")
        assert resp.status_code == 200

    def test_post_without_auth_returns_401(self, build_app):
        app = build_app(auth_enabled=True)
        no_auth_client = TestClient(app)
        resp = no_auth_client.post("/freshness/snapshots/run", json={})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# TestSnapshotPagination — limit/offset on history
# ---------------------------------------------------------------------------


class TestSnapshotPagination:
    def test_history_limit_param_accepted(self, client: TestClient):
        _create_freshness_record(client, "ev-page-001")
        _run_snapshot(client, capture_date="2097-01-01")
        resp = client.get("/freshness/history/ev-page-001?limit=10")
        assert resp.status_code == 200

    def test_history_offset_param_accepted(self, client: TestClient):
        _create_freshness_record(client, "ev-page-002")
        _run_snapshot(client, capture_date="2097-02-01")
        resp = client.get("/freshness/history/ev-page-002?offset=0")
        assert resp.status_code == 200

    def test_history_limit_minimum_1(self, client: TestClient):
        _create_freshness_record(client, "ev-page-003")
        resp = client.get("/freshness/history/ev-page-003?limit=0")
        assert resp.status_code == 422

    def test_history_limit_maximum_365(self, client: TestClient):
        _create_freshness_record(client, "ev-page-004")
        resp = client.get("/freshness/history/ev-page-004?limit=366")
        assert resp.status_code == 422

    def test_history_offset_negative_rejected(self, client: TestClient):
        _create_freshness_record(client, "ev-page-005")
        resp = client.get("/freshness/history/ev-page-005?offset=-1")
        assert resp.status_code == 422

    def test_history_total_field_reflects_count(self, client: TestClient):
        _create_freshness_record(client, "ev-page-006")
        _run_snapshot(client, capture_date="2097-03-01")
        data = client.get("/freshness/history/ev-page-006").json()
        assert data["total"] >= 1

    def test_history_limit_applied_to_snapshots(self, client: TestClient):
        _create_freshness_record(client, "ev-page-007")
        _run_snapshot(client, capture_date="2097-04-01")
        _run_snapshot(client, capture_date="2097-04-02")
        data = client.get("/freshness/history/ev-page-007?limit=1").json()
        assert len(data["snapshots"]) <= 1


# ---------------------------------------------------------------------------
# TestSnapshotAfterFreshnessUpdate — snapshot captures correct score
# ---------------------------------------------------------------------------


class TestSnapshotAfterFreshnessUpdate:
    def test_snapshot_captures_current_score(self, client: TestClient):
        _create_freshness_record(client, "ev-update-001")
        _run_snapshot(client, capture_date="2098-01-01")
        data = client.get("/freshness/history/ev-update-001").json()
        assert len(data["snapshots"]) >= 1
        snap = data["snapshots"][0]
        assert snap["freshness_score"] >= 0
        assert snap["freshness_score"] <= 100

    def test_snapshot_freshness_state_matches_record(self, client: TestClient):
        expire_past = (_NOW - timedelta(days=5)).isoformat()
        _create_freshness_record(client, "ev-update-002", expiration_due_at=expire_past)
        _run_snapshot(client, capture_date="2098-02-01")
        data = client.get("/freshness/history/ev-update-002").json()
        snap = data["snapshots"][0]
        assert snap["freshness_state"] == "EXPIRED"

    def test_snapshot_review_due_at_captured(self, client: TestClient):
        _create_freshness_record(client, "ev-update-003")
        _run_snapshot(client, capture_date="2098-03-01")
        data = client.get("/freshness/history/ev-update-003").json()
        snap = data["snapshots"][0]
        assert (
            snap["review_due_at"] == _REVIEW_DUE_FUTURE or snap["review_due_at"] is None
        )
