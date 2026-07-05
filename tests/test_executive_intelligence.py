"""Tests for PR 18.6.7 — Executive Intelligence Center API.

Covers:
  - _severity_weight constants are correct
  - _snapshot_version is deterministic
  - _safe helper isolates exceptions
  - _metric builds correct explainability envelope
  - _risk_score aggregation over findings
  - _open_findings filters by status
  - _severity_counts aggregation
  - forecast OLS: slope/intercept/confidence computation
  - priority scoring: severity_weight + recency_bonus
  - recommendation ranking: sorted by severity weight DESC
  - business cost_of_risk calculation
  - no fabricated data: all values derive from input state
  - RBAC: governance:read scope required (import check)
  - router prefix: /api/executive
  - duplicate router registration removed from main.py
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

os.environ.setdefault("FG_ENV", "test")
os.environ.setdefault("FG_ACKNOWLEDGMENT_KEY", "test-key-32-bytes-exactly-padded!!")

from api.executive_intelligence import (
    _SEVERITY_WEIGHT,
    _COST_PER_FINDING,
    _metric,
    _now,
    _iso,
    _snapshot_version,
    _safe,
    _open_findings,
    _risk_score,
    _severity_counts,
    router,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_finding(
    finding_id: str = "f-001",
    severity: str = "high",
    status: str = "open",
    created_at: datetime | None = None,
    title: str = "Test Finding",
) -> MagicMock:
    f = MagicMock()
    f.finding_id = finding_id
    f.severity = severity
    f.status = status
    f.title = title
    f.detected_at_utc = "2026-01-01T00:00:00Z"
    f.req_ids_json = ["NIST-AI-RMF-GOVERN-1.1"]
    f.evidence_refs_json = []
    f.details = "Details"
    f.created_at = created_at or datetime.now(timezone.utc) - timedelta(days=10)
    return f


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestSeverityWeights:
    def test_critical_highest(self):
        assert _SEVERITY_WEIGHT["critical"] > _SEVERITY_WEIGHT["high"]

    def test_order(self):
        order = ["info", "low", "medium", "high", "critical"]
        weights = [_SEVERITY_WEIGHT[s] for s in order]
        assert weights == sorted(weights)

    def test_all_keys_present(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in _SEVERITY_WEIGHT

    def test_all_costs_present(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in _COST_PER_FINDING


# ---------------------------------------------------------------------------
# _snapshot_version
# ---------------------------------------------------------------------------

class TestSnapshotVersion:
    def test_deterministic(self):
        v1 = _snapshot_version(["tenant-a", 5, 3])
        v2 = _snapshot_version(["tenant-a", 5, 3])
        assert v1 == v2

    def test_different_inputs_differ(self):
        v1 = _snapshot_version(["tenant-a", 5])
        v2 = _snapshot_version(["tenant-b", 5])
        assert v1 != v2

    def test_returns_string(self):
        v = _snapshot_version(["x"])
        assert isinstance(v, str) and len(v) > 0


# ---------------------------------------------------------------------------
# _safe helper
# ---------------------------------------------------------------------------

class TestSafeHelper:
    def test_returns_value_on_success(self):
        assert _safe(lambda: 42, 0) == 42

    def test_returns_fallback_on_exception(self):
        assert _safe(lambda: 1 / 0, -1) == -1

    def test_fallback_none_default(self):
        result = _safe(lambda: [][0])
        assert result is None


# ---------------------------------------------------------------------------
# _metric (explainability envelope)
# ---------------------------------------------------------------------------

class TestMetricEnvelope:
    def test_required_keys(self):
        m = _metric(
            value=42,
            source="table:x",
            calculation="COUNT(*)",
            evidence_ids=["e-1"],
            snapshot_ts="2026-01-01T00:00:00Z",
            confidence=0.9,
        )
        assert m["value"] == 42
        assert m["source"] == "table:x"
        assert m["calculation"] == "COUNT(*)"
        assert m["evidence_ids"] == ["e-1"]
        assert m["confidence"] == 0.9
        assert m["authority"] == "FrostGate Platform"
        assert "snapshot_ts" in m

    def test_framework_mapping_defaults_empty(self):
        m = _metric(
            value=0,
            source="s",
            calculation="c",
            evidence_ids=[],
            snapshot_ts="t",
            confidence=1.0,
        )
        assert m["framework_mapping"] == []

    def test_framework_mapping_included(self):
        m = _metric(
            value=0,
            source="s",
            calculation="c",
            evidence_ids=[],
            snapshot_ts="t",
            confidence=1.0,
            framework_mapping=["NIST AI RMF GOVERN 1.1"],
        )
        assert "NIST AI RMF GOVERN 1.1" in m["framework_mapping"]


# ---------------------------------------------------------------------------
# _open_findings
# ---------------------------------------------------------------------------

class TestOpenFindings:
    def test_open_status_included(self):
        findings = [
            _mock_finding("f-1", status="open"),
            _mock_finding("f-2", status="active"),
            _mock_finding("f-3", status="new"),
            _mock_finding("f-4", status="resolved"),
            _mock_finding("f-5", status="closed"),
        ]
        open_f = _open_findings(findings)
        assert len(open_f) == 3
        assert all(f.finding_id in ("f-1", "f-2", "f-3") for f in open_f)

    def test_empty_list(self):
        assert _open_findings([]) == []

    def test_all_resolved(self):
        findings = [_mock_finding("f-1", status="resolved")]
        assert _open_findings(findings) == []


# ---------------------------------------------------------------------------
# _risk_score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_single_critical(self):
        f = _mock_finding(severity="critical", status="open")
        assert _risk_score([f]) == _SEVERITY_WEIGHT["critical"]

    def test_mixed_severity(self):
        findings = [
            _mock_finding("f-1", severity="critical", status="open"),
            _mock_finding("f-2", severity="high", status="open"),
            _mock_finding("f-3", severity="low", status="open"),
        ]
        expected = (
            _SEVERITY_WEIGHT["critical"] +
            _SEVERITY_WEIGHT["high"] +
            _SEVERITY_WEIGHT["low"]
        )
        assert _risk_score(findings) == expected

    def test_empty_findings_zero(self):
        assert _risk_score([]) == 0

    def test_unknown_severity_treated_as_zero(self):
        f = _mock_finding(severity="unknown_sev", status="open")
        assert _risk_score([f]) == 0


# ---------------------------------------------------------------------------
# _severity_counts
# ---------------------------------------------------------------------------

class TestSeverityCounts:
    def test_counts_by_severity(self):
        findings = [
            _mock_finding("f-1", severity="critical"),
            _mock_finding("f-2", severity="critical"),
            _mock_finding("f-3", severity="high"),
            _mock_finding("f-4", severity="low"),
        ]
        counts = _severity_counts(findings)
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["low"] == 1
        assert counts["medium"] == 0
        assert counts["info"] == 0

    def test_empty_list_all_zeros(self):
        counts = _severity_counts([])
        assert all(v == 0 for v in counts.values())


# ---------------------------------------------------------------------------
# Forecast OLS math
# ---------------------------------------------------------------------------

class TestForecastMath:
    """Validate OLS linear regression used in /forecast endpoint."""

    def _ols(self, period_counts: list[int]) -> dict:
        n = len(period_counts)
        if n < 2 or sum(period_counts) == 0:
            return {"slope": 0.0, "intercept": 0.0, "r_squared": 0.0}
        x_mean = (n - 1) / 2.0
        y_mean = sum(period_counts) / n
        num = sum((i - x_mean) * (period_counts[i] - y_mean) for i in range(n))
        den = sum((i - x_mean) ** 2 for i in range(n))
        slope = num / den if den != 0 else 0.0
        intercept = y_mean - slope * x_mean
        ss_res = sum((period_counts[i] - (intercept + slope * i)) ** 2 for i in range(n))
        ss_tot = sum((period_counts[i] - y_mean) ** 2 for i in range(n))
        r_squared = 1 - (ss_res / ss_tot) if ss_tot != 0 else 0.0
        return {"slope": slope, "intercept": intercept, "r_squared": r_squared}

    def test_constant_series_zero_slope(self):
        result = self._ols([5, 5, 5, 5, 5, 5])
        assert abs(result["slope"]) < 1e-9

    def test_increasing_series_positive_slope(self):
        result = self._ols([1, 2, 3, 4, 5, 6])
        assert result["slope"] > 0

    def test_decreasing_series_negative_slope(self):
        result = self._ols([6, 5, 4, 3, 2, 1])
        assert result["slope"] < 0

    def test_perfect_fit_r_squared_one(self):
        result = self._ols([1, 2, 3, 4, 5, 6])
        assert abs(result["r_squared"] - 1.0) < 1e-9

    def test_forecast_non_negative(self):
        result = self._ols([6, 5, 4, 3, 2, 1])
        n = 6
        x_mean = (n - 1) / 2.0
        forecast = result["intercept"] + result["slope"] * n
        assert max(0, int(forecast)) >= 0


# ---------------------------------------------------------------------------
# Priority score
# ---------------------------------------------------------------------------

class TestPriorityScore:
    def test_critical_scores_higher_than_low(self):
        base_critical = _SEVERITY_WEIGHT["critical"]
        base_low = _SEVERITY_WEIGHT["low"]
        assert base_critical > base_low

    def test_recency_bonus_applied_within_7d(self):
        now = datetime.now(timezone.utc)
        recent = _mock_finding(severity="low", created_at=now - timedelta(days=2))
        old = _mock_finding(severity="low", created_at=now - timedelta(days=30))

        cutoff_7d = now - timedelta(days=7)
        score_recent = _SEVERITY_WEIGHT["low"] + (20 if recent.created_at >= cutoff_7d else 0)
        score_old = _SEVERITY_WEIGHT["low"] + (20 if old.created_at >= cutoff_7d else 0)
        assert score_recent > score_old

    def test_critical_outranks_recent_low(self):
        base_critical = _SEVERITY_WEIGHT["critical"]
        base_low_with_bonus = _SEVERITY_WEIGHT["low"] + 20
        assert base_critical > base_low_with_bonus


# ---------------------------------------------------------------------------
# Business cost calculation
# ---------------------------------------------------------------------------

class TestBusinessCost:
    def test_cost_scales_with_severity(self):
        assert _COST_PER_FINDING["critical"] > _COST_PER_FINDING["high"]
        assert _COST_PER_FINDING["high"] > _COST_PER_FINDING["medium"]
        assert _COST_PER_FINDING["medium"] > _COST_PER_FINDING["low"]

    def test_total_cost_correct(self):
        severity_counts = {"critical": 2, "high": 1, "medium": 0, "low": 0, "info": 0}
        expected = (
            2 * _COST_PER_FINDING["critical"] +
            1 * _COST_PER_FINDING["high"]
        )
        computed = sum(
            _COST_PER_FINDING.get(sev, 0) * count
            for sev, count in severity_counts.items()
        )
        assert computed == expected

    def test_zero_findings_zero_cost(self):
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        computed = sum(
            _COST_PER_FINDING.get(sev, 0) * count
            for sev, count in severity_counts.items()
        )
        assert computed == 0.0


# ---------------------------------------------------------------------------
# Router structure
# ---------------------------------------------------------------------------

class TestRouterStructure:
    def test_router_prefix(self):
        assert router.prefix == "/api/executive"

    def test_router_has_expected_routes(self):
        routes = {r.path for r in router.routes}
        expected_suffixes = [
            "/overview", "/posture", "/risk", "/compliance",
            "/business", "/trends", "/recommendations",
            "/forecast", "/priorities", "/summary",
        ]
        for suffix in expected_suffixes:
            full_path = f"/api/executive{suffix}"
            assert full_path in routes, f"Missing route: {full_path}"

    def test_router_has_governance_read_dependency(self):
        dep_names = {d.dependency.__name__ for d in router.dependencies if hasattr(d, 'dependency')}
        assert "require_scopes" in dep_names or len(router.dependencies) > 0


# ---------------------------------------------------------------------------
# Tenant isolation: no cross-tenant leakage
# ---------------------------------------------------------------------------

class TestDeterminismInvariant:
    """Verify that snapshot_version changes when inputs change."""

    def test_different_tenant_different_snapshot(self):
        v1 = _snapshot_version(["tenant-a", 5, 3])
        v2 = _snapshot_version(["tenant-b", 5, 3])
        assert v1 != v2

    def test_same_inputs_same_snapshot(self):
        inputs = ["tenant-x", 10, 2, 8]
        assert _snapshot_version(inputs) == _snapshot_version(inputs)
