"""Tests for GPS posture scorer and drift severity classification."""

from __future__ import annotations

from dataclasses import dataclass, field
from services.connectors.drift.engine import DriftFindingRecord, DriftResult
from services.connectors.drift.scorer import compute_posture_delta, _drift_confidence


def _make_drift_result(**counts: int) -> DriftResult:
    findings: list[DriftFindingRecord] = []
    for delta_class, count in counts.items():
        sev = "critical" if "regress" in delta_class or delta_class == "escalated" else "high"
        for i in range(count):
            findings.append(
                DriftFindingRecord(
                    finding_id=f"{delta_class}-{i}",
                    findings_hash=f"{delta_class}-{i}-hash",
                    title=f"Finding {delta_class} {i}",
                    severity=sev,
                    baseline_severity=None,
                    delta_class=delta_class,
                    evidence_ref_ids=[],
                    rationale="test",
                )
            )
    return DriftResult(
        tenant_id="t",
        engagement_id="e",
        baseline_scan_id="base",
        current_scan_id="curr",
        findings=findings,
    )


class TestDriftConfidence:
    def test_fresh_scan_is_100(self) -> None:
        from datetime import UTC, datetime, timedelta
        now = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        conf, _ = _drift_confidence(now)
        assert conf == 100

    def test_week_old_scan_is_85(self) -> None:
        from datetime import UTC, datetime, timedelta
        ts = (datetime.now(UTC) - timedelta(days=5)).isoformat()
        conf, _ = _drift_confidence(ts)
        assert conf == 85

    def test_old_scan_degrades(self) -> None:
        from datetime import UTC, datetime, timedelta
        ts = (datetime.now(UTC) - timedelta(days=60)).isoformat()
        conf, _ = _drift_confidence(ts)
        assert conf == 30

    def test_unparseable_timestamp_returns_50(self) -> None:
        conf, reason = _drift_confidence("not-a-timestamp")
        assert conf == 50
        assert "unparseable" in reason


class TestComputePostureDelta:
    def test_no_baseline_severity(self) -> None:
        drift = _make_drift_result()
        result = compute_posture_delta(
            drift,
            current_open_findings=[{"severity": "high", "nist_ai_rmf_mappings": []}],
            baseline_open_findings=[],
            current_scan_collected_at="2026-05-20T00:00:00Z",
            no_baseline=True,
        )
        assert result.drift_severity == "no_baseline"
        assert result.gps_delta == 0

    def test_critical_regression_severity(self) -> None:
        drift = _make_drift_result(regressed=1)
        result = compute_posture_delta(
            drift,
            current_open_findings=[{"severity": "critical", "nist_ai_rmf_mappings": []}],
            baseline_open_findings=[{"severity": "critical", "nist_ai_rmf_mappings": []}],
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        assert result.drift_severity == "critical_regression"

    def test_posture_degraded_on_new_high_critical(self) -> None:
        drift = _make_drift_result(new=3)
        result = compute_posture_delta(
            drift,
            current_open_findings=[
                {"severity": "high", "nist_ai_rmf_mappings": []},
                {"severity": "high", "nist_ai_rmf_mappings": []},
                {"severity": "high", "nist_ai_rmf_mappings": []},
            ],
            baseline_open_findings=[],
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        assert result.drift_severity == "posture_degraded"

    def test_posture_improved_on_net_resolutions(self) -> None:
        drift = _make_drift_result(resolved=3)
        result = compute_posture_delta(
            drift,
            current_open_findings=[],
            baseline_open_findings=[
                {"severity": "high", "nist_ai_rmf_mappings": []},
                {"severity": "high", "nist_ai_rmf_mappings": []},
                {"severity": "high", "nist_ai_rmf_mappings": []},
            ],
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        assert result.drift_severity == "posture_improved"

    def test_gps_delta_is_positive_on_improvement(self) -> None:
        drift = _make_drift_result(resolved=2)
        result = compute_posture_delta(
            drift,
            current_open_findings=[],
            baseline_open_findings=[
                {"severity": "critical", "nist_ai_rmf_mappings": []},
                {"severity": "critical", "nist_ai_rmf_mappings": []},
            ],
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        assert result.gps_delta > 0
        assert result.current_gps > result.baseline_gps

    def test_nist_domain_subscores_populated(self) -> None:
        drift = _make_drift_result()
        result = compute_posture_delta(
            drift,
            current_open_findings=[
                {
                    "severity": "high",
                    "nist_ai_rmf_mappings": [{"function": "GOVERN", "category": "1.1"}],
                }
            ],
            baseline_open_findings=[],
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        functions = {s.function for s in result.domain_subscores}
        assert "GOVERN" in functions
        assert "MAP" in functions

    def test_stable_when_no_significant_change(self) -> None:
        drift = _make_drift_result(persisted=5)
        result = compute_posture_delta(
            drift,
            current_open_findings=[{"severity": "low", "nist_ai_rmf_mappings": []}] * 5,
            baseline_open_findings=[{"severity": "low", "nist_ai_rmf_mappings": []}] * 5,
            current_scan_collected_at="2026-05-20T00:00:00Z",
        )
        assert result.drift_severity == "stable"
