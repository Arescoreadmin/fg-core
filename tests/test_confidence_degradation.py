"""Unit tests for evidence freshness degradation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from services.field_assessment.confidence import (
    degrade_confidence,
    evidence_age_days,
)


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


class TestEvidenceAgeDays:
    def test_recent(self) -> None:
        assert evidence_age_days(_iso(5)) == 5

    def test_zero_age(self) -> None:
        assert evidence_age_days(_iso(0)) == 0

    def test_z_suffix(self) -> None:
        dt = (datetime.now(timezone.utc) - timedelta(days=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        assert evidence_age_days(dt) == 10

    def test_invalid_date_returns_zero(self) -> None:
        assert evidence_age_days("not-a-date") == 0

    def test_empty_string_returns_zero(self) -> None:
        assert evidence_age_days("") == 0


class TestDegradeConfidence:
    def test_no_decay_within_30_days(self) -> None:
        assert degrade_confidence(95, _iso(0)) == 95
        assert degrade_confidence(95, _iso(15)) == 95
        assert degrade_confidence(95, _iso(30)) == 95

    def test_minus_5_at_31_to_60_days(self) -> None:
        assert degrade_confidence(95, _iso(31)) == 90
        assert degrade_confidence(95, _iso(60)) == 90

    def test_minus_15_at_61_to_90_days(self) -> None:
        assert degrade_confidence(95, _iso(61)) == 80
        assert degrade_confidence(95, _iso(90)) == 80

    def test_minus_30_beyond_90_days(self) -> None:
        assert degrade_confidence(95, _iso(91)) == 65
        assert degrade_confidence(95, _iso(365)) == 65

    def test_floor_enforced(self) -> None:
        # Even a very low base score at maximum staleness cannot go below 30
        assert degrade_confidence(30, _iso(365)) == 30
        assert degrade_confidence(20, _iso(365)) == 30

    def test_medium_finding_stale(self) -> None:
        # 70-point finding, 120 days old → 40, approaches readiness threshold
        assert degrade_confidence(70, _iso(120)) == 40

    def test_readiness_threshold_crossing(self) -> None:
        # confidence 85, 91+ days → 55, which is below the 60-point escalation threshold
        assert degrade_confidence(85, _iso(91)) == 55

    def test_invalid_date_returns_base(self) -> None:
        # Bad updated_at — degradation returns base score unchanged
        assert degrade_confidence(90, "not-a-date") == 90

    @pytest.mark.parametrize(
        "base,days,expected",
        [
            (100, 0, 100),
            (100, 30, 100),
            (100, 31, 95),
            (100, 60, 95),
            (100, 61, 85),
            (100, 90, 85),
            (100, 91, 70),
            (80, 91, 50),
            (50, 91, 30),  # floor
        ],
    )
    def test_parametrized(self, base: int, days: int, expected: int) -> None:
        assert degrade_confidence(base, _iso(days)) == expected
