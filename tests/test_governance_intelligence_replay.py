"""Tests for PR 18.5A — Historical Replay Engine.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.replay import (
    build_replay_snapshot,
    diff_replays,
    replay_governance,
    validate_replay_request,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WINDOW = {"start": "2026-01-01", "end": "2026-01-31"}
_EVIDENCE = {"e1": "ctrl-1", "e2": "ctrl-2"}
_TRANSPARENCY = {"t1": "entry-1"}


def _snapshot(
    policy_version: str = "v1.0",
    evidence: dict | None = None,
    trust_version: str = "trust-v1",
    transparency: dict | None = None,
    window: dict | None = None,
) -> dict:
    return build_replay_snapshot(
        policy_version,
        evidence or _EVIDENCE,
        trust_version,
        transparency or _TRANSPARENCY,
        window or _WINDOW,
    )


# ---------------------------------------------------------------------------
# validate_replay_request
# ---------------------------------------------------------------------------


class TestValidateReplayRequest:
    def test_valid_inputs_do_not_raise(self):
        validate_replay_request("v1.0", _WINDOW)

    def test_empty_policy_version_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request("", _WINDOW)

    def test_non_string_policy_version_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request(None, _WINDOW)  # type: ignore[arg-type]

    def test_non_dict_time_window_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request("v1.0", "bad")  # type: ignore[arg-type]

    def test_time_window_missing_start_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request("v1.0", {"end": "2026-01-31"})

    def test_time_window_missing_end_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request("v1.0", {"start": "2026-01-01"})

    def test_empty_window_dict_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_replay_request("v1.0", {})


# ---------------------------------------------------------------------------
# build_replay_snapshot
# ---------------------------------------------------------------------------


class TestBuildReplaySnapshot:
    def test_returns_dict(self):
        snap = _snapshot()
        assert isinstance(snap, dict)

    def test_contains_snapshot_id(self):
        snap = _snapshot()
        assert "snapshot_id" in snap

    def test_snapshot_id_is_64_char(self):
        snap = _snapshot()
        assert len(snap["snapshot_id"]) == 64

    def test_contains_policy_version(self):
        snap = _snapshot()
        assert snap["policy_version"] == "v1.0"

    def test_contains_evidence_snapshot(self):
        snap = _snapshot()
        assert "evidence_snapshot" in snap

    def test_contains_trust_version(self):
        snap = _snapshot()
        assert snap["trust_version"] == "trust-v1"

    def test_contains_time_window(self):
        snap = _snapshot()
        assert snap["time_window"] == _WINDOW

    def test_deterministic_same_inputs(self):
        s1 = _snapshot()
        s2 = _snapshot()
        assert s1["snapshot_id"] == s2["snapshot_id"]

    def test_different_policy_version_different_id(self):
        s1 = _snapshot(policy_version="v1.0")
        s2 = _snapshot(policy_version="v2.0")
        assert s1["snapshot_id"] != s2["snapshot_id"]

    def test_different_evidence_different_id(self):
        s1 = _snapshot(evidence={"e1": "ctrl-1"})
        s2 = _snapshot(evidence={"e2": "ctrl-2"})
        assert s1["snapshot_id"] != s2["snapshot_id"]

    def test_invalid_policy_version_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            build_replay_snapshot("", {}, "trust-v1", {}, _WINDOW)

    def test_empty_evidence_snapshot_allowed(self):
        snap = build_replay_snapshot("v1.0", {}, "trust-v1", {}, _WINDOW)
        assert snap["evidence_snapshot"] == {}


# ---------------------------------------------------------------------------
# replay_governance
# ---------------------------------------------------------------------------


class TestReplayGovernance:
    def test_replay_label_is_replay(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert result["replay_label"] == "REPLAY"

    def test_is_production_false(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert result["is_production"] is False

    def test_contains_snapshot_id(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "snapshot_id" in result

    def test_contains_policy_evaluation(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "policy_evaluation" in result

    def test_contains_recommendations(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "recommendations" in result

    def test_contains_forecasts(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "forecasts" in result

    def test_contains_dashboard(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "dashboard" in result

    def test_contains_executive_report(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "executive_report" in result

    def test_policy_evaluation_has_score(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "score" in result["policy_evaluation"]

    def test_policy_evaluation_score_in_range(self):
        snap = _snapshot()
        result = replay_governance(snap)
        score = result["policy_evaluation"]["score"]
        assert 0.0 <= score <= 1.0

    def test_invalid_snapshot_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            replay_governance("not_a_dict")  # type: ignore[arg-type]

    def test_empty_snapshot_allowed(self):
        result = replay_governance({})
        assert result["replay_label"] == "REPLAY"
        assert result["is_production"] is False

    def test_deterministic_same_snapshot(self):
        snap = _snapshot()
        r1 = replay_governance(snap)
        r2 = replay_governance(snap)
        assert r1["snapshot_id"] == r2["snapshot_id"]
        assert r1["policy_evaluation"]["score"] == r2["policy_evaluation"]["score"]

    def test_risk_level_present(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert "risk_level" in result["policy_evaluation"]

    def test_risk_level_valid_value(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert result["policy_evaluation"]["risk_level"] in ("LOW", "MEDIUM", "HIGH")

    def test_forecast_horizon_is_replay_window(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert result["forecasts"]["horizon"] == "REPLAY_WINDOW"

    def test_forecasts_confidence_is_historical(self):
        snap = _snapshot()
        result = replay_governance(snap)
        assert result["forecasts"]["confidence"] == "HISTORICAL"


# ---------------------------------------------------------------------------
# diff_replays
# ---------------------------------------------------------------------------


class TestDiffReplays:
    def _make_result(self, evidence: dict) -> dict:
        snap = build_replay_snapshot("v1.0", evidence, "trust-v1", {}, _WINDOW)
        return replay_governance(snap)

    def test_diff_returns_dict(self):
        r1 = self._make_result({"e1": "c1"})
        r2 = self._make_result({"e1": "c1", "e2": "c2"})
        diff = diff_replays(r1, r2)
        assert isinstance(diff, dict)

    def test_diff_has_score_delta(self):
        r1 = self._make_result({})
        r2 = self._make_result({"e1": "c1"})
        diff = diff_replays(r1, r2)
        assert "score_delta" in diff

    def test_diff_has_risk_changed(self):
        r1 = self._make_result({})
        r2 = self._make_result({"e1": "c1"})
        diff = diff_replays(r1, r2)
        assert "risk_changed" in diff

    def test_diff_same_snapshots_zero_delta(self):
        snap = _snapshot()
        r = replay_governance(snap)
        diff = diff_replays(r, r)
        assert diff["score_delta"] == 0.0

    def test_diff_snapshot_ids_present(self):
        r1 = self._make_result({"e1": "c1"})
        r2 = self._make_result({"e2": "c2"})
        diff = diff_replays(r1, r2)
        assert "snapshot_a" in diff
        assert "snapshot_b" in diff

    def test_diff_added_and_removed_lists(self):
        r1 = self._make_result({"e1": "c1"})
        r2 = self._make_result({"e2": "c2"})
        diff = diff_replays(r1, r2)
        assert "added" in diff
        assert "removed" in diff
        assert "changed" in diff

    def test_diff_score_delta_computed(self):
        r1 = self._make_result({})
        r2 = self._make_result({"e1": "c1", "e2": "c2", "e3": "c3"})
        diff = diff_replays(r1, r2)
        score_a = r1["policy_evaluation"]["score"]
        score_b = r2["policy_evaluation"]["score"]
        expected_delta = round(score_b - score_a, 4)
        assert abs(diff["score_delta"] - expected_delta) < 1e-6
