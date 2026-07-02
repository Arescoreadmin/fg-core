"""Tests for PR 18.5A — Intelligence Quality Score.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.quality_score import (
    QUALITY_GRADES,
    _WEIGHTS,
    _assign_grade,
    build_quality_response,
    compute_quality_score,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _score_all(value: float) -> tuple[float, str]:
    return compute_quality_score(
        value, value, value, value, value, value, value, value, value, value
    )


# ---------------------------------------------------------------------------
# QUALITY_GRADES constant
# ---------------------------------------------------------------------------


class TestQualityGradesConstant:
    def test_is_list(self):
        assert isinstance(QUALITY_GRADES, list)

    def test_contains_a_plus(self):
        assert "A+" in QUALITY_GRADES

    def test_contains_a(self):
        assert "A" in QUALITY_GRADES

    def test_contains_b(self):
        assert "B" in QUALITY_GRADES

    def test_contains_c(self):
        assert "C" in QUALITY_GRADES

    def test_contains_insufficient_evidence(self):
        assert "INSUFFICIENT_EVIDENCE" in QUALITY_GRADES

    def test_has_5_grades(self):
        assert len(QUALITY_GRADES) == 5


# ---------------------------------------------------------------------------
# _WEIGHTS
# ---------------------------------------------------------------------------


class TestWeights:
    def test_weights_sum_to_one(self):
        total = sum(_WEIGHTS.values())
        assert abs(total - 1.0) < 1e-9

    def test_all_weights_positive(self):
        for k, v in _WEIGHTS.items():
            assert v > 0, f"Weight for {k} is not positive"

    def test_evidence_coverage_weight_present(self):
        assert "evidence_coverage" in _WEIGHTS

    def test_10_weight_dimensions(self):
        assert len(_WEIGHTS) == 10


# ---------------------------------------------------------------------------
# Grade thresholds
# ---------------------------------------------------------------------------


class TestGradeThresholds:
    def test_score_1_0_is_a_plus(self):
        _, grade = _score_all(1.0)
        assert grade == "A+"

    def test_score_0_9_is_a_plus(self):
        _, grade = compute_quality_score(
            1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
        )
        assert grade == "A+"

    def test_assign_grade_0_90_is_a_plus(self):
        assert _assign_grade(0.90) == "A+"

    def test_assign_grade_0_95_is_a_plus(self):
        assert _assign_grade(0.95) == "A+"

    def test_assign_grade_0_80_is_a(self):
        assert _assign_grade(0.80) == "A"

    def test_assign_grade_0_85_is_a(self):
        assert _assign_grade(0.85) == "A"

    def test_assign_grade_0_89_is_a(self):
        assert _assign_grade(0.89) == "A"

    def test_assign_grade_0_65_is_b(self):
        assert _assign_grade(0.65) == "B"

    def test_assign_grade_0_70_is_b(self):
        assert _assign_grade(0.70) == "B"

    def test_assign_grade_0_79_is_b(self):
        assert _assign_grade(0.79) == "B"

    def test_assign_grade_0_50_is_c(self):
        assert _assign_grade(0.50) == "C"

    def test_assign_grade_0_60_is_c(self):
        assert _assign_grade(0.60) == "C"

    def test_assign_grade_0_64_is_c(self):
        assert _assign_grade(0.64) == "C"

    def test_assign_grade_0_49_is_insufficient(self):
        assert _assign_grade(0.49) == "INSUFFICIENT_EVIDENCE"

    def test_assign_grade_0_0_is_insufficient(self):
        assert _assign_grade(0.0) == "INSUFFICIENT_EVIDENCE"

    def test_score_0_is_insufficient(self):
        _, grade = _score_all(0.0)
        assert grade == "INSUFFICIENT_EVIDENCE"


# ---------------------------------------------------------------------------
# compute_quality_score
# ---------------------------------------------------------------------------


class TestComputeQualityScore:
    def test_returns_tuple(self):
        result = compute_quality_score(1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0)
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_score_is_float(self):
        score, _ = _score_all(0.5)
        assert isinstance(score, float)

    def test_grade_is_string(self):
        _, grade = _score_all(0.5)
        assert isinstance(grade, str)

    def test_score_in_range_0_1(self):
        score, _ = _score_all(0.7)
        assert 0.0 <= score <= 1.0

    def test_all_zeros_produces_zero_score(self):
        score, _ = _score_all(0.0)
        assert score == 0.0

    def test_all_ones_produces_one_score(self):
        score, _ = _score_all(1.0)
        assert abs(score - 1.0) < 1e-6

    def test_out_of_range_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            compute_quality_score(1.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5)

    def test_negative_input_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            compute_quality_score(-0.1, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5)

    def test_non_numeric_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            compute_quality_score("bad", 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5)  # type: ignore[arg-type]

    def test_weighted_sum(self):
        score, _ = compute_quality_score(
            1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        )
        expected = _WEIGHTS["evidence_coverage"]
        assert abs(score - expected) < 1e-9

    def test_monotonic_with_all_equal_inputs(self):
        scores = [_score_all(v)[0] for v in [0.0, 0.25, 0.5, 0.75, 1.0]]
        assert scores == sorted(scores)

    def test_boundary_0_exactly(self):
        score, _ = compute_quality_score(
            0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        )
        assert score == 0.0

    def test_boundary_1_exactly(self):
        score, _ = compute_quality_score(
            1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0
        )
        assert abs(score - 1.0) < 1e-9


# ---------------------------------------------------------------------------
# build_quality_response
# ---------------------------------------------------------------------------


class TestBuildQualityResponse:
    def test_returns_dict(self):
        assert isinstance(build_quality_response({}), dict)

    def test_has_score(self):
        r = build_quality_response({})
        assert "score" in r

    def test_has_grade(self):
        r = build_quality_response({})
        assert "grade" in r

    def test_has_inputs(self):
        r = build_quality_response({})
        assert "inputs" in r

    def test_has_weights(self):
        r = build_quality_response({})
        assert "weights" in r

    def test_empty_inputs_defaults_to_zero_score(self):
        r = build_quality_response({})
        assert r["score"] == 0.0
        assert r["grade"] == "INSUFFICIENT_EVIDENCE"

    def test_full_inputs_produces_high_grade(self):
        full = {k: 1.0 for k in _WEIGHTS}
        r = build_quality_response(full)
        assert r["grade"] == "A+"

    def test_inputs_normalized_to_known_keys(self):
        r = build_quality_response({"evidence_coverage": 0.9})
        assert "evidence_coverage" in r["inputs"]

    def test_unknown_keys_excluded(self):
        r = build_quality_response({"unknown_key": 0.9, "evidence_coverage": 0.5})
        assert "unknown_key" not in r["inputs"]

    def test_weights_match_module_weights(self):
        r = build_quality_response({})
        assert r["weights"] == dict(_WEIGHTS)
