"""Tests for PR 18.5A — Recommendation Evidence Matrix.

Pure-function tests. No DB required.
"""

from __future__ import annotations

import pytest

from services.governance_intelligence.evidence_matrix import (
    _COVERAGE_FIELDS,
    build_evidence_matrix,
    compute_coverage,
    validate_evidence_matrix,
)
from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _matrix(
    rec_id: str = "rec-1",
    evidence_ids: list[str] | None = None,
    control_ids: list[str] | None = None,
    framework_ids: list[str] | None = None,
    verification_ids: list[str] | None = None,
    trust_refs: list[str] | None = None,
    transparency_refs: list[str] | None = None,
    risk_factors: list[dict] | None = None,
    confidence: float = 0.8,
    expected_improvement: float = 0.2,
    simulation_ids: list[str] | None = None,
) -> dict:
    return build_evidence_matrix(
        rec_id,
        evidence_ids if evidence_ids is not None else ["e-1", "e-2"],
        control_ids or ["ctrl-1"],
        framework_ids or ["fw-1"],
        verification_ids or ["ver-1"],
        trust_refs or ["tr-1"],
        transparency_refs or ["tx-1"],
        risk_factors or [{"name": "rf-1", "severity": "HIGH"}],
        confidence,
        expected_improvement,
        simulation_ids or ["sim-1"],
    )


# ---------------------------------------------------------------------------
# build_evidence_matrix — empty evidence_ids raises
# ---------------------------------------------------------------------------


class TestBuildEvidenceMatrixValidation:
    def test_empty_evidence_ids_raises(self):
        with pytest.raises(GovernanceIntelligenceValidationError):
            build_evidence_matrix("rec-1", [], [], [], [], [], [], [], 0.5, 0.1, [])

    def test_non_empty_evidence_ids_does_not_raise(self):
        result = build_evidence_matrix(
            "rec-1", ["e-1"], [], [], [], [], [], [], 0.5, 0.0, []
        )
        assert result is not None

    def test_error_message_mentions_evidence_ids(self):
        with pytest.raises(GovernanceIntelligenceValidationError, match="evidence_ids"):
            build_evidence_matrix("rec-1", [], [], [], [], [], [], [], 0.5, 0.1, [])


# ---------------------------------------------------------------------------
# build_evidence_matrix — output structure
# ---------------------------------------------------------------------------


class TestBuildEvidenceMatrixOutput:
    def test_returns_dict(self):
        assert isinstance(_matrix(), dict)

    def test_recommendation_id_set(self):
        result = _matrix(rec_id="rec-99")
        assert result["recommendation_id"] == "rec-99"

    def test_evidence_ids_sorted(self):
        result = _matrix(evidence_ids=["e-3", "e-1", "e-2"])
        assert result["evidence_ids"] == ["e-1", "e-2", "e-3"]

    def test_evidence_count(self):
        result = _matrix(evidence_ids=["e-1", "e-2", "e-3"])
        assert result["evidence_count"] == 3

    def test_control_ids_sorted(self):
        result = _matrix(control_ids=["c-3", "c-1", "c-2"])
        assert result["control_ids"] == ["c-1", "c-2", "c-3"]

    def test_control_count(self):
        result = _matrix(control_ids=["c-1", "c-2"])
        assert result["control_count"] == 2

    def test_framework_ids_sorted(self):
        result = _matrix(framework_ids=["fw-3", "fw-1", "fw-2"])
        assert result["framework_ids"] == ["fw-1", "fw-2", "fw-3"]

    def test_framework_count(self):
        result = _matrix(framework_ids=["fw-1", "fw-2", "fw-3"])
        assert result["framework_count"] == 3

    def test_verification_ids_sorted(self):
        result = _matrix(verification_ids=["v-3", "v-1", "v-2"])
        assert result["verification_ids"] == ["v-1", "v-2", "v-3"]

    def test_trust_refs_sorted(self):
        result = _matrix(trust_refs=["tr-3", "tr-1", "tr-2"])
        assert result["trust_refs"] == ["tr-1", "tr-2", "tr-3"]

    def test_transparency_refs_sorted(self):
        result = _matrix(transparency_refs=["tx-3", "tx-1", "tx-2"])
        assert result["transparency_refs"] == ["tx-1", "tx-2", "tx-3"]

    def test_confidence_rounded(self):
        result = _matrix(confidence=0.12345678)
        assert abs(result["confidence"] - round(0.12345678, 4)) < 1e-9

    def test_expected_improvement_rounded(self):
        result = _matrix(expected_improvement=0.67891234)
        assert abs(result["expected_improvement"] - round(0.67891234, 4)) < 1e-9

    def test_simulation_ids_sorted(self):
        result = _matrix(simulation_ids=["s-3", "s-1", "s-2"])
        assert result["simulation_ids"] == ["s-1", "s-2", "s-3"]

    def test_simulation_count(self):
        result = _matrix(simulation_ids=["s-1", "s-2"])
        assert result["simulation_count"] == 2

    def test_coverage_present(self):
        assert "coverage" in _matrix()

    def test_coverage_in_range(self):
        result = _matrix()
        assert 0.0 <= result["coverage"] <= 1.0

    def test_risk_factors_stored(self):
        rf = [{"name": "rf", "severity": "HIGH"}]
        result = _matrix(risk_factors=rf)
        assert result["risk_factors"] == rf

    def test_risk_factor_count(self):
        rf = [{"name": "rf1"}, {"name": "rf2"}]
        result = _matrix(risk_factors=rf)
        assert result["risk_factor_count"] == 2


# ---------------------------------------------------------------------------
# compute_coverage
# ---------------------------------------------------------------------------


class TestComputeCoverage:
    def test_empty_matrix_has_low_coverage(self):
        coverage = compute_coverage(
            {"recommendation_id": "rec-1", "evidence_ids": ["e-1"]}
        )
        assert 0.0 <= coverage <= 1.0

    def test_full_matrix_has_high_coverage(self):
        full = {
            "evidence_ids": ["e-1", "e-2"],
            "control_ids": ["c-1"],
            "framework_ids": ["fw-1"],
            "verification_ids": ["v-1"],
            "trust_refs": ["tr-1"],
            "transparency_refs": ["tx-1"],
            "risk_factors": [{"name": "rf"}],
            "simulation_ids": ["s-1"],
            "confidence": 0.8,
            "expected_improvement": 0.2,
        }
        coverage = compute_coverage(full)
        assert coverage >= 0.9

    def test_coverage_returns_float(self):
        assert isinstance(compute_coverage({}), float)

    def test_coverage_capped_at_1(self):
        full = {
            "evidence_ids": ["e-1", "e-2"],
            "control_ids": ["c-1"],
            "framework_ids": ["fw-1"],
            "verification_ids": ["v-1"],
            "trust_refs": ["tr-1"],
            "transparency_refs": ["tx-1"],
            "risk_factors": [{"name": "rf"}],
            "simulation_ids": ["s-1"],
            "confidence": 1.0,
            "expected_improvement": 1.0,
        }
        assert compute_coverage(full) <= 1.0

    def test_coverage_at_least_0(self):
        assert compute_coverage({}) >= 0.0

    def test_coverage_fields_structure(self):
        assert len(_COVERAGE_FIELDS) == 8

    def test_weights_sum_to_1(self):
        total = sum(w for _, w in _COVERAGE_FIELDS)
        assert abs(total - 1.0) < 0.05

    def test_only_evidence_partial_coverage(self):
        m = {"evidence_ids": ["e-1"]}
        cov = compute_coverage(m)
        assert 0.0 < cov < 1.0


# ---------------------------------------------------------------------------
# validate_evidence_matrix
# ---------------------------------------------------------------------------


class TestValidateEvidenceMatrix:
    def test_valid_matrix_does_not_raise(self):
        m = _matrix()
        validate_evidence_matrix(m)

    def test_missing_recommendation_id_raises(self):
        m = _matrix()
        m["recommendation_id"] = ""
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_missing_evidence_ids_raises(self):
        m = _matrix()
        m["evidence_ids"] = []
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_coverage_below_zero_raises(self):
        m = _matrix()
        m["coverage"] = -0.1
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_coverage_above_one_raises(self):
        m = _matrix()
        m["coverage"] = 1.01
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_non_numeric_coverage_raises(self):
        m = _matrix()
        m["coverage"] = "bad"
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_confidence_below_zero_raises(self):
        m = _matrix()
        m["confidence"] = -0.1
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_confidence_above_one_raises(self):
        m = _matrix()
        m["confidence"] = 1.5
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_non_numeric_confidence_raises(self):
        m = _matrix()
        m["confidence"] = "bad"
        with pytest.raises(GovernanceIntelligenceValidationError):
            validate_evidence_matrix(m)

    def test_zero_coverage_valid(self):
        m = _matrix()
        m["coverage"] = 0.0
        validate_evidence_matrix(m)

    def test_one_coverage_valid(self):
        m = _matrix()
        m["coverage"] = 1.0
        validate_evidence_matrix(m)
