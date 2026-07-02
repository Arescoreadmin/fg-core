"""Recommendation Evidence Matrix (PR 18.5A).

Pure functions only.  No DB I/O.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)


# ---------------------------------------------------------------------------
# Matrix builder
# ---------------------------------------------------------------------------


def build_evidence_matrix(
    recommendation_id: str,
    evidence_ids: list[str],
    control_ids: list[str],
    framework_ids: list[str],
    verification_ids: list[str],
    trust_refs: list[str],
    transparency_refs: list[str],
    risk_factors: list[dict[str, Any]],
    confidence: float,
    expected_improvement: float,
    simulation_ids: list[str],
) -> dict[str, Any]:
    """Build the full recommendation evidence matrix.

    Raises GovernanceIntelligenceValidationError if evidence_ids is empty.
    """
    if not evidence_ids:
        raise GovernanceIntelligenceValidationError(
            "evidence_ids must not be empty — at least one evidence item is required"
        )

    coverage = compute_coverage(
        {
            "recommendation_id": recommendation_id,
            "evidence_ids": evidence_ids,
            "control_ids": control_ids,
            "framework_ids": framework_ids,
            "verification_ids": verification_ids,
            "trust_refs": trust_refs,
            "transparency_refs": transparency_refs,
            "risk_factors": risk_factors,
            "confidence": confidence,
            "expected_improvement": expected_improvement,
            "simulation_ids": simulation_ids,
        }
    )

    return {
        "recommendation_id": recommendation_id,
        "evidence_ids": sorted(evidence_ids),
        "evidence_count": len(evidence_ids),
        "control_ids": sorted(control_ids),
        "control_count": len(control_ids),
        "framework_ids": sorted(framework_ids),
        "framework_count": len(framework_ids),
        "verification_ids": sorted(verification_ids),
        "verification_count": len(verification_ids),
        "trust_refs": sorted(trust_refs),
        "transparency_refs": sorted(transparency_refs),
        "risk_factors": risk_factors,
        "risk_factor_count": len(risk_factors),
        "confidence": round(float(confidence), 4),
        "expected_improvement": round(float(expected_improvement), 4),
        "simulation_ids": sorted(simulation_ids),
        "simulation_count": len(simulation_ids),
        "coverage": round(coverage, 4),
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_evidence_matrix(matrix: dict[str, Any]) -> None:
    """Validate a matrix dict.  Fail-closed: raises on any violation."""
    if not matrix.get("recommendation_id"):
        raise GovernanceIntelligenceValidationError("matrix missing recommendation_id")
    if not matrix.get("evidence_ids"):
        raise GovernanceIntelligenceValidationError(
            "matrix evidence_ids must not be empty"
        )
    coverage = matrix.get("coverage", -1)
    if not isinstance(coverage, (int, float)):
        raise GovernanceIntelligenceValidationError("matrix coverage must be numeric")
    if not (0.0 <= float(coverage) <= 1.0):
        raise GovernanceIntelligenceValidationError(
            f"matrix coverage {coverage} is outside [0.0, 1.0]"
        )
    confidence = matrix.get("confidence", -1)
    if not isinstance(confidence, (int, float)):
        raise GovernanceIntelligenceValidationError("matrix confidence must be numeric")
    if not (0.0 <= float(confidence) <= 1.0):
        raise GovernanceIntelligenceValidationError(
            f"matrix confidence {confidence} is outside [0.0, 1.0]"
        )


# ---------------------------------------------------------------------------
# Coverage computation
# ---------------------------------------------------------------------------

_COVERAGE_FIELDS = [
    ("evidence_ids", 0.25),
    ("control_ids", 0.15),
    ("framework_ids", 0.15),
    ("verification_ids", 0.15),
    ("trust_refs", 0.10),
    ("transparency_refs", 0.10),
    ("risk_factors", 0.05),
    ("simulation_ids", 0.05),
]


def compute_coverage(matrix: dict[str, Any]) -> float:
    """Compute coverage score (0.0 – 1.0) based on how many fields are populated."""
    score = 0.0
    for field_name, weight in _COVERAGE_FIELDS:
        val = matrix.get(field_name)
        if val:
            score += weight
    # Confidence and expected_improvement also contribute
    if matrix.get("confidence", 0.0) > 0.0:
        score = min(1.0, score + 0.025)
    if matrix.get("expected_improvement", 0.0) > 0.0:
        score = min(1.0, score + 0.025)
    return round(min(1.0, score), 4)
