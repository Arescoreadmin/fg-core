"""Intelligence Quality Score (PR 18.5A).

Pure functions only.  No DB I/O.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)

# ---------------------------------------------------------------------------
# Grade constants
# ---------------------------------------------------------------------------

QUALITY_GRADES = ["A+", "A", "B", "C", "INSUFFICIENT_EVIDENCE"]

# Weights — must sum to exactly 1.00
_WEIGHTS = {
    "evidence_coverage": 0.20,
    "evidence_freshness": 0.15,
    "verification_coverage": 0.15,
    "policy_confidence": 0.10,
    "benchmark_confidence": 0.10,
    "simulation_confidence": 0.05,
    "historical_stability": 0.05,
    "trust_integrity": 0.10,
    "transparency_integrity": 0.05,
    "data_completeness": 0.05,
}

assert abs(sum(_WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"


# ---------------------------------------------------------------------------
# Core computation
# ---------------------------------------------------------------------------


def compute_quality_score(
    evidence_coverage: float,
    evidence_freshness: float,
    verification_coverage: float,
    policy_confidence: float,
    benchmark_confidence: float,
    simulation_confidence: float,
    historical_stability: float,
    trust_integrity: float,
    transparency_integrity: float,
    data_completeness: float,
) -> tuple[float, str]:
    """Compute weighted quality score and assign a grade.

    All inputs must be in [0.0, 1.0].
    Returns (score: float, grade: str).
    Grade thresholds:
      >= 0.90 → A+
      >= 0.80 → A
      >= 0.65 → B
      >= 0.50 → C
      else    → INSUFFICIENT_EVIDENCE
    """
    inputs = {
        "evidence_coverage": evidence_coverage,
        "evidence_freshness": evidence_freshness,
        "verification_coverage": verification_coverage,
        "policy_confidence": policy_confidence,
        "benchmark_confidence": benchmark_confidence,
        "simulation_confidence": simulation_confidence,
        "historical_stability": historical_stability,
        "trust_integrity": trust_integrity,
        "transparency_integrity": transparency_integrity,
        "data_completeness": data_completeness,
    }
    for name, val in inputs.items():
        if not isinstance(val, (int, float)):
            raise GovernanceIntelligenceValidationError(
                f"quality score input '{name}' must be numeric, got {type(val).__name__}"
            )
        if not (0.0 <= float(val) <= 1.0):
            raise GovernanceIntelligenceValidationError(
                f"quality score input '{name}' = {val} is outside [0.0, 1.0]"
            )

    score = sum(_WEIGHTS[k] * float(v) for k, v in inputs.items())
    score = round(min(1.0, max(0.0, score)), 6)

    grade = _assign_grade(score)
    return score, grade


def _assign_grade(score: float) -> str:
    if score >= 0.90:
        return "A+"
    if score >= 0.80:
        return "A"
    if score >= 0.65:
        return "B"
    if score >= 0.50:
        return "C"
    return "INSUFFICIENT_EVIDENCE"


# ---------------------------------------------------------------------------
# Response builder
# ---------------------------------------------------------------------------


def build_quality_response(inputs: dict[str, float]) -> dict[str, Any]:
    """Build a quality response dict from a flat inputs dict."""
    defaults = {k: 0.0 for k in _WEIGHTS}
    merged = {**defaults, **inputs}
    score, grade = compute_quality_score(
        evidence_coverage=merged["evidence_coverage"],
        evidence_freshness=merged["evidence_freshness"],
        verification_coverage=merged["verification_coverage"],
        policy_confidence=merged["policy_confidence"],
        benchmark_confidence=merged["benchmark_confidence"],
        simulation_confidence=merged["simulation_confidence"],
        historical_stability=merged["historical_stability"],
        trust_integrity=merged["trust_integrity"],
        transparency_integrity=merged["transparency_integrity"],
        data_completeness=merged["data_completeness"],
    )
    return {
        "score": score,
        "grade": grade,
        "inputs": {k: round(float(merged.get(k, 0.0)), 6) for k in _WEIGHTS},
        "weights": dict(_WEIGHTS),
    }
