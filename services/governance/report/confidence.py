"""Deterministic confidence scoring for governance reports.

All functions are pure Python: no I/O, no randomness, no timestamps.

Scoring contract:
  evidence_completeness = validated_count / total_count   (0.0 if no evidence)
  evidence_freshness    = mean(1 - min(days/90, 1))      (0.0 if all freshness unknown)
  control_coverage      = validated_count / max(total_count, 1)

  overall = (
      0.4 * evidence_completeness
      + 0.3 * evidence_freshness
      + 0.2 * control_coverage
      + 0.1 * (1.0 if reviewer_validated else 0.0)
  ) * (assessment_completion_pct / 100.0)

Fails closed:
  - Empty evidence_refs → overall = 0.0, reasons = ("no evidence",)
  - assessment_completion_pct must be in [0, 100]; clamped defensively.
  - Each component < 0.5 → explicit degradation reason appended.
"""

from __future__ import annotations

from .models import ConfidenceScore, EvidenceRef, ValidationState

_EVIDENCE_COMPLETENESS_WEIGHT = 0.4
_EVIDENCE_FRESHNESS_WEIGHT = 0.3
_CONTROL_COVERAGE_WEIGHT = 0.2
_REVIEWER_VALIDATED_WEIGHT = 0.1

_FRESHNESS_STALENESS_DAYS = 90.0
_DEGRADATION_THRESHOLD = 0.5


def calculate_confidence(
    evidence_refs: list[EvidenceRef],
    assessment_completion_pct: float,
    reviewer_validated: bool,
) -> ConfidenceScore:
    """Calculate a deterministic ConfidenceScore from evidence and assessment state.

    Args:
        evidence_refs: All evidence references for the report.
        assessment_completion_pct: Percentage of assessment completed (0–100).
        reviewer_validated: Whether a human reviewer has validated the report.

    Returns:
        ConfidenceScore with all components computed deterministically.

    Fails closed:
        Empty evidence_refs → overall = 0.0, reasons = ("no evidence",).
    """
    # Clamp completion pct defensively.
    completion = max(0.0, min(100.0, float(assessment_completion_pct)))

    if not evidence_refs:
        return ConfidenceScore(
            overall=0.0,
            evidence_completeness=0.0,
            evidence_freshness=0.0,
            control_coverage=0.0,
            reviewer_validated=reviewer_validated,
            degradation_reasons=("no evidence",),
        )

    total_count = len(evidence_refs)
    validated_count = sum(
        1 for ref in evidence_refs if ref.validation_state == ValidationState.VALIDATED
    )

    # evidence_completeness
    evidence_completeness = validated_count / total_count

    # evidence_freshness — mean across refs that have freshness_days
    freshness_values: list[float] = []
    for ref in evidence_refs:
        if ref.freshness_days is not None:
            score = 1.0 - min(ref.freshness_days / _FRESHNESS_STALENESS_DAYS, 1.0)
            freshness_values.append(score)
    evidence_freshness = (
        sum(freshness_values) / len(freshness_values) if freshness_values else 0.0
    )

    # control_coverage
    control_coverage = validated_count / max(total_count, 1)

    # reviewer weight
    reviewer_weight = 1.0 if reviewer_validated else 0.0

    # overall (pre-completion scaling)
    pre_completion = (
        _EVIDENCE_COMPLETENESS_WEIGHT * evidence_completeness
        + _EVIDENCE_FRESHNESS_WEIGHT * evidence_freshness
        + _CONTROL_COVERAGE_WEIGHT * control_coverage
        + _REVIEWER_VALIDATED_WEIGHT * reviewer_weight
    )
    overall = pre_completion * (completion / 100.0)

    # Degradation reasons — explicit when any component is weak
    reasons: list[str] = []
    if evidence_completeness < _DEGRADATION_THRESHOLD:
        reasons.append(
            f"evidence completeness low ({evidence_completeness:.2f} < {_DEGRADATION_THRESHOLD})"
        )
    if evidence_freshness < _DEGRADATION_THRESHOLD:
        reasons.append(
            f"evidence freshness low ({evidence_freshness:.2f} < {_DEGRADATION_THRESHOLD})"
        )
    if control_coverage < _DEGRADATION_THRESHOLD:
        reasons.append(
            f"control coverage low ({control_coverage:.2f} < {_DEGRADATION_THRESHOLD})"
        )
    if not reviewer_validated:
        reasons.append("not reviewer-validated")
    if completion < 50.0:
        reasons.append(f"assessment completion low ({completion:.1f}%)")

    return ConfidenceScore(
        overall=overall,
        evidence_completeness=evidence_completeness,
        evidence_freshness=evidence_freshness,
        control_coverage=control_coverage,
        reviewer_validated=reviewer_validated,
        degradation_reasons=tuple(reasons),
    )
