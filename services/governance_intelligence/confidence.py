"""Confidence scoring utilities for the Governance Intelligence Authority.

Pure functions. No I/O. No SQLAlchemy. No Pydantic.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.models import ConfidenceLevel
from services.canonical import utc_iso8601_z_now


def compute_data_freshness_score(
    items: list[dict[str, Any]], max_age_days: int
) -> float:
    """Return 0.0-1.0 freshness score based on how recently items were created/updated."""
    if not items:
        return 0.0
    if max_age_days <= 0:
        return 1.0

    import datetime

    now_str = utc_iso8601_z_now()
    now = datetime.datetime.fromisoformat(now_str.replace("Z", "+00:00"))
    max_age_seconds = max_age_days * 86400

    fresh_count = 0
    for item in items:
        ts_str = item.get("updated_at") or item.get("created_at") or ""
        if not ts_str:
            continue
        try:
            ts = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            age_seconds = (now - ts).total_seconds()
            if age_seconds <= max_age_seconds:
                fresh_count += 1
        except (ValueError, TypeError):
            continue

    return round(fresh_count / len(items), 4)


def compute_coverage_score(covered: int, total: int) -> float:
    """Return 0.0-1.0 coverage score."""
    if total <= 0:
        return 0.0
    return round(min(1.0, max(0.0, covered / total)), 4)


def compute_sample_confidence(sample_size: int) -> float:
    """Return a confidence float (0.0-1.0) based on sample size.

    small samples (< 10) → LOW (0.33)
    < 30 → MEDIUM (0.66)
    else → HIGH (1.0)
    """
    if sample_size < 10:
        return 0.33
    if sample_size < 30:
        return 0.66
    return 1.0


def compute_overall_confidence(scores: list[float]) -> tuple[float, str]:
    """Return (score, ConfidenceLevel value) from a list of component scores."""
    if not scores:
        return 0.0, ConfidenceLevel.INSUFFICIENT.value

    avg = sum(scores) / len(scores)
    avg = round(avg, 4)

    if avg >= 0.75:
        level = ConfidenceLevel.HIGH.value
    elif avg >= 0.50:
        level = ConfidenceLevel.MEDIUM.value
    elif avg > 0.0:
        level = ConfidenceLevel.LOW.value
    else:
        level = ConfidenceLevel.INSUFFICIENT.value

    return avg, level


def build_confidence_response(
    dimension: str, scores: dict[str, float]
) -> dict[str, Any]:
    """Build a confidence response dict."""
    score_list = list(scores.values())
    overall_score, level = compute_overall_confidence(score_list)
    return {
        "dimension": dimension,
        "score": overall_score,
        "level": level,
        "factors": scores,
        "computed_at": utc_iso8601_z_now(),
    }
