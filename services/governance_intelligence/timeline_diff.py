"""Governance Timeline Diff (PR 18.5A).

Pure functions only.  No DB I/O.
"""

from __future__ import annotations

from typing import Any

from services.governance_intelligence.schemas import (
    GovernanceIntelligenceValidationError,
)

# ---------------------------------------------------------------------------
# Supported windows
# ---------------------------------------------------------------------------

SUPPORTED_WINDOWS: frozenset[str] = frozenset(
    {
        "NOW",
        "YESTERDAY",
        "LAST_WEEK",
        "LAST_MONTH",
        "QUARTER",
        "BEFORE_AFTER_REMEDIATION",
        "BEFORE_AFTER_ACQUISITION",
        "BEFORE_AFTER_INCIDENT",
    }
)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def validate_window(window: str) -> None:
    """Raise GovernanceIntelligenceValidationError if window is not supported."""
    if window not in SUPPORTED_WINDOWS:
        raise GovernanceIntelligenceValidationError(
            f"Unsupported timeline diff window '{window}'. "
            f"Supported: {sorted(SUPPORTED_WINDOWS)}"
        )


# ---------------------------------------------------------------------------
# Diff computation
# ---------------------------------------------------------------------------


def _extract_ids(period: dict[str, Any], key: str) -> set[str]:
    val = period.get(key, [])
    if isinstance(val, list):
        return set(str(v) for v in val)
    return set()


def compute_timeline_diff(
    period_a: dict[str, Any],
    period_b: dict[str, Any],
    window: str,
) -> dict[str, Any]:
    """Compute a deterministic diff between two governance timeline periods.

    Returns: window, added, removed, changed, risk_delta, governance_delta,
    recommendation_delta, confidence_delta.
    """
    validate_window(window)

    # Compare ID sets for findings / events
    findings_a = _extract_ids(period_a, "finding_ids")
    findings_b = _extract_ids(period_b, "finding_ids")

    added = [{"id": fid, "type": "finding"} for fid in sorted(findings_b - findings_a)]
    removed = [
        {"id": fid, "type": "finding"} for fid in sorted(findings_a - findings_b)
    ]

    # Look for changed items by comparing metadata dicts if provided
    changed: list[dict[str, Any]] = []
    meta_a = period_a.get("metadata", {})
    meta_b = period_b.get("metadata", {})
    if isinstance(meta_a, dict) and isinstance(meta_b, dict):
        common_keys = set(meta_a.keys()) & set(meta_b.keys())
        for key in sorted(common_keys):
            if meta_a[key] != meta_b[key]:
                changed.append({"field": key, "from": meta_a[key], "to": meta_b[key]})

    # Numeric deltas
    def _f(d: dict[str, Any], k: str, default: float = 0.0) -> float:
        try:
            return float(d.get(k, default))
        except (TypeError, ValueError):
            return default

    risk_delta = round(_f(period_b, "risk_score") - _f(period_a, "risk_score"), 4)
    governance_delta = round(
        _f(period_b, "governance_score") - _f(period_a, "governance_score"), 4
    )
    rec_a = int(_f(period_a, "recommendation_count"))
    rec_b = int(_f(period_b, "recommendation_count"))
    recommendation_delta = rec_b - rec_a
    confidence_delta = round(_f(period_b, "confidence") - _f(period_a, "confidence"), 4)

    return {
        "window": window,
        "added": added,
        "removed": removed,
        "changed": changed,
        "risk_delta": risk_delta,
        "governance_delta": governance_delta,
        "recommendation_delta": recommendation_delta,
        "confidence_delta": confidence_delta,
    }


# ---------------------------------------------------------------------------
# Human-readable summary
# ---------------------------------------------------------------------------


def summarize_diff(diff: dict[str, Any]) -> str:
    """Return a short human-readable summary of a timeline diff."""
    window = diff.get("window", "UNKNOWN")
    added = len(diff.get("added", []))
    removed = len(diff.get("removed", []))
    changed = len(diff.get("changed", []))
    risk_delta = diff.get("risk_delta", 0.0)
    gov_delta = diff.get("governance_delta", 0.0)

    risk_str = f"+{risk_delta:.4f}" if risk_delta >= 0 else f"{risk_delta:.4f}"
    gov_str = f"+{gov_delta:.4f}" if gov_delta >= 0 else f"{gov_delta:.4f}"

    parts = [
        f"Window: {window}",
        f"Added: {added}, Removed: {removed}, Changed: {changed}",
        f"Risk delta: {risk_str}",
        f"Governance delta: {gov_str}",
    ]
    return " | ".join(parts)
