"""Evidence freshness degradation for finding confidence scores.

Confidence scores set at scan time decay as evidence ages.  The stored
``confidence_score`` on ``FaNormalizedFinding`` is always the *base* value
(as assessed by the scanner).  Call ``degrade_confidence`` at read time to
obtain the *effective* score that should be shown to users and used in report
aggregations.

Decay schedule (applied against ``updated_at`` — last time the finding was
corroborated by a scan):

    0–30 days   →  no decay         (evidence is current)
    31–60 days  →  −5 points        (minor staleness)
    61–90 days  →  −15 points       (moderate staleness; approaching re-assessment window)
    91+ days    →  −30 points       (stale; rescanning is overdue)

Floor: 30.  Evidence never becomes worthless — it just signals that a
re-scan is needed.  Findings at or below 60 after degradation trigger the
low-confidence escalation path in the readiness engine.

Fail-closed timestamp handling:
    A malformed or missing ``updated_at`` value cannot be silently treated as
    fully fresh (age zero).  ``evidence_age_days`` returns ``_FAIL_CLOSED_AGE_DAYS``
    (91, one past the maximum decay threshold) so downstream callers and
    epistemic authorities always apply maximum decay and treat such evidence
    as STALE.
"""

from __future__ import annotations

from datetime import datetime, timezone

# (days_threshold, points_to_subtract) — applied in order; first match wins
_DECAY_TABLE: list[tuple[int, int]] = [
    (30, 0),
    (60, 5),
    (90, 15),
]
_DECAY_BEYOND_90 = 30
_CONFIDENCE_FLOOR = 30

# Fail-closed sentinel: returned when a timestamp cannot be parsed.
# Value is one past the highest threshold in _DECAY_TABLE so the caller
# always takes the maximum-decay path (_DECAY_BEYOND_90).  This is a
# conservative sentinel, not an asserted factual age — the caller must
# treat the evidence as STALE rather than CURRENT.
_FAIL_CLOSED_AGE_DAYS: int = 91


def evidence_age_days(iso_date: str) -> int:
    """Return how many days have elapsed since *iso_date* (UTC ISO 8601).

    Fail-closed: a malformed or missing timestamp cannot be interpreted as
    age zero (fully fresh).  Returns _FAIL_CLOSED_AGE_DAYS so the caller
    applies maximum decay and downstream epistemic authorities treat the
    evidence as STALE rather than CURRENT.
    """
    try:
        dt = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except (ValueError, AttributeError):
        return _FAIL_CLOSED_AGE_DAYS


def degrade_confidence(base_score: int, updated_at: str) -> int:
    """Return the effective confidence score after applying evidence-age decay."""
    age = evidence_age_days(updated_at)
    reduction = _DECAY_BEYOND_90
    for threshold, points in _DECAY_TABLE:
        if age <= threshold:
            reduction = points
            break
    return max(_CONFIDENCE_FLOOR, base_score - reduction)
