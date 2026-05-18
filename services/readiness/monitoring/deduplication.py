"""Deterministic drift event deduplication.

All functions are pure Python: no I/O, no side effects, no randomness.

Deduplication contract:
  - Events with identical event_fingerprints within a single run are duplicates.
  - Deduplication keeps the highest-severity event (by DriftSeverity rank).
  - When severity is equal, the event with the more specific certainty wins
    (CONFIRMED > SUSPECTED > INCOMPLETE_EVALUATION > others).
  - Output order is stable: sorted by (severity_rank DESC, drift_type, affected_scope).
  - Unique events are NEVER suppressed — only exact fingerprint duplicates are collapsed.
  - The deduplication result is explainable: collapsed_count shows how many were merged.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import DriftCertainty, DriftEvent, severity_rank

# Certainty ordering for tie-breaking (higher = preferred when severity is equal).
_CERTAINTY_RANK: dict[DriftCertainty, int] = {
    DriftCertainty.CONFIRMED: 6,
    DriftCertainty.SUSPECTED: 5,
    DriftCertainty.INCOMPLETE_EVALUATION: 4,
    DriftCertainty.DEGRADED_VISIBILITY: 3,
    DriftCertainty.STALE_MONITORING_STATE: 2,
    DriftCertainty.MONITORING_SOURCE_FAILURE: 1,
    DriftCertainty.UNVERIFIABLE: 1,
    DriftCertainty.UNKNOWN: 0,
}


def _certainty_rank(c: DriftCertainty) -> int:
    return _CERTAINTY_RANK.get(c, 0)


def _event_sort_key(e: DriftEvent) -> tuple[int, str, str]:
    # Descending severity, then stable alphabetic on type/scope.
    return (-severity_rank(e.severity), e.drift_type.value, e.affected_scope)


@dataclass(frozen=True)
class DeduplicationResult:
    events: tuple[DriftEvent, ...]
    total_before: int
    total_after: int
    collapsed_count: int


def deduplicate_drift_events(events: list[DriftEvent]) -> DeduplicationResult:
    """Deduplicate drift events by fingerprint, keeping the highest-severity per fingerprint.

    Deduplication is deterministic: identical input lists → identical output.
    Output is sorted by (severity DESC, drift_type, affected_scope) for stable ordering.
    """
    total_before = len(events)
    by_fingerprint: dict[str, DriftEvent] = {}

    for event in events:
        fp = event.event_fingerprint
        existing = by_fingerprint.get(fp)
        if existing is None:
            by_fingerprint[fp] = event
        else:
            # Keep highest severity; break ties by certainty rank.
            existing_rank = severity_rank(existing.severity)
            candidate_rank = severity_rank(event.severity)
            if candidate_rank > existing_rank:
                by_fingerprint[fp] = event
            elif candidate_rank == existing_rank:
                if _certainty_rank(event.certainty) > _certainty_rank(
                    existing.certainty
                ):
                    by_fingerprint[fp] = event

    deduped = sorted(by_fingerprint.values(), key=_event_sort_key)
    total_after = len(deduped)

    return DeduplicationResult(
        events=tuple(deduped),
        total_before=total_before,
        total_after=total_after,
        collapsed_count=total_before - total_after,
    )
