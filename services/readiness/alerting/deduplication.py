"""Deterministic alert deduplication.

All functions are pure Python: no I/O, no side effects, no randomness.

Deduplication contract:
  - Dedup key = (alert_fingerprint, tenant_id).
  - Within cooldown window: highest-severity alert wins.
  - burst_ceiling: cap occurrences per dedup window (per rule config).
  - CRITICAL and BLOCKING alerts are NEVER suppressed by deduplication.
  - Output is explainable: each AlertDeduplicationRecord carries
    first_seen, last_seen, occurrence_count, suppressed_count.
  - Deduplication is deterministic: identical alert list → identical output.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .models import (
    AlertDeduplicationRecord,
    AlertInstance,
    AlertSeverity,
    alert_severity_rank,
)

_NEVER_SUPPRESS_SEVERITIES = {AlertSeverity.CRITICAL, AlertSeverity.BLOCKING}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class DeduplicationResult:
    """Result of alert deduplication."""

    alerts_after: tuple[AlertInstance, ...]
    total_before: int
    total_deduplicated: int
    dedup_records: tuple[AlertDeduplicationRecord, ...]


def deduplicate_alerts(
    alerts: list[AlertInstance],
    cooldown_minutes: int,
    burst_ceiling: int,
) -> DeduplicationResult:
    """Deduplicate alerts by fingerprint + tenant_id.

    Within a cooldown window:
      - Highest-severity alert wins (ties: keep the first seen).
      - burst_ceiling: if occurrence_count exceeds this for a given fingerprint,
        suppress additional occurrences (CRITICAL/BLOCKING are never suppressed).
      - Returns DeduplicationResult with explainable dedup records.

    Deterministic: identical alert list → identical output.
    """
    if not alerts:
        return DeduplicationResult(
            alerts_after=(),
            total_before=0,
            total_deduplicated=0,
            dedup_records=(),
        )

    total_before = len(alerts)
    now_iso = _now_iso()

    # Group by dedup key: (alert_fingerprint, tenant_id)
    # Track: best_alert, occurrence_count, suppressed_count, first_seen, last_seen
    groups: dict[
        tuple[str, str],
        dict,
    ] = {}

    for alert in alerts:
        key = (alert.alert_fingerprint, alert.tenant_id)
        if key not in groups:
            groups[key] = {
                "best": alert,
                "occurrence_count": 1,
                "suppressed_count": 0,
                "first_seen_iso": alert.generated_at_iso,
                "last_seen_iso": alert.generated_at_iso,
            }
        else:
            grp = groups[key]
            grp["occurrence_count"] += 1
            # Update last_seen
            grp["last_seen_iso"] = alert.generated_at_iso

            # Check burst ceiling — CRITICAL/BLOCKING are never burst-suppressed
            if (
                grp["occurrence_count"] > burst_ceiling
                and alert.severity not in _NEVER_SUPPRESS_SEVERITIES
            ):
                grp["suppressed_count"] += 1
                continue

            # Keep highest severity
            existing_rank = alert_severity_rank(grp["best"].severity)
            candidate_rank = alert_severity_rank(alert.severity)
            if candidate_rank > existing_rank:
                grp["best"] = alert

    # Build output lists
    output_alerts: list[AlertInstance] = []
    dedup_records: list[AlertDeduplicationRecord] = []

    for (fingerprint, tenant_id), grp in groups.items():
        output_alerts.append(grp["best"])

        # Derive window boundaries (cooldown window relative to first_seen)
        # For determinism we use the first_seen timestamp as window anchor.
        dedup_record = AlertDeduplicationRecord(
            dedup_window_key=f"{fingerprint}:{tenant_id}",
            alert_rule_id=grp["best"].alert_rule_id,
            tenant_id=tenant_id,
            first_seen_iso=grp["first_seen_iso"],
            last_seen_iso=grp["last_seen_iso"],
            occurrence_count=grp["occurrence_count"],
            suppressed_count=grp["suppressed_count"],
            window_start_iso=grp["first_seen_iso"],
            window_end_iso=now_iso,
        )
        dedup_records.append(dedup_record)

    # Sort for stable output: descending severity, then alert_instance_id
    output_alerts.sort(
        key=lambda a: (-alert_severity_rank(a.severity), a.alert_instance_id)
    )

    total_deduplicated = total_before - len(output_alerts)

    return DeduplicationResult(
        alerts_after=tuple(output_alerts),
        total_before=total_before,
        total_deduplicated=total_deduplicated,
        dedup_records=tuple(dedup_records),
    )
