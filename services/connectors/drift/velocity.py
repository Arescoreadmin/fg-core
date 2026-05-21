"""Drift velocity and MTTR computation over multi-scan history.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Deferred from PR 5.5, implemented in PR 6.

Velocity metrics:
  new_per_day      — average net-new findings per day over the scan window
  mttr_days        — mean time to resolve: average days a finding was open before
                     it disappeared from the scan series (None if no resolutions)
  regression_rate  — fraction of ever-resolved findings that reappeared (0.0–1.0)

Design:
  Uses FaScanResult.finding_count (added in PR 6) for rate computation — avoids
  calling compute_drift() per pair (which would cost 6 DB queries × N pairs).
  MTTR requires per-finding presence tracking via FaEvidenceLink stable-key join;
  implemented as a single scan over link rows, not N compute_drift() calls.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaNormalizedFinding,
    FaScanResult,
)

log = logging.getLogger("frostgate.connectors.drift.velocity")


@dataclass(frozen=True)
class DriftVelocity:
    tenant_id: str
    engagement_id: str
    scans_analyzed: int
    new_per_day: float
    mttr_days: float | None
    regression_rate: float
    window_start: str
    window_end: str


def _parse_iso(ts: str) -> datetime | None:
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%fZ",
    ):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _stable_key(finding_type: str, title: str) -> str:
    return hashlib.sha256(f"{finding_type}:{title}".encode()).hexdigest()


def compute_drift_velocity(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    n_scans: int = 10,
) -> DriftVelocity | None:
    """Compute drift velocity metrics from the last n_scans scan results.

    Returns None when fewer than 2 scans exist for the engagement.
    """
    scans = (
        db.execute(
            select(FaScanResult)
            .where(
                FaScanResult.tenant_id == tenant_id,
                FaScanResult.engagement_id == engagement_id,
            )
            .order_by(FaScanResult.collected_at.asc())
            .limit(max(n_scans, 2))
        )
        .scalars()
        .all()
    )

    if len(scans) < 2:
        return None

    # --- new_per_day via finding_count deltas ---
    total_new = 0
    for i in range(1, len(scans)):
        delta = scans[i].finding_count - scans[i - 1].finding_count
        if delta > 0:
            total_new += delta

    first_dt = _parse_iso(scans[0].collected_at)
    last_dt = _parse_iso(scans[-1].collected_at)
    if first_dt is None or last_dt is None or first_dt >= last_dt:
        days_spanned = 1.0
    else:
        days_spanned = max((last_dt - first_dt).total_seconds() / 86400, 1.0)

    new_per_day = total_new / days_spanned

    # --- MTTR and regression_rate via stable-key presence matrix ---
    scan_ids = [s.id for s in scans]
    link_rows = (
        db.execute(
            select(
                FaEvidenceLink.source_entity_id,
                FaEvidenceLink.evidence_entity_id,
            ).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "finding",
                FaEvidenceLink.evidence_entity_type == "scan_result",
                FaEvidenceLink.evidence_entity_id.in_(scan_ids),
            )
        )
        .all()
    )

    finding_ids = {row[0] for row in link_rows}
    if not finding_ids:
        return DriftVelocity(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            scans_analyzed=len(scans),
            new_per_day=new_per_day,
            mttr_days=None,
            regression_rate=0.0,
            window_start=scans[0].collected_at,
            window_end=scans[-1].collected_at,
        )

    finding_rows = (
        db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.id.in_(finding_ids),
            )
        )
        .scalars()
        .all()
    )
    finding_key_map: dict[str, str] = {
        r.id: _stable_key(r.finding_type, r.title) for r in finding_rows
    }

    # Build presence matrix: scan_index → set of stable_keys present
    scan_index = {s.id: i for i, s in enumerate(scans)}
    presence: dict[str, set[int]] = {}
    for finding_id, scan_id in link_rows:
        key = finding_key_map.get(finding_id)
        if key is None:
            continue
        idx = scan_index.get(scan_id)
        if idx is None:
            continue
        presence.setdefault(key, set()).add(idx)

    # MTTR: findings not present in the last scan (resolved at some point)
    last_idx = len(scans) - 1
    resolution_days: list[float] = []
    ever_resolved: set[str] = set()
    regressed: set[str] = set()

    for key, indices in presence.items():
        if not indices:
            continue
        first_seen = min(indices)
        last_seen = max(indices)

        if last_seen < last_idx:
            # Finding resolved before the last scan (absent in final state)
            ever_resolved.add(key)
            first_dt_k = _parse_iso(scans[first_seen].collected_at)
            last_dt_k = _parse_iso(scans[last_seen].collected_at)
            if first_dt_k and last_dt_k and last_dt_k > first_dt_k:
                resolution_days.append(
                    (last_dt_k - first_dt_k).total_seconds() / 86400
                )

        # Regression: gap in presence (present, absent, then present again)
        sorted_idx = sorted(indices)
        for j in range(1, len(sorted_idx)):
            if sorted_idx[j] > sorted_idx[j - 1] + 1:
                # Gap detected — was absent in at least one intermediate scan
                regressed.add(key)
                ever_resolved.add(key)  # was resolved at least once
                break

    mttr_days = (
        sum(resolution_days) / len(resolution_days) if resolution_days else None
    )
    regression_rate = (
        len(regressed) / len(ever_resolved) if ever_resolved else 0.0
    )

    return DriftVelocity(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        scans_analyzed=len(scans),
        new_per_day=round(new_per_day, 4),
        mttr_days=round(mttr_days, 2) if mttr_days is not None else None,
        regression_rate=round(regression_rate, 4),
        window_start=scans[0].collected_at,
        window_end=scans[-1].collected_at,
    )
