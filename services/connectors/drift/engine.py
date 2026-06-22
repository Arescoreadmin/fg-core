"""Connector-agnostic drift detection engine.

Operates on FaNormalizedFinding and FaEvidenceLink rows — not on connector-specific
schema objects. Any connector whose findings land in fa_normalized_findings gets
drift detection for free.

Delta classes:
  new          — finding in current scan, absent from all earlier scans
  persisted    — finding in both current and baseline scans (severity unchanged)
  resolved     — finding in baseline, absent from current scan
  regressed    — finding in current scan, absent from baseline, but present in
                 scans that predate the baseline (was present before, resolved, returned)
  escalated    — finding in both scans; severity is higher now than at baseline
  de_escalated — finding in both scans; severity is lower now than at baseline

Cross-scan matching uses a stable logical key derived from (finding_type, title) —
NOT FaNormalizedFinding.id, which is scan-specific because the MS Graph import path
includes scan.scan_id and manifest_hash in source_ref, producing a different row ID
per scan for the same logical finding. Severity comparison reads directly from the
baseline scan's FaNormalizedFinding row, not from the normalized_payload blob.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import (
    FaEvidenceLink,
    FaNormalizedFinding,
    FaScanResult,
)

log = logging.getLogger("frostgate.connectors.drift.engine")

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


def _stable_key(finding_type: str, title: str) -> str:
    """Content-stable cross-scan identifier for a logical finding.

    Derived from (finding_type, title) — fields that are consistent across scan
    runs for the same governance control failure. Does NOT include scan.scan_id,
    manifest_hash, or source_ref, which change per run.
    """
    raw = f"{finding_type}:{title}"
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass(frozen=True)
class DriftFindingRecord:
    """Classification result for a single finding in a drift computation."""

    finding_id: str  # FaNormalizedFinding.id from the current scan row
    findings_hash: str
    title: str
    severity: str  # current severity
    baseline_severity: str | None  # None when not in baseline
    delta_class: (
        str  # new | persisted | resolved | regressed | escalated | de_escalated
    )
    evidence_ref_ids: list[str]
    rationale: str  # human-readable explanation of classification


@dataclass
class DriftResult:
    """Full drift computation result for a (baseline_scan, current_scan) pair."""

    tenant_id: str
    engagement_id: str
    baseline_scan_id: str
    current_scan_id: str
    findings: list[DriftFindingRecord] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for f in self.findings:
            tally[f.delta_class] = tally.get(f.delta_class, 0) + 1
        return tally

    @property
    def has_critical_regression(self) -> bool:
        return any(
            f.delta_class == "regressed" and f.severity == "critical"
            for f in self.findings
        )


def _findings_for_scan(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_id: str,
) -> dict[str, FaNormalizedFinding]:
    """Return {stable_key: FaNormalizedFinding} for all findings linked to scan_id.

    Uses (finding_type, title) as the stable key so the same logical finding
    matches across scans regardless of per-run row ID variation.
    """
    link_ids = (
        db.execute(
            select(FaEvidenceLink.source_entity_id).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "finding",
                FaEvidenceLink.evidence_entity_type == "scan_result",
                FaEvidenceLink.evidence_entity_id == scan_id,
            )
        )
        .scalars()
        .all()
    )

    if not link_ids:
        return {}

    rows = (
        db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.id.in_(set(link_ids)),
            )
        )
        .scalars()
        .all()
    )

    return {_stable_key(r.finding_type, r.title): r for r in rows}


def _stable_keys_in_earlier_scans(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    before_collected_at: str,
    candidate_keys: set[str],
) -> set[str]:
    """Return which candidate_keys appeared in any scan collected before before_collected_at.

    Used for regressed detection: a finding is regressed (not new) if it existed
    in a scan that predates the baseline scan.
    """
    if not candidate_keys:
        return set()

    earlier_scan_ids = (
        db.execute(
            select(FaScanResult.id).where(
                FaScanResult.tenant_id == tenant_id,
                FaScanResult.engagement_id == engagement_id,
                FaScanResult.collected_at < before_collected_at,
            )
        )
        .scalars()
        .all()
    )

    if not earlier_scan_ids:
        return set()

    earlier_finding_ids = set(
        db.execute(
            select(FaEvidenceLink.source_entity_id).where(
                FaEvidenceLink.tenant_id == tenant_id,
                FaEvidenceLink.engagement_id == engagement_id,
                FaEvidenceLink.source_entity_type == "finding",
                FaEvidenceLink.evidence_entity_type == "scan_result",
                FaEvidenceLink.evidence_entity_id.in_(set(earlier_scan_ids)),
            )
        )
        .scalars()
        .all()
    )

    if not earlier_finding_ids:
        return set()

    earlier_rows = (
        db.execute(
            select(FaNormalizedFinding).where(
                FaNormalizedFinding.tenant_id == tenant_id,
                FaNormalizedFinding.engagement_id == engagement_id,
                FaNormalizedFinding.id.in_(earlier_finding_ids),
            )
        )
        .scalars()
        .all()
    )

    earlier_keys = {_stable_key(r.finding_type, r.title) for r in earlier_rows}
    return earlier_keys & candidate_keys


def compute_drift(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    baseline_scan_id: str,
    current_scan_id: str,
) -> DriftResult:
    """Compute drift between a pinned baseline scan and a current scan.

    Both scans must belong to (tenant_id, engagement_id).
    Raises ValueError when either scan is not found.
    """
    baseline_scan = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == baseline_scan_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()
    if baseline_scan is None:
        raise ValueError(f"baseline scan {baseline_scan_id!r} not found for engagement")

    current_scan = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == current_scan_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()
    if current_scan is None:
        raise ValueError(f"current scan {current_scan_id!r} not found for engagement")

    baseline_map = _findings_for_scan(
        db, tenant_id=tenant_id, engagement_id=engagement_id, scan_id=baseline_scan_id
    )
    current_map = _findings_for_scan(
        db, tenant_id=tenant_id, engagement_id=engagement_id, scan_id=current_scan_id
    )

    all_keys = set(baseline_map) | set(current_map)
    if not all_keys:
        return DriftResult(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
        )

    # For findings only in current scan, determine regressed vs new
    only_in_current = set(current_map) - set(baseline_map)
    regressed_keys = _stable_keys_in_earlier_scans(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        before_collected_at=baseline_scan.collected_at,
        candidate_keys=only_in_current,
    )

    records: list[DriftFindingRecord] = []

    for key in all_keys:
        in_baseline = key in baseline_map
        in_current = key in current_map

        # Use current row when available; fall back to baseline row for resolved findings
        current_row = current_map.get(key)
        baseline_row = baseline_map.get(key)
        row = current_row or baseline_row
        assert row is not None  # guaranteed by all_keys construction

        current_sev = (
            current_row.severity
            if current_row
            else (baseline_row.severity if baseline_row else "informational")
        )
        baseline_sev: str | None = baseline_row.severity if baseline_row else None

        if in_current and in_baseline:
            assert current_row is not None and baseline_row is not None
            cur_rank = _SEVERITY_RANK.get(current_sev, 0)
            base_rank = _SEVERITY_RANK.get(baseline_sev or "", 0)
            if cur_rank > base_rank:
                delta = "escalated"
                rationale = (
                    f"Finding persisted from baseline with severity increase: "
                    f"{baseline_sev} → {current_sev}."
                )
            elif cur_rank < base_rank:
                delta = "de_escalated"
                rationale = (
                    f"Finding persisted from baseline with severity decrease: "
                    f"{baseline_sev} → {current_sev}."
                )
            else:
                delta = "persisted"
                rationale = "Finding present in both baseline and current scan."
        elif in_current and not in_baseline:
            if key in regressed_keys:
                delta = "regressed"
                rationale = (
                    "Finding absent from baseline scan but present in earlier scans — "
                    "previously resolved and has returned."
                )
            else:
                delta = "new"
                rationale = "Finding not present in baseline — new attack surface."
        else:
            delta = "resolved"
            rationale = (
                "Finding present in baseline but absent from current scan — resolved."
            )

        assert current_row is not None or baseline_row is not None
        output_row = current_row if current_row is not None else baseline_row
        assert output_row is not None

        records.append(
            DriftFindingRecord(
                finding_id=output_row.id,
                findings_hash=output_row.findings_hash,
                title=output_row.title,
                severity=current_sev,
                baseline_severity=baseline_sev,
                delta_class=delta,
                evidence_ref_ids=list(output_row.evidence_ref_ids or []),
                rationale=rationale,
            )
        )

    return DriftResult(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        baseline_scan_id=baseline_scan_id,
        current_scan_id=current_scan_id,
        findings=records,
    )
