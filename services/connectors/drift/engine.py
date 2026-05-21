"""Connector-agnostic drift detection engine.

Operates on FaNormalizedFinding and FaEvidenceLink rows — not on connector-specific
schema objects. Any connector whose findings land in fa_normalized_findings gets
drift detection for free.

Delta classes:
  new        — finding in current scan, absent from baseline, created after baseline
  persisted  — finding in both current and baseline scans (severity unchanged)
  resolved   — finding in baseline, absent from current scan
  regressed  — finding in current scan, absent from baseline, created before baseline
               (was present before, went away, came back)
  escalated  — finding in both scans; severity is higher now than in baseline payload
  de_escalated — finding in both scans; severity is lower now than in baseline payload

Regressed detection uses FaNormalizedFinding.created_at vs baseline scan collected_at:
  if finding.created_at < baseline.collected_at → the finding predates the baseline
  and was absent (resolved) at baseline time → now it has returned.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaEvidenceLink, FaNormalizedFinding, FaScanResult

log = logging.getLogger("frostgate.connectors.drift.engine")

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


@dataclass(frozen=True)
class DriftFindingRecord:
    """Classification result for a single finding in a drift computation."""

    finding_id: str          # FaNormalizedFinding.id (deterministic hash)
    findings_hash: str
    title: str
    severity: str            # current severity
    baseline_severity: str | None  # None when not in baseline
    delta_class: str         # new | persisted | resolved | regressed | escalated | de_escalated
    evidence_ref_ids: list[str]
    rationale: str           # human-readable explanation of classification


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


def _finding_ids_for_scan(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_id: str,
) -> set[str]:
    """Return FaNormalizedFinding.id values linked to scan_id via FaEvidenceLink."""
    rows = db.execute(
        select(FaEvidenceLink.source_entity_id).where(
            FaEvidenceLink.tenant_id == tenant_id,
            FaEvidenceLink.engagement_id == engagement_id,
            FaEvidenceLink.source_entity_type == "finding",
            FaEvidenceLink.evidence_entity_type == "scan_result",
            FaEvidenceLink.evidence_entity_id == scan_id,
        )
    ).scalars().all()
    return set(rows)


def _baseline_severity_map(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    baseline_scan_id: str,
    finding_ids: set[str],
) -> dict[str, str]:
    """Extract per-finding severity from the baseline scan's normalized_payload.

    Falls back to the current DB severity when the payload is absent or unparseable.
    Returns {finding_id: severity_at_baseline_time}.
    """
    if not finding_ids:
        return {}

    scan_row = db.execute(
        select(FaScanResult).where(
            FaScanResult.id == baseline_scan_id,
            FaScanResult.tenant_id == tenant_id,
            FaScanResult.engagement_id == engagement_id,
        )
    ).scalar_one_or_none()

    if scan_row is None or not scan_row.normalized_payload:
        return {}

    payload = scan_row.normalized_payload
    findings_list: list[Any] = []
    if isinstance(payload, dict):
        findings_list = payload.get("findings", [])
    elif isinstance(payload, list):
        findings_list = payload

    result: dict[str, str] = {}
    for f in findings_list:
        if not isinstance(f, dict):
            continue
        fid = f.get("finding_id") or f.get("id")
        sev = f.get("severity")
        if fid and sev:
            result[fid] = str(sev)
    return result


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

    baseline_ids = _finding_ids_for_scan(
        db, tenant_id=tenant_id, engagement_id=engagement_id, scan_id=baseline_scan_id
    )
    current_ids = _finding_ids_for_scan(
        db, tenant_id=tenant_id, engagement_id=engagement_id, scan_id=current_scan_id
    )

    all_ids = baseline_ids | current_ids
    if not all_ids:
        return DriftResult(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
        )

    finding_rows = db.execute(
        select(FaNormalizedFinding).where(
            FaNormalizedFinding.tenant_id == tenant_id,
            FaNormalizedFinding.engagement_id == engagement_id,
            FaNormalizedFinding.id.in_(all_ids),
        )
    ).scalars().all()
    finding_map = {r.id: r for r in finding_rows}

    # Baseline severity lookup from stored payload (for escalated/de_escalated)
    baseline_sev_map = _baseline_severity_map(
        db,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        baseline_scan_id=baseline_scan_id,
        finding_ids=baseline_ids,
    )

    baseline_collected_at = baseline_scan.collected_at

    records: list[DriftFindingRecord] = []

    for fid in all_ids:
        row = finding_map.get(fid)
        if row is None:
            log.warning("finding %s in evidence links but not in findings table", fid)
            continue

        in_baseline = fid in baseline_ids
        in_current = fid in current_ids
        current_sev = row.severity
        baseline_sev: str | None = baseline_sev_map.get(fid) if in_baseline else None

        if in_current and in_baseline:
            # Check severity change
            cur_rank = _SEVERITY_RANK.get(current_sev, 0)
            base_rank = _SEVERITY_RANK.get(baseline_sev or "", 0) if baseline_sev else 0
            if baseline_sev and cur_rank > base_rank:
                delta = "escalated"
                rationale = (
                    f"Finding persisted from baseline with severity increase: "
                    f"{baseline_sev} → {current_sev}."
                )
            elif baseline_sev and cur_rank < base_rank:
                delta = "de_escalated"
                rationale = (
                    f"Finding persisted from baseline with severity decrease: "
                    f"{baseline_sev} → {current_sev}."
                )
            else:
                delta = "persisted"
                rationale = "Finding present in both baseline and current scan."
        elif in_current and not in_baseline:
            # New or regressed: compare creation time to baseline collection time
            if row.created_at < baseline_collected_at:
                delta = "regressed"
                rationale = (
                    f"Finding predates baseline (created {row.created_at}) but was "
                    f"absent from baseline scan ({baseline_collected_at}) — previously "
                    "resolved and has returned."
                )
            else:
                delta = "new"
                rationale = "Finding not present in baseline — new attack surface."
        else:
            # in_baseline and not in_current
            delta = "resolved"
            rationale = "Finding present in baseline but absent from current scan — resolved."

        records.append(
            DriftFindingRecord(
                finding_id=fid,
                findings_hash=row.findings_hash,
                title=row.title,
                severity=current_sev,
                baseline_severity=baseline_sev,
                delta_class=delta,
                evidence_ref_ids=list(row.evidence_ref_ids or []),
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
