"""MS Graph connector delta enrichment.

Extends the base export.py delta (new/persisted/resolved/regressed) with:
  escalated    — same finding_id in both scans; severity is higher now
  de_escalated — same finding_id in both scans; severity is lower now
  regressed    — finding absent from baseline; creation time predates baseline
                 (was present before, resolved, now returned)

This module enriches connector-level Finding objects (in-memory schema) before
they are imported into the DB. The connector-agnostic DB engine (drift/engine.py)
performs the same classification on persisted FaNormalizedFinding rows for
subsequent drift reports.

Usage:
  enriched_findings = enrich_delta(
      current_findings=all_findings,
      baseline_findings=baseline_finding_objects,  # Finding list from baseline scan payload
      baseline_scan_id=baseline_scan_id,
  )

The baseline Finding list must be sourced from the stored scan's normalized_payload
(deserialized to Finding objects). This is the caller's responsibility.
"""

from __future__ import annotations

from services.connectors.msgraph.schema.scan_result import Finding

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
}


def enrich_delta(
    *,
    current_findings: list[Finding],
    baseline_findings: list[Finding],
    baseline_scan_id: str,
) -> list[Finding]:
    """Apply full delta classification to current_findings relative to a baseline.

    Extends the basic new/persisted/resolved logic from export._apply_delta with:
      - escalated / de_escalated: finding_id present in both; severity changed
      - regressed: finding_id absent from baseline (would normally be "new"),
                   but first_seen_scan_id on the Finding indicates prior presence

    Returns a new list of Finding objects with delta_status populated.
    """
    baseline_by_id: dict[str, Finding] = {f.finding_id: f for f in baseline_findings}
    baseline_ids = set(baseline_by_id)

    result: list[Finding] = []
    for f in current_findings:
        in_baseline = f.finding_id in baseline_ids

        if in_baseline:
            base_f = baseline_by_id[f.finding_id]
            cur_rank = _SEVERITY_RANK.get(f.severity, 0)
            base_rank = _SEVERITY_RANK.get(base_f.severity, 0)
            if cur_rank > base_rank:
                delta = "escalated"
            elif cur_rank < base_rank:
                delta = "de_escalated"
            else:
                delta = "persisted"
            result.append(
                f.model_copy(
                    update={
                        "delta_status": delta,
                        "first_seen_scan_id": baseline_scan_id,
                    }
                )
            )
        else:
            # Check regressed: finding has a first_seen_scan_id that predates baseline
            # (set by a prior scan's delta enrichment)
            if f.first_seen_scan_id and f.first_seen_scan_id != baseline_scan_id:
                delta = "regressed"
            else:
                delta = "new"
            result.append(
                f.model_copy(
                    update={
                        "delta_status": delta,
                        "first_seen_scan_id": f.first_seen_scan_id,
                    }
                )
            )

    return result
