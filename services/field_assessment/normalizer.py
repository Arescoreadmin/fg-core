"""Shared finding normalization for manual scan uploads.

This subsystem is NOT standalone.
It is a tenant-scoped component of the Field Assessment Engagement Substrate.

Provides normalize_scan_findings() — extracts FaNormalizedFinding rows from
a manually-provided normalized_payload dict and links them to the scan result.

Expected normalized_payload shape:
  {
    "findings": [
      {
        "finding_type":        str  (required),
        "title":               str  (required),
        "description":         str  (required),
        "severity":            str  one of critical/high/medium/low/info (default: medium),
        "confidence_score":    int  0-100 (default: 70),
        "nist_ai_rmf_mappings": list (optional),
        "framework_mappings":  list (optional),
        "remediation_hint":    str  (optional),
      },
      ...
    ]
  }

Idempotent: create_finding() uses a deterministic SHA-256 key (finding_type +
engagement_id + source_ref). Re-ingesting the same payload is safe — existing
rows are returned unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_field_assessment import FaNormalizedFinding, FaScanResult
from services.field_assessment.models import EvidenceLinkDuplicate
from services.field_assessment.store import create_evidence_link, create_finding

log = logging.getLogger("frostgate.field_assessment.normalizer")

_NORMALIZER_VERSION = "1"
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})


def normalize_scan_findings(
    db: Session,
    *,
    tenant_id: str,
    engagement_id: str,
    scan_result: FaScanResult,
    normalized_payload: dict[str, Any],
    source_attribution: str = "manual_upload",
) -> list[FaNormalizedFinding]:
    """Extract and persist findings from a manually-uploaded normalized_payload.

    Returns the list of created (or pre-existing) FaNormalizedFinding rows.
    Updates scan_result.finding_count to match. Skips malformed entries with a
    warning log rather than raising, so a bad finding doesn't abort the import.
    """
    raw_findings = normalized_payload.get("findings")
    if not raw_findings or not isinstance(raw_findings, list):
        return []

    imported: list[FaNormalizedFinding] = []
    for idx, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            log.warning("normalizer: skipping finding[%d] — not a dict", idx)
            continue

        finding_type = item.get("finding_type", "")
        title = item.get("title", "")
        description = item.get("description", "")

        if not finding_type or not title or not description:
            log.warning(
                "normalizer: skipping finding[%d] — missing required fields "
                "(finding_type=%r, title=%r, description present=%s)",
                idx,
                finding_type,
                title,
                bool(description),
            )
            continue

        severity = item.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            log.warning(
                "normalizer: finding[%d] has unknown severity %r, defaulting to medium",
                idx,
                severity,
            )
            severity = "medium"

        confidence_score = item.get("confidence_score", 70)
        if not isinstance(confidence_score, int) or not (0 <= confidence_score <= 100):
            confidence_score = 70

        source_ref = f"manual:{scan_result.id}:{idx}"

        finding = create_finding(
            db,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            finding_type=finding_type,
            source_ref=source_ref,
            severity=severity,
            title=title,
            description=description,
            source_attribution=source_attribution,
            confidence_score=confidence_score,
            framework_mappings=item.get("framework_mappings") or [],
            nist_ai_rmf_mappings=item.get("nist_ai_rmf_mappings") or [],
            evidence_ref_ids=[scan_result.id],
            remediation_hint=item.get("remediation_hint") or None,
        )
        imported.append(finding)

        try:
            create_evidence_link(
                db,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                source_entity_type="finding",
                source_entity_id=finding.id,
                evidence_entity_type="scan_result",
                evidence_entity_id=scan_result.id,
                link_metadata={
                    "source": "manual_upload",
                    "scan_result_id": scan_result.id,
                    "normalizer_version": _NORMALIZER_VERSION,
                },
            )
        except EvidenceLinkDuplicate:
            pass

    scan_result.finding_count = len(imported)
    db.flush()
    return imported
