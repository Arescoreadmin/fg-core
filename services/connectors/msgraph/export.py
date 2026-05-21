"""ScanResult export and delta classification.

Assembles findings, evidence refs, and analyzer outputs from all analyzer
run() return values into a final ScanResult. Optionally applies delta
classification against a baseline scan.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from services.connectors.msgraph.findings.derivation import hash_tenant_id
from services.connectors.msgraph.integrity import bind_manifest_content
from services.connectors.msgraph.schema.analyzer_outputs import AnalyzerOutputs
from services.connectors.msgraph.schema.integrity import SignedManifest
from services.connectors.msgraph.schema.scan_result import (
    AcknowledgmentReceipt,
    EvidenceRef,
    Finding,
    ScanResult,
)
from services.connectors.msgraph.delta import enrich_delta

_DELTA_STATUS_MAP = {
    # (in_current, in_baseline) -> delta_status
    (True, False): "new",
    (True, True): "persisted",
    (False, True): "resolved",
}


def _apply_delta(
    findings: list[Finding],
    baseline_finding_ids: set[str],
    baseline_scan_id: str,
) -> list[Finding]:
    """Annotate findings with delta_status relative to a baseline scan."""
    result: list[Finding] = []
    for f in findings:
        in_baseline = f.finding_id in baseline_finding_ids
        status = _delta_status(in_current=True, in_baseline=in_baseline)
        # Pydantic frozen model — rebuild with updated fields
        result.append(
            f.model_copy(
                update={
                    "delta_status": status,
                    "first_seen_scan_id": baseline_scan_id if in_baseline else None,
                }
            )
        )
    return result


def _delta_status(*, in_current: bool, in_baseline: bool) -> str:
    return _DELTA_STATUS_MAP.get((in_current, in_baseline), "new")


def build_scan_result(
    *,
    tenant_id: str,
    engagement_id: str,
    receipt: AcknowledgmentReceipt,
    scopes_authorized: list[str],
    scopes_in_token: list[str],
    pages_fetched: dict[str, int],
    endpoints_called: list[str],
    scan_initiated_at: str,
    all_findings: list[Finding],
    all_evidence: list[EvidenceRef],
    analyzer_outputs: AnalyzerOutputs,
    manifest: SignedManifest,
    baseline_scan_id: str | None = None,
    baseline_finding_ids: set[str] | None = None,
    baseline_findings: list[Finding] | None = None,
    scan_status: str = "completed",
) -> ScanResult:
    """Build a complete ScanResult.

    When baseline_findings (full Finding objects) are provided, uses the richer
    enrich_delta() which adds escalated/de_escalated severity-change states.
    When only baseline_finding_ids (a set of IDs) are provided, falls back to
    the simpler _apply_delta() with new/persisted/resolved/regressed states.
    """
    scan_completed_at = datetime.now(timezone.utc).isoformat()

    try:
        initiated = datetime.fromisoformat(scan_initiated_at)
        completed = datetime.fromisoformat(scan_completed_at)
        duration = int((completed - initiated).total_seconds())
    except Exception:
        duration = 0

    findings = all_findings
    if baseline_scan_id and baseline_findings is not None:
        # Full Finding objects available — use rich delta with severity comparison
        findings = enrich_delta(
            current_findings=findings,
            baseline_findings=baseline_findings,
            baseline_scan_id=baseline_scan_id,
        )
    elif baseline_scan_id and baseline_finding_ids is not None:
        # Only IDs available — fall back to basic 4-state delta
        findings = _apply_delta(findings, baseline_finding_ids, baseline_scan_id)
    analyzer_payload = analyzer_outputs.model_dump()
    manifest = bind_manifest_content(
        manifest,
        findings=findings,
        evidence_refs=all_evidence,
        analyzer_outputs=analyzer_payload,
    )

    return ScanResult(
        scan_id=uuid.uuid4().hex,
        tenant_id_hash=hash_tenant_id(tenant_id),
        engagement_id=engagement_id,
        operator_acknowledgment_receipt=receipt,
        scan_initiated_at=scan_initiated_at,
        scan_completed_at=scan_completed_at,
        scan_duration_seconds=duration,
        scan_status=scan_status,  # type: ignore[arg-type]
        scopes_authorized=scopes_authorized,
        scopes_in_token=scopes_in_token,
        pages_fetched=pages_fetched,
        endpoints_called=endpoints_called,
        findings=findings,
        evidence_references=all_evidence,
        analyzer_outputs=analyzer_payload,
        integrity_manifest=manifest.model_dump(),
        baseline_scan_id=baseline_scan_id,
    )
