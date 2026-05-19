"""Deterministic governance report exports.

The export hash is derived only from canonical manifest JSON. Rendered PDF/HTML
bytes are delivery formats and never become the authority for verification.
"""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from api.assessments import _resolve_caller_tenant
from api.db_models import AssessmentRecord, ReportRecord
from api.report_jobs import ReportJobState

MANIFEST_VERSION = "governance-export-manifest-v1"
EXPORT_VERSION = "governance-export-v1"

REQUIRED_CONTENT_SECTIONS = (
    "findings",
    "evidence",
    "framework_mappings",
    "remediations",
    "confidence",
)

EXPORT_AUDIT_GENERATED = "governance_export_generated"
EXPORT_AUDIT_DOWNLOADED = "governance_export_downloaded"
EXPORT_AUDIT_FINALIZED = "governance_export_finalized"
EXPORT_AUDIT_REPLAY_REQUESTED = "governance_export_replay_requested"
EXPORT_AUDIT_REPLAY_COMPLETED = "governance_export_replay_completed"
EXPORT_AUDIT_REPLAY_MISMATCH = "governance_export_replay_mismatch_detected"
EXPORT_AUDIT_HASH_VERIFIED = "governance_export_hash_verification"
EXPORT_AUDIT_HASH_FAILED = "governance_export_hash_verification_failed"
EXPORT_AUDIT_RETRIEVAL_DENIED = "governance_export_retrieval_denied"
EXPORT_AUDIT_REGENERATED = "governance_export_regenerated"
EXPORT_AUDIT_REVIEWER_ASSIGNED = "governance_export_reviewer_assigned"
EXPORT_AUDIT_SUPERSEDED = "governance_export_superseded"


class ExportValidationError(ValueError):
    """Raised when a report cannot produce a regulator-grade export."""


def canonical_json(data: dict[str, Any]) -> str:
    try:
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as exc:
        raise ExportValidationError("canonical serialization failed") from exc


def manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = {"prefix": prefix, "parts": list(parts)}
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)


def _sorted_dicts(values: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        raise ExportValidationError(f"{key} must be a list")
    normalized: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, dict):
            raise ExportValidationError(f"{key} entries must be objects")
        if "id" not in value:
            raise ExportValidationError(f"{key} entries require id")
        normalized.append(dict(sorted(value.items())))
    return sorted(normalized, key=lambda item: str(item["id"]))


def _legacy_text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("title", "summary", "description", "gap", "finding", "text"):
            if value.get(key):
                return str(value[key])
        return canonical_json(dict(sorted(value.items())))
    return str(value)


def _legacy_control(value: Any) -> tuple[str, str]:
    if isinstance(value, dict):
        framework = str(value.get("framework") or value.get("name") or "advisory")
        control = str(value.get("control") or value.get("control_id") or "alignment")
        return framework, control
    text = str(value)
    parts = text.split(maxsplit=1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "advisory", text or "alignment"


def _roadmap_items(roadmap: Any) -> list[str]:
    if isinstance(roadmap, dict):
        items: list[str] = []
        for key in sorted(roadmap):
            value = roadmap[key]
            if isinstance(value, list):
                items.extend(_legacy_text(item) for item in value)
            elif value:
                items.append(_legacy_text(value))
        return sorted(item for item in items if item)
    if isinstance(roadmap, list):
        return sorted(_legacy_text(item) for item in roadmap if item)
    return []


def _legacy_findings(content: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    critical_gaps = content.get("critical_gaps")
    if isinstance(critical_gaps, list):
        findings.extend(_legacy_text(item) for item in critical_gaps)

    domain_findings = content.get("domain_findings")
    if isinstance(domain_findings, dict):
        for domain in sorted(domain_findings):
            values = domain_findings[domain]
            if isinstance(values, list):
                findings.extend(f"{domain}: {_legacy_text(item)}" for item in values)
            elif values:
                findings.append(f"{domain}: {_legacy_text(values)}")
    elif isinstance(domain_findings, list):
        findings.extend(_legacy_text(item) for item in domain_findings)

    return sorted(item for item in findings if item)


def populate_deterministic_export_sections(content: dict[str, Any]) -> dict[str, Any]:
    """Map legacy generated reports into deterministic export sections."""
    mapped = dict(content)
    findings_source = _legacy_findings(mapped)
    framework_source = mapped.get("framework_alignments")
    roadmap_source = _roadmap_items(mapped.get("roadmap"))
    has_legacy_source = bool(findings_source or framework_source or roadmap_source)
    missing = [key for key in REQUIRED_CONTENT_SECTIONS if key not in mapped]
    if missing and not has_legacy_source:
        return mapped

    if "findings" not in mapped:
        if not findings_source and mapped.get("executive_summary"):
            findings_source = [str(mapped["executive_summary"])]
        findings: list[dict[str, Any]] = []
        for index, text in enumerate(findings_source, start=1):
            finding_id = _stable_id("finding", index, text)
            findings.append(
                {
                    "id": finding_id,
                    "title": text,
                    "evidence_ids": [_stable_id("evidence", finding_id, text)],
                    "framework_mapping_ids": [_stable_id("mapping", finding_id, text)],
                    "confidence_score": 0.75,
                }
            )
        mapped["findings"] = findings

    if "evidence" not in mapped:
        section_names = [
            key
            for key in (
                "critical_gaps",
                "domain_findings",
                "framework_alignments",
                "key_strengths",
                "roadmap",
            )
            if mapped.get(key)
        ]
        mapped["evidence"] = [
            {
                "id": str(finding["evidence_ids"][0]),
                "lineage": "report_generation:legacy_schema_mapping",
                "provenance": "generated_report_content",
                "validation_state": "report-derived",
                "freshness": "report-generated-at",
                "source_metadata": {"legacy_sections": sorted(section_names)},
                "linked_findings": [str(finding["id"])],
                "linked_controls": [str(finding["framework_mapping_ids"][0])],
            }
            for finding in mapped.get("findings", [])
            if isinstance(finding, dict) and finding.get("evidence_ids")
        ]

    if "framework_mappings" not in mapped:
        alignments = framework_source if isinstance(framework_source, list) else []
        mappings: list[dict[str, Any]] = []
        for index, finding in enumerate(mapped.get("findings", [])):
            if not isinstance(finding, dict):
                continue
            alignment = alignments[index % len(alignments)] if alignments else None
            framework, control = _legacy_control(alignment or "advisory_alignment")
            mappings.append(
                {
                    "id": str(finding["framework_mapping_ids"][0]),
                    "finding_id": str(finding["id"]),
                    "framework": framework,
                    "control": control,
                }
            )
        mapped["framework_mappings"] = mappings

    if "remediations" not in mapped:
        remediations: list[dict[str, Any]] = []
        for index, finding in enumerate(mapped.get("findings", [])):
            if not isinstance(finding, dict):
                continue
            action = (
                roadmap_source[index % len(roadmap_source)]
                if roadmap_source
                else "Review and remediate finding"
            )
            remediations.append(
                {
                    "id": _stable_id("remediation", finding["id"], action),
                    "finding_id": str(finding["id"]),
                    "owner": "governance",
                    "action": action,
                }
            )
        mapped["remediations"] = remediations

    if "confidence" not in mapped:
        mapped["confidence"] = {
            "method": "deterministic-legacy-report-mapping",
            "score": 0.75 if findings_source else 0.6,
        }

    return mapped


def _report_content(report: ReportRecord) -> dict[str, Any]:
    if report.status != "complete":
        raise ExportValidationError("report must be complete")
    if not isinstance(report.content, dict):
        raise ExportValidationError("report content missing")
    content = populate_deterministic_export_sections(report.content)
    missing = [key for key in REQUIRED_CONTENT_SECTIONS if key not in content]
    if missing:
        raise ExportValidationError(
            f"report missing required sections: {','.join(missing)}"
        )
    return content


def build_export_manifest(
    report: ReportRecord, assessment: AssessmentRecord | None
) -> dict[str, Any]:
    content = _report_content(report)
    frozen_finalized = bool(getattr(report, "finalized_manifest_hash", None))
    approval_status = (
        "finalized"
        if frozen_finalized
        else getattr(report, "approval_status", None) or "unapproved"
    )
    following_report_id = (
        None if frozen_finalized else getattr(report, "superseded_by_report_id", None)
    )
    findings = _sorted_dicts(content["findings"], "findings")
    evidence = _sorted_dicts(content["evidence"], "evidence")
    framework_mappings = _sorted_dicts(
        content["framework_mappings"], "framework_mappings"
    )
    remediations = _sorted_dicts(content["remediations"], "remediations")
    confidence = content["confidence"]
    if not isinstance(confidence, dict):
        raise ExportValidationError("confidence must be an object")

    finding_ids = {str(item["id"]) for item in findings}
    evidence_ids = {str(item["id"]) for item in evidence}
    for item in evidence:
        linked_findings = item.get("linked_findings", [])
        if not isinstance(linked_findings, list):
            raise ExportValidationError("evidence linked_findings must be a list")
        if any(str(fid) not in finding_ids for fid in linked_findings):
            raise ExportValidationError("evidence references unknown finding")
    for item in findings:
        linked_evidence = item.get("evidence_ids", [])
        if not isinstance(linked_evidence, list):
            raise ExportValidationError("finding evidence_ids must be a list")
        if any(str(eid) not in evidence_ids for eid in linked_evidence):
            raise ExportValidationError("finding references unknown evidence")

    generated_at = _iso(report.completed_at or report.created_at)
    if not generated_at:
        raise ExportValidationError("generated-at metadata missing")

    return {
        "manifest_version": getattr(report, "manifest_version", None)
        or MANIFEST_VERSION,
        "export_version": getattr(report, "export_version", None) or EXPORT_VERSION,
        "report": {
            "id": report.id,
            "tenant_id": report.tenant_id,
            "assessment_id": report.assessment_id,
            "org_id": report.org_id,
            "org_profile_id": report.org_profile_id,
            "report_version": getattr(report, "report_version", None) or 1,
            "status": report.status,
            "previous_report_id": getattr(report, "previous_report_id", None),
            "superseded_by_report_id": following_report_id,
        },
        "lineage": {
            "prior_report_id": getattr(report, "previous_report_id", None),
            "following_report_id": following_report_id,
            "assessment_id": report.assessment_id,
            "assessment_status": getattr(assessment, "status", None)
            if assessment
            else None,
        },
        "metadata": {
            "generated_at": generated_at,
            "finalized_at": _iso(getattr(report, "finalized_at", None)),
            "report_version": getattr(report, "report_version", None) or 1,
            "manifest_version": getattr(report, "manifest_version", None)
            or MANIFEST_VERSION,
            "scoring_contract_version": getattr(
                report, "scoring_contract_version", None
            )
            or "assessment-scoring-v1",
            "framework_mapping_version": getattr(
                report, "framework_mapping_version", None
            )
            or "framework-mapping-v1",
            "evidence_snapshot_version": getattr(
                report, "evidence_snapshot_version", None
            )
            or "evidence-snapshot-v1",
        },
        "reviewer": {
            "reviewer_ref": getattr(report, "reviewer_ref", None),
            "approval_status": approval_status,
            "approval_timestamp": _iso(getattr(report, "finalized_at", None)),
        },
        "findings": findings,
        "evidence": evidence,
        "framework_mappings": framework_mappings,
        "remediations": remediations,
        "confidence": dict(sorted(confidence.items())),
        "scoring": {
            "overall_score": getattr(assessment, "overall_score", None)
            if assessment
            else None,
            "risk_band": getattr(assessment, "risk_band", None) if assessment else None,
            "domain_scores": getattr(assessment, "scores", None)
            if assessment
            else None,
        },
        "ai_narrative": {
            "advisory_only": True,
            "executive_summary": content.get("executive_summary"),
        },
    }


def build_hashed_manifest(
    report: ReportRecord, assessment: AssessmentRecord | None
) -> dict[str, Any]:
    manifest = build_export_manifest(report, assessment)
    digest = manifest_sha256(manifest)
    return {"manifest": manifest, "manifest_hash": digest}


def render_html_export(manifest: dict[str, Any], digest: str) -> bytes:
    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        "<title>FrostGate Governance Export</title>",
        "</head>",
        "<body>",
        "<h1>FrostGate Governance Export</h1>",
        f"<p>Report ID: {html.escape(str(manifest['report']['id']))}</p>",
        f"<p>Manifest Hash: {html.escape(digest)}</p>",
        f"<p>Generated At: {html.escape(str(manifest['metadata']['generated_at']))}</p>",
        "<h2>Findings</h2>",
    ]
    for finding in manifest["findings"]:
        lines.append(f"<h3>{html.escape(str(finding['id']))}</h3>")
        lines.append(f"<pre>{html.escape(canonical_json(finding))}</pre>")
    lines.append("<h2>Evidence Appendix</h2>")
    for evidence in manifest["evidence"]:
        lines.append(f"<h3>{html.escape(str(evidence['id']))}</h3>")
        lines.append(f"<pre>{html.escape(canonical_json(evidence))}</pre>")
    lines.append("<h2>Framework Mappings</h2>")
    lines.append(
        f"<pre>{html.escape(canonical_json({'framework_mappings': manifest['framework_mappings']}))}</pre>"
    )
    lines.append("<h2>Remediations</h2>")
    lines.append(
        f"<pre>{html.escape(canonical_json({'remediations': manifest['remediations']}))}</pre>"
    )
    lines.append("</body></html>")
    return "\n".join(lines).encode("utf-8")


def render_pdf_export(manifest: dict[str, Any], digest: str) -> bytes:
    payload = {
        "title": "FrostGate Governance Export",
        "report_id": manifest["report"]["id"],
        "manifest_hash": digest,
        "generated_at": manifest["metadata"]["generated_at"],
        "reviewer": manifest["reviewer"],
        "finding_ids": [item["id"] for item in manifest["findings"]],
        "evidence_ids": [item["id"] for item in manifest["evidence"]],
        "framework_mappings": manifest["framework_mappings"],
        "confidence": manifest["confidence"],
        "remediations": manifest["remediations"],
        "export_version": manifest["export_version"],
    }
    body = canonical_json(payload)
    return (
        "%PDF-1.4\n% FrostGate deterministic governance export\n" + body + "\n%%EOF\n"
    ).encode("utf-8")


def load_report_for_export(
    db: Session,
    request: Request,
    report_id: str,
    *,
    x_assessment_id: str | None = None,
) -> ReportRecord:
    caller_tenant = _resolve_caller_tenant(request)
    q = db.query(ReportRecord).filter(ReportRecord.id == report_id)
    if caller_tenant:
        q = q.filter(ReportRecord.tenant_id == caller_tenant)
    else:
        assessment_token = (x_assessment_id or "").strip()
        if not assessment_token:
            raise HTTPException(status_code=404, detail="Report not found")
        q = q.filter(ReportRecord.tenant_id == f"lead:{assessment_token}")
    report = q.first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def load_assessment(db: Session, report: ReportRecord) -> AssessmentRecord | None:
    if not report.assessment_id:
        return None
    return (
        db.query(AssessmentRecord)
        .filter(AssessmentRecord.id == report.assessment_id)
        .first()
    )


def emit_export_event(
    event_name: str,
    tenant_id: str,
    report_id: str,
    assessment_id: str | None,
    *,
    state: ReportJobState = ReportJobState.SUCCEEDED,
    reason_code: str | None = None,
    manifest_hash_value: str | None = None,
    actor_id: str | None = None,
) -> None:
    from api.reports_engine import _emit_report_event

    _emit_report_event(
        event_name,
        tenant_id,
        report_id,
        assessment_id,
        state=state,
        reason_code=reason_code or manifest_hash_value,
    )
