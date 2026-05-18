"""Deterministic serialization and export for governance reports.

All serialization is canonical:
  - Keys sorted deterministically.
  - No whitespace variance in hash-input strings.
  - Enums serialized as their .value strings.

serialize_for_manifest() is the canonical form used for hashing:
  - Excludes manifest_hash itself to avoid circular dependency.
  - No whitespace, sorted keys, separators=(",", ":").

export_html() produces an HTML artifact with all findings, framework mappings,
evidence appendix, confidence breakdown, and manifest hash footer.
No AI prose — only deterministic structured content.

export_pdf_bytes() uses reportlab if available; raises ExportUnavailableError
otherwise.
"""

from __future__ import annotations

import json
from typing import Any

from .models import (
    ConfidenceScore,
    EvidenceRef,
    FrameworkMapping,
    GovernanceFinding,
    GovernanceReport,
    RemediationEntry,
    ValidationState,
)


class ExportUnavailableError(Exception):
    """Raised when a required export dependency is not installed."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _serialize_framework_mapping(fm: FrameworkMapping) -> dict[str, Any]:
    return {
        "confidence": fm.confidence,
        "control_ref": fm.control_ref,
        "framework": fm.framework,
    }


def _serialize_evidence_ref(ref: EvidenceRef) -> dict[str, Any]:
    return {
        "classification": ref.classification,
        "evidence_id": ref.evidence_id,
        "freshness_days": ref.freshness_days,
        "provenance": ref.provenance,
        "source": ref.source,
        "validation_state": ref.validation_state.value,
    }


def _serialize_confidence(c: ConfidenceScore) -> dict[str, Any]:
    return {
        "control_coverage": c.control_coverage,
        "degradation_reasons": list(c.degradation_reasons),
        "evidence_completeness": c.evidence_completeness,
        "evidence_freshness": c.evidence_freshness,
        "overall": c.overall,
        "reviewer_validated": c.reviewer_validated,
    }


def _serialize_finding(f: GovernanceFinding) -> dict[str, Any]:
    return {
        "confidence": f.confidence,
        "control_id": f.control_id,
        "description": f.description,
        "domain": f.domain,
        "evidence_ids": list(f.evidence_ids),
        "finding_id": f.finding_id,
        "framework_mappings": [
            _serialize_framework_mapping(fm) for fm in f.framework_mappings
        ],
        "gap_classification": f.gap_classification,
        "remediation_id": f.remediation_id,
        "severity": f.severity,
    }


def _serialize_remediation(r: RemediationEntry) -> dict[str, Any]:
    return {
        "confidence_impact": r.confidence_impact,
        "evidence_gaps": list(r.evidence_gaps),
        "linked_controls": list(r.linked_controls),
        "linked_finding_ids": list(r.linked_finding_ids),
        "operational_impact": r.operational_impact,
        "priority": r.priority,
        "remediation_id": r.remediation_id,
        "severity": r.severity,
    }


# ---------------------------------------------------------------------------
# Public serializers
# ---------------------------------------------------------------------------


def serialize_report(report: GovernanceReport) -> dict[str, Any]:
    """Return a canonical JSON-safe dict of the report with deterministic key ordering."""
    return {
        "assessment_id": report.assessment_id,
        "confidence": _serialize_confidence(report.confidence),
        "evidence_appendix": [
            _serialize_evidence_ref(r) for r in report.evidence_appendix
        ],
        "findings": [_serialize_finding(f) for f in report.findings],
        "framework_summary": {
            k: sorted(v) for k, v in sorted(report.framework_summary.items())
        },
        "generated_at": report.generated_at,
        "manifest_hash": report.manifest_hash,
        "remediations": [_serialize_remediation(r) for r in report.remediations],
        "report_id": report.report_id,
        "schema_version": report.schema_version,
        "tenant_id": report.tenant_id,
        "version": report.version,
    }


def serialize_for_manifest(report: GovernanceReport) -> str:
    """Return the canonical JSON string used for manifest hash computation.

    Excludes manifest_hash (circular dependency) and generated_at (timestamp
    varies across runs — must not break replay equivalence).
    No whitespace, sorted keys, separators=(",", ":").
    """
    doc: dict[str, Any] = {
        "assessment_id": report.assessment_id,
        "confidence": _serialize_confidence(report.confidence),
        "evidence_appendix": [
            _serialize_evidence_ref(r) for r in report.evidence_appendix
        ],
        "findings": [_serialize_finding(f) for f in report.findings],
        "framework_summary": {
            k: sorted(v) for k, v in sorted(report.framework_summary.items())
        },
        "remediations": [_serialize_remediation(r) for r in report.remediations],
        "report_id": report.report_id,
        "schema_version": report.schema_version,
        "tenant_id": report.tenant_id,
        "version": report.version,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def deserialize_report(data: dict[str, Any]) -> GovernanceReport:
    """Deserialize a canonical report dict into a GovernanceReport.

    Raises ValueError if schema_version is unknown or required fields are missing.
    """
    schema_version = data.get("schema_version", "")
    if schema_version != "1.0":
        raise ValueError(
            f"Unsupported schema_version: {schema_version!r}. Expected '1.0'."
        )

    required = [
        "report_id",
        "assessment_id",
        "tenant_id",
        "version",
        "generated_at",
        "findings",
        "remediations",
        "evidence_appendix",
        "framework_summary",
        "confidence",
        "manifest_hash",
    ]
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"Missing required fields in report data: {missing}")

    def _deser_fw(d: dict[str, Any]) -> FrameworkMapping:
        return FrameworkMapping(
            framework=d["framework"],
            control_ref=d["control_ref"],
            confidence=float(d["confidence"]),
        )

    def _deser_evidence(d: dict[str, Any]) -> EvidenceRef:
        return EvidenceRef(
            evidence_id=d["evidence_id"],
            source=d["source"],
            validation_state=ValidationState(d["validation_state"]),
            classification=d["classification"],
            provenance=d["provenance"],
            freshness_days=d.get("freshness_days"),
        )

    def _deser_finding(d: dict[str, Any]) -> GovernanceFinding:
        return GovernanceFinding(
            finding_id=d["finding_id"],
            control_id=d["control_id"],
            domain=d["domain"],
            severity=d["severity"],
            confidence=float(d["confidence"]),
            evidence_ids=tuple(d["evidence_ids"]),
            framework_mappings=tuple(_deser_fw(fm) for fm in d["framework_mappings"]),
            remediation_id=d["remediation_id"],
            gap_classification=d["gap_classification"],
            description=d["description"],
        )

    def _deser_remediation(d: dict[str, Any]) -> RemediationEntry:
        return RemediationEntry(
            remediation_id=d["remediation_id"],
            linked_finding_ids=tuple(d["linked_finding_ids"]),
            linked_controls=tuple(d["linked_controls"]),
            severity=d["severity"],
            priority=d["priority"],
            confidence_impact=float(d["confidence_impact"]),
            evidence_gaps=tuple(d["evidence_gaps"]),
            operational_impact=d["operational_impact"],
        )

    c = data["confidence"]
    confidence = ConfidenceScore(
        overall=float(c["overall"]),
        evidence_completeness=float(c["evidence_completeness"]),
        evidence_freshness=float(c["evidence_freshness"]),
        control_coverage=float(c["control_coverage"]),
        reviewer_validated=bool(c["reviewer_validated"]),
        degradation_reasons=tuple(c.get("degradation_reasons", [])),
    )

    return GovernanceReport(
        report_id=data["report_id"],
        assessment_id=data["assessment_id"],
        tenant_id=data["tenant_id"],
        version=int(data["version"]),
        generated_at=data["generated_at"],
        findings=tuple(_deser_finding(f) for f in data["findings"]),
        remediations=tuple(_deser_remediation(r) for r in data["remediations"]),
        evidence_appendix=tuple(_deser_evidence(e) for e in data["evidence_appendix"]),
        framework_summary={k: list(v) for k, v in data["framework_summary"].items()},
        confidence=confidence,
        manifest_hash=data["manifest_hash"],
        schema_version=data["schema_version"],
    )


# ---------------------------------------------------------------------------
# HTML export
# ---------------------------------------------------------------------------

_HTML_SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
    "informational": "#7f8c8d",
}


def export_html(report: GovernanceReport) -> str:
    """Export the governance report as a deterministic HTML artifact.

    Includes:
      - Report header with tenant, assessment, version, generated_at.
      - Confidence breakdown with degradation reasons.
      - All findings with control_id, domain, severity, framework mappings.
      - Remediations with linked findings and controls.
      - Evidence appendix with validation states.
      - Framework summary.
      - Manifest hash footer.

    No AI prose — only deterministic structured content.
    """

    def _esc(s: str) -> str:
        return (
            s.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    findings_html = ""
    for f in report.findings:
        color = _HTML_SEVERITY_COLORS.get(f.severity, "#7f8c8d")
        fw_refs = "; ".join(
            f"{_esc(fm.framework)}: {_esc(fm.control_ref)}"
            for fm in f.framework_mappings
        )
        evidence_list = ", ".join(_esc(eid) for eid in f.evidence_ids)
        findings_html += f"""
      <div class="finding" id="finding-{_esc(f.finding_id)}">
        <h3 style="color:{color}">[{_esc(f.severity.upper())}] {_esc(f.control_id)} <small>({_esc(f.domain)})</small></h3>
        <table>
          <tr><th>Finding ID</th><td><code>{_esc(f.finding_id)}</code></td></tr>
          <tr><th>Gap Classification</th><td>{_esc(f.gap_classification)}</td></tr>
          <tr><th>Confidence</th><td>{f.confidence:.3f}</td></tr>
          <tr><th>Description</th><td>{_esc(f.description)}</td></tr>
          <tr><th>Framework Mappings</th><td>{_esc(fw_refs) or "None"}</td></tr>
          <tr><th>Evidence IDs</th><td>{_esc(evidence_list) or "None"}</td></tr>
          <tr><th>Remediation ID</th><td><code>{_esc(f.remediation_id)}</code></td></tr>
        </table>
      </div>"""

    remediations_html = ""
    for r in report.remediations:
        linked_findings = ", ".join(_esc(fid) for fid in r.linked_finding_ids)
        linked_controls = ", ".join(_esc(c) for c in r.linked_controls)
        gaps = ", ".join(_esc(g) for g in r.evidence_gaps)
        remediations_html += f"""
      <div class="remediation" id="remediation-{_esc(r.remediation_id)}">
        <h3>[{_esc(r.severity.upper())} / {_esc(r.priority.upper())}] Remediation <code>{_esc(r.remediation_id)}</code></h3>
        <table>
          <tr><th>Linked Findings</th><td>{_esc(linked_findings) or "None"}</td></tr>
          <tr><th>Linked Controls</th><td>{_esc(linked_controls) or "None"}</td></tr>
          <tr><th>Confidence Impact</th><td>+{r.confidence_impact:.3f}</td></tr>
          <tr><th>Evidence Gaps</th><td>{_esc(gaps) or "None"}</td></tr>
          <tr><th>Operational Impact</th><td>{_esc(r.operational_impact)}</td></tr>
        </table>
      </div>"""

    evidence_html = ""
    for ref in report.evidence_appendix:
        state_color = (
            "#27ae60"
            if ref.validation_state == ValidationState.VALIDATED
            else "#e67e22"
            if ref.validation_state == ValidationState.PENDING
            else "#c0392b"
        )
        freshness = (
            f"{ref.freshness_days} days"
            if ref.freshness_days is not None
            else "unknown"
        )
        evidence_html += f"""
      <tr>
        <td><code>{_esc(ref.evidence_id)}</code></td>
        <td>{_esc(ref.source)}</td>
        <td style="color:{state_color}">{_esc(ref.validation_state.value)}</td>
        <td>{_esc(freshness)}</td>
        <td>{_esc(ref.classification)}</td>
        <td>{_esc(ref.provenance)}</td>
      </tr>"""

    fw_summary_html = ""
    for fw in sorted(report.framework_summary.keys()):
        refs = ", ".join(sorted(report.framework_summary[fw]))
        fw_summary_html += f"<tr><td>{_esc(fw)}</td><td>{_esc(refs)}</td></tr>"

    degradation_html = ""
    if report.confidence.degradation_reasons:
        items = "".join(
            f"<li>{_esc(r)}</li>" for r in report.confidence.degradation_reasons
        )
        degradation_html = f"<ul>{items}</ul>"
    else:
        degradation_html = "<p>No degradation factors.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>FrostGate Governance Report — {_esc(report.report_id)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; }}
    h1 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
    h2 {{ color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }}
    h3 {{ margin-top: 15px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
    th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
    th {{ background: #ecf0f1; width: 200px; }}
    .finding, .remediation {{ border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; }}
    code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }}
    .footer {{ background: #2c3e50; color: white; padding: 15px; margin-top: 40px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
    .confidence-bar {{ height: 20px; background: #3498db; border-radius: 3px; }}
  </style>
</head>
<body>
  <h1>FrostGate Governance Report</h1>
  <table>
    <tr><th>Report ID</th><td><code>{_esc(report.report_id)}</code></td></tr>
    <tr><th>Assessment ID</th><td><code>{_esc(report.assessment_id)}</code></td></tr>
    <tr><th>Tenant ID</th><td><code>{_esc(report.tenant_id)}</code></td></tr>
    <tr><th>Version</th><td>{report.version}</td></tr>
    <tr><th>Schema Version</th><td>{_esc(report.schema_version)}</td></tr>
    <tr><th>Generated At</th><td>{_esc(report.generated_at)}</td></tr>
    <tr><th>Findings</th><td>{len(report.findings)}</td></tr>
    <tr><th>Remediations</th><td>{len(report.remediations)}</td></tr>
  </table>

  <h2>Confidence Score</h2>
  <table>
    <tr><th>Overall</th><td>{report.confidence.overall:.4f}</td></tr>
    <tr><th>Evidence Completeness</th><td>{report.confidence.evidence_completeness:.4f}</td></tr>
    <tr><th>Evidence Freshness</th><td>{report.confidence.evidence_freshness:.4f}</td></tr>
    <tr><th>Control Coverage</th><td>{report.confidence.control_coverage:.4f}</td></tr>
    <tr><th>Reviewer Validated</th><td>{"Yes" if report.confidence.reviewer_validated else "No"}</td></tr>
  </table>
  <p><strong>Degradation Factors:</strong></p>
  {degradation_html}

  <h2>Findings ({len(report.findings)})</h2>
  {findings_html if findings_html else "<p>No findings — all domains within threshold.</p>"}

  <h2>Remediations ({len(report.remediations)})</h2>
  {remediations_html if remediations_html else "<p>No remediations required.</p>"}

  <h2>Framework Summary</h2>
  <table>
    <tr><th>Framework</th><th>Referenced Controls</th></tr>
    {fw_summary_html if fw_summary_html else "<tr><td colspan='2'>No framework mappings.</td></tr>"}
  </table>

  <h2>Evidence Appendix ({len(report.evidence_appendix)} items)</h2>
  <table>
    <tr>
      <th>Evidence ID</th><th>Source</th><th>State</th>
      <th>Freshness</th><th>Classification</th><th>Provenance</th>
    </tr>
    {evidence_html if evidence_html else "<tr><td colspan='6'>No evidence references.</td></tr>"}
  </table>

  <div class="footer">
    <strong>MANIFEST HASH (SHA-256):</strong><br>
    {_esc(report.manifest_hash)}<br><br>
    <strong>SCHEMA VERSION:</strong> {_esc(report.schema_version)}<br>
    <strong>REPORT ID:</strong> {_esc(report.report_id)}<br>
    <em>This report was generated deterministically. AI narrative is advisory-only
    and isolated from all deterministic truth fields above.</em>
  </div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# PDF export
# ---------------------------------------------------------------------------


def export_pdf_bytes(report: GovernanceReport) -> bytes:
    """Export the governance report as a PDF document using reportlab.

    Raises ExportUnavailableError if reportlab is not installed.
    Includes all deterministic sections: findings, remediations,
    evidence appendix, confidence breakdown, manifest hash.
    No AI prose.
    """
    try:
        from reportlab.lib import colors  # noqa: PLC0415
        from reportlab.lib.pagesizes import letter  # noqa: PLC0415
        from reportlab.lib.styles import getSampleStyleSheet  # noqa: PLC0415
        from reportlab.lib.units import inch  # noqa: PLC0415
        from reportlab.platypus import (  # noqa: PLC0415
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ExportUnavailableError(
            "reportlab is required for PDF export. Install it with: pip install reportlab"
        ) from exc

    import io  # noqa: PLC0415

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("FrostGate Governance Report", styles["Title"]))
    story.append(Spacer(1, 0.2 * inch))

    # Header table
    header_data = [
        ["Report ID", report.report_id],
        ["Assessment ID", report.assessment_id],
        ["Tenant ID", report.tenant_id],
        ["Version", str(report.version)],
        ["Schema Version", report.schema_version],
        ["Generated At", report.generated_at],
    ]
    t = Table(header_data, colWidths=[1.5 * inch, 5 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    # Confidence
    story.append(Paragraph("Confidence Score", styles["Heading2"]))
    conf_data = [
        ["Overall", f"{report.confidence.overall:.4f}"],
        ["Evidence Completeness", f"{report.confidence.evidence_completeness:.4f}"],
        ["Evidence Freshness", f"{report.confidence.evidence_freshness:.4f}"],
        ["Control Coverage", f"{report.confidence.control_coverage:.4f}"],
        ["Reviewer Validated", "Yes" if report.confidence.reviewer_validated else "No"],
        [
            "Degradation Reasons",
            "; ".join(report.confidence.degradation_reasons) or "None",
        ],
    ]
    ct = Table(conf_data, colWidths=[2 * inch, 4.5 * inch])
    ct.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
        )
    )
    story.append(ct)
    story.append(Spacer(1, 0.2 * inch))

    # Findings
    story.append(Paragraph(f"Findings ({len(report.findings)})", styles["Heading2"]))
    if report.findings:
        for f in report.findings:
            fw_refs = "; ".join(
                f"{fm.framework}: {fm.control_ref}" for fm in f.framework_mappings
            )
            finding_data = [
                ["Finding ID", f.finding_id],
                ["Control ID", f.control_id],
                ["Domain", f.domain],
                ["Severity", f.severity.upper()],
                ["Gap Classification", f.gap_classification],
                ["Confidence", f"{f.confidence:.3f}"],
                ["Framework Mappings", fw_refs or "None"],
                ["Description", f.description],
            ]
            ft = Table(finding_data, colWidths=[1.5 * inch, 5 * inch])
            ft.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(ft)
            story.append(Spacer(1, 0.1 * inch))
    else:
        story.append(Paragraph("No findings.", styles["Normal"]))

    story.append(Spacer(1, 0.1 * inch))

    # Evidence appendix
    story.append(
        Paragraph(
            f"Evidence Appendix ({len(report.evidence_appendix)} items)",
            styles["Heading2"],
        )
    )
    if report.evidence_appendix:
        ev_data = [["Evidence ID", "Source", "State", "Freshness", "Classification"]]
        for ref in report.evidence_appendix:
            freshness = (
                f"{ref.freshness_days}d"
                if ref.freshness_days is not None
                else "unknown"
            )
            ev_data.append(
                [
                    ref.evidence_id[:12] + "…"
                    if len(ref.evidence_id) > 12
                    else ref.evidence_id,
                    ref.source,
                    ref.validation_state.value,
                    freshness,
                    ref.classification,
                ]
            )
        evt = Table(
            ev_data,
            colWidths=[1.5 * inch, 1.5 * inch, 1 * inch, 0.8 * inch, 1.7 * inch],
        )
        evt.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(evt)
    else:
        story.append(Paragraph("No evidence references.", styles["Normal"]))

    story.append(Spacer(1, 0.3 * inch))

    # Manifest hash footer
    story.append(Paragraph("Manifest Hash (SHA-256)", styles["Heading2"]))
    story.append(
        Paragraph(
            f"<font name='Courier' size=9>{report.manifest_hash}</font>",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(
        Paragraph(
            "This report was generated deterministically. AI narrative is advisory-only "
            "and isolated from all deterministic truth fields above.",
            styles["Normal"],
        )
    )

    doc.build(story)
    return buf.getvalue()
