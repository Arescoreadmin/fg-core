# services/governance_reporting/engine.py
"""Governance Reporting Engine — PR 14.5.

Orchestrates the generation, verification, attestation, and export of
governance reports that synthesize risk acceptance, approval chain, review
history, compensating controls, and the full governance timeline.

All DB writes go through the engine. Caller (API layer) owns db.commit().
"""

from __future__ import annotations

import hashlib
import html as _html
import json
import uuid
from io import BytesIO
from typing import Any

from sqlalchemy.orm import Session

from api.db_models_control_registry import (
    ControlEvidenceLink,
    ControlRegistry,
    RiskAcceptanceControlLink,
)
from api.db_models_governance_portal import PortalAcknowledgement
from api.db_models_governance_reporting import (
    GovernanceAttestation,
    GovernanceReport,
    GovernanceReportAudit,
    GovernanceReportManifest,
)
from api.db_models_risk_acceptance import RiskAcceptance, RiskAcceptanceAudit
from api.db_models_risk_governance import (
    RiskAcceptanceApproval,
    RiskAcceptanceApprovalAudit,
    RiskReview,
)
from api.observability.metrics import (
    GOVERNANCE_REPORTING_ATTESTATIONS_TOTAL,
    GOVERNANCE_REPORTING_EXPORTS_TOTAL,
    GOVERNANCE_REPORTING_REPORTS_TOTAL,
    GOVERNANCE_REPORTING_SUPERSEDED_TOTAL,
    GOVERNANCE_REPORTING_VERIFICATIONS_TOTAL,
    GOVERNANCE_REPORTING_VIEWS_TOTAL,
)
from services.canonical import utc_iso8601_z_now
from services.governance.timeline.adapters import governance_reporting_to_timeline_event
from services.governance.timeline.store import TimelineStore
from services.governance_reporting.repository import (
    count_attestations,
    count_reports,
    fetch_approval_audit_trail,
    fetch_approvals_for_risk,
    fetch_attestations,
    fetch_control_links_for_risk,
    fetch_controls_by_ids,
    fetch_evidence_for_control,
    fetch_manifest_for_report,
    fetch_portal_acks_for_risk,
    fetch_report_by_id,
    fetch_reports,
    fetch_risk_acceptance,
    fetch_risk_audit_trail,
    fetch_reviews_for_risk,
    get_max_report_version,
    insert_attestation,
    insert_manifest,
    insert_report,
    insert_report_audit,
    supersede_previous_reports,
)
from services.governance_reporting.schemas import (
    ApprovalEntry,
    AttestationListResponse,
    AttestationResponse,
    ControlEntry,
    CreateAttestationRequest,
    EvidenceEntry,
    GenerateReportRequest,
    GovernanceReportDetail,
    GovernanceReportListResponse,
    GovernanceReportSummary,
    ManifestResponse,
    ReportAuditEventType,
    ReportNotFound,
    ReportStatus,
    ReportTimelineEntry,
    ReportTimelineResponse,
    ReviewEntry,
    RiskSection,
    VerificationResponse,
    VerificationResult,
)

_timeline_store = TimelineStore()


def _now_iso() -> str:
    return utc_iso8601_z_now()


def _sha256(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


def _section_hash(obj: Any) -> str:
    """Compute SHA-256 of deterministically serialized object."""
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return _sha256(serialized)


# ---------------------------------------------------------------------------
# PDF / HTML generation helpers
# ---------------------------------------------------------------------------


def _e(value: object) -> str:
    """HTML-escape a value for safe interpolation into the report document."""
    return _html.escape(str(value) if value is not None else "")


def _build_html(detail: GovernanceReportDetail) -> str:
    """Generate a complete HTML governance report document."""
    risk = detail.risk_section
    approval_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _e(a.approver_name),
            _e(a.approver_role or ""),
            _e(a.approval_type),
            _e(a.status),
            _e(a.approved_at or ""),
        )
        for a in detail.approval_chain
    )
    review_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _e(r.review_type),
            _e(r.reviewer or ""),
            _e(r.status),
            _e(r.review_due_at),
            _e(r.review_completed_at or ""),
            _e(r.outcome or ""),
        )
        for r in detail.review_history
    )
    control_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _e(c.control_id),
            _e(c.title),
            _e(c.control_type),
            _e(c.control_status),
            _e(c.effectiveness_rating),
            _e(c.verification_status),
            _e(c.evidence_count),
        )
        for c in detail.compensating_controls
    )
    timeline_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _e(t.occurred_at), _e(t.source), _e(t.event_type), _e(t.actor or "")
        )
        for t in detail.governance_timeline
    )

    if detail.approval_chain:
        approval_section = (
            "<table>"
            "<thead><tr><th>Approver</th><th>Role</th><th>Type</th><th>Status</th><th>Approved At</th></tr></thead>"
            "<tbody>{}</tbody></table>".format(approval_rows)
        )
    else:
        approval_section = "<p>No approvals recorded.</p>"

    if detail.review_history:
        review_section = (
            "<table>"
            "<thead><tr><th>Type</th><th>Reviewer</th><th>Status</th><th>Due At</th><th>Completed At</th><th>Outcome</th></tr></thead>"
            "<tbody>{}</tbody></table>".format(review_rows)
        )
    else:
        review_section = "<p>No reviews recorded.</p>"

    if detail.compensating_controls:
        controls_section = (
            "<table>"
            "<thead><tr><th>Control ID</th><th>Title</th><th>Type</th><th>Status</th>"
            "<th>Effectiveness</th><th>Verification</th><th>Evidence</th></tr></thead>"
            "<tbody>{}</tbody></table>".format(control_rows)
        )
    else:
        controls_section = "<p>No compensating controls linked.</p>"

    if detail.governance_timeline:
        timeline_section = (
            "<table>"
            "<thead><tr><th>Occurred At</th><th>Source</th><th>Event Type</th><th>Actor</th></tr></thead>"
            "<tbody>{}</tbody></table>".format(timeline_rows)
        )
    else:
        timeline_section = "<p>No timeline events recorded.</p>"

    html = (
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n'
        '<meta charset="UTF-8"/>\n'
        "<title>Governance Report &mdash; {title}</title>\n"
        "<style>\n"
        "  body {{ font-family: Arial, sans-serif; margin: 40px; color: #222; }}\n"
        "  h1 {{ color: #1a237e; border-bottom: 2px solid #1a237e; padding-bottom: 8px; }}\n"
        "  h2 {{ color: #283593; margin-top: 32px; border-bottom: 1px solid #c5cae9; padding-bottom: 4px; }}\n"
        "  .meta {{ background: #f5f5f5; padding: 16px; border-radius: 4px; margin-bottom: 24px; }}\n"
        "  .meta dt {{ font-weight: bold; color: #555; float: left; width: 200px; }}\n"
        "  .meta dd {{ margin-left: 210px; margin-bottom: 6px; }}\n"
        "  table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}\n"
        "  th {{ background: #3949ab; color: white; padding: 8px 12px; text-align: left; }}\n"
        "  td {{ padding: 6px 12px; border-bottom: 1px solid #e0e0e0; }}\n"
        "  tr:nth-child(even) td {{ background: #f9f9f9; }}\n"
        "  .hash {{ font-family: monospace; font-size: 11px; color: #666; word-break: break-all; }}\n"
        "  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;"
        " background: #e8eaf6; color: #1a237e; font-size: 12px; }}\n"
        "  .footer {{ margin-top: 48px; font-size: 11px; color: #999; border-top: 1px solid #eee; padding-top: 12px; }}\n"
        "</style>\n</head>\n<body>\n"
        "<h1>Governance Report</h1>\n"
        '<div class="meta"><dl>\n'
        "  <dt>Report ID</dt><dd>{report_id}</dd>\n"
        "  <dt>Version</dt><dd>{version}</dd>\n"
        "  <dt>Generated At</dt><dd>{generated_at}</dd>\n"
        "  <dt>Generated By</dt><dd>{generated_by}</dd>\n"
        '  <dt>Status</dt><dd><span class="badge">{status}</span></dd>\n'
        "  <dt>Schema Version</dt><dd>{schema_version}</dd>\n"
        '  <dt>Report Hash</dt><dd class="hash">{report_hash}</dd>\n'
        "</dl></div>\n"
        "<h2>Risk Acceptance</h2>\n"
        '<div class="meta"><dl>\n'
        "  <dt>Title</dt><dd>{risk_title}</dd>\n"
        '  <dt>Status</dt><dd><span class="badge">{risk_status}</span></dd>\n'
        "  <dt>Accepted By</dt><dd>{accepted_by}</dd>\n"
        "  <dt>Accepted At</dt><dd>{accepted_at}</dd>\n"
        "  <dt>Expires At</dt><dd>{expires_at}</dd>\n"
        "  <dt>Next Review At</dt><dd>{next_review_at}</dd>\n"
        "  <dt>Inherent Risk</dt><dd>{inherent_risk}</dd>\n"
        "  <dt>Residual Risk</dt><dd>{residual_risk}</dd>\n"
        "  <dt>Business Justification</dt><dd>{business_justification}</dd>\n"
        "  <dt>Risk Rationale</dt><dd>{risk_rationale}</dd>\n"
        "</dl></div>\n"
        "<h2>Approval Chain ({approval_count} records)</h2>\n"
        "{approval_section}\n"
        "<h2>Review History ({review_count} records)</h2>\n"
        "{review_section}\n"
        "<h2>Compensating Controls ({control_count} controls, {evidence_count} evidence records)</h2>\n"
        "{controls_section}\n"
        "<h2>Governance Timeline ({timeline_count} events)</h2>\n"
        "{timeline_section}\n"
        '<div class="footer">\n'
        "  Generated by FrostGate Governance Reporting Engine v{schema_version} &bull;\n"
        '  Manifest Hash: <span class="hash">{manifest_hash}</span>\n'
        "</div>\n</body>\n</html>"
    ).format(
        title=_e(risk.title),
        report_id=_e(detail.id),
        version=_e(detail.report_version),
        generated_at=_e(detail.generated_at),
        generated_by=_e(detail.generated_by),
        status=_e(detail.status),
        schema_version=_e(detail.schema_version),
        report_hash=_e(detail.report_hash),
        risk_title=_e(risk.title),
        risk_status=_e(risk.status),
        accepted_by=_e(risk.accepted_by),
        accepted_at=_e(risk.accepted_at or "N/A"),
        expires_at=_e(risk.expires_at or "N/A"),
        next_review_at=_e(risk.next_review_at or "N/A"),
        inherent_risk=_e(risk.inherent_risk or "N/A"),
        residual_risk=_e(risk.residual_risk or "N/A"),
        business_justification=_e(risk.business_justification),
        risk_rationale=_e(risk.risk_rationale),
        approval_count=_e(detail.approval_count),
        approval_section=approval_section,
        review_count=_e(detail.review_count),
        review_section=review_section,
        control_count=_e(detail.control_count),
        evidence_count=_e(detail.evidence_count),
        controls_section=controls_section,
        timeline_count=_e(len(detail.governance_timeline)),
        timeline_section=timeline_section,
        manifest_hash=_e(detail.manifest_hash or "N/A"),
    )
    return html


def _build_pdf(detail: GovernanceReportDetail) -> bytes:
    """Generate a PDF governance report using reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )
    styles = getSampleStyleSheet()
    mono_style = ParagraphStyle(
        "Mono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#666666"),
    )
    label_style = ParagraphStyle(
        "Label",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        textColor=colors.HexColor("#555555"),
    )

    story: list[Any] = []

    # Title
    story.append(Paragraph("Governance Report", styles["Title"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"Risk: {detail.risk_section.title}", styles["Heading1"]))
    story.append(Spacer(1, 2 * mm))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#1a237e")))
    story.append(Spacer(1, 4 * mm))

    # Report metadata
    meta_data = [
        ["Report ID", detail.id],
        ["Version", str(detail.report_version)],
        ["Generated At", detail.generated_at],
        ["Generated By", detail.generated_by],
        ["Status", detail.status],
        ["Schema Version", detail.schema_version],
    ]
    meta_table = Table(meta_data, colWidths=[50 * mm, None])
    meta_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#555555")),
                (
                    "ROWBACKGROUNDS",
                    (0, 0),
                    (-1, -1),
                    [colors.HexColor("#f5f5f5"), colors.white],
                ),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(meta_table)
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph("Report Hash:", label_style))
    story.append(Paragraph(detail.report_hash, mono_style))
    story.append(Spacer(1, 6 * mm))

    # Risk section
    story.append(Paragraph("Risk Acceptance", styles["Heading2"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c5cae9")))
    story.append(Spacer(1, 2 * mm))
    risk = detail.risk_section
    risk_data = [
        ["Title", risk.title],
        ["Status", risk.status],
        ["Accepted By", risk.accepted_by],
        ["Accepted At", risk.accepted_at or "N/A"],
        ["Expires At", risk.expires_at or "N/A"],
        ["Next Review At", risk.next_review_at or "N/A"],
        ["Inherent Risk", risk.inherent_risk or "N/A"],
        ["Residual Risk", risk.residual_risk or "N/A"],
        ["Business Justification", risk.business_justification],
        ["Risk Rationale", risk.risk_rationale],
    ]
    risk_table = Table(risk_data, colWidths=[50 * mm, None])
    risk_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                (
                    "ROWBACKGROUNDS",
                    (0, 0),
                    (-1, -1),
                    [colors.HexColor("#f5f5f5"), colors.white],
                ),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(risk_table)
    story.append(Spacer(1, 6 * mm))

    # Approval chain
    story.append(
        Paragraph(
            f"Approval Chain ({detail.approval_count} records)", styles["Heading2"]
        )
    )
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c5cae9")))
    story.append(Spacer(1, 2 * mm))
    if detail.approval_chain:
        approval_header = [["Approver", "Role", "Type", "Status", "Approved At"]]
        approval_rows = [
            [
                a.approver_name,
                a.approver_role or "",
                a.approval_type,
                a.status,
                a.approved_at or "",
            ]
            for a in detail.approval_chain
        ]
        approval_table = Table(
            approval_header + approval_rows,
            colWidths=[40 * mm, 30 * mm, 30 * mm, 25 * mm, 35 * mm],
        )
        approval_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f9f9f9")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(approval_table)
    else:
        story.append(Paragraph("No approvals recorded.", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    # Review history
    story.append(
        Paragraph(f"Review History ({detail.review_count} records)", styles["Heading2"])
    )
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c5cae9")))
    story.append(Spacer(1, 2 * mm))
    if detail.review_history:
        review_header = [
            ["Type", "Reviewer", "Status", "Due At", "Completed At", "Outcome"]
        ]
        review_rows = [
            [
                r.review_type,
                r.reviewer or "",
                r.status,
                r.review_due_at,
                r.review_completed_at or "",
                r.outcome or "",
            ]
            for r in detail.review_history
        ]
        review_table = Table(
            review_header + review_rows,
            colWidths=[25 * mm, 35 * mm, 20 * mm, 30 * mm, 30 * mm, 20 * mm],
        )
        review_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f9f9f9")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(review_table)
    else:
        story.append(Paragraph("No reviews recorded.", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    # Compensating controls
    story.append(
        Paragraph(
            f"Compensating Controls ({detail.control_count} controls, {detail.evidence_count} evidence records)",
            styles["Heading2"],
        )
    )
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c5cae9")))
    story.append(Spacer(1, 2 * mm))
    if detail.compensating_controls:
        ctrl_header = [
            ["Control ID", "Title", "Type", "Status", "Effectiveness", "Evidence"]
        ]
        ctrl_rows = [
            [
                c.control_id,
                c.title,
                c.control_type,
                c.control_status,
                c.effectiveness_rating,
                str(c.evidence_count),
            ]
            for c in detail.compensating_controls
        ]
        ctrl_table = Table(
            ctrl_header + ctrl_rows,
            colWidths=[30 * mm, 45 * mm, 25 * mm, 25 * mm, 25 * mm, 15 * mm],
        )
        ctrl_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f9f9f9")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(ctrl_table)
    else:
        story.append(Paragraph("No compensating controls linked.", styles["Normal"]))
    story.append(Spacer(1, 6 * mm))

    # Governance timeline
    story.append(
        Paragraph(
            f"Governance Timeline ({len(detail.governance_timeline)} events)",
            styles["Heading2"],
        )
    )
    story.append(HRFlowable(width="100%", color=colors.HexColor("#c5cae9")))
    story.append(Spacer(1, 2 * mm))
    if detail.governance_timeline:
        tl_header = [["Occurred At", "Source", "Event Type", "Actor"]]
        tl_rows = [
            [t.occurred_at, t.source, t.event_type, t.actor or ""]
            for t in detail.governance_timeline
        ]
        tl_table = Table(
            tl_header + tl_rows,
            colWidths=[40 * mm, 30 * mm, 50 * mm, 40 * mm],
        )
        tl_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3949ab")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f9f9f9")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e0e0e0")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        story.append(tl_table)
    else:
        story.append(Paragraph("No timeline events recorded.", styles["Normal"]))
    story.append(Spacer(1, 8 * mm))

    # Footer
    story.append(HRFlowable(width="100%", color=colors.HexColor("#eeeeee")))
    story.append(Spacer(1, 2 * mm))
    story.append(
        Paragraph(
            f"Generated by FrostGate Governance Reporting Engine v{detail.schema_version}",
            mono_style,
        )
    )
    if detail.manifest_hash:
        story.append(Paragraph(f"Manifest Hash: {detail.manifest_hash}", mono_style))

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class GovernanceReportingEngine:
    """Governance Reporting Engine — orchestrates report generation, verification, and export."""

    def __init__(self, db: Session, tenant_id: str) -> None:
        self._db = db
        self._tenant_id = tenant_id

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _build_report_content(
        self,
        risk: RiskAcceptance,
        approvals: list[RiskAcceptanceApproval],
        reviews: list[RiskReview],
        control_links: list[RiskAcceptanceControlLink],
        controls_map: dict[str, ControlRegistry],
        evidence_map: dict[str, list[ControlEvidenceLink]],
        acks: list[PortalAcknowledgement],
        risk_audits: list[RiskAcceptanceAudit],
        approval_audits: list[RiskAcceptanceApprovalAudit],
    ) -> tuple[
        RiskSection,
        list[ApprovalEntry],
        list[ReviewEntry],
        list[ControlEntry],
        list[ReportTimelineEntry],
    ]:
        """Build structured report content from raw ORM rows."""

        # Risk section
        risk_section = RiskSection(
            id=risk.id,
            title=risk.title,
            business_justification=risk.business_justification,
            risk_rationale=risk.risk_rationale,
            residual_risk=risk.residual_risk,
            inherent_risk=risk.inherent_risk,
            status=risk.status,
            accepted_by=risk.accepted_by,
            accepted_at=risk.accepted_at,
            expires_at=risk.expires_at,
            next_review_at=risk.next_review_at,
            review_frequency_days=risk.review_frequency_days,
            schema_version=getattr(risk, "schema_version", "1.0"),
        )

        # Approval chain
        approval_chain = [
            ApprovalEntry(
                id=a.id,
                approver_name=a.approver_name,
                approver_email=a.approver_email,
                approver_role=a.approver_role,
                approval_authority=a.approval_authority,
                approval_type=a.approval_type,
                status=a.status,
                comments=a.comments,
                approved_at=a.approved_at,
                quorum_required=a.quorum_required,
                quorum_position=a.quorum_position,
                is_required=a.is_required,
            )
            for a in approvals
        ]

        # Review history
        review_history = [
            ReviewEntry(
                id=r.id,
                review_type=r.review_type,
                reviewer=r.reviewer,
                status=r.status,
                review_due_at=r.review_due_at,
                review_completed_at=r.review_completed_at,
                outcome=r.outcome,
                review_notes=r.review_notes,
            )
            for r in reviews
        ]

        # Compensating controls
        compensating_controls: list[ControlEntry] = []
        for link in control_links:
            ctrl = controls_map.get(link.control_id)
            if ctrl is None:
                continue
            evidence_list = evidence_map.get(ctrl.id, [])
            evidence_entries = [
                EvidenceEntry(
                    id=ev.id,
                    evidence_id=ev.evidence_id,
                    evidence_type=ev.evidence_type,
                    linked_by=ev.linked_by,
                    linked_at=ev.linked_at,
                )
                for ev in evidence_list
            ]
            compensating_controls.append(
                ControlEntry(
                    id=ctrl.id,
                    control_id=ctrl.control_id,
                    title=ctrl.title,
                    description=ctrl.description,
                    control_type=ctrl.control_type,
                    control_status=ctrl.control_status,
                    effectiveness_rating=ctrl.effectiveness_rating,
                    verification_status=ctrl.verification_status,
                    criticality=ctrl.criticality,
                    owner=ctrl.owner,
                    last_verified_at=ctrl.last_verified_at,
                    review_frequency_days=ctrl.review_frequency_days,
                    evidence_count=len(evidence_entries),
                    evidence=evidence_entries,
                    rationale=link.rationale,
                )
            )

        # Governance timeline — merge and sort from multiple sources
        timeline_events: list[ReportTimelineEntry] = []
        seen: set[tuple[str, str]] = set()

        def _add_event(
            source: str,
            row_id: str,
            event_type: str,
            occurred_at: str,
            actor: str | None,
            details: dict[str, Any],
        ) -> None:
            key = (source, row_id)
            if key in seen:
                return
            seen.add(key)
            event_id = _sha256(f"{source}:{row_id}:{occurred_at}")[:32]
            timeline_events.append(
                ReportTimelineEntry(
                    event_id=event_id,
                    event_type=event_type,
                    source=source,
                    actor=actor,
                    occurred_at=occurred_at,
                    details=details,
                )
            )

        for audit in risk_audits:
            _add_event(
                source="risk_acceptance",
                row_id=audit.id,
                event_type=audit.event_type,
                occurred_at=audit.event_at,
                actor=audit.actor,
                details={},
            )

        for audit in approval_audits:
            _add_event(
                source="approval",
                row_id=audit.id,
                event_type=audit.event_type,
                occurred_at=audit.event_at,
                actor=audit.actor,
                details={},
            )

        for review in reviews:
            if review.review_completed_at:
                _add_event(
                    source="review",
                    row_id=review.id,
                    event_type=f"review.{review.status}",
                    occurred_at=review.review_completed_at,
                    actor=review.reviewer,
                    details={"outcome": review.outcome or ""},
                )

        for ack in acks:
            _add_event(
                source="portal",
                row_id=ack.id,
                event_type="portal.acknowledgement_created",
                occurred_at=ack.acknowledged_at,
                actor=ack.acknowledged_by,
                details={"entity_type": ack.entity_type},
            )

        # Sort by occurred_at ASC
        timeline_events.sort(key=lambda e: e.occurred_at)

        return (
            risk_section,
            approval_chain,
            review_history,
            compensating_controls,
            timeline_events,
        )

    def _compute_section_hashes(
        self,
        risk_section: RiskSection,
        approval_chain: list[ApprovalEntry],
        review_history: list[ReviewEntry],
        compensating_controls: list[ControlEntry],
        governance_timeline: list[ReportTimelineEntry],
    ) -> tuple[str, str, str, str, str, str, str]:
        """Compute cryptographic hashes for each section and overall."""
        risk_hash = _section_hash(risk_section.model_dump())
        approval_hash = _section_hash([a.model_dump() for a in approval_chain])
        review_hash = _section_hash([r.model_dump() for r in review_history])
        control_hash = _section_hash([c.model_dump() for c in compensating_controls])
        timeline_hash = _section_hash([t.model_dump() for t in governance_timeline])

        overall_hash = _sha256(
            json.dumps(
                {
                    "risk": risk_hash,
                    "approvals": approval_hash,
                    "reviews": review_hash,
                    "controls": control_hash,
                    "timeline": timeline_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

        report_hash = _sha256(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "risk": risk_hash,
                    "approvals": approval_hash,
                    "reviews": review_hash,
                    "controls": control_hash,
                    "timeline": timeline_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

        return (
            risk_hash,
            approval_hash,
            review_hash,
            control_hash,
            timeline_hash,
            overall_hash,
            report_hash,
        )

    def _emit_audit(
        self,
        report_id: str,
        event_type: ReportAuditEventType,
        actor: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        now = _now_iso()
        audit = GovernanceReportAudit(
            id=uuid.uuid4().hex,
            report_id=report_id,
            tenant_id=self._tenant_id,
            event_type=event_type.value,
            actor=actor,
            event_at=now,
            details=details,
            created_at=now,
        )
        insert_report_audit(self._db, audit)

    def _build_detail(
        self,
        report: GovernanceReport,
        risk_section: RiskSection,
        approval_chain: list[ApprovalEntry],
        review_history: list[ReviewEntry],
        compensating_controls: list[ControlEntry],
        governance_timeline: list[ReportTimelineEntry],
    ) -> GovernanceReportDetail:
        evidence_count = sum(c.evidence_count for c in compensating_controls)
        return GovernanceReportDetail(
            id=report.id,
            tenant_id=report.tenant_id,
            risk_acceptance_id=report.risk_acceptance_id,
            report_version=report.report_version,
            generated_at=report.generated_at,
            generated_by=report.generated_by,
            report_hash=report.report_hash,
            manifest_hash=report.manifest_hash,
            schema_version=report.schema_version,
            snapshot_timestamp=report.snapshot_timestamp,
            status=report.status,
            risk_section=risk_section,
            approval_chain=approval_chain,
            review_history=review_history,
            compensating_controls=compensating_controls,
            governance_timeline=governance_timeline,
            evidence_count=evidence_count,
            control_count=len(compensating_controls),
            approval_count=len(approval_chain),
            review_count=len(review_history),
        )

    def _fetch_full_content(
        self, risk_acceptance_id: str
    ) -> tuple[
        RiskAcceptance,
        list[ApprovalEntry],
        list[ReviewEntry],
        list[ControlEntry],
        list[ReportTimelineEntry],
    ]:
        """Fetch and build all report content sections for a given risk_acceptance_id."""
        risk = fetch_risk_acceptance(self._db, self._tenant_id, risk_acceptance_id)
        approvals = fetch_approvals_for_risk(
            self._db, self._tenant_id, risk_acceptance_id
        )
        reviews = fetch_reviews_for_risk(self._db, self._tenant_id, risk_acceptance_id)
        control_links = fetch_control_links_for_risk(
            self._db, self._tenant_id, risk_acceptance_id
        )

        # Build controls_map and evidence_map
        control_ids = [link.control_id for link in control_links]
        controls = fetch_controls_by_ids(self._db, self._tenant_id, control_ids)
        controls_map: dict[str, ControlRegistry] = {c.id: c for c in controls}
        evidence_map: dict[str, list[ControlEvidenceLink]] = {
            c.id: fetch_evidence_for_control(self._db, self._tenant_id, c.id)
            for c in controls
        }

        acks = fetch_portal_acks_for_risk(self._db, self._tenant_id, risk_acceptance_id)
        risk_audits = fetch_risk_audit_trail(
            self._db, self._tenant_id, risk_acceptance_id
        )
        approval_audits = fetch_approval_audit_trail(
            self._db, self._tenant_id, risk_acceptance_id
        )

        (
            risk_section,
            approval_chain,
            review_history,
            compensating_controls,
            governance_timeline,
        ) = self._build_report_content(
            risk=risk,
            approvals=approvals,
            reviews=reviews,
            control_links=control_links,
            controls_map=controls_map,
            evidence_map=evidence_map,
            acks=acks,
            risk_audits=risk_audits,
            approval_audits=approval_audits,
        )
        return (
            risk,
            approval_chain,
            review_history,
            compensating_controls,
            governance_timeline,
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def generate_report(
        self, request: GenerateReportRequest, actor: str
    ) -> GovernanceReportDetail:
        """Generate a new governance report for a risk acceptance."""
        risk_acceptance_id = request.risk_acceptance_id
        now = _now_iso()

        # Step 1-5: Fetch all source data
        (
            risk,
            approval_chain,
            review_history,
            compensating_controls,
            governance_timeline,
        ) = self._fetch_full_content(risk_acceptance_id)

        # Need risk_section too — rebuild from risk object
        risk_section = RiskSection(
            id=risk.id,
            title=risk.title,
            business_justification=risk.business_justification,
            risk_rationale=risk.risk_rationale,
            residual_risk=risk.residual_risk,
            inherent_risk=risk.inherent_risk,
            status=risk.status,
            accepted_by=risk.accepted_by,
            accepted_at=risk.accepted_at,
            expires_at=risk.expires_at,
            next_review_at=risk.next_review_at,
            review_frequency_days=risk.review_frequency_days,
            schema_version=getattr(risk, "schema_version", "1.0"),
        )

        # Step 7: Compute hashes
        (
            risk_hash,
            approval_hash,
            review_hash,
            control_hash,
            timeline_hash,
            overall_hash,
            report_hash,
        ) = self._compute_section_hashes(
            risk_section,
            approval_chain,
            review_history,
            compensating_controls,
            governance_timeline,
        )

        # Step 8: Create report
        report_id = uuid.uuid4().hex
        max_version = get_max_report_version(
            self._db, self._tenant_id, risk_acceptance_id
        )
        report = GovernanceReport(
            id=report_id,
            tenant_id=self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            report_version=max_version + 1,
            generated_at=now,
            generated_by=request.generated_by,
            report_hash=report_hash,
            manifest_hash=overall_hash,
            schema_version="1.0",
            snapshot_timestamp=request.snapshot_timestamp,
            status=ReportStatus.COMPLETED.value,
            created_at=now,
        )
        insert_report(self._db, report)

        # Step 9: Supersede previous reports
        supersede_previous_reports(
            self._db, self._tenant_id, risk_acceptance_id, report_id
        )
        GOVERNANCE_REPORTING_SUPERSEDED_TOTAL.inc(
            0
        )  # only counts actual superseded below

        # Step 10: Create manifest
        manifest_id = uuid.uuid4().hex
        manifest = GovernanceReportManifest(
            id=manifest_id,
            report_id=report_id,
            risk_acceptance_hash=risk_hash,
            approval_chain_hash=approval_hash,
            review_history_hash=review_hash,
            control_evidence_hash=control_hash,
            timeline_hash=timeline_hash,
            overall_hash=overall_hash,
        )
        insert_manifest(self._db, manifest)

        # Step 11: Emit audit
        self._emit_audit(report_id, ReportAuditEventType.GENERATED, actor)

        # Step 12: Emit timeline event
        timeline_event = governance_reporting_to_timeline_event(
            tenant_id=self._tenant_id,
            source_id=report_id,
            event_type="governance_report.generated",
            occurred_at=now,
            payload={
                "risk_acceptance_id": risk_acceptance_id,
                "report_version": report.report_version,
                "generated_by": request.generated_by,
            },
        )
        _timeline_store.record(self._db, timeline_event)

        # Step 13: Emit metric
        GOVERNANCE_REPORTING_REPORTS_TOTAL.inc()

        # Step 15: Build and return detail (db.commit() is caller's responsibility)
        detail = self._build_detail(
            report=report,
            risk_section=risk_section,
            approval_chain=approval_chain,
            review_history=review_history,
            compensating_controls=compensating_controls,
            governance_timeline=governance_timeline,
        )
        return detail

    def list_reports(
        self,
        risk_acceptance_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> GovernanceReportListResponse:
        """List governance reports for the tenant."""
        reports = fetch_reports(
            self._db,
            self._tenant_id,
            risk_acceptance_id=risk_acceptance_id,
            limit=limit,
            offset=offset,
        )
        total = count_reports(
            self._db, self._tenant_id, risk_acceptance_id=risk_acceptance_id
        )
        GOVERNANCE_REPORTING_VIEWS_TOTAL.inc()

        # For summaries, we need counts — build lightweight summaries without full content
        items: list[GovernanceReportSummary] = []
        for report in reports:
            # Fetch control links for count
            control_links = fetch_control_links_for_risk(
                self._db, self._tenant_id, report.risk_acceptance_id
            )
            control_ids = [link.control_id for link in control_links]
            controls = fetch_controls_by_ids(self._db, self._tenant_id, control_ids)
            evidence_count = sum(
                len(fetch_evidence_for_control(self._db, self._tenant_id, c.id))
                for c in controls
            )
            approvals = fetch_approvals_for_risk(
                self._db, self._tenant_id, report.risk_acceptance_id
            )
            reviews = fetch_reviews_for_risk(
                self._db, self._tenant_id, report.risk_acceptance_id
            )
            items.append(
                GovernanceReportSummary(
                    id=report.id,
                    risk_acceptance_id=report.risk_acceptance_id,
                    report_version=report.report_version,
                    generated_at=report.generated_at,
                    generated_by=report.generated_by,
                    report_hash=report.report_hash,
                    status=report.status,
                    schema_version=report.schema_version,
                    evidence_count=evidence_count,
                    control_count=len(control_ids),
                    approval_count=len(approvals),
                    review_count=len(reviews),
                )
            )

        return GovernanceReportListResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_report(self, report_id: str) -> GovernanceReportDetail:
        """Get full detail for a single report."""
        report = fetch_report_by_id(self._db, self._tenant_id, report_id)
        GOVERNANCE_REPORTING_VIEWS_TOTAL.inc()

        (
            risk,
            approval_chain,
            review_history,
            compensating_controls,
            governance_timeline,
        ) = self._fetch_full_content(report.risk_acceptance_id)
        risk_section = RiskSection(
            id=risk.id,
            title=risk.title,
            business_justification=risk.business_justification,
            risk_rationale=risk.risk_rationale,
            residual_risk=risk.residual_risk,
            inherent_risk=risk.inherent_risk,
            status=risk.status,
            accepted_by=risk.accepted_by,
            accepted_at=risk.accepted_at,
            expires_at=risk.expires_at,
            next_review_at=risk.next_review_at,
            review_frequency_days=risk.review_frequency_days,
            schema_version=getattr(risk, "schema_version", "1.0"),
        )
        return self._build_detail(
            report=report,
            risk_section=risk_section,
            approval_chain=approval_chain,
            review_history=review_history,
            compensating_controls=compensating_controls,
            governance_timeline=governance_timeline,
        )

    def get_manifest(self, report_id: str) -> ManifestResponse:
        """Get the manifest for a report."""
        report = fetch_report_by_id(self._db, self._tenant_id, report_id)
        manifest = fetch_manifest_for_report(self._db, report.id)
        if manifest is None:
            raise ReportNotFound(f"Manifest for report {report_id} not found")
        GOVERNANCE_REPORTING_VIEWS_TOTAL.inc()
        return ManifestResponse(
            id=manifest.id,
            report_id=manifest.report_id,
            risk_acceptance_hash=manifest.risk_acceptance_hash,
            approval_chain_hash=manifest.approval_chain_hash,
            review_history_hash=manifest.review_history_hash,
            control_evidence_hash=manifest.control_evidence_hash,
            timeline_hash=manifest.timeline_hash,
            overall_hash=manifest.overall_hash,
        )

    def get_report_timeline(
        self, report_id: str, limit: int = 100, offset: int = 0
    ) -> ReportTimelineResponse:
        """Get timeline events within a report."""
        report = fetch_report_by_id(self._db, self._tenant_id, report_id)
        GOVERNANCE_REPORTING_VIEWS_TOTAL.inc()

        _, _, _, _, governance_timeline = self._fetch_full_content(
            report.risk_acceptance_id
        )
        total = len(governance_timeline)
        items = governance_timeline[offset : offset + limit]
        return ReportTimelineResponse(items=items, total=total)

    def list_attestations(
        self, report_id: str, limit: int = 50, offset: int = 0
    ) -> AttestationListResponse:
        """List attestations for a report."""
        # Verify report exists and is tenant-scoped
        fetch_report_by_id(self._db, self._tenant_id, report_id)
        GOVERNANCE_REPORTING_VIEWS_TOTAL.inc()

        attestations = fetch_attestations(
            self._db, self._tenant_id, report_id, limit=limit, offset=offset
        )
        total = count_attestations(self._db, self._tenant_id, report_id)
        items = [
            AttestationResponse(
                id=a.id,
                report_id=a.report_id,
                attestor=a.attestor,
                attestor_role=a.attestor_role,
                attestation_type=a.attestation_type,
                attested_at=a.attested_at,
                attestation_statement=a.attestation_statement,
                signature_hash=a.signature_hash,
                schema_version=a.schema_version,
                actor_type=a.actor_type,
                created_at=a.created_at,
            )
            for a in attestations
        ]
        return AttestationListResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
        )

    def create_attestation(
        self,
        report_id: str,
        request: CreateAttestationRequest,
        actor: str,
    ) -> AttestationResponse:
        """Create a formal attestation for a report."""
        # Verify report exists
        fetch_report_by_id(self._db, self._tenant_id, report_id)

        now = _now_iso()
        attested_at = now

        # Compute signature hash
        signature_hash = _sha256(
            json.dumps(
                {
                    "report_id": report_id,
                    "attestor": request.attestor,
                    "attestation_type": request.attestation_type.value,
                    "attested_at": attested_at,
                    "statement": request.attestation_statement,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )

        attestation = GovernanceAttestation(
            id=uuid.uuid4().hex,
            report_id=report_id,
            tenant_id=self._tenant_id,
            attestor=request.attestor,
            attestor_role=request.attestor_role,
            attestation_type=request.attestation_type.value,
            attested_at=attested_at,
            attestation_statement=request.attestation_statement,
            signature_hash=signature_hash,
            schema_version="1.0",
            actor_type=request.actor_type.value,
            created_at=now,
        )
        insert_attestation(self._db, attestation)
        self._emit_audit(
            report_id,
            ReportAuditEventType.ATTESTED,
            actor,
            details={
                "attestor": request.attestor,
                "attestation_type": request.attestation_type.value,
            },
        )
        GOVERNANCE_REPORTING_ATTESTATIONS_TOTAL.inc()

        return AttestationResponse(
            id=attestation.id,
            report_id=attestation.report_id,
            attestor=attestation.attestor,
            attestor_role=attestation.attestor_role,
            attestation_type=attestation.attestation_type,
            attested_at=attestation.attested_at,
            attestation_statement=attestation.attestation_statement,
            signature_hash=attestation.signature_hash,
            schema_version=attestation.schema_version,
            actor_type=attestation.actor_type,
            created_at=attestation.created_at,
        )

    def verify_report(self, report_id: str, actor: str) -> VerificationResponse:
        """Verify the integrity of a governance report."""
        report = fetch_report_by_id(self._db, self._tenant_id, report_id)
        manifest = fetch_manifest_for_report(self._db, report.id)
        if manifest is None:
            raise ReportNotFound(f"Manifest for report {report_id} not found")

        now = _now_iso()
        result_str = VerificationResult.VALID.value
        details: dict[str, Any] = {}

        # Step 3: Verify manifest internal integrity
        recomputed_overall = _sha256(
            json.dumps(
                {
                    "risk": manifest.risk_acceptance_hash,
                    "approvals": manifest.approval_chain_hash,
                    "reviews": manifest.review_history_hash,
                    "controls": manifest.control_evidence_hash,
                    "timeline": manifest.timeline_hash,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        if recomputed_overall != manifest.overall_hash:
            result_str = VerificationResult.TAMPERED.value
            details["manifest_integrity"] = "FAILED: overall_hash mismatch"
        else:
            # Step 4-6: Re-fetch source data and recompute section hashes
            (
                risk,
                approval_chain,
                review_history,
                compensating_controls,
                governance_timeline,
            ) = self._fetch_full_content(report.risk_acceptance_id)
            risk_section = RiskSection(
                id=risk.id,
                title=risk.title,
                business_justification=risk.business_justification,
                risk_rationale=risk.risk_rationale,
                residual_risk=risk.residual_risk,
                inherent_risk=risk.inherent_risk,
                status=risk.status,
                accepted_by=risk.accepted_by,
                accepted_at=risk.accepted_at,
                expires_at=risk.expires_at,
                next_review_at=risk.next_review_at,
                review_frequency_days=risk.review_frequency_days,
                schema_version=getattr(risk, "schema_version", "1.0"),
            )
            (
                fresh_risk_hash,
                fresh_approval_hash,
                fresh_review_hash,
                fresh_control_hash,
                fresh_timeline_hash,
                _fresh_overall_hash,
                fresh_report_hash,
            ) = self._compute_section_hashes(
                risk_section,
                approval_chain,
                review_history,
                compensating_controls,
                governance_timeline,
            )

            mismatches: list[str] = []
            if fresh_risk_hash != manifest.risk_acceptance_hash:
                mismatches.append("risk_section")
            if fresh_approval_hash != manifest.approval_chain_hash:
                mismatches.append("approval_chain")
            if fresh_review_hash != manifest.review_history_hash:
                mismatches.append("review_history")
            if fresh_control_hash != manifest.control_evidence_hash:
                mismatches.append("control_evidence")
            if fresh_timeline_hash != manifest.timeline_hash:
                mismatches.append("governance_timeline")

            if mismatches:
                result_str = VerificationResult.INVALID.value
                details["mismatched_sections"] = mismatches
            elif fresh_report_hash != report.report_hash:
                # Section hashes match but the stored report_hash differs:
                # the report row's report_hash column was modified after generation.
                result_str = VerificationResult.TAMPERED.value
                details["report_hash_integrity"] = "FAILED: report_hash mismatch"
            else:
                details["verified_sections"] = [
                    "risk_section",
                    "approval_chain",
                    "review_history",
                    "control_evidence",
                    "governance_timeline",
                ]

        # Fetch counts for response
        control_links = fetch_control_links_for_risk(
            self._db, self._tenant_id, report.risk_acceptance_id
        )
        control_ids = [link.control_id for link in control_links]
        controls = fetch_controls_by_ids(self._db, self._tenant_id, control_ids)
        evidence_count = sum(
            len(fetch_evidence_for_control(self._db, self._tenant_id, c.id))
            for c in controls
        )
        approvals = fetch_approvals_for_risk(
            self._db, self._tenant_id, report.risk_acceptance_id
        )
        reviews = fetch_reviews_for_risk(
            self._db, self._tenant_id, report.risk_acceptance_id
        )

        self._emit_audit(report_id, ReportAuditEventType.DOWNLOADED, actor)
        GOVERNANCE_REPORTING_VERIFICATIONS_TOTAL.inc()

        return VerificationResponse(
            result=result_str,
            report_id=report.id,
            report_hash=report.report_hash,
            manifest_hash=manifest.overall_hash,
            verified_at=now,
            evidence_count=evidence_count,
            control_count=len(control_ids),
            approval_count=len(approvals),
            review_count=len(reviews),
            details=details,
        )

    def export_html(self, report_id: str, actor: str) -> str:
        """Export a report as HTML."""
        detail = self.get_report(report_id)
        html_str = _build_html(detail)
        self._emit_audit(
            report_id,
            ReportAuditEventType.EXPORTED,
            actor,
            details={"format": "html"},
        )
        GOVERNANCE_REPORTING_EXPORTS_TOTAL.inc()
        return html_str

    def export_pdf(self, report_id: str, actor: str) -> bytes:
        """Export a report as PDF."""
        detail = self.get_report(report_id)
        pdf_bytes = _build_pdf(detail)
        self._emit_audit(
            report_id,
            ReportAuditEventType.EXPORTED,
            actor,
            details={"format": "pdf"},
        )
        GOVERNANCE_REPORTING_EXPORTS_TOTAL.inc()
        return pdf_bytes
