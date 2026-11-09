"""PDF page decoration and proof-driven report sections — L14-SCAN-REPORT-PROOF-001.

This module is NOT standalone.  It is a component of the canonical governance
report renderer: it is used ONLY by ``serialization.export_pdf_bytes`` (the
single PDF entry point).  It renders the signed ``report_proof`` section built
by ``services.field_assessment.report_proof``; it derives nothing itself —
every count, status and classification comes from that persisted proof, and
the DRAFT / FINAL marking comes from the export route's authoritative state.

Requires reportlab (imported lazily by the caller's availability check).
"""

from __future__ import annotations

from typing import Any
from xml.sax.saxutils import escape as _xml_escape

_SEV_HEX = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#15803d",
    "informational": "#475569",
    "unrated": "#6b7280",
}
_SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "unrated": "Unrated",
}
_PROVENANCE_TEXT = {
    "VERIFIED_AUTHENTIC": "Integrity and source authenticity verified",
    "VERIFIED_INTEGRITY_ONLY": "Integrity verified (SHA-256); source not authenticated",
    "UNVERIFIED": "Not verified",
    "MISSING": "No evidence envelope captured",
    "INVALID": "Integrity check FAILED — evidence altered or unresolvable",
    "INDETERMINATE": "Integrity indeterminate",
}
_CONFIDENCE_TEXT = {
    "CONFIRMED": "Confirmed",
    "PROBABLE": "Probable — requires validation",
    "SUSPECTED": "Suspected — requires validation",
    "UNKNOWN": "Unknown — requires validation",
}
DEFAULT_MARKING = "DRAFT — NOT VERIFIED"
_LONG_TOKEN = 56
# Table cells cannot split across pages: anything unbounded that would sit in
# a cell is previewed there and rendered in full as splittable paragraphs.
_AFFECTED_PREVIEW = 3
_CELL_TEXT_LIMIT = 280


def _clip(text: str, limit: int = _CELL_TEXT_LIMIT) -> str:
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _wrap_token(tok: str) -> list[str]:
    if len(tok) <= _LONG_TOKEN:
        return [tok]
    # Prefer natural boundaries (":" and "/") before a hard split.
    pieces, cur = [], ""
    for ch in tok:
        cur += ch
        if ch in ":/" and len(cur) >= 8:
            pieces.append(cur)
            cur = ""
    if cur:
        pieces.append(cur)
    out: list[str] = []
    for piece in pieces:
        while len(piece) > _LONG_TOKEN:
            out.append(piece[:_LONG_TOKEN])
            piece = piece[_LONG_TOKEN:]
        out.append(piece)
    return out


def esc(value: Any) -> str:
    """Escape for reportlab Paragraph markup and soft-wrap unbreakable tokens."""
    text = "" if value is None else str(value)
    return _xml_escape(" ".join(p for tok in text.split(" ") for p in _wrap_token(tok)))


def fmt_ts(value: Any) -> str:
    s = str(value or "")
    if len(s) >= 16 and s[10] in "T ":
        return f"{s[:10]} {s[11:16]} UTC"
    return s or "—"


def _fit(canvas: Any, text: str, font: str, size: float, max_w: float) -> str:
    from reportlab.pdfbase.pdfmetrics import stringWidth  # noqa: PLC0415

    if stringWidth(text, font, size) <= max_w:
        return text
    while text and stringWidth(text + "…", font, size) > max_w:
        text = text[:-1]
    return text + "…"


def make_decorated_canvas(
    *,
    marking: str,
    is_draft: bool,
    report_id: str,
    revision: str,
    digest: str,
    classification: str = "CONFIDENTIAL",
) -> Any:
    """Canvas class drawing status band, watermark and footer with Page X of Y."""
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import letter  # noqa: PLC0415
    from reportlab.lib.units import inch  # noqa: PLC0415
    from reportlab.pdfbase.pdfmetrics import stringWidth  # noqa: PLC0415
    from reportlab.pdfgen import canvas as rl_canvas  # noqa: PLC0415

    width, height = letter
    margin = 0.85 * inch

    def _decorate(c: Any, page: int, total: int) -> None:
        c.saveState()
        # Status band — inside the top margin, never over body content.
        band_h = 0.26 * inch
        band_y = height - 0.52 * inch
        c.setFillColor(colors.HexColor("#fef3c7" if is_draft else "#e0f2fe"))
        c.setStrokeColor(colors.HexColor("#b45309" if is_draft else "#0369a1"))
        c.setLineWidth(0.6)
        c.rect(margin, band_y, width - 2 * margin, band_h, stroke=1, fill=1)
        c.setFillColor(colors.HexColor("#78350f" if is_draft else "#0c4a6e"))
        c.setFont("Helvetica-Bold", 8.5)
        c.drawCentredString(width / 2, band_y + 0.09 * inch, marking)
        # Diagonal watermark: very light, drawn once per page.
        if is_draft:
            c.saveState()
            c.setFillColor(colors.HexColor("#9ca3af"))
            c.setFillAlpha(0.10)
            c.translate(width / 2, height / 2)
            c.rotate(35)
            c.setFont("Helvetica-Bold", 96)
            c.drawCentredString(0, -30, "DRAFT")
            c.restoreState()
        # Footer: two lines, right column measured first so left never collides.
        c.setStrokeColor(colors.HexColor("#d1d5db"))
        c.setLineWidth(0.4)
        c.line(margin, 0.66 * inch, width - margin, 0.66 * inch)
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#4b5563"))
        right1 = f"Page {page} of {total}"
        right2 = f"SHA-256 {digest[:16]}…" if digest else ""
        rw = max(
            stringWidth(right1, "Helvetica", 7), stringWidth(right2, "Helvetica", 7)
        )
        left_w = width - 2 * margin - rw - 18
        left1 = _fit(
            c,
            f"FrostGate  ·  Report {report_id}  ·  {classification}",
            "Helvetica",
            7,
            left_w,
        )
        left2 = _fit(c, f"Revision {revision}  ·  {marking}", "Helvetica", 7, left_w)
        c.drawString(margin, 0.50 * inch, left1)
        c.drawRightString(width - margin, 0.50 * inch, right1)
        c.drawString(margin, 0.36 * inch, left2)
        if right2:
            c.drawRightString(width - margin, 0.36 * inch, right2)
        c.restoreState()

    class _DecoratedCanvas(rl_canvas.Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._saved_pages: list[dict[str, Any]] = []

        def showPage(self) -> None:  # noqa: N802 — reportlab API
            self._saved_pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._saved_pages)
            for state in self._saved_pages:
                self.__dict__.update(state)
                _decorate(self, self._pageNumber, total)
                super().showPage()
            super().save()

    return _DecoratedCanvas


def _humanize_limitation(code: str) -> str:
    parts = code.split(":")
    if len(parts) >= 4 and parts[1] == "job":
        return f"{parts[0]} scan job {parts[2][:12]}… ended {parts[3]}"
    if len(parts) >= 4 and parts[2] == "TARGETS_NOT_STARTED":
        return f"{parts[0]} scan {parts[1][:12]}…: {parts[3]} authorized target(s) not started (scan interrupted)"
    if len(parts) >= 3:
        status = parts[-1]
        subject = ":".join(parts[1:-1])
        if len(subject) == 32 and all(ch in "0123456789abcdef" for ch in subject):
            subject = f"scan {subject[:12]}…"
        if status == "EVIDENCE_NOT_CAPTURED":
            return f"{parts[0]} {subject}: evidence capture failed or absent"
        return f"{parts[0]} {subject}: collection {status}"
    return code


def proof_story(
    *,
    report: Any,
    proof: dict[str, Any],
    state: dict[str, Any],
    engagement_name: str | None,
    assessment_type: str | None,
    connector_descriptions: dict[str, tuple[str, str]],
) -> list[Any]:
    """Enterprise report sections rendered from the signed report proof."""
    from reportlab.lib import colors  # noqa: PLC0415
    from reportlab.lib.pagesizes import letter  # noqa: PLC0415
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # noqa: PLC0415
    from reportlab.lib.units import inch  # noqa: PLC0415
    from reportlab.platypus import (  # noqa: PLC0415
        CondPageBreak,
        KeepTogether,
        PageBreak,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
    )

    width, _ = letter
    content_w = width - 2 * 0.85 * inch
    base = getSampleStyleSheet()
    navy = colors.HexColor("#1e3a5f")
    grid = colors.HexColor("#d1d5db")
    h1 = ParagraphStyle(
        "pf_h1",
        parent=base["Heading1"],
        fontSize=15,
        spaceBefore=4,
        spaceAfter=8,
        textColor=navy,
    )
    h2 = ParagraphStyle(
        "pf_h2",
        parent=base["Heading2"],
        fontSize=11.5,
        spaceBefore=10,
        spaceAfter=4,
        textColor=navy,
    )
    body = ParagraphStyle("pf_body", parent=base["Normal"], fontSize=9, leading=12.5)
    small = ParagraphStyle(
        "pf_small",
        parent=base["Normal"],
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#1f2937"),
    )
    muted = ParagraphStyle(
        "pf_muted", parent=small, fontSize=7.5, textColor=colors.HexColor("#4b5563")
    )
    label = ParagraphStyle(
        "pf_label",
        parent=small,
        fontName="Helvetica-Bold",
        textColor=colors.HexColor("#374151"),
    )
    th = ParagraphStyle(
        "pf_th", parent=small, fontName="Helvetica-Bold", textColor=colors.white
    )
    bullet = ParagraphStyle("pf_bullet", parent=body, leftIndent=10, bulletIndent=2)
    detail = ParagraphStyle("pf_detail", parent=small, leftIndent=4, rightIndent=4)

    def table(rows: list[list[Any]], widths: list[float], header: bool = True) -> Any:
        t = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
        style = [
            ("GRID", (0, 0), (-1, -1), 0.3, grid),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]
        if header:
            style += [("BACKGROUND", (0, 0), (-1, 0), navy)]
        t.setStyle(TableStyle(style))
        return t

    def p(text: str, style: Any = small) -> Any:
        return Paragraph(text, style)

    def dp(text: str) -> Any:
        return Paragraph(text, detail)

    findings: list[dict[str, Any]] = proof.get("findings") or []
    sev = proof.get("severity_counts") or {}
    conf = proof.get("confidence_counts") or {}
    cov = proof.get("coverage") or {}
    rec = proof.get("finding_reconciliation") or {}
    limitations: list[str] = cov.get("limitations") or []
    scans: list[dict[str, Any]] = cov.get("scans") or []
    marking = state.get("marking") or DEFAULT_MARKING
    is_draft = bool(state.get("is_draft", True))
    synthetic = bool((proof.get("synthetic") or {}).get("is_synthetic"))
    client = engagement_name or report.tenant_id
    window = cov.get("collection_window") or {}
    period = (
        f"{fmt_ts(window.get('start'))} – {fmt_ts(window.get('end'))}"
        if window
        else "No collection recorded"
    )
    title_type = " ".join(
        w.upper() if w in ("ai", "soc2", "hipaa", "cmmc", "nist", "iso") else w.title()
        for w in (assessment_type or "security").split("_")
    )

    def scanner_name(f: dict[str, Any]) -> str:
        key = (f.get("evidence") or {}).get("source_scanner") or str(
            f.get("source_attribution") or ""
        ).split(":")[0]
        return connector_descriptions.get(key, (key or "recorded", ""))[0]

    def section(heading: str, *flowables: Any) -> Any:
        """Heading kept with its first block — no orphaned section headers."""
        return KeepTogether([Paragraph(heading, h2), *flowables])

    story: list[Any] = []

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.6 * inch))
    story.append(
        Paragraph(
            "FrostGate",
            ParagraphStyle(
                "pf_brand",
                parent=base["Title"],
                fontSize=26,
                textColor=navy,
                alignment=0,
                spaceAfter=2,
            ),
        )
    )
    story.append(
        Paragraph(
            "Security Assessment Report",
            ParagraphStyle(
                "pf_sub",
                parent=base["Normal"],
                fontSize=15,
                leading=19,
                textColor=colors.HexColor("#374151"),
                spaceAfter=10,
            ),
        )
    )
    story.append(
        Table(
            [[""]],
            colWidths=[content_w],
            rowHeights=[2.5],
            style=TableStyle(
                [("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#2563eb"))]
            ),
        )
    )
    story.append(Spacer(1, 0.2 * inch))
    cover_rows = [
        ["Customer organization", esc(client)],
        ["Assessment", esc(f"{title_type} Assessment")],
        ["Engagement ID", esc(report.assessment_id)],
        ["Assessment period", esc(period)],
        ["Report ID", esc(report.report_id)],
        ["Report revision", f"v{report.version}"],
        ["Generated", esc(fmt_ts(report.generated_at))],
        ["Data cut-off", esc(fmt_ts(proof.get("data_cutoff")))],
        ["Classification", "CONFIDENTIAL"],
        ["Report status", f"<b>{esc(marking)}</b>"],
    ]
    story.append(
        table(
            [[p(k, label), p(v)] for k, v in cover_rows],
            [1.7 * inch, content_w - 1.7 * inch],
            header=False,
        )
    )
    story.append(Spacer(1, 0.25 * inch))
    status_note = (
        "This document contains synthetic demonstration data. It is not a customer "
        "assessment, has not completed quality review, and must not be relied upon."
        if synthetic
        else (
            "This document is a draft. It has not completed quality review and "
            "production qualification, and must not be relied upon as a final assessment."
            if is_draft
            else "This revision completed QA approval and production qualification."
        )
    )
    story.append(p(f"<b>Status.</b> {esc(status_note)}", body))
    story.append(Spacer(1, 0.1 * inch))
    story.append(
        p(
            "CONFIDENTIAL — distribution is restricted to authorized personnel of the "
            "customer organization. Findings, evidence references and coverage records "
            "in this document are bound to the report manifest hash shown in the "
            "Verification section.",
            muted,
        )
    )
    story.append(PageBreak())

    # ── Executive summary ───────────────────────────────────────────────────
    total = int(rec.get("included_total") or len(findings))
    confirmed = int(conf.get("CONFIRMED", 0))
    collectors = sorted({s["scanner"] for s in scans})
    collector_names = [
        connector_descriptions.get(c, (c, ""))[0] for c in collectors
    ] or ["none recorded"]
    obs_total = sum(int(s.get("observation_count") or 0) for s in scans)
    story.append(Paragraph("Executive Summary", h1))
    story.append(
        section(
            "Purpose",
            p(
                f"This report records the results of a technical security assessment of "
                f"{esc(client)} performed with FrostGate automated collectors. It states what "
                "was observed, how strongly the stored evidence supports each observation, "
                "and where collection was incomplete.",
                body,
            ),
        )
    )
    story.append(
        section(
            "Scope",
            p(
                f"Collectors: {esc(', '.join(collector_names))}. {len(scans)} scan result(s) "
                f"and {obs_total} recorded observation(s); collection period {esc(period)}.",
                body,
            ),
        )
    )
    story.append(CondPageBreak(1.2 * inch))
    story.append(Paragraph("Key Findings", h2))
    sev_line = ", ".join(
        f"{sev.get(k, 0)} {_SEV_LABEL[k].lower()}"
        for k in ("critical", "high", "medium", "low", "informational")
    )
    if sev.get("unrated"):
        sev_line += f", {sev['unrated']} unrated"
    story.append(p(f"{total} finding(s): {sev_line}.", body))
    top = [f for f in findings if f["severity"] in ("critical", "high")][:6]
    for f in top:
        story.append(
            Paragraph(
                f"<b>{_SEV_LABEL[f['severity']]}</b> — {esc(f['title'])} "
                f"<font color='#4b5563'>({esc(_CONFIDENCE_TEXT.get(f['confidence_effective'], f['confidence_effective']))})</font>",
                bullet,
                bulletText="•",
            )
        )
    story.append(CondPageBreak(1.2 * inch))
    story.append(Paragraph("Material Limitations", h2))
    if limitations:
        story.append(
            p(
                f"Collection was incomplete: {len(limitations)} limitation(s) were recorded. "
                "Absence of findings in areas that were not fully assessed must not be "
                "read as absence of risk.",
                body,
            )
        )
        for code in limitations[:8]:
            story.append(
                Paragraph(esc(_humanize_limitation(code)), bullet, bulletText="•")
            )
        if len(limitations) > 8:
            story.append(
                p(
                    f"{len(limitations) - 8} further limitation(s) are listed in the appendix.",
                    muted,
                )
            )
    else:
        story.append(
            p("No collection limitation was recorded for the recorded scope.", body)
        )
    story.append(
        p(
            f"<b>{esc(cov.get('coverage_statement') or '')}.</b> Coverage percentage: "
            f"{'not determinable' if cov.get('coverage_percentage') is None else cov['coverage_percentage']}"
            f" — {esc(cov.get('coverage_not_determinable_reason') or '')}",
            small,
        )
    )
    crit, high = int(sev.get("critical", 0)), int(sev.get("high", 0))
    if crit or high:
        posture = (
            f"{crit} critical and {high} high severity finding(s) indicate exposure that "
            "warrants prioritized remediation."
        )
    elif total:
        posture = (
            "No critical or high severity finding was recorded in the assessed scope."
        )
    else:
        posture = "No finding was recorded in the assessed scope."
    posture += (
        " This interpretation covers only the recorded scope; it is not a statement "
        "that the environment is free of risk, and it is not a compliance certification."
    )
    story.append(section("Security Posture Interpretation", p(esc(posture), body)))
    story.append(CondPageBreak(1.2 * inch))
    story.append(Paragraph("Remediation Priorities", h2))
    pri = [
        f
        for f in findings
        if f["severity"] in ("critical", "high") and f.get("remediation")
    ][:5]
    if pri:
        for f in pri:
            story.append(
                Paragraph(
                    f"<b>{esc(f['title'])}</b>: {esc(f['remediation'])}",
                    bullet,
                    bulletText="•",
                )
            )
    else:
        story.append(
            p(
                "No remediation guidance was recorded for critical or high findings.",
                body,
            )
        )
    story.append(
        section(
            "Assessment Confidence",
            p(
                f"{confirmed} of {total} finding(s) are CONFIRMED by integrity-checked "
                f"evidence; {total - confirmed} require additional validation (probable, "
                "suspected or unknown confidence). Evidence integrity is checked by SHA-256 "
                "digest only; source authenticity is not cryptographically attested.",
                body,
            ),
        )
    )

    # ── Findings summary ────────────────────────────────────────────────────
    story.append(CondPageBreak(3.2 * inch))
    story.append(Paragraph("Findings Summary", h1))
    order = ["critical", "high", "medium", "low", "informational"]
    if sev.get("unrated"):
        order.append("unrated")
    sev_t = Table(
        [
            [p(_SEV_LABEL[k], th) for k in order] + [p("Total", th)],
            [p(f"<b>{sev.get(k, 0)}</b>", body) for k in order]
            + [p(f"<b>{total}</b>", body)],
        ],
        colWidths=[content_w / (len(order) + 1)] * (len(order) + 1),
    )
    sev_style = [
        ("GRID", (0, 0), (-1, -1), 0.3, grid),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("BACKGROUND", (len(order), 0), (len(order), 0), navy),
    ]
    for i, k in enumerate(order):
        sev_style.append(("BACKGROUND", (i, 0), (i, 0), colors.HexColor(_SEV_HEX[k])))
    sev_t.setStyle(TableStyle(sev_style))
    story.append(sev_t)
    story.append(Spacer(1, 0.12 * inch))
    conf_rows = [[p("Confidence", th), p("Findings", th), p("Meaning", th)]]
    for k in ("CONFIRMED", "PROBABLE", "SUSPECTED", "UNKNOWN"):
        conf_rows.append([p(k), p(str(conf.get(k, 0))), p(esc(_CONFIDENCE_TEXT[k]))])
    story.append(table(conf_rows, [1.4 * inch, 0.9 * inch, content_w - 2.3 * inch]))
    story.append(Spacer(1, 0.12 * inch))
    prov_rows = [[p("Evidence classification", th), p("Findings", th)]]
    for k, v in sorted((proof.get("provenance_counts") or {}).items()):
        prov_rows.append([p(esc(f"{k} — {_PROVENANCE_TEXT.get(k, k)}")), p(str(v))])
    story.append(table(prov_rows, [content_w - 0.9 * inch, 0.9 * inch]))
    assets = sorted({r for f in findings for r in f.get("affected_resources") or []})
    if assets:
        story.append(Spacer(1, 0.08 * inch))
        shown = ", ".join(assets[:30]) + (
            f" (+{len(assets) - 30} more)" if len(assets) > 30 else ""
        )
        story.append(p(f"<b>Affected assets ({len(assets)}):</b> {esc(shown)}", small))
    if rec.get("excluded_total"):
        story.append(
            p(
                f"<b>Excluded from the register:</b> {rec['excluded_total']} finding(s) — "
                + esc(
                    ", ".join(
                        f"{x['finding_id']} ({x['reason']})" for x in rec["excluded"]
                    )
                ),
                small,
            )
        )

    # ── Scope and methodology ───────────────────────────────────────────────
    story.append(CondPageBreak(3.0 * inch))
    story.append(Paragraph("Scope and Methodology", h1))
    m_rows = [
        [
            p("Collector", th),
            p("Method and data accessed", th),
            p("Collection", th),
            p("Observations", th),
        ]
    ]
    for s in scans:
        name, desc = connector_descriptions.get(
            s["scanner"], (s["scanner"], "Recorded scan result.")
        )
        obs = (
            ", ".join(
                f"{v} {k}"
                for k, v in (s.get("observation_status_counts") or {}).items()
            )
            or "—"
        )
        if s.get("targets_not_started"):
            obs += f"; {s['targets_not_started']} not started"
        m_rows.append(
            [
                p(
                    f"<b>{esc(name)}</b><br/><font size='6.5'>{esc(s['scan_result_id'])}</font>"
                ),
                p(esc(desc)),
                p(f"<b>{esc(s['collection_status'])}</b>"),
                p(esc(obs)),
            ]
        )
    if len(m_rows) == 1:
        m_rows.append([p("—"), p("No collection recorded."), p("NOT_ASSESSED"), p("—")])
    story.append(
        table(m_rows, [1.45 * inch, 2.9 * inch, 0.95 * inch, content_w - 5.3 * inch])
    )
    story.append(Spacer(1, 0.08 * inch))
    story.append(p(f"<b>Collection period:</b> {esc(period)}.", small))
    unfinished = cov.get("unfinished_job_ids") or []
    story.append(
        p(
            f"<b>Incomplete assessments:</b> {sum(1 for s in scans if s['collection_status'] != 'COMPLETE')} "
            f"scan(s) did not complete collection; {len(unfinished)} scan job(s) still in progress.",
            small,
        )
    )
    denied = [c for c in limitations if c.endswith(":DENIED")]
    story.append(
        p(
            "<b>Explicit exclusions:</b> "
            + (
                esc("; ".join(_humanize_limitation(c) for c in denied))
                if denied
                else "none recorded"
            )
            + ".",
            small,
        )
    )
    story.append(
        p(
            "<b>Evidence limitations:</b> evidence integrity is checked by SHA-256 digest "
            "against stored records; signatures attesting source authenticity are not "
            "applied. Findings without a captured evidence envelope are shown with "
            "reduced confidence, never as confirmed.",
            small,
        )
    )

    # ── Detailed findings ───────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph(f"Detailed Findings ({total})", h1))
    if not findings:
        story.append(p("No eligible finding was recorded for this engagement.", body))
    for f in findings:
        color = colors.HexColor(_SEV_HEX.get(f["severity"], _SEV_HEX["unrated"]))
        hdr = Table(
            [
                [
                    p(
                        f"{_SEV_LABEL.get(f['severity'], 'Unrated').upper()}  ·  {esc(f['title'])}",
                        th,
                    )
                ]
            ],
            colWidths=[content_w],
            style=TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), color),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ]
            ),
        )
        ev = f.get("evidence") or {}
        conf_txt = _CONFIDENCE_TEXT.get(
            f["confidence_effective"], f["confidence_effective"]
        )
        if (
            f.get("confidence_stored")
            and f["confidence_stored"] != f["confidence_effective"]
        ):
            conf_txt += f" (capped from {f['confidence_stored']})"
        res = f.get("affected_resources") or []
        meta = Table(
            [
                [
                    p("Finding ID", label),
                    p(f"<font name='Courier'>{esc(f['finding_id'])}</font>"),
                    p("Status", label),
                    p(esc(f.get("status"))),
                ],
                [
                    p("Severity", label),
                    p(esc(_SEV_LABEL.get(f["severity"], f["severity"]))),
                    p("Confidence", label),
                    p(esc(conf_txt)),
                ],
                [
                    p("Collection", label),
                    p(esc(f.get("collection_status"))),
                    p("Verification", label),
                    p(
                        esc(
                            _PROVENANCE_TEXT.get(
                                str(ev.get("provenance_status")),
                                str(ev.get("provenance_status")),
                            )
                        )
                    ),
                ],
                [
                    p("Affected", label),
                    p(
                        esc(
                            ", ".join(res[:_AFFECTED_PREVIEW])
                            + (
                                f" (+{len(res) - _AFFECTED_PREVIEW} more, listed below)"
                                if len(res) > _AFFECTED_PREVIEW
                                else ""
                            )
                            if res
                            else "Not recorded"
                        )
                    ),
                    p("Collector", label),
                    p(esc(scanner_name(f))),
                ],
            ],
            colWidths=[
                0.85 * inch,
                content_w / 2 - 0.85 * inch,
                0.85 * inch,
                content_w / 2 - 0.85 * inch,
            ],
        )
        meta.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.3, grid),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f4f6")),
                    ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#f3f4f6")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.append(KeepTogether([hdr, meta]))
        if len(res) > _AFFECTED_PREVIEW:
            # Complete list as paragraph text (splits across pages; every
            # resource preserved).
            story.append(
                dp(f"<b>Affected resources ({len(res)}).</b> {esc(', '.join(res))}")
            )
        story.append(dp(f"<b>Description.</b> {esc(f.get('description'))}"))
        story.append(
            dp(
                f"<b>Risk.</b> Rated {esc(_SEV_LABEL.get(f['severity'], f['severity']).lower())} "
                f"severity by the {esc(scanner_name(f))} rule set. Severity "
                "expresses potential impact and is independent of evidence confidence."
            )
        )
        ev_ids = ev.get("evidence_ids") or []
        ev_txt = (
            ", ".join(ev_ids[:6])
            + (f" (+{len(ev_ids) - 6})" if len(ev_ids) > 6 else "")
            if ev_ids
            else "no evidence envelope"
        )
        srs = ev.get("scan_result_ids") or []
        story.append(
            dp(
                f"<b>Supporting evidence.</b> {esc(ev_txt)}"
                + (f"; scan result {esc(', '.join(srs))}" if srs else "")
                + (
                    f"; authorization proof {esc(ev.get('authorization_proof_level'))}"
                    if ev.get("authorization_proof_level")
                    else ""
                )
                + "."
            )
        )
        story.append(
            dp(
                "<b>Remediation.</b> "
                + esc(
                    f.get("remediation")
                    or "No remediation guidance was recorded for this finding."
                )
            )
        )
        lim = f.get("limitations") or []
        story.append(
            dp(
                "<b>Limitations.</b> "
                + (esc(", ".join(lim)) if lim else "None recorded.")
            )
        )
        story.append(Spacer(1, 0.14 * inch))

    # ── Remediation roadmap ─────────────────────────────────────────────────
    story.append(CondPageBreak(2.5 * inch))
    story.append(Paragraph("Remediation Roadmap", h1))
    story.append(
        p(
            "Recommendations are taken from the recorded finding guidance and grouped by "
            "severity. No cost, deadline or outcome is implied.",
            muted,
        )
    )
    groups = [
        ("Priority 1 — critical and high", ("critical", "high")),
        ("Priority 2 — medium", ("medium",)),
        ("Priority 3 — low and informational", ("low", "informational", "unrated")),
    ]
    rr = [[p("Priority", th), p("Finding", th), p("Remediation", th)]]
    for name, sevs in groups:
        for f in findings:
            if f["severity"] in sevs and f.get("status") not in (
                "remediated",
                "accepted",
            ):
                rr.append(
                    [
                        p(esc(name)),
                        p(
                            f"{esc(_clip(f['title']))}<br/><font name='Courier' size='6.5'>{esc(f['finding_id'])}</font>"
                        ),
                        p(
                            esc(_clip(f.get("remediation") or "Guidance not recorded."))
                            + (
                                " <i>(full text in Detailed Findings)</i>"
                                if len(f.get("remediation") or "") > _CELL_TEXT_LIMIT
                                else ""
                            )
                        ),
                    ]
                )
    if len(rr) == 1:
        rr.append([p("—"), p("No open finding."), p("—")])
    story.append(table(rr, [1.35 * inch, 2.3 * inch, content_w - 3.65 * inch]))

    # ── Evidence and coverage appendix ──────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("Appendix A — Evidence and Coverage", h1))
    idx = proof.get("evidence_index") or {}
    ev_rows = [
        [
            p("Evidence ID", th),
            p("Collector", th),
            p("Observation", th),
            p("Collection", th),
            p("Integrity", th),
        ]
    ]
    for eid, e in idx.items():
        ev_rows.append(
            [
                p(f"<font name='Courier' size='6'>{esc(eid)}</font>"),
                p(esc(e.get("scanner"))),
                p(
                    esc(
                        "scan-level record"
                        if e.get("observation") == "$"
                        else e.get("observation")
                    )
                ),
                p(esc(e.get("collection_status"))),
                p(esc(e.get("provenance_status"))),
            ]
        )
    if len(ev_rows) == 1:
        ev_rows.append(
            [p("—"), p("No evidence envelope captured."), p("—"), p("—"), p("MISSING")]
        )
    story.append(
        table(
            ev_rows,
            [
                2.1 * inch,
                1.0 * inch,
                1.55 * inch,
                0.85 * inch,
                content_w - 5.5 * inch,
            ],
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(Paragraph(f"Coverage limitations ({len(limitations)})", h2))
    if limitations:
        lt = [[p("Recorded limitation", th)]] + [
            [p(f"<font name='Courier' size='7'>{esc(c)}</font>")] for c in limitations
        ]
        story.append(table(lt, [content_w]))
    else:
        story.append(p("None recorded.", small))
    story.append(
        p(
            f"Coverage calculation {esc(cov.get('calculation_version'))}; sources: "
            f"{esc(', '.join(cov.get('data_source') or []))}.",
            muted,
        )
    )

    # ── Verification and QA ─────────────────────────────────────────────────
    story.append(CondPageBreak(3.0 * inch))
    story.append(Paragraph("Verification and Quality Review", h1))
    blockers = state.get("release_blockers") or []
    qa = (
        f"Approved by {state.get('qa_approved_by')} at {fmt_ts(state.get('qa_approved_at'))}"
        if state.get("qa_approved")
        else "Not approved"
    )
    v_rows = [
        ["Report status", f"<b>{esc(marking)}</b>"],
        ["Quality review (QA)", esc(qa)],
        [
            "Production qualification",
            "Qualified" if state.get("production_qualified") else "Not qualified",
        ],
        ["Release blockers", esc(", ".join(blockers)) if blockers else "None"],
        [
            "Finding reconciliation",
            esc(
                f"{rec.get('included_total', 0)} included of {rec.get('eligible_total', 0)} eligible "
                f"({rec.get('persisted_total', 0)} persisted, {rec.get('excluded_total', 0)} excluded); "
                f"{'reconciled' if rec.get('reconciled') else 'NOT reconciled'}"
            ),
        ],
        [
            "Signed report SHA-256",
            f"<font name='Courier' size='7'>{esc(state.get('signed_manifest_hash') or report.manifest_hash)}</font>",
        ],
        [
            "Proof fingerprint",
            f"<font name='Courier' size='7'>{esc(proof.get('proof_fingerprint'))}</font>",
        ],
        ["Evidence checked at", esc(fmt_ts(proof.get("evidence_verified_at")))],
    ]
    story.append(
        table(
            [[p(k, label), p(v)] for k, v in v_rows],
            [1.7 * inch, content_w - 1.7 * inch],
            header=False,
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(
        p(
            "The manifest hash identifies the signed report content. A SHA-256 digest "
            "proves the content is unchanged since generation; it does not by itself prove "
            "who produced it. No compliance certification is expressed or implied.",
            muted,
        )
    )
    return story
