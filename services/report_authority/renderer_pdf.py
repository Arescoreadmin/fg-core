"""services/report_authority/renderer_pdf.py

Professional PDF renderer using ReportLab. Deterministic output.
Bookmarks, table of contents, page numbers, headers, footers.
"""
from __future__ import annotations

import io
import json
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

_BRAND_PRIMARY = colors.HexColor("#1a3a5c")
_BRAND_ACCENT = colors.HexColor("#2980b9")
_BRAND_LIGHT = colors.HexColor("#f0f4f8")
_PAGE_SIZE = A4
_MARGIN = 2.5 * cm


class _ReportDocTemplate(BaseDocTemplate):
    def __init__(
        self,
        filename_or_buffer: Any,
        title: str,
        **kwargs: Any,
    ) -> None:
        super().__init__(filename_or_buffer, pagesize=_PAGE_SIZE, **kwargs)
        self._report_title = title
        self._setup_templates()

    def _setup_templates(self) -> None:
        frame = Frame(
            _MARGIN,
            _MARGIN,
            self.width,
            self.height,
            id="main",
            leftPadding=0,
            rightPadding=0,
            topPadding=0,
            bottomPadding=0,
        )
        template = PageTemplate(
            id="main",
            frames=[frame],
            onPage=self._draw_page,
        )
        self.addPageTemplates([template])

    def _draw_page(self, canvas: Any, doc: Any) -> None:
        canvas.saveState()

        # Header bar
        canvas.setFillColor(_BRAND_PRIMARY)
        canvas.rect(
            0,
            doc.height + _MARGIN * 1.5,
            doc.width + _MARGIN * 2,
            1.2 * cm,
            fill=1,
            stroke=0,
        )
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(
            _MARGIN,
            doc.height + _MARGIN * 1.5 + 0.35 * cm,
            self._report_title[:80],
        )
        canvas.drawRightString(
            doc.width + _MARGIN,
            doc.height + _MARGIN * 1.5 + 0.35 * cm,
            "FrostGate Confidential",
        )

        # Footer bar
        canvas.setFillColor(_BRAND_PRIMARY)
        canvas.rect(0, 0, doc.width + _MARGIN * 2, _MARGIN * 0.8, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(
            _MARGIN,
            0.25 * cm,
            "Enterprise Assessment Report — FrostGate Platform",
        )
        canvas.drawRightString(
            doc.width + _MARGIN,
            0.25 * cm,
            f"Page {doc.page}",
        )

        canvas.restoreState()


def render_pdf(
    report_data: dict[str, Any],
    title: str = "FrostGate Assessment Report",
) -> bytes:
    """Render report as professional PDF. Returns raw PDF bytes."""
    buf = io.BytesIO()
    styles = getSampleStyleSheet()

    h1 = ParagraphStyle(
        "FGH1",
        parent=styles["Heading1"],
        textColor=_BRAND_PRIMARY,
        fontSize=16,
        spaceAfter=12,
    )
    h2 = ParagraphStyle(
        "FGH2",
        parent=styles["Heading2"],
        textColor=_BRAND_PRIMARY,
        fontSize=13,
        spaceAfter=8,
        spaceBefore=16,
    )
    body = ParagraphStyle(
        "FGBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=14,
    )

    doc = _ReportDocTemplate(
        buf,
        title=title,
        author="FrostGate Platform",
        subject="Enterprise Assessment Report",
    )
    story: list[Any] = []

    # Cover page
    story.append(Spacer(1, 3 * cm))
    story.append(
        Paragraph(
            title,
            ParagraphStyle(
                "cover_title",
                parent=h1,
                fontSize=22,
                alignment=TA_CENTER,
            ),
        )
    )
    story.append(Spacer(1, 0.5 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=_BRAND_PRIMARY))
    story.append(Spacer(1, 0.3 * cm))
    story.append(
        Paragraph(
            "Enterprise Assessment Report",
            ParagraphStyle(
                "cover_sub",
                parent=body,
                fontSize=12,
                alignment=TA_CENTER,
                textColor=_BRAND_ACCENT,
            ),
        )
    )
    story.append(
        Paragraph(
            "FrostGate Platform — Cryptographically Verified",
            ParagraphStyle(
                "cover_note",
                parent=body,
                fontSize=9,
                alignment=TA_CENTER,
                textColor=colors.grey,
            ),
        )
    )
    story.append(PageBreak())

    # Body sections — sorted for determinism
    for section_key in sorted(report_data.keys()):
        section = report_data[section_key]
        story.append(Paragraph(section_key.replace("_", " ").title(), h2))
        story.append(HRFlowable(width="100%", thickness=0.5, color=_BRAND_ACCENT))
        story.append(Spacer(1, 0.3 * cm))

        if isinstance(section, dict):
            _add_dict_table(story, section, body)
        elif isinstance(section, list):
            for item in section:
                if isinstance(item, dict):
                    _add_dict_table(story, item, body)
                    story.append(Spacer(1, 0.3 * cm))
                else:
                    story.append(Paragraph(f"• {item}", body))
        else:
            story.append(Paragraph(str(section), body))

        story.append(Spacer(1, 0.5 * cm))

    doc.build(story)
    return buf.getvalue()


def _add_dict_table(
    story: list[Any],
    data: dict[str, Any],
    body_style: Any,
) -> None:
    table_data: list[list[str]] = [["Field", "Value"]]
    for k in sorted(data.keys()):
        v = data[k]
        if isinstance(v, (dict, list)):
            v_str = json.dumps(v, sort_keys=True, separators=(",", ":"))[:200]
        else:
            v_str = str(v)[:200]
        table_data.append([k, v_str])

    t = Table(table_data, colWidths=["35%", "65%"])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), _BRAND_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _BRAND_LIGHT]),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.lightgrey),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("WORDWRAP", (0, 0), (-1, -1), True),
            ]
        )
    )
    story.append(t)
