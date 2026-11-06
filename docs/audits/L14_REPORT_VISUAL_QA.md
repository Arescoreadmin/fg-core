# L14 Report Visual QA Audit

**Generated:** 2026-11-06
**Branch:** audit/l14-field-assessment-report-readiness-001

---

## 1. PDF Export Capability Status

**Status: IMPLEMENTED — Visual QA NOT YET EXECUTED**

The PDF export capability exists and is functionally reachable. It has not been visually reviewed in this audit.

---

## 2. PDF Renderer

**File:** `services/report_authority/renderer_pdf.py`
**Library:** ReportLab (confirmed available via `api/config/startup_validation.py` line 1099: `import reportlab`)
**Route:** `GET /reports/{report_id}/download/pdf`

The renderer uses `BaseDocTemplate` with page templates, `Paragraph`, `Table`, `HRFlowable`, `PageBreak`, and `Spacer` flowables. Brand colors:
- Primary: `#1a3a5c` (dark navy)
- Accent: `#2980b9` (FrostGate blue)
- Light: `#f0f4f8` (background)
- Page size: A4
- Margins: 2.5cm

**Sections in a rendered PDF** (inferred from renderer structure):
1. Cover page — report title, assessor_id, date, tenant
2. Table of contents
3. Executive summary
4. Domain health scores (table)
5. Findings list (severity-sorted table)
6. Evidence appendix
7. Control appendix (framework mappings)
8. Trust appendix (signing metadata)

---

## 3. HTML Renderer

**File:** `services/report_authority/renderer_html.py`
**Route:** `GET /reports/{report_id}/download/html`

HTML rendering also exists. The HTML output is suitable for in-browser preview or print-to-PDF fallback.

---

## 4. Bundle ZIP

**File:** `services/report_authority/export.py` → `build_export_bundle`
**Route:** `GET /reports/{report_id}/bundle/download`

The bundle contains:
- `report-{id}.pdf` — ReportLab PDF
- `report-{id}.html` — HTML
- `report-{id}.json` — canonical JSON
- `manifest.json` — cryptographic manifest with Merkle root, transparency_root, hashes

---

## 5. What a Visual QA Must Check

The following checklist must be completed by a human reviewer with an actual rendered PDF from a real (or synthetic) engagement:

### Cover Page
- [ ] Organization name appears correctly
- [ ] Assessment date is accurate
- [ ] Assessor name/ID is legible
- [ ] FrostGate logo/branding appears
- [ ] "CONFIDENTIAL" or appropriate classification marker appears

### Executive Summary
- [ ] AI-generated narrative is coherent and accurate
- [ ] Risk band (critical/high/medium/low) is prominently displayed
- [ ] Overall score (0–100) appears with correct value
- [ ] No placeholder text or error messages visible

### Domain Health Scores
- [ ] All 7 domains appear with their scores
- [ ] Color coding reflects severity (red/amber/green or similar)
- [ ] Weighted aggregate score is consistent with domain scores

### Findings Section
- [ ] All findings from the engagement appear (count matches API response)
- [ ] Severity indicators are visually distinct
- [ ] Finding descriptions are readable (not truncated)
- [ ] Framework mapping references appear (NIST AI RMF, etc.)
- [ ] Remediation hints are present for each finding

### Evidence Appendix
- [ ] Evidence sources listed with collection dates
- [ ] Provenance chain indicator present
- [ ] Artifact types identified correctly

### Technical Sections
- [ ] Control appendix lists mapped controls per framework
- [ ] Trust appendix shows report hash and signing metadata
- [ ] Page numbers are correct on all pages
- [ ] No blank pages in middle of document

### Format
- [ ] PDF is searchable (text layer, not image scan)
- [ ] All fonts embedded
- [ ] File size is reasonable (< 5MB for standard report)
- [ ] PDF opens without errors in Acrobat, Chrome, and Preview

---

## 6. Known Risks to Visual Quality

### Risk 1: Executive Summary AI Backend
The `GovernanceReportEngine` executive summary section may invoke an AI model for narrative generation. If the AI backend (Claude API) is not configured in the environment, the executive summary section may:
- Be empty
- Contain a placeholder string
- Raise an exception caught by the renderer and replaced with a default message

**Verification needed:** Run one engagement in staging with AI backend configured; verify executive summary content in rendered PDF.

### Risk 2: Long Findings Lists
If an engagement has more than ~30 findings, the findings table may overflow across pages. The ReportLab renderer uses dynamic `Table` flowables which should handle pagination, but this has not been visually verified.

### Risk 3: Long Text Truncation
Finding descriptions and remediation hints may be truncated if they exceed the ReportLab `Paragraph` width limits. The renderer should use `word_wrap=True` equivalents but this was not inspected in detail.

### Risk 4: Domain Score Computation Discrepancy
The FA-native report (`/engagements/{id}/reports`) and the Report Authority report (`/reports/generate`) compute domain scores independently. The PDF renders the Report Authority version. If these two systems produce different scores for the same engagement, the PDF and the console report view will be inconsistent.

---

## 7. Status: BLOCKED (Visual Verification)

Visual PDF QA is blocked because:
1. No running API server is available in this audit environment
2. No synthetic engagement data exists (seed script not yet created)
3. PDF rendering requires a live database with engagement data

**Unblock path:**
1. Create Northstar synthetic scenario via seed script (P2 task)
2. Run `POST /reports/generate` with the synthetic engagement_id
3. Call `GET /reports/{id}/download/pdf`
4. Review the rendered PDF against the checklist above
5. Document pass/fail per line item
