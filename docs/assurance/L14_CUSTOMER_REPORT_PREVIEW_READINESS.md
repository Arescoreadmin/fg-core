# L14 Customer Report Preview Readiness (Customer-Zero Synthetic Preview)

> **Update — L14-CUSTOMER-ZERO-E2E-001.** A full synthetic customer journey (provisioning → portal) is now exercised. See `L14_CUSTOMER_ZERO_E2E_ACCEPTANCE.md` for the acceptance matrix and launch blockers.
>
> **Update — L14-SCAN-REPORT-PROOF-001.** The preview was regenerated from a deterministic synthetic fixture, through the same routes and the upgraded canonical renderer. It is now a 10-page PDF with 14 of 14 findings rendered. Coverage is disclosed with no percentage. Evidence classifications and capped confidence are shown, and every page carries `DRAFT — SYNTHETIC DATA — NOT VERIFIED`. **Verdict: READY for internal draft review; it must not be delivered as a verified assessment** (synthetic data blocks release by design). §11 records the defect resolution. The sections below describe the original PR #813 preview.

**Verdict: PARTIAL.** A synthetic preview PDF **was generated** through existing routes in an isolated SQLite environment. However, the PDF does not render the scanner findings by severity, hides collection limitations, and makes unsupported "verified" and compliance claims. It is fit for internal visual QA. It is **not** fit to show a customer as representative of a verified assessment.

**Scope:** discovery plus one safe demonstration (L14-SCAN-RUNNER-INTEGRITY-001 addendum). There is no new renderer, report API, provisioning or QA bypass. Every artifact is **DRAFT / SYNTHETIC / NOT VERIFIED**.

## 1. Existing reporting architecture

| Layer | Canonical implementation |
|---|---|
| Report generation | `POST /field-assessment/engagements/{id}/reports` (`create_engagement_report_route`, `report.generate`). It builds `report_json` via `_build_engagement_report_json`, signs it (`FG_REPORT_SIGNING_KEY` / trust binding), and versions it. |
| Report JSON content | `findings` (derived governance domain gaps), `normalized_findings` (scanner findings), `remediations`, `evidence_appendix`, `framework_summary`, `confidence`, `executive_summary` (advisory AI narrative), `result_truth_gate`, `production_qualification` |
| Export / render | `GET …/reports/{version}/export?format=json\|pdf` (`report.read`). It verifies the signature and enforces trust before rendering. The PDF comes from `services/governance/report/serialization.export_pdf_bytes` (ReportLab). |
| Second PDF stack | `services/report_authority/renderer_pdf.py` (`api/report_exports.py`). It is the governance-report authority and not used by the engagement export. |
| QA and release | `…/reports/{id}/qa-approve`, `/qualify/*`, `/versions/*/submit-for-review → approve → deliver`, `/governed-delivery`. Previewing does not need any of them; the export works on an unapproved version. |
| Portal | Governed delivery and portal grants. Not exercised. |

## 2. Existing seed utilities

- `scripts/seed_demo_decisions.sh`, `scripts/demo.sh`: seed the *decision/event* plane of a running stack. They seed no Field Assessment data.
- `customer_one/*.json`: ceremony and cost-authorization evidence. These are not engagement fixtures.
- There is **no** canonical Field Assessment seed command. The closest supported path is the `build_app` test fixture (isolated SQLite). It is used throughout `tests/test_field_assessment_reports.py`.

## 3. Synthetic seed requirements (and what the demo used)

| Item | Demo implementation |
|---|---|
| Company identity | Engagement client name `SYNTHETIC DEMO - Northwind Analytics (NOT A REAL CUSTOMER)` |
| Tenant and assessor | Tenant `tenant-synthetic-preview`; API-key credential with the `analyst` role (canonical `issue_credential` + `assign_role`) |
| Customer administrator | **Not created.** The SQLite path can't hold #812 customer receipts (Postgres-only SQL), and none was fabricated. |
| Scope and observations | Synthetic web, DNS and network payloads persisted through the **production bridges** (`import_web_headers_scan`, `import_dns_email_scan`, `import_network_scan`). No scanning. |
| Severity mix | 2 critical, 3 high, 4 medium, 3 low, 2 informational. Verified from persisted findings. |
| Incomplete and denied collection | Web scan PARTIAL with a DENIED target; DNS domain TIMEOUT; network scan CANCELLED (interrupted) |
| Unknown confidence | All findings. No runtime evidence capture, because no authorization context exists to attribute. |
| Evidence envelopes | **Not created**, deliberately. Creating them would require fabricating an `authorization_context`. |
| Remediation roadmap / executive summary | Whatever the existing builder derives |

## 4. Canonical generation commands

```
FG_REPORT_PREVIEW_OUT=<dir> FG_ENV=test .venv/bin/pytest -q tests/test_report_preview/test_synthetic_report_preview.py
```

The test calls the real routes, in order:

1. `POST /field-assessment/engagements`
2. Bridges, for the synthetic findings
3. `GET /field-assessment/engagements/{id}/findings`
4. `POST /field-assessment/engagements/{id}/reports` with `{"report_type":"full_assessment"}`
5. `GET /field-assessment/engagements/{id}/reports/{v}/export?format=json`
6. `GET /field-assessment/engagements/{id}/reports/{v}/export?format=pdf`

The test also runs in CI without the env var. It asserts that the pipeline renders a valid PDF of at least 2 pages that contains the SYNTHETIC marker.

## 5. Preview readiness matrix

| Capability | Status | Evidence |
|---|---|---|
| Cover page | READY | Page 1: client, report id, version, manifest hash, confidentiality notice |
| Executive summary | PARTIAL | Advisory AI narrative only. It states "verified critical governance deficiency" although nothing is reviewer-validated, and it leaves most of page 2 empty. |
| Overall risk presentation | PARTIAL | A "CRITICAL RISK" badge derived from one domain gap |
| Findings by severity | **BLOCKED** | The PDF renders `findings` (1 derived `data_governance` gap). The 14 scanner findings exist in JSON `normalized_findings` but **are not rendered**. |
| Finding confidence | PARTIAL | A numeric `0.760` score only. Canonical labels (CONFIRMED…UNKNOWN) are not rendered, and `normalized_findings` doesn't serialize `confidence_level`. |
| Evidence references | PARTIAL | The appendix lists 3 scan results as "validated". There are no per-finding evidence ids and no envelope or integrity status. |
| Assessment scope | NOT_IMPLEMENTED | No scope section (targets, operations, window) |
| Collection limitations | **BLOCKED** | PARTIAL, DENIED, TIMEOUT and CANCELLED collection are not shown. "Evidence Completeness 100%" and "Control Coverage 100%" are displayed, and `result_truth_gate.decision=PASS`. |
| Remediation recommendations | PARTIAL | One row for the derived gap. Per-finding remediation hints are not rendered. |
| Appendices | PARTIAL | Evidence appendix, data-collection disclosure, verification hash |
| Verification / QA status | PARTIAL | "Reviewer Validated: No" appears, but there is **no DRAFT / NOT VERIFIED banner or watermark**. `production_qualification=NOT_REQUESTED` is not shown. |
| Pre-QA internal render | READY | Export works on an unapproved version; delivery routes are separate and were not called |

## 6. Demonstrated output

| Item | Value |
|---|---|
| Artifact | `synthetic_report_preview.pdf`, 9,763 bytes, 4 pages, valid `%PDF-` header, parsed with `pypdf` |
| Companion files | `.json` export, extracted text, `preview_meta.json` |
| Location (this session) | `/tmp/claude-1000/-home-jcosat-Projects-fg-core/e16059a2-ebcc-4cec-bef9-87b7ff86e0b7/scratchpad/report_preview/`. Not committed; regenerate with §4. |
| Persisted findings | critical 2, high 3, medium 4, low 3, informational 2 |
| Rendered findings | 1 |

## 7. Preview limitations

- SQLite only, so no customer receipts or runtime evidence envelopes. The report can't show authorization provenance or evidence integrity even once rendering supports them.
- The manifest signature uses a test signing key.
- Synthetic marking relies only on the client name. The renderer has no draft or synthetic flag.

## 8. Visual-QA defect inventory (observed in the generated PDF)

| # | Defect | Severity |
|---|---|---|
| V-1 | Scanner findings (14) not rendered; only 1 derived gap shown | Critical |
| V-2 | Collection limitations hidden; "Evidence Completeness 100%" and "Control Coverage 100%" despite partial, denied, timed-out and cancelled collection; truth gate PASS | Critical |
| V-3 | Unsupported "verified" claim in the executive summary | High |
| V-4 | Compliance mappings (SOC 2, CMMC, HIPAA) presented for a scanner-only synthetic assessment; reads as compliance coverage | High |
| V-5 | No DRAFT / NOT VERIFIED / SYNTHETIC banner or watermark | High |
| V-6 | Canonical confidence labels absent; numeric score only | Medium |
| V-7 | No per-finding evidence ids or integrity status; appendix says "validated" for incomplete scans | Medium |
| V-8 | Footer overlap: a long client name collides with the hash text ("…NortSHA-256…") on every page | Medium |
| V-9 | Data Collection Disclosure table header text nearly invisible (dark text on a dark header) | Medium |
| V-10 | Large empty regions (page 1 lower half, most of page 2) | Low |
| V-11 | Raw ISO timestamp with microseconds on the cover | Low |
| V-12 | "Redaction: strict" and "90-day retention" stated as fact without being derived from engagement configuration | Medium (claim accuracy) |
| V-13 | Duplicated header label "data_governance · data_governance" | Low |
| V-14 | No assessment scope or limitations section | High |

## 9. Missing dependencies

1. A PDF renderer path for `normalized_findings`, grouped by severity, with confidence label, collection status, evidence ids and remediation hint.
2. Finding serialization of `confidence_level`, `collection_status` and `evidence_envelope_id` (columns now mapped by this PR).
3. Consumption of `runtime_evidence.build_evidence_manifest()` report constraints: coverage limitations, no full-coverage claim, no authenticated-evidence claim.
4. A draft-status banner sourced from QA and `production_qualification` state.
5. A result-truth gate that accounts for collection status.
6. A Postgres-backed synthetic environment for receipts and envelopes. Any approach needs explicit approval because of the database safety rules.

## 10. Smallest next step to a first credible preview

**L14-SCAN-REPORT-PROOF-001**, scoped to the export path. It should:
- render `normalized_findings` by severity with canonical confidence labels;
- serialize the new finding columns;
- render coverage limitations and report constraints from the manifest;
- add a DRAFT/NOT VERIFIED banner whenever the version is not QA-approved and production-qualified;
- fix footer truncation (V-8) and header contrast (V-9).

**Effort basis:** all inputs already exist in persisted data (JSON `normalized_findings` = 14; the manifest builder exists and is tested). The work is confined to `export_pdf_bytes`, finding serialization, and the report builder's truth-gate inputs. It needs no migration, no new route and no new tenant tooling. The existing preview test (§4) becomes the regression harness. A reasonable estimate is about 2–3 engineering days including tests. That estimate assumes no design changes to page layout beyond V-8 and V-9.


## 11. Defect resolution (L14-SCAN-REPORT-PROOF-001)

| # | Resolution |
|---|---|
| V-1 | **Fixed.** The proof renders all eligible persisted findings (14/14), reconciled against an independent read. Root cause: the PDF rendered the engine's derived domain gaps. |
| V-2 | **Fixed.** Coverage comes from persisted collection status. Every non-COMPLETE scan, observation and job is disclosed, and the percentage reads "not determinable". The truth gate FAILs on proof blockers. |
| V-3 | **Fixed in the PDF.** A deterministic executive summary is rendered; the advisory AI narrative is not. The JSON narrative is unchanged (see `L14_SCAN_REPORT_PROOF.md` §17). |
| V-4 | **Fixed.** Framework compliance mappings are not rendered in proof mode. |
| V-5 | **Fixed.** An authoritative marking band appears on every page, plus a draft watermark and footer marking. |
| V-6 | **Fixed.** Canonical confidence labels are shown, including "capped from" when the evidence is insufficient. |
| V-7 | **Fixed.** Per-finding evidence ids and classification, plus an evidence appendix with integrity status. |
| V-8 | **Fixed.** Two-line measured footer with Page X of Y and no client name. A geometry test asserts there is no overlap. |
| V-9 | **Fixed.** Table headers are white bold on navy. |
| V-10 | **Improved.** Sections flow with conditional page breaks. The cover's lower half is intentionally sparse. |
| V-11 | **Fixed.** Timestamps are formatted `YYYY-MM-DD HH:MM UTC`. |
| V-12 | **Fixed.** The retention and redaction statements are not rendered in proof mode. |
| V-13 | **Fixed.** Finding headers show severity and title. |
| V-14 | **Fixed.** A Scope and Methodology section covers collectors, methods, collection, observations, exclusions and incomplete assessments. |

Regenerate with:

```
FG_REPORT_PREVIEW_OUT=<dir> FG_ENV=test .venv/bin/pytest -q tests/test_report_preview/
```

This writes the PDF, JSON, text, one PNG per page and the metadata file.
