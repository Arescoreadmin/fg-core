# L14 Assessment Report Remediation Backlog

**Generated:** 2026-11-06
**Branch:** audit/l14-field-assessment-report-readiness-001
**Commit:** ab72e44f922e60c48a48259ff32930c15dfb81d5

Prioritized by launch impact. All items ranked by business risk to first paid engagement.

---

## REM-001 [CRITICAL] — Operator Runbook Missing

**Severity:** CRITICAL (blocks first engagement execution)
**Description:** No step-by-step operator runbook exists for the founder/assessor to execute a complete engagement from intake through PDF delivery.
**Root cause:** Development has focused on building the platform; operations documentation has not been written.
**Fix:** Create `docs/ops/ASSESSOR_ENGAGEMENT_RUNBOOK.md` with:
  1. Create engagement via console
  2. Run each scan connector (or import scan results)
  3. Capture interview observations
  4. Generate engagement report: `POST /field-assessment/engagements/{id}/reports`
  5. QA-approve the report
  6. Run production qualification (all 4 gate attestations)
  7. Download PDF: `GET /field-assessment/engagements/{id}/reports/{version}/export?format=pdf`
  8. Deliver to client
  Note: Do NOT use `POST /reports/generate` (Report Authority) — that serves delivery-metadata, not engagement findings.
**Effort:** Small (documentation only, ~4 hours)
**Dependencies:** None
**Acceptance criteria:** A new operator can deliver a complete engagement PDF to a client following the runbook without additional support.

---

## REM-002 [MEDIUM] — Console lacks "Download PDF" button for FA export route

**Severity:** MEDIUM (friction for every engagement delivery, but workaround is a direct API call)
**Description:** The FA-native PDF export route exists at `GET /field-assessment/engagements/{id}/reports/{version}/export?format=pdf` and returns the full engagement findings PDF via `export_pdf_bytes`. The console engagement detail page does not expose a download link for it, requiring the operator to call the route manually.
**Root cause:** Console integration for the FA export endpoint was not completed. Note: `POST /reports/generate` (Report Authority) must NOT be used as a substitute — it serves delivery-metadata, not the engagement findings or domain scores.
**Fix:** Add a "Download Report PDF" button to the field assessment engagement report panel (`apps/console/app/field-assessment/[engagementId]/page.tsx`) that calls `GET /field-assessment/engagements/{id}/reports/{version}/export?format=pdf` with `Content-Type: application/pdf`.
**Effort:** Small (console UI change, ~half day)
**Dependencies:** REM-001 (runbook should describe the button)
**Schema changes:** None
**Acceptance criteria:** Operator can download the FA engagement findings PDF directly from the engagement detail page.

---

## REM-003 [HIGH] — Synthetic seed script does not exist

**Severity:** HIGH (blocks demo preparation and training)
**Description:** No `tools/demo/seed_field_assessment.py` exists. Demo preparation requires manual API calls or direct DB manipulation.
**Root cause:** No demo tooling priority in prior sprints.
**Fix:** Create `tools/demo/seed_field_assessment.py` that:
  1. Guards against non-synthetic environments (`FROSTGATE_SYNTHETIC_DEMO=true` required)
  2. Creates a synthetic tenant with clearly synthetic org name ("Northstar Regional Services — SYNTHETIC")
  3. Creates an engagement with Northstar scenario parameters
  4. Ingests synthetic scan payloads for microsoft_graph, endpoint_inventory, oauth_inventory, dns_email
  5. Creates 15 synthetic observations across all domains
  6. Outputs created engagement_id and evidence counts
  7. Is idempotent (skips creation if engagement already exists for the synthetic tenant)
**Effort:** Large (requires synthetic payload construction, ~1–2 days)
**Dependencies:** None; calls canonical API routes against a running server
**Schema changes:** None
**Acceptance criteria:** Running the script twice produces the same engagement_id; output includes at least 10 findings across 5 domains.

---

## REM-004 [HIGH] — Report Authority / FA-native report systems not bridged

**Severity:** HIGH (quality score discrepancy risk)
**Description:** The FA-native report (`/engagements/{id}/reports`) and the Report Authority report (`/reports/generate`) compute domain scores independently from the same evidence tables. No mechanism synchronizes them or verifies they agree.
**Root cause:** Two independent report generation paths evolved for different use cases; integration was deferred.
**Fix Option A (minimal):** Document in operator runbook that Report Authority report must be generated immediately after FA-native report finalization to minimize divergence.
**Fix Option B (preferred):** Store the FA-native report's domain_scores JSON in the engagement record on report finalization, and pass it to `GenerateReportRequest.branding_config` or a new optional field so the Report Authority engine can use the pre-computed scores rather than recomputing from live evidence.
**Effort:** Medium for Option A (documentation), Large for Option B (schema + engine changes)
**Dependencies:** None
**Schema changes:** Option B would add a `domain_scores` JSON column to the Report Authority report request.
**Acceptance criteria:** The domain scores in the PDF match the domain scores shown in the console engagement summary.

---

## REM-005 [MEDIUM] — Assessment scope has no formal document model

**Severity:** MEDIUM (audit trail gap)
**Description:** There is no "scope agreement" or "scope document" record attached to an engagement. The scope is implicitly encoded in `assessment_type` (enum) plus unstructured `engagement_metadata`.
**Root cause:** Early MVP did not require formal scope documentation.
**Fix:** Add two fields to `FaEngagement`:
  - `scope_description TEXT` — human-readable scope definition
  - `scope_agreed_at TEXT` — ISO 8601 datetime when scope was agreed by client
  Alternatively, allow a `FaFieldObservation` of type `scope_agreement` to serve as the formal record.
**Effort:** Small (migration + API field addition)
**Dependencies:** None
**Schema changes:** YES — adds two nullable columns to `fa_engagements`
**Acceptance criteria:** Engagement detail API response includes scope_description and scope_agreed_at.

---

## REM-006 [MEDIUM] — Executive summary AI backend not verified in staging

**Severity:** MEDIUM (may produce empty/placeholder PDF sections)
**Description:** The `GovernanceReportEngine` executive summary may rely on a live AI model call. If the AI backend is not configured, the executive summary in the PDF may be empty or show placeholder text.
**Root cause:** AI backend configuration is environment-dependent; no test verifies the content quality.
**Fix:** 
  1. Verify in staging that the executive summary generates correctly with a real engagement
  2. Add a fallback narrative template that activates when AI backend returns empty/error
  3. Document the required environment variable (`ANTHROPIC_API_KEY` or equivalent) in the operator runbook
**Effort:** Small (verification + fallback, ~2 hours)
**Dependencies:** Staging environment must be available
**Schema changes:** None
**Acceptance criteria:** A PDF with an empty executive summary is never delivered to a client; a fallback narrative must exist.

---

## REM-007 [MEDIUM] — Visual PDF QA not performed

**Severity:** MEDIUM (unknown rendering quality)
**Description:** No human has reviewed an actual rendered PDF from a real or synthetic engagement. The renderer exists and returns HTTP 200, but visual quality, formatting, and content accuracy have not been verified.
**Root cause:** No synthetic engagement data exists; no staging environment was available during this audit.
**Fix:**
  1. Complete REM-003 (seed script)
  2. Generate a Northstar scenario PDF in staging
  3. Complete the visual QA checklist in `docs/audits/L14_REPORT_VISUAL_QA.md`
  4. Document any rendering issues found
**Effort:** Small once seed script exists (~2 hours)
**Dependencies:** REM-003
**Schema changes:** None
**Acceptance criteria:** All items in `L14_REPORT_VISUAL_QA.md` checklist marked pass/fail with evidence.

---

## REM-008 [LOW] — Assessor ID not validated against identity registry

**Severity:** LOW (acceptable for single-operator OFFER A)
**Description:** The `assessor_id` on a new engagement is a free-form string. Any actor with `assessment.create` permission can claim any assessor_id.
**Root cause:** Intentional design for MVP; assessor authorization delegated to console authentication.
**Fix:** For OFFER B (multi-assessor), add a roster validation endpoint and foreign key reference.
**Effort:** Medium (requires assessor roster model)
**Dependencies:** Multi-assessor scenario authorization design
**Schema changes:** YES — adds assessor roster table
**Acceptance criteria:** Creating an engagement with an unrecognized assessor_id returns 422 (optional, OFFER B only).

---

## REM-009 [LOW] — No "send report to client" delivery workflow in console

**Severity:** LOW (manual workaround exists for OFFER A)
**Description:** There is no "Send Report to Client" action in the engagement console that triggers email delivery of the PDF to the client organization. The PDF download exists but the assessor must download and deliver manually.
**Root cause:** The governed delivery service was built for portal-based activation (email → portal), not for assessor-hands-off delivery.
**Fix:** Add a "Send PDF to Client" action that calls the governed delivery service to email the PDF bundle to the client contact on record. Requires client email to be captured at engagement creation.
**Effort:** Large (delivery workflow, email template, tracking)
**Dependencies:** Client email field on engagement, email delivery service configured
**Schema changes:** Adds client_email to fa_engagements
**Acceptance criteria:** Clicking "Send to Client" triggers a secure email with PDF bundle link; delivery event logged to fa_governed_delivery_attempts.

---

## Priority Matrix

| ID | Severity | Effort | Launch Impact | Do First? |
|----|----------|--------|---------------|-----------|
| REM-001 | CRITICAL | Small | Maximum | Yes |
| REM-002 | HIGH | Medium | High | Yes |
| REM-003 | HIGH | Large | High | Next sprint |
| REM-004 | HIGH | Medium | Medium | Next sprint |
| REM-005 | MEDIUM | Small | Medium | Yes (small) |
| REM-006 | MEDIUM | Small | Medium | Yes (small) |
| REM-007 | MEDIUM | Small | Medium | Unblocked by REM-003 |
| REM-008 | LOW | Medium | Low | OFFER B only |
| REM-009 | LOW | Large | Low | OFFER B only |
