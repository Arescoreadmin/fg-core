# L14-SCAN-REPORT-PROOF-001 — Report Completeness, Coverage Truth, Evidence Proof and Draft Rendering

**Verdict: PARTIAL.**

What this PR enforces:
- The canonical engagement report now renders every eligible persisted finding.
- Coverage is reported only from persisted collection data, never as an invented percentage.
- Each finding carries its re-verified evidence classification and evidence-capped confidence.
- Every page shows an authoritative DRAFT / FINAL marking.
- Release now enforces the findings, evidence and coverage proof.

What it does not do:
- Independent QA (FVA-05) is not implemented. QA approval exists, but there is no reviewer-qualification or conflict-of-interest enforcement (L14-ASSESSMENT-ASSURANCE-001).
- Evidence provenance is integrity-only (L14-SCAN-VAULT-001).
- There is no correction or dispute workflow (FVA-06 remains partial).

Predecessors: #811 (collection status), #812 (scan authorization), #813 (runtime evidence and manifest).

---

## 1. Canonical reporting authority

There is no new report authority. The lifecycle is unchanged:

| Stage | Canonical owner | Change in this PR |
|---|---|---|
| Generate | `POST /field-assessment/engagements/{id}/reports` → `_build_engagement_report_json` | Adds the signed `report_proof` section (`services/field_assessment/report_proof.py`). Finding serialization gains `confidence_level`, `verification_method`, `collection_status`, `evidence_envelope_id`, `remediation_hint`, `asset_id`. |
| Truth gate | `services/governance/report/result_truth_gate.evaluate_result_truth_gate` | Consumes `report_proof.release_blockers` (`REPORT_PROOF_BLOCKED:<code>`). The proof fingerprint is bound into `result_fingerprint`. |
| Export | `GET …/reports/{v}/export?format=json\|pdf` | Derives `report_state` (marking) from authoritative state. The PDF is rendered from the proof. |
| PDF renderer | `services/governance/report/serialization.export_pdf_bytes` (single entry point) | Uses `pdf_layout.py` for page decoration and proof sections. The legacy path keeps its sections but gains the same band and footer. |
| QA approve | `…/reports/{id}/qa-approve` | Unchanged. |
| Qualification | `…/qualify/*` (truth gate must PASS) | Fails automatically when proof blockers exist. |
| Delivery | `_require_production_qualified` (versioned deliver and governed delivery) | Requires the proof, no blockers, and evidence that re-verifies unchanged. |

`services/report_authority/renderer_pdf.py` (governance-report authority) is not the engagement export path and is unchanged.

## 2. Finding reconciliation (root cause of "14 findings → 1 gap")

**Root cause.** The PDF rendered `report.findings`. Those are the `GovernanceReportEngine`'s *derived domain gaps*: findings are collapsed into domain health scores (minimum per domain), and one domain produced one gap. The 14 persisted `fa_normalized_findings` existed only in the JSON `normalized_findings` section and were never rendered. Nothing in the query was wrong: `list_findings` pages deterministically (`created_at, id`), 100 at a time.

**Fix.** `build_report_proof` takes the builder's paginated read and reconciles it against an **independent** read: the evidence manifest's own `fa_normalized_findings` query.

- **Eligible:** every persisted finding for the (tenant, engagement).
- **Explicit exclusion rule:** only `status = false_positive` is excluded. It is listed with reason `FALSE_POSITIVE_DISPOSITION` and counted.
- **Preserved fields:** id, title, severity (normalized `info`→`informational`; unknown → `unrated`, never dropped), status, description, affected resources, remediation, evidence reference, collection status, limitations.
- **Ordering:** severity rank, then finding id (deterministic).
- **Release blockers:**
  - `FINDING_RECONCILIATION_MISMATCH`: the two reads disagree, e.g. a pagination defect.
  - `DUPLICATE_FINDING_IDENTITY`.
  - `CROSS_SCOPE_FINDING_REFERENCE`.
  - `FINDING_NOT_IN_EVIDENCE_MANIFEST`.
- **No deduplication by content.** Distinct ids with identical titles are both rendered (test-proven). Identity is the bridges' deterministic finding id.
- **No silent removal.** A finding with missing or invalid evidence is rendered with its classification and limitations.

## 3. Coverage calculation

**Root cause of the false "100%".** The PDF showed the report engine's `evidence_completeness` and `control_coverage` ratios. Those are computed over evidence refs that the builder marks `VALIDATED` unconditionally, with no awareness of collection status. The truth gate validated lineage only, so it said PASS.

**Fix (`fg.coverage.persisted_collection_status.v1`).** Sources:
- `fa_scan_results.raw_payload.collection_status`, per scan;
- per-observation status (hosts, domains, targets) via `runtime_evidence.extract_observations`;
- interrupted-scan `remaining_targets_not_started`;
- `fa_scan_jobs.status`, where non-complete jobs are limitations and queued/running jobs block release (`SCAN_JOBS_IN_PROGRESS`);
- the evidence manifest's limitations (`EVIDENCE_NOT_CAPTURED`).

Every non-COMPLETE status is a recorded limitation: PARTIAL, DENIED, TIMEOUT, FAILED, CANCELLED, TRUNCATED, UNKNOWN and NOT_ASSESSED. A missing status is UNKNOWN and is never treated as complete. No collection at all gives `NOT_ASSESSED`.

**No percentage.** No persisted authorized-scope inventory supplies an eligible denominator. `coverage_percentage` is therefore always `null`, `coverage_determinable` is `false`, and the PDF prints "Coverage percentage: not determinable", followed by the reason. `may_claim_full_coverage` requires all of:
- at least one scan;
- no limitations;
- the manifest's own full-coverage constraint.

Coverage limitations never downgrade a validly observed finding. A finding's confidence comes from its own observations (#813).

## 4. Evidence verification

The proof calls `runtime_evidence.build_evidence_manifest` (#813), which re-verifies every envelope digest against the stored payload at assembly time. The manifest now also returns `evidence_integrity` (envelope → status), so nothing is recomputed. Per-finding classifications:
- `VERIFIED_AUTHENTIC` (never produced today; Vault is not wired);
- `VERIFIED_INTEGRITY_ONLY`;
- `UNVERIFIED`;
- `MISSING`;
- `INVALID`;
- `INDETERMINATE`.

The PDF wording keeps integrity separate from authenticity: "Integrity verified (SHA-256); source not authenticated". `may_claim_authenticated_evidence` stays false.

Manual and legacy findings keep their `evidence_ref_ids` (scan-result ids). They are shown as supporting records with classification `MISSING` (no envelope) rather than being rejected.

## 5. Confidence rules

No new rules. Effective confidence is the manifest's `_cap_confidence`, and severity is never modified:

- INVALID or MISSING evidence caps confidence at SUSPECTED.
- INDETERMINATE or UNVERIFIED evidence caps it at PROBABLE.
- A legacy NULL confidence gives UNKNOWN, with the limitation `CONFIDENCE_UNCLASSIFIED`.

`CONFIRMED_WITHOUT_VERIFIED_EVIDENCE` is a defensive release blocker. The executive summary separates "CONFIRMED by integrity-checked evidence" from "require additional validation".

## 6. Draft rendering

`report_proof.evaluate_report_state` takes no caller-controlled input. The export route passes the stored record's QA fields, the existence of a QUALIFIED decision, and the signed proof. Evidence is re-verified at export time.

| Condition | State | Marking |
|---|---|---|
| Any synthetic source (payload `synthetic: true` or a `SYNTHETIC*` proof level) | `DRAFT_SYNTHETIC` | `DRAFT — SYNTHETIC DATA — NOT VERIFIED` |
| Not QA-approved, not qualified, or any release blocker (including `REPORT_PROOF_MISSING`, `EVIDENCE_CHANGED_SINCE_GENERATION`) | `DRAFT` | `DRAFT — NOT VERIFIED` |
| QA-approved and qualified, no blockers, limitations recorded | `FINAL` | `FINAL — QA APPROVED — LIMITED COVERAGE` |
| As above, full recorded coverage | `FINAL` | `FINAL — QA APPROVED` |

Each page carries the marking in a status band inside the top margin, so it never overlaps body content. Draft pages also get a light (10% alpha) diagonal "DRAFT" watermark, and the marking is repeated in the footer. Unknown query parameters (`draft=false`, `marking=FINAL`) are ignored (test-proven). The JSON export returns `report_state`, and the PDF response carries an `X-Report-State` header.

## 7. PDF layout standards

- Decorations are drawn by a page-count-aware canvas (`pdf_layout.make_decorated_canvas`), giving "Page X of Y" without hardcoding.
- **Footer:**
  - Line 1: FrostGate · Report id · CONFIDENTIAL | Page X of Y.
  - Line 2: Revision · marking | SHA-256 prefix.
  - The right column is measured first, and the left text is truncated to the remaining width, so the two can't overlap. The client name was removed from the footer; it caused defect V-8.
- All scanner-sourced text is XML-escaped. Long tokens are soft-wrapped at `:` and `/` boundaries.
- **Page breaks:**
  - Finding header and metadata are kept together, and the long description and remediation flow across pages.
  - Section headings are kept with their first block, so there are no orphaned headers.
  - Tables repeat their header row.
- Sections, in order:
  1. Cover
  2. Executive Summary: purpose, scope, key findings, material limitations, posture interpretation, remediation priorities, assessment confidence
  3. Findings Summary
  4. Scope and Methodology
  5. Detailed Findings
  6. Remediation Roadmap
  7. Appendix A: Evidence and Coverage
  8. Verification and Quality Review
- **Not rendered in proof mode:**
  - the advisory AI narrative (it produced the unsupported "verified" wording, V-3);
  - framework compliance mappings (V-4);
  - the hardcoded "90-day retention / strict redaction" statements (V-12).

## 8. Report snapshot consistency

- The proof is built inside the same generation call and session as the rest of `report_json`. Its `data_cutoff` is the report's `generated_at`.
- It is stored inside the signed `report_json`, so the manifest hash covers it. Its `proof_fingerprint` excludes only the verification timestamp, and coverage and proof are reproducible (test-proven).
- Report ids and versions come from the existing per-(tenant, engagement) version mutex.
- Later changes (new findings, late scans, new integrity failures) never alter a stored revision. They require a new revision.
- At export and delivery, evidence is re-verified against the snapshot's `evidence_index`. Any change adds `EVIDENCE_CHANGED_SINCE_GENERATION`, which forces DRAFT and blocks delivery.

## 9. QA integration

QA approval is the existing `qa-approve` route (`report.qa_approve` permission). This PR neither forges nor auto-grants approval. The marking reads `qa_approved_by`. QA approval alone never yields FINAL: a QUALIFIED decision is also required, and qualification needs the truth gate to PASS, which needs zero proof blockers.

## 10. Release enforcement

| Path | Enforcement |
|---|---|
| Qualification finalize | `result_truth_gate` FAIL whenever `report_proof.release_blockers` is non-empty |
| Versioned deliver, governed delivery, QA-approve auto-advance | `_require_production_qualified` → `release_blockers_now`. Blocks on missing proof, stored blockers, scope mismatch, or evidence changed since generation (422 `REPORT_PROOF_BLOCKED`) |
| Export | Allowed for authorized readers (internal draft). The marking reflects the true state |

Release blockers:
- `SYNTHETIC_DATA`
- `EVIDENCE_INTEGRITY_FAILED`
- `FINDING_RECONCILIATION_MISMATCH`
- `DUPLICATE_FINDING_IDENTITY`
- `CROSS_SCOPE_FINDING_REFERENCE`
- `FINDING_NOT_IN_EVIDENCE_MANIFEST`
- `CONFIRMED_WITHOUT_VERIFIED_EVIDENCE`
- `SCAN_JOBS_IN_PROGRESS`
- at decision time, also `REPORT_PROOF_MISSING`, `REPORT_PROOF_SCOPE_MISMATCH` and `EVIDENCE_CHANGED_SINCE_GENERATION`

**Limited-scope policy.** Incomplete coverage is disclosed, not blocked, consistent with FVA-04 ("must be disclosed"). A limited report can be released only after the full chain (QA, qualification, no blockers), and then only as `FINAL — QA APPROVED — LIMITED COVERAGE`. Missing evidence on a non-confirmed finding is disclosed, not blocked (FVA-02 governs CONFIRMED findings).

**Proven on the real delivery route:** the report is DRAFT and delivery returns 422 without qualification. With qualification, delivery returns 200 and the report is marked FINAL — LIMITED COVERAGE. After stored evidence is altered, delivery returns 422 with `EVIDENCE_CHANGED_SINCE_GENERATION` and the report is marked DRAFT.

Existing tests that monkeypatch `_require_production_qualified` (`tests/test_governed_delivery*.py`) still bypass the gate, as before. The new tests exercise the unpatched gate.

## 11. Correction and revision handling

- Revisions are immutable `governance_reports` rows (`is_finalized`). A correction is a new version with a new report id, manifest hash and proof fingerprint. Earlier revisions remain retrievable unchanged (test-proven).
- The existing `fa_report_versions` lineage (`parent_version_id`, `superseded_by_id`) and the "only approved versions deliver" rule are unchanged.
- An out-of-band edit of stored `report_json` is rejected at export and QA (`REPORT_CONTENT_INTEGRITY_FAILED`, test-proven for a proof edit).

**Not implemented (FVA-06 remains PARTIAL):**
- a correction-reason field;
- a retraction workflow;
- a client dispute API;
- automatic re-generation on evidence change.

Evidence change after generation is detected and blocks delivery, but it does not create a new revision.

## 12. Tenant isolation

- Every proof read is scoped by (tenant, engagement). A cross-tenant proof sees no findings and no evidence (test-proven).
- Routes return 404 for another tenant's report: export JSON/PDF, and generate for a foreign engagement.
- The `read_only` role cannot generate (403) or QA-approve (403). An unauthenticated export is rejected.
- No filesystem paths or internals are exposed. Render failure is a controlled 501 with no partial PDF.

## 13. Failure behavior

| Failure | Draft | Verification / release | Response | Audited |
|---|---|---|---|---|
| Missing envelope / failed capture | Rendered, UNKNOWN, `EVIDENCE_NOT_CAPTURED` | Not a blocker (non-confirmed) | 200 | `scan.evidence.capture_failed` (#813) |
| Tampered evidence (before generation) | Rendered, INVALID, capped | `EVIDENCE_INTEGRITY_FAILED` blocks | 200 | — |
| Tampered evidence (after generation) | Marking → DRAFT | `EVIDENCE_CHANGED_SINCE_GENERATION` blocks delivery | 422 on delivery | — |
| Missing scan result / unknown status | UNKNOWN limitation | Not full coverage | 200 | — |
| Failed job | Limitation | Not a blocker | 200 | — |
| Unfinished job | Limitation | `SCAN_JOBS_IN_PROGRESS` blocks | 200 | — |
| Missing finding confidence | UNKNOWN, `CONFIDENCE_UNCLASSIFIED` | — | 200 | — |
| Empty engagement | `NOT_ASSESSED`, "No eligible finding" | Truth gate FAIL (existing `EMPTY_EVIDENCE_POPULATION`) | 200 | Generation audited |
| Render exception / corrupt template | No PDF | — | 501 `PDF_EXPORT_UNAVAILABLE` | — |
| Report JSON edited after QA | — | Export blocked | 403 | — |
| Legacy report without proof | DRAFT — NOT VERIFIED | `REPORT_PROOF_MISSING` blocks delivery | 422 on delivery | — |

## 14. Performance (test environment, SQLite, single process; not a production benchmark)

| Findings | Generate (route) | PDF export (route) | Pages | Bytes |
|---|---|---|---|---|
| 14 (scenario) | < 1 s | < 1 s | 10 | ≈ 30 KB |
| 100 | 0.04 s | 0.36 s | 44 | 101,568 |
| 500 | 0.07 s | 2.06 s | 202 | 456,322 |

There are no per-finding queries: findings come in pages of 100, envelopes in one query, and the manifest does one verification per envelope. No raw evidence is expanded into the PDF and no network calls are made. Rendering goes into an in-memory buffer, with no temp files.

## 15. Threat model

| Threat | Control |
|---|---|
| Report omits findings | Independent-read reconciliation, a release blocker, and a PDF test asserting every id |
| False full-coverage claim | Persisted-status coverage, no invented percentage, `may_claim_full_coverage` gate |
| Altered evidence supports a claim | Re-verified digests: INVALID caps confidence and blocks release. Re-verification at delivery |
| Draft passed off as final | Server-derived marking on every page. Synthetic data can never be FINAL |
| Approval forged via request | No caller input to the state. QA and qualification come from DB records |
| Report content edited after signing | Manifest-hash recompute at export, QA and delivery (existing) |
| Cross-tenant disclosure | Tenant/engagement scoping on every read. 404 on foreign ids |
| Malicious scanner text breaks rendering | XML-escaped Paragraph text, bounded token wrapping |

## 16. Test evidence

- `tests/test_report_proof/test_proof_assembly.py`: 25 tests on real persistence (SQLite ORM metadata), covering completeness, coverage, evidence and release-state matrix.
- `tests/test_report_proof/test_report_end_to_end.py`: 18 tests through real routes and a real PDF:
  - reconciliation;
  - classifications;
  - coverage disclosure;
  - truth gate;
  - every id in the PDF;
  - marking, Page X of Y and report id on every page;
  - forbidden claims;
  - footer geometry (pypdf positions and string widths);
  - rasterization via pdftoppm (non-blank);
  - real delivery path;
  - report edit after QA;
  - tenant isolation;
  - parameter tampering;
  - revisions;
  - empty engagement;
  - render failure;
  - 100 and 500 findings.
- `tests/test_report_proof/test_release_bypass.py`: 3 tests.
  - A synthetic report is driven through every release route: QA approve; qualification request, attest and finalize (refused); versioned deliver and governed delivery (refused); then an out-of-band QUALIFIED row (still refused, still DRAFT).
  - The PDF's signed report hash and proof fingerprint equal the stored snapshot, and its blockers equal the release decision.
  - An unfinished job prevents full coverage.
- `tests/test_report_preview/test_synthetic_report_preview.py`: the artifact generator. With `FG_REPORT_PREVIEW_OUT` set it writes `validation_record.json`: the artifact SHA-256, the signed report hash, the proof fingerprint and every acceptance check result.

**Snapshot binding fix.** The PDF previously printed the report engine's internal `manifest_hash`, which does not cover `report_proof`. It now prints the signed record hash, which is the hash verified at export, QA and delivery.

Command:

```
FG_REPORT_PREVIEW_OUT=<dir> FG_ENV=test .venv/bin/pytest -q tests/test_report_preview/
```

It writes the PDF, JSON, text, one PNG per page and `preview_meta.json`.

## 17. Remaining gaps

1. FVA-05: no reviewer qualification, conflict of interest or self-review enforcement.
2. FVA-06: no correction reason, retraction, dispute workflow or automatic re-generation.
3. Evidence is integrity-only (Vault Transit signatures: L14-SCAN-VAULT-001).
4. Graph-family scanners have scan-level evidence only, so their per-finding affected resources are often "Not recorded".
5. No authorized-scope inventory, so the coverage percentage is not determinable by design.
6. The JSON `executive_summary` (advisory AI narrative) still contains template wording. It is not rendered in proof-mode PDFs.
7. The second PDF stack (`services/report_authority/renderer_pdf.py`) is unchanged and not reachable from the engagement export.
8. Synthetic detection depends on the payload `synthetic` flag or a `SYNTHETIC*` proof level. Real scanners never set either.

## 18. Next PR handoff

**L14-ASSESSMENT-ASSURANCE-001** comes next. Report truth is now enforced end to end. What still separates a FINAL report from an independently verified one is the QA authority:
- reviewer qualification;
- conflict-of-interest and self-review rules;
- the confidence-field enforcement at the schema level.

L14-FA-REPORT-BRIDGE-001 is not a prerequisite for correct reports.
