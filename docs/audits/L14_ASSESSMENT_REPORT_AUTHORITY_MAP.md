# L14 Assessment Report Authority Map

**Generated:** 2026-11-06
**Branch:** audit/l14-field-assessment-report-readiness-001
**Commit:** ab72e44f922e60c48a48259ff32930c15dfb81d5

This document maps every identified API route, service, and component in the assessment pipeline.

---

## Field Assessment Engagement Routes

All routes mount under `/field-assessment/`.

| Route | File | Description | Auth Required | State | Test Coverage |
|-------|------|-------------|---------------|-------|---------------|
| `GET /engagements` | api/field_assessment.py:1337 | List engagements for tenant | assessment.view | any | test_list_engagements_* |
| `POST /engagements` | api/field_assessment.py:1371 | Create new engagement | assessment.create | — | test_create_engagement_* |
| `GET /engagements/{id}` | api/field_assessment.py:1453 | Get engagement detail | assessment.view | any | test_create_and_get_engagement |
| `PATCH /engagements/{id}` | api/field_assessment.py:1478 | Update engagement metadata | assessment.create | non-terminal | partial coverage |
| `PATCH /engagements/{id}/transition` | api/field_assessment.py:1525 | Advance engagement status | assessment.create | gate-enforced | test_engagement_status_transition_* |
| `GET /engagements/{id}/execution-state` | api/field_assessment.py:3184 | Get readiness gate status | assessment.view | any | coverage via readiness tests |
| `GET /engagements/{id}/next-actions` | api/field_assessment.py:3211 | Get guided next actions | assessment.view | any | partial coverage |
| `POST /engagements/{id}/scan-results` | api/field_assessment.py:1652 | Ingest automated scan | evidence.upload | non-terminal | test_ingest_scan_result_* |
| `GET /engagements/{id}/scan-results` | api/field_assessment.py:1849 | List scan results | evidence.view | any | test_list_scan_results |
| `GET /engagements/{id}/scan-results/{scan_id}` | api/field_assessment.py:1875 | Get scan result detail | evidence.view | any | partial |
| `POST /engagements/{id}/document-analyses` | api/field_assessment.py:1914 | Register document review | evidence.upload | non-terminal | test_register_document_analysis |
| `GET /engagements/{id}/document-analyses` | api/field_assessment.py:1978 | List document analyses | evidence.view | any | partial |
| `POST /engagements/{id}/observations` | api/field_assessment.py:2009 | Capture field observation | evidence.upload | non-terminal | test_capture_observation |
| `POST /engagements/{id}/observations/bulk` | api/field_assessment.py:2079 | Bulk import observations | evidence.upload | non-terminal | test_bulk_import |
| `GET /engagements/{id}/observations` | api/field_assessment.py:2168 | List observations | evidence.view | any | test_list_observations |
| `GET /engagements/{id}/interview-templates` | api/field_assessment.py:2200 | Retrieve interview templates | evidence.view | any | partial |
| `PATCH /engagements/{id}/observations/{obs_id}` | api/field_assessment.py:2255 | Update observation | evidence.upload | non-terminal | test_update_observation_* |
| `DELETE /engagements/{id}/observations/{obs_id}` | api/field_assessment.py:2355 | Soft-delete observation | evidence.upload | non-terminal | partial |
| `GET /engagements/{id}/findings` | api/field_assessment.py:2441 | List normalized findings | finding.view | any | test_list_findings |
| `GET /engagements/{id}/findings/{finding_id}` | api/field_assessment.py:2487 | Get finding detail | finding.view | any | partial |
| `PATCH /engagements/{id}/findings/{finding_id}/status` | api/field_assessment.py:2529 | Update finding status | finding.close | any | test_finding_closed_loop |
| `PATCH /engagements/{id}/findings/{finding_id}/remediation` | api/field_assessment.py:2693 | Update remediation | finding.close | any | partial |
| `POST /engagements/{id}/evidence-links` | api/field_assessment.py:2779 | Create evidence link | evidence.upload | non-terminal | test_evidence_link_* |
| `GET /engagements/{id}/evidence-links` | api/field_assessment.py:2916 | List evidence links | evidence.view | any | test_evidence_link_* |
| `GET /engagements/{id}/summary` | api/field_assessment.py:2951 | Get engagement summary | assessment.view | any | partial |
| `POST /engagements/{id}/msgraph-import` | api/field_assessment.py:3268 | Import MS Graph connector run | evidence.upload | non-terminal | test_field_assessment_msgraph_bridge |
| `POST /engagements/{id}/msgraph-scan` | api/field_assessment.py:3610 | Initiate MS Graph scan | evidence.upload | non-terminal | test_field_assessment_msgraph_bridge |
| `POST /engagements/{id}/oauth-inventory-scan` | api/field_assessment.py:3882 | Initiate OAuth scan | evidence.upload | non-terminal | partial |
| `GET /engagements/{id}/audit-events` | api/field_assessment.py:6792 | Get engagement audit log | audit.read | any | test_audit_events_* |
| `POST /engagements/{id}/reports` | api/field_assessment.py:9551 | Generate engagement report (JSON) | report.generate | gated | test_field_assessment_reports.py |
| `GET /engagements/{id}/reports` | api/field_assessment.py:9743 | List engagement reports | report.view | any | partial |
| `GET /engagements/{id}/reports/{report_id}` | api/field_assessment.py:9798 | Get engagement report | report.view | any | partial |
| `POST /engagements/{id}/reports/{report_id}/qa-approve` | api/field_assessment.py:7556 | QA-approve report | report.qa_approve | FINALIZED | test_field_assessment_report_qa_gate |
| `POST /engagements/{id}/qualify/request` | api/field_assessment.py:8000 | Initiate production qualification | report.generate | QA_APPROVED | partial |
| `POST /engagements/{id}/qualify/{qual_id}/attest` | api/field_assessment.py:8133 | Submit gate attestation | report.qa_approve | REQUESTED | partial |
| `POST /engagements/{id}/qualify/{qual_id}/finalize` | api/field_assessment.py:8236 | Finalize production qualification | report.qa_approve | REQUESTED | partial |
| `GET /engagements/{id}/qualify/{qual_id}/status` | api/field_assessment.py:8440 | Get qualification status | report.view | any | partial |
| `POST /engagements/{id}/artifacts` | api/field_assessment.py:~1646 | Upload evidence artifact | evidence.upload | non-terminal | test_upload_artifact_* |

---

## Report Authority Routes (Enterprise PDF Export)

All routes mount under `/reports/`.

| Route | File | Description | Auth Required | State | Test Coverage |
|-------|------|-------------|---------------|-------|---------------|
| `GET /reports/health` | api/report_authority.py:124 | Health check | None | — | implicit |
| `GET /reports/statistics` | api/report_authority.py:142 | Tenant report statistics | audit:read | any | partial |
| `GET /reports` | api/report_authority.py:162 | List reports | audit:read | any | test_list_pagination_is_deterministic |
| `POST /reports/generate` | api/report_authority.py:193 | Generate report (all formats) | audit:write | — | test_field_assessment_reports.py |
| `POST /reports/compare` | api/report_authority.py:228 | Compare report versions | audit:read | any | partial |
| `GET /reports/{report_id}` | api/report_authority.py:256 | Get report | audit:read | any | test_field_assessment_reports.py |
| `GET /reports/{report_id}/manifest` | api/report_authority.py:281 | Get cryptographic manifest | audit:read | any | test_manifest_hash_is_stable |
| `GET /reports/{report_id}/quality` | api/report_authority.py:306 | Get quality breakdown | audit:read | any | partial |
| `GET /reports/{report_id}/download/pdf` | api/report_authority.py:331 | Download PDF | audit:read | any | test_export_pdf_returns_200_or_501 |
| `GET /reports/{report_id}/download/html` | api/report_authority.py:369 | Download HTML | audit:read | any | partial |
| `GET /reports/{report_id}/download/json` | api/report_authority.py:406 | Download canonical JSON | audit:read | any | test_export_json_works |
| `GET /reports/{report_id}/bundle` | api/report_authority.py:443 | Get bundle metadata | audit:read | any | partial |
| `GET /reports/{report_id}/bundle/download` | api/report_authority.py:468 | Download signed ZIP bundle | audit:read | any | partial |
| `POST /reports/{report_id}/publish` | api/report_authority.py:534 | Publish report | audit:write | GENERATED | partial |
| `POST /reports/{report_id}/verify` | api/report_authority.py:571 | Verify report integrity | audit:read | any | test_valid_report_verifies |

---

## Customer Intake Routes (Self-Service Assessment)

All routes mount under `/ingest/assessment/`.

| Route | File | Description | Auth Required | Notes |
|-------|------|-------------|---------------|-------|
| `POST /ingest/assessment/orgs` | api/assessments.py:336 | Create org + draft assessment | ingest:assessment | Customer-facing entry |
| `GET /ingest/assessment/{id}/questions` | api/assessments.py:412 | Fetch question bank | ingest:assessment | NIST-mapped |
| `GET /ingest/assessment/{id}` | api/assessments.py:419 | Get assessment + scores | ingest:assessment | Includes overall_score |
| `PATCH /ingest/assessment/{id}/responses` | api/assessments.py:442 | Autosave responses | ingest:assessment | Idempotent |
| `POST /ingest/assessment/{id}/checkout` | api/assessments.py:465 | Create Stripe checkout | ingest:assessment | Server-side pricing |
| `POST /ingest/assessment/{id}/submit` | api/assessments.py:595 | Score and finalize | ingest:assessment | Requires payment_status=paid |
| `GET /ingest/assessment/{id}/payment-status` | api/assessments.py:653 | Payment status check | Public | Anti-enumeration |
| `POST /ingest/assessment/{id}/activate` | api/assessments.py:693 | Portal activation | Public | OIDC + activation token |

---

## Service Layer Components

| Service | Location | Purpose | Used By |
|---------|----------|---------|---------|
| ReportAuthorityEngine | services/report_authority/engine.py | Report CRUD, state machine, quality | report_authority.py |
| GovernanceReportEngine | services/governance/report/ | FA-native report JSON generation | field_assessment.py |
| EngagementReadinessEngine | services/field_assessment/readiness.py | Gate evaluation, readiness score | field_assessment.py |
| EvidenceLifecycleService | services/field_assessment/evidence_lifecycle.py | Evidence state transitions | field_assessment.py |
| AuditAtomicityService | services/field_assessment/audit.py | Atomic audit event write | field_assessment.py |
| DurableJobService | services/field_assessment/durable_job_service.py | Scan job lifecycle | field_assessment.py |
| GovernanceDecisionService | services/field_assessment/governance_decision_service.py | Finding approval workflow | field_assessment.py |
| ReportRepository | services/report_authority/repository.py | Report ORM isolation | engine.py |
| render_pdf | services/report_authority/renderer_pdf.py | ReportLab PDF generation | report_authority.py |
| render_html | services/report_authority/renderer_html.py | HTML report generation | report_authority.py |
| render_json | services/report_authority/renderer_json.py | Canonical JSON generation | report_authority.py |
| build_export_bundle | services/report_authority/export.py | Signed ZIP bundle | report_authority.py |
| compute_quality_inputs | services/report_authority/quality_inputs.py | Evidence-based quality scoring | engine.py |
| TrustBindingAuthority | services/governance/trust_binding.py | Vault Transit signing | field_assessment.py |
| GovernedDeliveryService | services/governance/report/governed_delivery_service.py | Authorized delivery records | field_assessment.py |

---

## Console UI Components

| Path | Component | Description |
|------|-----------|-------------|
| apps/console/app/field-assessment/page.tsx | Engagement list | Lists all engagements for tenant |
| apps/console/app/field-assessment/[engagementId]/page.tsx | Engagement detail | StatusTransitionBar, GuidedExecutionPanel, ScanImportPanel, MsgraphScanPanel, etc. |
| apps/console/app/reports/page.tsx | Reports list | Links to /field-assessment |
| apps/console/app/reports/[reportId]/page.tsx | Report detail | (exists but not inspected in depth) |

---

## Data Model (Key Tables)

| Table | Model | Purpose | Append-Only |
|-------|-------|---------|-------------|
| fa_engagements | FaEngagement | Top-level engagement | No |
| fa_scan_results | FaScanResult | Automated scan ingests | No (but hash-unique) |
| fa_document_analyses | FaDocumentAnalysis | Document review records | No |
| fa_field_observations | FaFieldObservation | Assessor observations | No (soft delete) |
| fa_normalized_findings | FaNormalizedFinding | Deduplicated findings | No (hash-unique) |
| fa_evidence_links | FaEvidenceLink | Evidence graph edges | No (unique constraint) |
| fa_engagement_audit_events | FaEngagementAuditEvent | Engagement mutations | Yes |
| fa_evidence_lifecycle_events | FaEvidenceLifecycleEvent | Evidence state changes | Yes |
| fa_evidence_provenance | FaEvidenceProvenance | Chain-of-custody ledger | Yes |
| fa_evidence_report_links | FaEvidenceReportLink | Evidence to report binding | Yes |
| fa_report_versions | FaReportVersion | Report lifecycle | No |
| fa_report_qa_decisions | FaReportQADecision | QA approval records | Yes |
| fa_production_qual_requests | FaProductionQualRequest | Qualification init | Yes |
| fa_production_attestations | FaProductionAttestation | Gate attestations | Yes |
| fa_qualification_decisions | FaQualificationDecision | Final qual decisions | Yes |
| fa_governed_delivery_requests | FaGovernedDeliveryRequest | Delivery authorization requests | Yes |
| fa_governed_delivery_attempts | FaGovernedDeliveryAttempt | Transport attempts | Yes |
