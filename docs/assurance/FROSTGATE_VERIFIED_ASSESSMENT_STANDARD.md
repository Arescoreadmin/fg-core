# FrostGate Verified Assessment Standard

**Document ID:** FROSTGATE-VERIFIED-ASSESSMENT-STANDARD-001  
**Version:** 1.0  
**Date:** 2026-11-06  
**Authority:** FrostGate Internal Engineering Standard  
**Status:** PARTIAL_IMPLEMENTATION — 6 controls defined; 0 fully implemented, 3 partially implemented, 3 policy-only

---

## Important Disclosure

This is FrostGate's internal quality standard for field assessments. It is:
- An internal engineering and delivery standard
- Self-defined and self-audited by FrostGate

It is NOT:
- An accredited industry standard
- A government certification
- An ISO certification (not ISO 17025, not ISO 27001, not ISO 42001)
- A SOC 2 attestation
- An independent external audit opinion
- A NIST AI RMF certification

Where the only available review process is founder-led, it is labeled as such. Claiming otherwise is a material misrepresentation.

---

## Purpose

The FrostGate Verified Assessment Standard (FVAS) defines the minimum quality requirements for a FrostGate field assessment to be delivered to a client as a verified assessment. It establishes six controls (FVA-01 through FVA-06) covering scope authorization, evidence sufficiency, finding accuracy, coverage transparency, quality review, and report integrity.

---

## FVA-01 — Authorized Scope

**Control**: Every assessment activity must be tied to an approved engagement record and explicitly permitted scope. No scanner or analyzer may execute against targets not covered by the engagement authorization.

**Required evidence**:
- Engagement record (FaEngagement row with approved status)
- Scope approval (fa_scan_authorizations row with status=active, approved target list, operator signature)
- Assessor authorization (credential with scan.trigger permission)

**Implementation status**: PARTIALLY_IMPLEMENTED

**What IS enforced (code-verified, L14-SCAN-SAFETY-001)**:

1. Operator identity and permission: `require_permission("scan.trigger")` enforced at every scan initiation route — `api/field_assessment.py` lines 4582, 4857, 5067.
2. Tenant-scoped engagement ownership: `get_engagement(db, engagement_id=..., tenant_id=...)` performs a compound WHERE on `(id, tenant_id)` — prevents cross-tenant scan initiation — `services/field_assessment/store.py:103`.
3. SSRF / private-range blocking: `SafeTargetValidationService` (called via `_c6_validate_and_store_targets`) rejects RFC1918, loopback, link-local, cloud-metadata targets before any connection — `services/connectors/safe_target_validator.py`.
4. Scan audit event emitted: `_c6_write_audit_event(event_type="scan.initiated")` on all scan dispatch paths — `api/field_assessment.py` lines 4668, 4876, 5153.
5. Acknowledgment receipt gate: Microsoft Graph scan requires `acknowledgment_receipt_id` parameter — `api/field_assessment.py:3610 initiate_msgraph_scan`.
6. Per-engagement authorized scope gate: `check_scan_authorized()` called before scan dispatch in `initiate_network_scan`, `initiate_dns_email_scan`, `initiate_web_headers_scan` via `_c6_check_all_targets_authorized()` — `api/field_assessment.py`. Fail-closed: missing/expired/revoked authorization → HTTP 403.
7. Target normalization: `normalize_target()` in `services/field_assessment/scan_authorization.py` — canonical form required before any scope comparison. IPv4-mapped IPv6, zone IDs, and malformed targets fail closed.
8. Emergency stop: `fa_scan_emergency_stops` table provides durable kill-switch at platform/tenant/engagement scope — `services/field_assessment/scan_authorization.py`.
9. Scan cancellation state machine: QUEUED/RUNNING → CANCEL_REQUESTED → CANCELLED. Atomic CAS transitions. Durable DB-backed state.
10. Scope management API: Operators create/activate/revoke authorized scope via `POST /field-assessment/engagements/{id}/scan-authorizations` with `scan.scope.manage` permission.

**What IS enforced (code-verified, L14-SCAN-AUTH-HARDENING-001)** — see `docs/assurance/L14_SCAN_AUTHORIZATION_HARDENING.md`:

11. Customer authorization receipts (`fa_customer_authorization_receipts`, migration 0203): an authenticated customer principal (interactive OIDC, verified email, `tenant_admin`/`client_security_owner`, same tenant, not the requester, never `platform_admin`) approves explicit targets, operations and a window. Every material field is bound by a canonical SHA-256 digest; server HMAC attestation under a trusted key id is required in production. Proof level is `SERVER_ATTESTED_AUTHENTICATED_APPROVAL` — a server attestation, **not** a customer-held signature.
12. Scope ⊆ receipt is verified at scope create and activate; in production an unbound (legacy) scope cannot be activated or authorize scans (`CUSTOMER_AUTHORIZATION_REQUIRED`).
13. `check_scan_authorized()` step 7 re-verifies the bound receipt (status, window, integrity, exact target + operation) on every call.
14. Execution-time revalidation (`ScanExecutionGuard`) at worker start (fresh session, all targets, job state) and before every target and redirect hop for network, DNS/email and web-header scanners. Store unavailability fails closed.
15. Compare-and-swap job transitions: a cancelled job cannot be revived or overwritten by a late success; late completion is rejected and audited; partial evidence is preserved with `CollectionStatus.CANCELLED`.
16. Emergency stop enforced at dispatch and worker start for all scanner families (Graph-family gate after device-code token acquisition, before Graph I/O); cross-tenant engagement-stop release closed.
17. Authorization decision records for dispatch, worker start, target denial, authority loss, cancellation, late completion and consent lifecycle.

**What is NOT enforced (remaining gaps — FVA-01 stays PARTIALLY_IMPLEMENTED)**:

1. Graph-family connectors (microsoft_graph, oauth_inventory, endpoint_inventory, entra_governance, sharepoint_onedrive, oauth_risk, ai_tool_discovery): no customer receipt binding and no per-page revalidation. Their authorization basis remains the customer administrator's interactive device-code login; the operator HMAC acknowledgment is not customer consent.
2. No customer-verifiable (asymmetric) signature on receipts — L14-SCAN-VAULT-001.
3. DNS-rebinding IP pinning between SSRF validation and connect — L14-SCAN-SAFETY-002.
4. DNS/email revalidation is per domain, not per record phase.
5. Cloud provider scanners (AWS/GCP/Azure): not implemented.

**Code references**:
- `services/field_assessment/scan_authorization.py` — canonical fail-closed authorization service
- `api/field_assessment.py:_c6_check_all_targets_authorized()` — batch authorization check helper
- `migrations/postgres/0200_fa_scan_authorization.sql` — fa_scan_authorizations, fa_scan_emergency_stops, cancel columns
- `tests/test_scan_safety/` — 89 adversarial tests covering all 12 domain invariants
- `services/field_assessment/customer_authorization.py`, `services/field_assessment/scan_execution_guard.py`, `migrations/postgres/0203_scan_customer_authorization.sql`
- `tests/test_scan_authorization_hardening/` — 181 adversarial tests (consent, execution guard, worker lifecycle, CAS, migration/RBAC contract)

**Testable criteria**:
- Scanner runner rejects execution without valid engagement_id — ENFORCED
- SafeTargetValidationService rejects private-IP targets — ENFORCED (see `tests/test_scan_accuracy/test_fva01_scope_enforcement.py`)
- Tenant-scoped engagement ownership check — ENFORCED
- Audit event at scan start — ENFORCED
- Acknowledgment receipt gate for all scanners — NOT ENFORCED (MsgGraph only)
- Target in per-engagement authorized scope — ENFORCED (L14-SCAN-SAFETY-001)
- Expired/revoked authorization blocks scan — ENFORCED
- Emergency stop blocks scan — ENFORCED
- Cross-tenant authorization use denied — ENFORCED

**Implemented by**: L14-SCAN-SAFETY-001

---

## FVA-02 — Evidence Sufficiency

**Control**: Material confirmed findings must have sufficient, valid, attributable evidence meeting the confidence policy. No finding may be delivered as CONFIRMED without meeting the evidence threshold defined in `FROSTGATE_FINDING_CONFIDENCE_POLICY.md`.

**Required evidence**:
- Evidence records with provenance (scan_id, engagement_id, tenant_id, timestamp)
- Confidence classification meeting CONFIRMED threshold (DIRECT_TECHNICAL_OBSERVATION or AUTHORITATIVE_CONFIGURATION_EXPORT)
- Evidence link from finding to source observation

**Implementation status**: PARTIALLY_IMPLEMENTED

**Runtime enforcement (L14-SCAN-RUNNER-INTEGRITY-001):** every scanner finding from the 10 wired worker paths is linked to canonical evidence envelopes (SHA-256 over stored evidence, append-only custody). If capture fails, the finding is explicitly UNKNOWN. **Report enforcement (L14-SCAN-REPORT-PROOF-001):** report assembly consumes the evidence manifest. Every rendered finding carries its re-verified evidence classification. A CONFIRMED finding without integrity-verified evidence is a release blocker. Evidence altered after generation blocks delivery. **Not yet enforced:** provenance is integrity-only, not authenticated (L14-SCAN-VAULT-001). Graph-family evidence is scan-level only. See `docs/assurance/L14_SCANNER_RUNTIME_EVIDENCE_INTEGRITY.md` and `docs/assurance/L14_SCAN_REPORT_PROOF.md`.

**Testable criteria** (fixture level):
- Scan result includes scan_id, engagement_id, timestamps (all scanners — IMPLEMENTED)
- Finding has explicit confidence label — NOT YET IMPLEMENTED at runner level
- Evidence chain: raw observation -> scan result -> normalized finding -> evidence link — IMPLEMENTED for Microsoft Graph; NOT IMPLEMENTED for network/web/dns runners

**Known gaps**:
- No `confidence` field in runner-level finding output (all scanners)
- FaNormalizedFinding schema does not enforce confidence classification
- Evidence link from finding to scan result not enforced at normalization layer

**Future enforcement PR**: L14-ASSESSMENT-ASSURANCE-001

---

## FVA-03 — Finding Accuracy

**Control**: Finding confidence and severity must be separately justified per the documented methodology. Confidence reflects evidence quality. Severity reflects impact. These are independent.

**Required evidence**:
- Confidence classification record (confidence level + verification methods)
- Severity justification (severity field + control_id mapping)
- Finding type documentation (finding type must be in the finding type registry)

**Implementation status**: PARTIALLY_IMPLEMENTED

**Runtime enforcement (L14-SCAN-RUNNER-INTEGRITY-001):** `classify_confidence` is applied at capture using each finding's own collection status and evidence provenance. Severity is never modified. INVALID or MISSING evidence caps effective confidence at report-manifest time. **Report enforcement (L14-SCAN-REPORT-PROOF-001):** the PDF renders every eligible scanner finding with its canonical confidence label (evidence-capped) and its unmodified severity, stated as independent. **Not yet enforced:** finding-type registry outside Microsoft Graph, and machine-checked severity justification.

**Testable criteria** (fixture level):
- Confidence model rules enforced (`test_confidence_model.py`) — IMPLEMENTED at policy level
- Known-answer accuracy tests confirm correct finding types — IMPLEMENTED for 6 scanners
- Finding type definitions exist in `services/connectors/msgraph/findings/registry.py` — IMPLEMENTED for Microsoft Graph only

**Known gaps**:
- Finding type registry only exists for Microsoft Graph connector; other connectors use ad-hoc strings
- No automated check that severity matches a documented severity justification
- Live detection effectiveness: NOT_MEASURED (fixture-validated only)

**Future enforcement PR**: L14-SCAN-REPORT-PROOF-001

---

## FVA-04 — Coverage Transparency

**Control**: Any incomplete, denied, or limited collection must be disclosed in the assessment report. Clients must not receive a report that implies complete coverage when collection was partial, denied, or truncated.

**Required evidence**:
- `collection_status` records for all scans: COMPLETE / PARTIAL / DENIED / TIMEOUT / TRUNCATED / FAILED
- Explicit disclosure of non-COMPLETE collection states in the report
- Summary section that accurately counts total_hosts, rejected_target_count, skipped sources

**Implementation status**: PARTIALLY_IMPLEMENTED

**Runtime enforcement (L14-SCAN-RUNNER-INTEGRITY-001):** canonical collection status persists per evidence envelope and per finding, and the evidence manifest lists every coverage limitation. **Proven gap:** the current PDF hides partial, denied, timed-out and cancelled collection and shows 100% coverage (`L14_CUSTOMER_REPORT_PREVIEW_READINESS.md` V-2). Report disclosure enforcement is L14-SCAN-REPORT-PROOF-001.

**Testable criteria** (all IMPLEMENTED as of L14-SCAN-COMPLETENESS-001):
- Canonical `CollectionStatus` enum: COMPLETE/PARTIAL/DENIED/TIMEOUT/TRUNCATED/FAILED/CANCELLED/NOT_ASSESSED/UNKNOWN — IMPLEMENTED
- DNS scan: timeout → `DnsQueryOutcome(status=TIMEOUT)` → no missing SPF/DMARC findings — IMPLEMENTED (DEF-001 closed)
- Endpoint inventory: absent timestamp → `is_stale=None` (INDETERMINATE), not `is_stale=False` — IMPLEMENTED (DEF-002 closed)
- Endpoint inventory: 403 on Intune → `intune_collection_status=DENIED`, no unencrypted_devices finding — IMPLEMENTED
- Endpoint inventory: missing Intune record → `encryption_status=UNKNOWN`, not `encrypted` — IMPLEMENTED
- Network scan: `collection_status` per run (COMPLETE/PARTIAL/FAILED) — IMPLEMENTED
- Web headers: `collection_status` per target (COMPLETE/DENIED/FAILED) — IMPLEMENTED
- SharePoint: `collection_status` with TRUNCATED/DENIED/COMPLETE; cap-aware — IMPLEMENTED
- OAuth inventory: per-source status (app_registrations, service_principals, grants) + overall — IMPLEMENTED
- `AssessmentCoverageSummary` machine-readable coverage record with `report_constraints` — IMPLEMENTED
- `report_constraints.may_claim_no_risks_found` gated on COMPLETE status — IMPLEMENTED
- `report_constraints.may_claim_fully_assessed` gated on COMPLETE status — IMPLEMENTED

**Report enforcement (L14-SCAN-REPORT-PROOF-001):** the engagement report renders the following from persisted collection data:
- every non-COMPLETE scan, observation and job (PARTIAL, DENIED, TIMEOUT, FAILED, CANCELLED, TRUNCATED, UNKNOWN, targets not started, evidence not captured);
- a `Coverage not determinable` statement instead of a percentage;
- a `LIMITED COVERAGE` final label.

The false "100%" metrics are no longer rendered.

**Remaining gap**:
- No authorized-scope inventory, so a coverage percentage is never computed.
- Graph-family scanners disclose scan-level status only.
- The governance-report PDF stack (`services/report_authority`) is not wired.

**Closed by**: L14-SCAN-COMPLETENESS-001

---

## FVA-05 — Independent Quality Review

**Control**: Assessments must undergo quality review before delivery. Reviewer qualifications, conflicts of interest, review responsibilities, and approval records must be documented.

Where founder-led review is the only available process, it is labeled as FOUNDER_REVIEW, not independent review.

**Required evidence**:
- QA record with: reviewer identity, reviewer qualifications, review date, approval signature
- Conflict of interest declaration (reviewer must not be the primary assessor for the same engagement)
- Review scope (what was checked)

**Implementation status**: PARTIALLY_IMPLEMENTED (L14-ASSESSMENT-ASSURANCE-001)

**Enforced** (server-side, on every QA decision route: `/qa-approve`, `/qa-reject`, `versions/{id}/approve`, `versions/{id}/reject`):
- QA decisions require a named human reviewer (OIDC or verified delegation). API keys, including role-bound QA keys, and service principals are refused (`HUMAN_REVIEWER_REQUIRED`), because a key has no holder binding and independence cannot be shown.
- Non-conflict: the reviewer's canonical principal, meaning every identity subject bound to it, must not be a report author or a material contributor to the engagement per the append-only audit trail (`REPORT_QA_SELF_REVIEW`). The caller-supplied `compiled_by` cannot narrow this exclusion.
- QA rejection exists, with a fixed reason vocabulary and an explanation. Every decision is an append-only, version-bound record with one terminal decision per record or version.
- FINAL requires an independent human approval. Legacy API-key approvals stay DRAFT (`QA_INDEPENDENT_APPROVAL_MISSING`).

**Known gaps**:
- No reviewer qualification (competence/credential) enforcement.
- Interactive OIDC reviewer login has not been rehearsed end-to-end. Tests simulate the resolution result.
- A human reviewer is independent of an API-key *author* only at the credential-subject level; credential holder binding is a follow-up.
- Founder-led review must still be labelled FOUNDER_REVIEW by policy.

**Future enforcement PR**: L14-ASSESSMENT-ASSURANCE-001

---

## FVA-06 — Report Integrity and Corrections

**Control**: Assessment reports must have versioning, a release record, a corrections/retractions log, a client dispute process, and re-verification triggers.

**Required evidence**:
- Version history (report_version field, generated_at timestamp)
- Release record (QA approval timestamp, release operator identity)
- Correction log (what changed, when, reason, re-verification required)
- Client dispute process (how clients can formally dispute a finding)

**Implementation status**: PARTIAL_IMPLEMENTATION

**Current state**:
- Report generation records `created_at`, `report_version` — IMPLEMENTED
- No correction/retraction workflow
- No client dispute process
- No re-verification trigger when evidence is updated post-report. **Partially addressed (L14-SCAN-REPORT-PROOF-001):** evidence is re-verified at export and delivery; any change forces DRAFT and blocks delivery (`EVIDENCE_CHANGED_SINCE_GENERATION`). It does not create a new revision automatically.
- No formal report release record separate from QA approval
- Every page carries an authoritative DRAFT / FINAL marking; revisions are immutable and remain retrievable (L14-SCAN-REPORT-PROOF-001)
- QA rejection is a terminal, audited state (`REJECTED`). A rejected record cannot be revived; rework is a corrected report whose first version links to the rejected one (L14-ASSESSMENT-ASSURANCE-001)

**Known gaps**:
- No `corrections_log` field or table
- No retraction workflow
- No client dispute API
- No trigger for confidence downgrade when evidence is revised

**Future enforcement PR**: L14-SCAN-REPORT-PROOF-001

---

## Summary Table

| Control | ID | Description | Status | Deferred To |
|---------|-----|-------------|--------|-------------|
| Authorized Scope | FVA-01 | Scanner execution tied to approved engagement and scope | PARTIALLY_IMPLEMENTED | L14-SCAN-SAFETY-001 + L14-SCAN-AUTH-HARDENING-001 (customer receipt + execution-time revalidation enforced for network/DNS/web scanners; Graph-family receipt binding, customer-held signature and rebinding pinning remain) |
| Evidence Sufficiency | FVA-02 | Confirmed findings meet confidence policy evidence threshold | PARTIALLY_IMPLEMENTED | Runtime links (L14-SCAN-RUNNER-INTEGRITY-001) and report/release sufficiency (L14-SCAN-REPORT-PROOF-001) enforced; canonical provenance drives every trust gate in every mode (L14-ASSESSMENT-ASSURANCE-001); authenticated provenance L14-SCAN-VAULT-001; schema enforcement L14-ASSESSMENT-ASSURANCE-001 |
| Finding Accuracy | FVA-03 | Confidence and severity independently justified | PARTIALLY_IMPLEMENTED | Runtime classification (L14-SCAN-RUNNER-INTEGRITY-001) and report rendering (L14-SCAN-REPORT-PROOF-001) done; finding-type registry and severity justification remain |
| Coverage Transparency | FVA-04 | Collection gaps explicitly disclosed | PARTIALLY_IMPLEMENTED | Engagement report discloses every recorded gap (L14-SCAN-REPORT-PROOF-001); scope inventory / Graph per-observation coverage remain |
| Independent Quality Review | FVA-05 | Qualified, non-conflicted reviewer approval | PARTIALLY_IMPLEMENTED | Named-human, non-conflicted QA, rejection and FINAL independence enforced (L14-ASSESSMENT-ASSURANCE-001); reviewer qualification registry, OIDC rehearsal and API-key holder binding remain |
| Report Integrity | FVA-06 | Version control, corrections, dispute process | PARTIAL_IMPLEMENTATION | Draft marking, immutable revisions and delivery-time evidence re-verification by L14-SCAN-REPORT-PROOF-001; QA rejection and rework lineage added (L14-ASSESSMENT-ASSURANCE-001); corrections log, retraction and dispute process remain |

---

## Cross-References

- `docs/assurance/FROSTGATE_FINDING_CONFIDENCE_POLICY.md` — Evidence confidence levels and rules
- `docs/audits/L14_SCAN_ACCURACY_BASELINE.md` — Fixture-validated accuracy per scanner
- `docs/audits/L14_SCAN_AUDIT_CORRECTIONS.md` — Corrections to original audit claims
- `tests/test_scan_accuracy/` — L14-SCAN-ACCURACY-001 known-answer fixture corpus
- L14-ASSESSMENT-ASSURANCE-001 — Full enforcement gate PR (future)
