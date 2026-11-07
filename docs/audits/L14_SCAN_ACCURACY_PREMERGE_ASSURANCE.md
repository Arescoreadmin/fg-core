# L14-SCAN-ACCURACY-001 — Pre-Merge Assurance Summary

**PR:** #808  
**Branch:** test/l14-scan-accuracy-001  
**Head SHA:** 98bd233b9c83b9ed489f56e09d0ccaad25f76ad9  
**Date:** 2026-11-06  
**Reviewer:** Automated hardening pass (L14-SCAN-ACCURACY-001)

---

## Scope

Files changed or added in PR #808 (cumulative, all commits):

**Test files** (in `tests/test_scan_accuracy/`):
- `test_confidence_model.py` — confidence policy rules (18 tests; ruff fixes applied)
- `test_dns_email_accuracy.py` — DNS/email scanner known-answer tests (22 tests; SA-DNS-014 DEF-001 regression added; ruff fixes applied)
- `test_endpoint_accuracy.py` — endpoint inventory known-answer tests (12 tests; ruff fixes applied)
- `test_evidence_traceability.py` — evidence chain structure tests (14 tests; ruff fixes applied)
- `test_fva01_scope_enforcement.py` — FVA-01 scope enforcement audit (11 tests; NEW)
- `test_msgraph_accuracy.py` — Microsoft Graph / Entra tests (9 tests; ruff fixes applied)
- `test_network_scanner_accuracy.py` — network scanner known-answer tests (33 tests; ruff fixes applied)
- `test_oauth_ai_accuracy.py` — OAuth/AI governance accuracy tests (9 tests; ruff fixes applied)
- `test_confidence_severity_separation.py` — confidence/severity independence + DEF-003 regression (10 tests; NEW)
- `test_web_headers_accuracy.py` — web security headers known-answer tests (24 tests; ruff fixes applied)

**Audit documents** (in `docs/audits/`):
- `L14_SCAN_ACCURACY_BASELINE.md` — scenario table updated with DEF-001 regression note
- `L14_SCAN_ACCURACY_MANIFEST.json` — test counts updated (138→162), FVA-01 status corrected, new test file entries added
- `L14_SCAN_ACCURACY_PREMERGE_ASSURANCE.md` — this document (NEW)
- `L14_SCAN_AUDIT_CORRECTIONS.md` — no changes (pre-existing, correct)

**Assurance documents** (in `docs/assurance/`):
- `FROSTGATE_VERIFIED_ASSESSMENT_STANDARD.md` — FVA-01 corrected from IMPLEMENTED to PARTIALLY_IMPLEMENTED with code references; summary table updated
- `FROSTGATE_FINDING_CONFIDENCE_POLICY.md` — no changes (pre-existing, correct)

**Other**:
- `ROADMAP.md` — scanning roadmap added (pre-existing in PR)
- `docs/ai/PR_FIX_LOG.md` — updated (pre-existing in PR)
- `customer_one/offline_simulation_evidence.json` — rebound after hardening pass

---

## Test Coverage

- **Total accuracy tests:** 162 (all pass)
- **Detection scenario tests** (TP/TN/FP/FN ground truth): 109
  - network_scan: 33
  - dns_email: 22
  - web_headers: 24
  - microsoft_graph / endpoint_inventory / oauth_ai: 30
- **Boundary/contract tests** (API shape, error handling, evidence fields): 24
  - evidence_traceability.py: 14
  - boundary conditions in scanner files: ~10
- **Confidence model tests:** 18
- **Confidence/severity separation + DEF-003 regression:** 10
- **FVA-01 scope enforcement audit:** 11

All 162 tests pass. No pre-existing failures introduced by this hardening pass.

---

## Ground-Truth Measurement Boundaries

FIXTURE_VALIDATED: Outcomes measured against synthetic known-answer fixtures.  
LIVE_DETECTION_ACCURACY: NOT_MEASURED — no field validation has occurred.  
Fixture set size is small. Zero FP/FN in fixtures does not imply zero FP/FN in production.

Precision/recall from small fixture sets (N < 34 per scanner) must not be extrapolated to live detection performance. The numbers are validity checks on classification logic, not population statistics.

---

## FVA-01 Enforcement Verdict

**PARTIALLY_IMPLEMENTED**

**What is enforced (code-verified):**

1. `require_permission("scan.trigger")` — operator identity and permission enforced at every scan dispatch route (`api/field_assessment.py:4582, 4857, 5067`)
2. `get_engagement(db, engagement_id=..., tenant_id=...)` — compound WHERE clause on `(id, tenant_id)` prevents cross-tenant scan initiation (`services/field_assessment/store.py:103`)
3. `SafeTargetValidationService` — SSRF / private-range blocking: RFC1918, loopback, link-local, cloud-metadata targets rejected before any connection (`services/connectors/safe_target_validator.py`)
4. `_c6_write_audit_event(event_type="scan.initiated")` — scan audit event emitted at every scan dispatch (`api/field_assessment.py:4668, 4876, 5153`)
5. `acknowledgment_receipt_id` gate — Microsoft Graph scan requires signed acknowledgment receipt (`api/field_assessment.py:3610`)

**What is NOT enforced (gap for L14-SCAN-SAFETY-001):**

- No authorized target scope list per engagement. Any publicly routable host passes SSRF validation regardless of engagement's `client_domain`. An operator can scan any internet-routable IP/hostname during any engagement.
- No pre-approved target allowlist stored per engagement.
- No `acknowledgment_receipt_id` gate for DNS (`initiate_dns_email_scan`), network (`initiate_network_scan`), or web header (`initiate_web_headers_scan`) scanners.
- No check that target domains/IPs match the engagement's `client_domain` field.

---

## Finding Confidence Implementation Status

Policy: DOCUMENTED (`docs/assurance/FROSTGATE_FINDING_CONFIDENCE_POLICY.md`)  
Policy tests: PASS (18 tests in `test_confidence_model.py`)  
Runtime enforcement: NOT_IMPLEMENTED — no `confidence` field in runner-level finding output (all scanners)  
Default when field absent: NOT_ASSESSED (policy rule; tested in `test_confidence_severity_separation.py`)  
Pending: L14-SCAN-INTEGRITY-001 (add confidence field to runner outputs), L14-ASSESSMENT-ASSURANCE-001 (schema enforcement)

---

## Evidence Traceability Verdict

Scanner output → Normalized finding: TESTED (fixture level, `test_evidence_traceability.py`)  
Tenant isolation invariant: TESTED (`TestTenantIsolationInvariant`)  
Normalized finding → Report evidence: NOT_PROVEN (pending L14-SCAN-REPORT-PROOF-001)

---

## Three Deferred Defects

| ID | Description | Regression Fixture | Owning PR |
|----|-------------|-------------------|-----------|
| DEF-001 | DNS timeout indistinguishable from genuine record absence — both produce `missing_spf` / `missing_dmarc` finding | PRESENT — SA-DNS-010 (behavior documented) + SA-DNS-014 (dns.resolver.LifetimeTimeout propagation verified) in `test_dns_email_accuracy.py` | L14-SCAN-COMPLETENESS-001 |
| DEF-002 | Unknown last_seen timestamp classified as not-stale instead of INDETERMINATE | PRESENT — SA-EP-007 `TestStaleDeviceUnknownTimestamp` in `test_endpoint_accuracy.py` | L14-SCAN-COMPLETENESS-001 |
| DEF-003 | No confidence field in runner outputs — web_headers, dns_email, endpoint_inventory, network_scan, oauth all omit field | PRESENT — `TestRunnerConfidenceFieldAbsent` in `test_confidence_severity_separation.py` | L14-SCAN-INTEGRITY-001 |

---

## Unsupported Claims Corrected in This PR

From `docs/audits/L14_SCAN_AUDIT_CORRECTIONS.md`:

| ID | Issue | Status |
|----|-------|--------|
| COR-001 | Scanner counting: 14 "connectors" vs 9 independent + 1 pipeline + 4 stubs | CORRECTED |
| COR-002 | Test count additive overlap | CORRECTED |
| COR-003 | Missing detection effectiveness label (NOT_MEASURED) | CORRECTED |
| COR-004 | "SSRF-proof" / "completely secure" overclaim | CORRECTED |
| COR-005 | SHA-256 UUID != cryptographic integrity proof | CORRECTED |
| COR-006 | NIST AI RMF mapping != NIST certification | CORRECTED |
| COR-007 | dns_email SafeTargetValidationService gap misclassified | RECLASSIFIED |
| COR-008 | No confidence field in finding output | DOCUMENTED |

Additionally corrected in this hardening pass:
- FVA-01 status changed from IMPLEMENTED to PARTIALLY_IMPLEMENTED (corrects overclaim)
- Summary table in FROSTGATE_VERIFIED_ASSESSMENT_STANDARD.md updated (0 implemented, 3 partial, 3 policy-only)

---

## Security Gate Results

| Gate | Result |
|------|--------|
| `check_route_scopes.py` | PASS |
| `check_plane_registry.py` | PASS (WARNING: runtime-only routes — pre-existing) |
| `guard_no_raw_percent_in_sql.py` | PASS |
| `ruff check tests/test_scan_accuracy/ docs/assurance/` | PASS (after fixes to pre-existing unused imports across all 8 test files) |
| `git diff --check` | PASS |

---

## Remaining Operational Risks Before First Client

1. **Live detection effectiveness not measured** — all accuracy is fixture-validated only; zero FP/FN in fixtures does not guarantee zero in production
2. **FVA-01 client authorization not fully enforced** — any publicly routable target passes SSRF check; no per-engagement scope boundary (L14-SCAN-SAFETY-001)
3. **Confidence not emitted by runners** — all findings are implicitly NOT_ASSESSED until L14-SCAN-INTEGRITY-001 adds the field
4. **End-to-end report evidence gate not enforced** — scanner output → report evidence chain is tested at fixture level only; full enforcement pending L14-SCAN-REPORT-PROOF-001
5. **DNS/endpoint collection completeness gaps** — DEF-001 (DNS timeout == record absent at runner level), DEF-002 (unknown last_seen not INDETERMINATE), pending L14-SCAN-COMPLETENESS-001

---

## Merge Recommendation

READY_FOR_REVIEW

Rationale: All 162 tests pass, three deferred defect regression fixtures are present, FVA-01 overclaim is corrected to PARTIALLY_IMPLEMENTED with exact code references, all CI security gates pass, and no unsupported claims remain in the assurance documents. The five remaining operational risks are documented and tracked under named future PRs.
