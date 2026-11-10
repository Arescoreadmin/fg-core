# L14-PORTAL-TRUTH-001 — implementation record

**Baseline:** `d31cdf1a8811936b7b89e288ebcb3d772ad3f426` (origin/main, 2026-11-09)
**Branch:** `fix/l14-portal-truth-001`
**Status:** PARTIAL. The synthetic authenticated browser flow and required security/contract checks pass. A released report with collection gaps and production OIDC remain pilot acceptance work.

## Summary

This change scopes portal engagement listing to the engagement bound to the validated session, uses the Field Assessment report-state gate for report-list status, aligns the portal summary adapter with backend field names, and removes unsupported coverage/effort timing assertions. The synthetic authenticated browser flow validates the repaired states, but does not establish overall production pilot readiness.

## Canonical authority map

| Customer-visible value | Canonical owner | Portal mapping |
|---|---|---|
| Tenant/principal/session | `portal_user_authority.validate_session` or `PortalGrantService.validate_session`; tenant from authenticated context | BFF forwards server-held session; client tenant fields are ignored |
| Engagement identity/list | `fa_engagements` through `services.field_assessment.store` | List query and count filter to middleware-derived grant engagement before pagination |
| Finding identity/status/severity | `fa_normalized_findings` | `/field-assessment/engagements/{id}/findings` and summary; adapter maps canonical `id` to stable portal `finding_id` |
| Summary counts | `/field-assessment/engagements/{id}/summary` | Typed adapter maps canonical keys (`total_findings`, `open_findings_count`, `critical_findings_count`) with legacy aliases only where present |
| Report identity/revision/hash | `GovernanceReportRecord` and `services.governance.report.versioning` | Field Assessment list/detail plus the `/portal/engagement/reports` read-only adapter; both expose report ID, version and manifest hash |
| QA, qualification, release and provenance state | `_authoritative_report_state` backed by assessment assurance and report proof | Only canonical FINAL state maps to the green finalized badge; unknown states fail closed |
| Coverage denominator/status | Engagement questionnaire responses and released report proof | Questionnaire percentage is nullable without a denominator; collection proof is shown after release, otherwise explicitly unavailable without implying completeness |
| Remediation resolution | `fa_normalized_findings.status` and governed status update route | Resolution shown only from returned canonical status; effort and timing are unestimated |

## Root causes found

- **CZ-18:** grant middleware guarded object routes but let the bare engagement list reach a tenant-wide query/count. The grant session did not contribute its originating engagement to the list request scope.
- **CZ-19:** `/portal/engagement/reports` read from legacy Engagement Portal `FaReport` records, while the Reports page called Field Assessment routes. The workspace is now a thin Field Assessment adapter; both list paths return matching canonical identity/state/hash. Portal-origin requests require the middleware-derived engagement binding.
- **CZ-24:** the Field Assessment report-list route derived `finalized` from `is_finalized`, bypassing independent QA, qualification, provenance and release blockers. The portal rendered `compiled_by` verbatim.
- **CZ-25:** backend summary emits `total_findings`, `open_findings_count` and `critical_findings_count`; portal types expected `normalized_findings`, `open_findings` and `critical_findings`, producing undefined card values and false completion language.

## Implemented controls

- Grant sessions are resolved to their exact originating active, unexpired grant. Revoked, expired, missing or cross-tenant grant records fail closed. Portal engagement list filtering and counts are applied at query time before pagination.
- Unbound named-user memberships no longer imply tenant-wide access. The existing role model does not include a canonical tenant-admin entitlement, so no broad scope is inferred.
- Report-list status now calls the same authoritative QA/qualification/provenance state evaluator used by report content access. Unknown states map to `unknown`; synthetic, rejected, pending QA and release-blocked states are explicit. Customer metadata omits raw compiler/reviewer principal identifiers. `/portal/engagement/reports` is a read-only adapter over those same records; legacy tenant-wide portal workspace routes fail closed for grant-scoped sessions.
- Summary keys are mapped through a typed portal adapter. Missing metrics remain unavailable, and dashboard completion requires authoritative resolved and total counts.
- Dashboard critical findings are styled as active risk, not as an application error. Finding IDs are normalized at the API boundary to prevent unstable React keys.
- Remediation coverage uses actual questionnaire responses as denominator and remains unavailable when none exist. Unsupported effort levels and day windows are no longer presented as estimates.
- Login shell navigation is displayed only when the server verifies the portal session. Access-denied errors use customer-safe language. Finding list items use stable identities.

## Verification

- Final targeted Python regression set: 274 passed across portal-truth, engagement-report, customer-zero journey/browser harness, assessment-assurance, report proof/preview/delivery, portal grants and tenant isolation.
- Portal tests: 85 passed, 0 failed.
- Portal lint: passed.
- Portal production build: passed (32 routes).
- Authenticated browser acceptance: synthetic Northstar grant-secret flow; 11/11 checks passed. Screenshots, network trace, console events and matrix are in `/tmp/portal-truth-browser-final5` (generated synthetic evidence, not committed).
- Browser evidence: login 200; 14 finding records; one engagement visible; unauthorized engagement and writes return 403; post-logout navigation returns to login; report-list and workspace ID/version/hash match; report state is `synthetic_draft`; author identity is redacted; dashboard shows 14 open findings and 2 critical; engagement shows 14 open and 0 resolved. Remediation uses unestimated effort/timing. Coverage says unreleased proof details are unavailable without implying complete coverage. No unexpected console errors after excluding expected policy denials and optional-resource 404s.
- Restricted draft download returned 403 as required. A second engagement with assessor-enabled draft review returned an 11,827-byte PDF through the BFF with a valid PDF header/xref, zero UTF-8 replacement bytes, visible DRAFT marking, and relayed state, manifest hash, report ID, report version and content disposition matching the canonical report list.
- `make fg-security`: passed (1,343 passed, 1 skipped); its canonical required-tests gate passed.
- `make fg-contract`: passed after the existing contract-authority refresh workflow updated generated OpenAPI mirrors and authority markers.
- Route-scope check: passed. Plane registry: passed with pre-existing runtime-only route warning. SQL percentage guard: passed. Ruff, targeted mypy and `git diff --check`: passed.
- Isolated SQLite query microbenchmarks (20 reads per case): 1/100/1,000 engagement tenants averaged 0.181/0.096/0.095 ms for one-engagement filtered listing; a 100-row page among 500 findings averaged 0.903 ms; listing 25 report revisions averaged 0.212 ms. These are local microbenchmarks, not production latency guarantees. No schema changes or migrations introduced.

## Remaining limitations and pilot impact

- Browser acceptance used development grant-secret login, not production OIDC named-user identity.
- Collection limitations from report proof appear after an authorized report is released. For the unreleased draft the portal explicitly reports that details are unavailable; pilot acceptance still needs a released report with actual collection failures.
- Local microbenchmarks do not cover PostgreSQL under concurrent production load, response size, caching, or more than 25 report revisions.
- The referenced `FROSTGATE_CORE_AUDIT_2026-11-09.md` was not present in the repository, so FG-AUD-004 is not declared reconciled. The dedicated customer-zero acceptance document records CZ-18/19/24/25; the broader audit remains open.
- This PR does not close production identity, frontend dependency security, signing, scanner execution, backup, or overall release acceptance work.

**Pilot readiness:** PARTIAL. CZ-18/19/24/25 and restricted/permitted draft download paths passed the synthetic browser probes. A released report with collection gaps and production OIDC remain to be validated; the broader audit and overall release acceptance remain open.
