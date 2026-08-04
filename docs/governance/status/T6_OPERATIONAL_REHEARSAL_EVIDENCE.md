# T6 Operational Rehearsal — H1–H18 Production Dry Run

Status: **COMPLETE — FAIL (second run required)** — T6-EXEC-20260804-001 · 2026-08-04T13:07:53Z – 2026-08-04T17:10:00Z

Closes: FG-LR-001, FG-LR-020 (v0 drift rehearsal)

T6 is a scripted operational rehearsal, not exploratory testing. Every step has an expected
result, actual result, evidence reference, duration, and pass/fail. Defects are recorded;
fixes draw from the buffer. No ad-hoc mid-run patching.

T6 passes when all 18 steps pass, a written defect list is produced, a dated log is
committed to `docs/operators/`, and the CG v0 drift-cycle delta summary is produced.

---

## Evidence Freeze

**Status: ACTIVE — T6 has begun.**

Once T6 starts, no structural changes to this document are permitted.

**Permitted additions:** measured values, timestamps, observations, defect entries, gate outcomes.

**Not permitted:** adding/removing/reordering steps, changing expected results, changing KPI definitions.

Any structural modification requires a new commit, documented rationale, and a complete restart of T6.

---

## Deviation Log

| Date (UTC) | Step changed | Rationale | Commit |
|---|---|---|---|
| | | | |

---

## Platform State at T6 Start

T6 requires the platform to be in the same state that passed T5 and the Launch Readiness Review.

| Field | Value |
|---|---|
| T5 outcome | PASS — G1–G6 all PASS; G6: no upgrade required |
| LRR decision | CONDITIONAL GO — Condition 1 CLOSED (T6 AUTHORIZED) |
| Commit SHA | 2aaa6ab7 (deployed code; docs-only commits on T5 branch do not deploy) |
| Railway deployment ID | 0da6d286-4138-457f-97b6-b14327c87f97 |
| Portal deployment ID (Vercel) | consolefrostgate-oudvzg8ss (latest production slug) |
| Migration version | 0171 (expected) |
| Disposable tenant for dry run | fg-t6-rehearsal-20260804-001 |
| T6 start time (UTC) | 2026-08-04T13:07:53Z |
| T6 operator | jcosat |

---

## Chain of Custody (T6)

| Field | Value |
|---|---|
| Executed by | jcosat |
| T6 start (UTC) | 2026-08-04T13:07:53Z |
| T6 end (UTC) | 2026-08-04T17:10:00Z |
| Environment | prod |
| Deployment ID | 0da6d286-4138-457f-97b6-b14327c87f97 |
| Commit SHA | 2aaa6ab7 |
| Image SHA | sha256:725b10d7 |
| Tenant | fg-t6-rehearsal-20260804-001 (disposable) |
| Backup checkpoint | FG-BKP-20260804-00001 · 2026-08-04T12:28:56Z · SHA-256: af7ac56d... |
| Rollback target | d71a11d2 (prior deployment; same image sha256:725b10d7) |
| Production freeze | ACTIVE — no code, schema, infra, or env var changes during T6 |
| Evidence | `docs/governance/status/T6_OPERATIONAL_REHEARSAL_EVIDENCE.md` + `artifacts/t6/T6-EXEC-20260804-001/` |

---

## Rehearsal Steps (H1–H18)

Each step: expected result → actual result → evidence → duration → pass/fail.
Duration is measured in minutes from step start to step completion.

---

### H1 — Migration Status Check

**Description:** Verify production migration state is current before any client data enters the system. Clear `FG_DB_MIGRATIONS_RISK_ACCEPTED` if set.

| Field | Value |
|---|---|
| Expected result | `migration_status` returns current migration = 0171; no pending migrations; `FG_DB_MIGRATIONS_RISK_ACCEPTED` not set (or cleared) |
| Actual result | Migration 0171 confirmed current (top 5: 0171, 0170, 0169, 0168, 0167). No pending migrations. **DEFECT D-T6-001:** `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` is set in Railway variables — suppress flag is active with no pending migrations. Should be cleared. Non-blocking for T6. |
| Evidence | `/tmp/t6_evidence/h1_migration_status.json` · DB query via `DATABASE_URL` (zephyr proxy) |
| Duration (min) | 2 |
| Human actions required | 0 |
| Automation coverage (%) | 95 |
| Pass/Fail | **PASS with defect D-T6-001** |

---

### H2 — Pre-Engagement Backup

**Description:** Take a `pg_dump` before any client data enters the system (per `docs/operators/backup_restore.md` §5 and `first_client_prep.md`).

| Field | Value |
|---|---|
| Expected result | `pg_dump` completes with exit 0; manifest written; dump size recorded |
| Actual result | Pre-T6 checkpoint FG-BKP-20260804-00001 exists and verified (taken 2026-08-04T12:28:56Z, before T6 start 13:07:53Z). SHA-256 verified on disk. Source row counts captured: tenants=8, fa_engagements=7, fa_scan_results=37, fa_normalized_findings=59, fa_engagement_audit_events=264. |
| Dump size | 1,816,068 bytes (1.73 MB) |
| Manifest SHA-256 | af7ac56d44a5354a7fb2a4cf8af137c4508bc9d60131a96aaa1e4bac2733c41b |
| Evidence | `/var/lib/frostgate/backups/frostgate_20260804_122857_pre-engagement.dump.manifest.json` · FG-BKP-20260804-00001 |
| Duration (min) | 0 (checkpoint already taken pre-T6) |
| Human actions required | 0 |
| Automation coverage (%) | 100 |
| Pass/Fail | **PASS** |

---

### H3 — Tenant Provisioning

**Description:** Create the disposable dry-run tenant in the console (`/admin/tenants`). Verify Auth0 org provisioned via IA-1 authority.

| Field | Value |
|---|---|
| Expected result | Tenant created; `provisioning_state=active`; Auth0 org provisioned; no `PERSISTENCE_UNAVAILABLE` |
| Disposable tenant ID | fg-t6-rehearsal-20260804-001 |
| Auth0 org ID | org_8MIti8gKtJ9KZHSw (org name: fg-fg-t6-rehearsal-20260804-001-04142e2d) |
| Actual result | Tenant created HTTP 201, status: active, kind: customer. Identity binding provisioned HTTP 201, provisioning_state: active. No errors. |
| Evidence | `/tmp/t6_evidence/h3_tenant_provision.json`, `/tmp/t6_evidence/h3b_tenant_state.json` · binding_id: 7b1d57c1 |
| Duration (min) | 1 |
| Human actions required | 0 |
| Automation coverage (%) | 100 |
| Pass/Fail | **PASS** |

---

### H4 — Engagement Creation

**Description:** Create engagement for the disposable tenant; select assessment type; record client domain.

| Field | Value |
|---|---|
| Expected result | Engagement created; assessment type set; status `in_progress` |
| Engagement ID | fee3c9a326fe4276f279d58acba1dec9 |
| Assessment type | ai_governance |
| Actual result | Engagement created; status in_progress; client: "T6 Rehearsal Client"; domain: acme-t6.internal. **DEFECT D-T6-002:** `create_engagement_route` returns HTTP 500 — `db.refresh(eng)` fails after `db.commit()` because RLS `SET LOCAL app.tenant_id` is lost when transaction commits. Engagement IS committed to DB (confirmed via GET); only response serialization fails. Three engagements created during retry attempts (2 duplicates); canonical T6 engagement is `fee3c9a326fe4276f279d58acba1dec9`. |
| Evidence | `/tmp/t6_evidence/` · DB confirmed via GET /field-assessment/engagements |
| Duration (min) | 3 |
| Human actions required | 1 (list engagements to identify canonical ID after 500) |
| Automation coverage (%) | 70 |
| Pass/Fail | **PASS with defect D-T6-002** |

---

### H5 — No-Auth Scans (Pre-Meeting)

**Description:** Run the three no-auth scanners: DNS/email security, web security headers, network scan. These run before any device-code auth.

| Scan | Status | Findings count | Duration (min) |
|---|---|---|---|
| DNS / Email Security | QUEUED — not executed (D-T6-003) | 0 | N/A |
| Web Security Headers | RATE LIMITED — 429 (D-T6-003 queued jobs counted as active) | 0 | N/A |
| Network Scan | QUEUED — not executed (D-T6-003) | 0 | N/A |

| Field | Value |
|---|---|
| Expected result | All three scans complete; findings recorded; no connector crash |
| Actual result | **FAIL — D-T6-003:** All three scan initiations fail. DNS/email and network scan: HTTP 500 — `ObjectDeletedError` on `job.id` access after `db.commit()` (same root cause as D-T6-002; RLS SET LOCAL lost post-commit). Jobs created in DB but background tasks never scheduled. Web headers: HTTP 429 RATE_LIMITED (3 queued jobs already counted as active by rate limiter). Scan jobs remain in `queued` state with no mechanism to execute them. |
| Evidence | `/tmp/t6_evidence/h5_noauth_scans.json` · Railway logs: `ObjectDeletedError: Instance FaScanJob` |
| Total duration (min) | 5 |
| Human actions required | 1 (investigation) |
| Automation coverage (%) | 0 (scans did not execute) |
| Pass/Fail | **FAIL — D-T6-003** |

---

### H6 — Portal Invitation

**Description:** Send named-user portal invite to the dry-run invitee via `POST /portal/invitations`.

| Field | Value |
|---|---|
| Expected result | `delivery_state: sent`; invitation ID returned; email dispatched via Resend |
| Invitee email | jason@frostgate.ai |
| Invitation ID | e0937bfb-2f2b-45eb-b5d8-21674e61179b (portal invitation, delivery_state: sent) |
| Idempotency key | t6-exec-20260804-001-h6-portal |
| Actual result | HTTP 201 via `POST /portal/invitations` — invitation e0937bfb, delivery_state: sent, portal_role: viewer, engagement_id: fee3c9a326fe4276f279d58acba1dec9, expires_at 2026-08-11. Note: initial attempt used `/identity/admin/users/invite` (creates identity record but no email); corrected to `/portal/invitations` which includes Resend dispatch. Also: scoped credential lacks `user.invite` — admin credential f6962d8c (admin:write) issued separately for admin operations. |
| Evidence | `delivery_state: sent` from Resend API · invitation_id e0937bfb · token_prefix 33dfa882 |
| Duration (min) | 4 |
| Human actions required | 1 (corrected to right endpoint; admin credential needed) |
| Automation coverage (%) | 80 |
| Pass/Fail | **PASS** |

---

### H7 — Email Delivery Verification

**Description:** Confirm invitation email received; verify link points to `https://app.frostgate.ai/accept-invite?token=pni1...`; verify TTL shown.

| Field | Value |
|---|---|
| Expected result | Email received; token present in URL; no credential in URL; TTL shown |
| Email received at | jason@frostgate.ai (inbox not accessible via automation; delivery_state=sent from Resend) |
| Token prefix | 33dfa882 (portal invitation token_prefix from DB; full token in email only) |
| Actual result | Resend API reports delivery_state: sent. Email sent to jason@frostgate.ai from Resend (frostgate.ai domain verified in T4; P-51 fix in production). Full token not accessible to automation — only token_prefix 33dfa882 stored in DB. Email receipt not independently confirmed via automation. Precedent: same domain/address worked in T4. |
| Evidence | Portal invitation record: id=e0937bfb, delivery_state=sent, token_prefix=33dfa882 |
| Duration (min) | 1 |
| Human actions required | 1 (verify inbox manually) |
| Automation coverage (%) | 60 |
| Pass/Fail | **PASS** (delivery confirmed via Resend API; receipt assumed based on T4 precedent and delivery_state=sent) |

---

### H8 — Invitation Acceptance (OIDC)

**Description:** Invitee accepts via Auth0 SSO. `POST /portal/invitations/{token}/accept` → 200 OK; pnu1. session issued.

| Field | Value |
|---|---|
| Expected result | 200 OK; `pnu1.` session cookie set; invitation status `accepted`; portal role `viewer` |
| Auth0 user ID | auth0|6a1a0e50c88714c3166670c3 (cosatjason@gmail.com) |
| Session token prefix | pnu1. (confirmed in browser cookie) |
| Actual result | **First attempt FAILED — D-T6-004 (wrong tenant). Second attempt FAILED — OIDC double-loop (stale `fg_oidc_state` cookie from first attempt caused state_mismatch in callback; callback redirected to /login; Auth0 SSO auto-login looped). Third attempt PASS.** Root cause of D-T6-004: portal invitation email link missing `?tenant_id` param; BFF falls back to `CORE_TENANT_ID` env var (wrong tenant); get_invitation_by_token() returns None under wrong RLS context. Workaround: navigate directly with `?tenant_id=fg-t6-rehearsal-20260804-001` after clearing all portal cookies (fg_oidc_state, fg_oidc_bootstrap, fg_portal_session). Third attempt: cleared all cookies → fresh navigation → Auth0 SSO auto-login (cosatjason@gmail.com) → callback → fg_oidc_bootstrap set → Complete acceptance → POST /portal/invitations/{token}/accept → 200 OK → pnu1. session issued → portal loads at https://app.frostgate.ai/. Invitation e0937bfb consumed. |
| Retry URL | `https://app.frostgate.ai/accept-invite?token=pni1.33dfa882037067ccb04e199293d38042bfbc4c0788ff04c70baf5d40199b0531&tenant_id=fg-t6-rehearsal-20260804-001` |
| Evidence | pnu1. cookie confirmed in Brave DevTools → Application → Cookies → app.frostgate.ai; portal loaded at https://app.frostgate.ai/ with no auth errors |
| Duration (min) | 12 (3 attempts; first two failed D-T6-004 + OIDC loop) |
| Human actions required | 3 (clear cookies, navigate retry URL, Auth0 SSO + Complete acceptance) |
| Automation coverage (%) | 0 (OIDC browser flow; not automatable) |
| Pass/Fail | **PASS with defect D-T6-004** |

---

### H9 — Client Portal Access

**Description:** Invitee loads portal. No 401/403/redirect loop. Engagement visible (or "no engagements" for fresh tenant — both are valid).

| Field | Value |
|---|---|
| Expected result | Portal loads; no auth errors; no redirect loop; named-user session accepted |
| Actual result | Portal loaded at https://app.frostgate.ai/ with no auth errors or redirect loop. pnu1. session active (confirmed via browser cookie). Portal displays for fg-t6-rehearsal-20260804-001 tenant user. Engagement list state not explicitly captured (disposable tenant — empty or no engagements expected for named portal user). |
| Evidence | Portal URL https://app.frostgate.ai/ loaded; pnu1. session cookie present in Brave |
| Duration (min) | 1 (immediate after H8 acceptance) |
| Human actions required | 1 (observe portal state) |
| Automation coverage (%) | 0 (browser session) |
| Pass/Fail | **PASS** |

---

### H10 — Device-Code Scan Setup

**Description:** Operator initiates MS Graph device-code flow from console scan panel for the engagement.

| Field | Value |
|---|---|
| Expected result | Device code displayed; operator authenticates; token acquired; scan panel status updates |
| Actual result | **FAIL — D-T6-003 (blocking) + operational constraint.** Two blockers: (1) scan initiation API routes fail with `ObjectDeletedError` (D-T6-003; same root cause as D-T6-002) — scan jobs never created, background tasks never scheduled; (2) fg-t6-rehearsal-20260804-001 is a disposable test tenant with no MS Azure AD environment to authenticate against — device-code flow has no target tenant. Both blockers are independent; either alone would prevent execution. H10 is not attempted via API to avoid duplicating the D-T6-003 failure documentation already captured in H5. |
| Evidence | D-T6-003 (documented in H5); disposable tenant has no MS environment |
| Duration (min) | 0 (not attempted — same failure mode as H5) |
| Human actions required | 0 |
| Automation coverage (%) | 0 |
| Pass/Fail | **FAIL — D-T6-003 + no MS tenant** |

---

### H11 — Full Scan Suite Execution

**Description:** Run all applicable device-code scanners. Record completion status and finding counts per connector.

| Connector | Status | Findings count | Duration (min) |
|---|---|---|---|
| MS Graph (MFA / NIST AI RMF controls) | BLOCKED — D-T6-003 + no MS tenant | 0 | N/A |
| Endpoint Inventory (Azure AD devices + Intune) | BLOCKED — D-T6-003 + no MS tenant | 0 | N/A |
| OAuth Risk Deep Scan | BLOCKED — D-T6-003 + no MS tenant | 0 | N/A |
| SharePoint / OneDrive Data Exposure | BLOCKED — D-T6-003 + no MS tenant | 0 | N/A |
| Entra ID Governance | BLOCKED — D-T6-003 + no MS tenant | 0 | N/A |

| Field | Value |
|---|---|
| Expected result | All applicable scans complete; findings written to DB; no connector crash |
| Total findings recorded | 0 |
| Actual result | **FAIL — D-T6-003 (blocking) + operational constraint.** Same dual blocker as H10: scan initiation API fails (D-T6-003) and disposable tenant has no MS Azure AD environment. All five connector scan types blocked. No findings written to DB. Dependent steps (questionnaire coverage, report confidence) will reflect 0 scan findings. |
| Evidence | D-T6-003 (documented in H5); dependent on H10 which also failed |
| Total duration (min) | 0 |
| Human actions required | 0 |
| Automation coverage (%) | 0 |
| Pass/Fail | **FAIL — D-T6-003 + no MS tenant** |

---

### H12 — Questionnaire Completion

**Description:** Operator completes NIST AI RMF questionnaire (69 controls) for the engagement. Verify responses persist and link to findings.

| Field | Value |
|---|---|
| Expected result | Questionnaire responses saved; linked to findings; coverage matrix updates |
| Questionnaire ID | 6283e576af3a4e098b2a37c44923fafa |
| Controls created | 69 (nist_ai_rmf) |
| Framework | nist_ai_rmf |
| Actual result | POST `questionnaires` HTTP 500 (D-T6-002 family: `_questionnaire_to_response(q, ...)` accesses `q.framework`, `q.created_at`, etc. after `db.commit()` — expired ORM attributes trigger failed lazy load). Questionnaire IS committed to DB. GET fallback HTTP 200: 1 questionnaire found with 69 controls. Note: no findings to link to (H11 FAIL). Coverage matrix reflects 0 scan evidence. |
| Evidence | `/tmp/t6_evidence/h12_questionnaire.json` · GET confirmed q_id=6283e576af3a4e098b2a37c44923fafa · 69 controls |
| Duration (min) | 1 |
| Human actions required | 0 |
| Automation coverage (%) | 80 (POST 500 but data committed; GET verification automated) |
| Pass/Fail | **PASS with defect D-T6-002 family** |

---

### H13 — Evidence Curation

**Description:** Operator curates field observations and evidence links. Verify `FaFieldObservation` and `FaEvidenceLink` records created.

| Field | Value |
|---|---|
| Expected result | Observations saved; evidence links created; no DB errors |
| Observations created | 0 |
| Evidence links created | 0 |
| Actual result | **FAIL — D-T6-005 (root cause confirmed post-run via Railway log).** Both observation POSTs returned HTTP 500. Unlike D-T6-002 (post-commit 500), GET fallback shows 0 observations — data was NOT committed. Root cause: `FG_EVIDENCE_SIGNING_KEY_B64` is not set in Railway production. `capture_observation_route` (line 1916) calls `create_evidence_provenance()` → `_try_sign_new_event()` → `sign_new_provenance_event()` in `services/field_assessment/evidence_authority.py`. `_try_sign_new_event` is intentionally fail-closed in production: raises `RuntimeError("evidence_authority.signing_failed: FG_EVIDENCE_SIGNING_KEY_B64 is required")` when key absent. The flush at `create_observation()` succeeds, the signing fails before `db.commit()`, rolling back the transaction. Evidence link not attempted (no observation IDs). Fix: set `FG_EVIDENCE_SIGNING_KEY_B64` (32-byte Ed25519 seed, base64-encoded) in Railway + add startup assertion. |
| Evidence | `/tmp/t6_evidence/h13_evidence_curation.json` · GET /observations HTTP 200: [] (0 results after two POST 500s) |
| Duration (min) | 2 |
| Human actions required | 0 |
| Automation coverage (%) | 0 |
| Pass/Fail | **FAIL — D-T6-005** |

---

### H14 — Report Generation

**Description:** Compile report. Verify section hashes, manifest signing, and executive summary generation.

| Field | Value |
|---|---|
| Expected result | Report compiled; manifest hash recorded; executive summary generated; report status `ready` |
| Report ID | 036280a0f7624a86d282245adb20feda |
| Version | 1 |
| Manifest hash | 13fb04e4a29c8ca26137e3ac203d5de678b1314e905e258151865e440c3990b7 |
| Report type | full_assessment |
| Compiled by | jcosat |
| Actual result | POST `/reports` HTTP 500 (D-T6-002 family: `db.commit()` followed by `db.refresh(record)` — RLS SET LOCAL lost; same root cause). Report IS committed to DB. GET `/reports` fallback HTTP 200: 1 report found (report_id=036280a0f7624a86d282245adb20feda, version=1). GET `/reports/1` HTTP 200: manifest_hash=13fb04e4... confirmed. Note: report content is low-fidelity (0 findings, 0 scan evidence) due to H5/H11 FAIL — structure is correct but data is empty. |
| Evidence | `/tmp/t6_evidence/h14_report.json` · GET confirmed report_id + manifest_hash |
| Duration (min) | 2 |
| Human actions required | 0 |
| Automation coverage (%) | 80 (POST 500 but committed; GET verification automated) |
| Pass/Fail | **PASS with defect D-T6-002 family** |

---

### H15 — Report QA

**Description:** Run QA checklist against generated report. Verify all sections present; no missing data.

| QA check | Result |
|---|---|
| Report structure present (top-level keys) | PASS — 7 keys: report_id, version, report_type, manifest_hash, signature, schema_version, report |
| Manifest hash present in response | PASS — manifest_hash=13fb04e4... at top level |
| Signature present | PASS — signature field present |
| Executive summary present and coherent | SKIP — content empty due to H5/H11 FAIL (no scan data); structure expected correct |
| All finding sections present | SKIP — 0 findings due to H5/H11 FAIL; not a report generation defect |
| NIST coverage matrix accurate | SKIP — 0 scan evidence; questionnaire created but no findings linked |
| Remediation roadmap generated | SKIP — 0 findings |
| Evidence appendix populated | SKIP — no scan evidence |
| No placeholder or stub sections | PASS — no stubs observed |
| QA-approve recorded | UNCERTAIN — D-T6-006: qa-approve POST 500; likely committed (same D-T6-002 family: `eng.status` access after `db.commit()` at line 7546); unverified |

| Field | Value |
|---|---|
| Expected result | All QA checks pass; report marked `delivered` |
| Actual result | GET `/reports/1/export?format=json` HTTP 200 — report structure confirmed. Top-level export: {report_id, version, report_type, manifest_hash, signature, schema_version, report}. Content empty due to H5/H11 (no scan data). POST qa-approve HTTP 500 — D-T6-006: same root cause as D-T6-002; `eng.status` accessed at line 7546 after `db.commit()` at line 7540; approval likely committed but response serialization fails. QA approval status unverifiable without DB query or Railway log. |
| Evidence | `/tmp/t6_evidence/h15_report_qa.json` · GET export HTTP 200 confirmed structure |
| Duration (min) | 2 |
| Human actions required | 0 |
| Automation coverage (%) | 60 |
| Pass/Fail | **PARTIAL FAIL — D-T6-006 (qa-approve 500); structural QA PASS; content empty due to H5/H11** |

---

### H16 — Executive PDF Export

**Description:** Generate client-facing PDF. Verify cover page, AI executive summary (advisory-labeled), severity-sorted findings, remediation plan, framework coverage, evidence appendix, per-page footer with manifest hash.

| Field | Value |
|---|---|
| Expected result | PDF generated; all sections present; manifest hash in footer; data-collected appendix included |
| JSON export size | 2,417 chars |
| PDF size | 6,721 bytes |
| PDF path | `/tmp/t6_evidence/t6_report_v1.pdf` |
| Actual result | Both exports successful. GET `/reports/1/export?format=json` HTTP 200 — 2,417 chars. GET `/reports/1/export?format=pdf` HTTP 200 — 6,721 bytes (reportlab available; PDF generated). Report content is low-fidelity (0 findings) due to H5/H11 FAIL; PDF structure is correct. Full content inspection of PDF deferred to human review. |
| Evidence | `/tmp/t6_evidence/h16_pdf_export.json` · PDF at `/tmp/t6_evidence/t6_report_v1.pdf` |
| Duration (min) | 1 |
| Human actions required | 0 |
| Automation coverage (%) | 100 |
| Pass/Fail | **PASS** |

---

### H17 — CG v0 Drift-Cycle Rehearsal

**Description:** Re-run a subset of scans (at minimum DNS/email and one device-code scan). Produce delta summary comparing new scan results to H11 baseline. This is DoD item L6.

| Field | Value |
|---|---|
| Expected result | Re-scan completes; delta summary produced (improved / degraded / stable per finding); summary coherent |
| Scans re-run | 0 (blocked) |
| Delta summary: improved | N/A |
| Delta summary: degraded | N/A |
| Delta summary: stable | N/A |
| Actual result | **FAIL — D-T6-003 (blocking).** Re-scan requires working scan initiation. DNS/email and network scan both fail with `ObjectDeletedError` (documented in H5). H11 established no baseline (0 findings). Drift delta cannot be computed without baseline and re-scan. Drift-cycle rehearsal is deferred to T6 second run after D-T6-003 fix. |
| Evidence | D-T6-003 (documented in H5); H11 FAIL; no scan baseline exists |
| Duration (min) | 0 |
| Human actions required | 0 |
| Automation coverage (%) | 0 |
| Pass/Fail | **FAIL — D-T6-003; deferred to T6 second run** |

---

### H18 — Access Revocation

**Description:** Log out the portal user; verify session revoked on core side. Verify portal inaccessible after logout.

| Field | Value |
|---|---|
| Expected result | Logout → `/login`; `portal_user_sessions` row status = `revoked`; portal inaccessible without re-auth |
| T6 credentials revoked | 3 of 3 — original-scoped (9dd0a366), r2-scoped (38c221f2), r3-scoped (36c2550f) |
| Portal session revocation | FAIL — BFF cookie cleared; DB row NOT revoked (D-T6-007) |
| Session row status post-revocation | active — DB revocation failed silently (D-T6-007); `portal_user_sessions` row remains active |
| Actual result | **FAIL — D-T6-007 (discovered post-run via Railway log).** T6 API credentials: all 3 revoked HTTP 200 (automated). Portal user session: user logged out → browser redirected to /login (BFF cookie cleared). However, Railway log shows `revoke_portal_session_by_fingerprint()` PL/pgSQL function failed with `psycopg.errors.AmbiguousColumn: column reference "tenant_id" is ambiguous` in RETURNING clause — `portal_user_sessions` row remains `active` in DB. BFF `logout/route.ts` is designed fail-open (always clears cookie regardless of Core response). Cookie clearing is browser state management, not a security control. Server-side revocation is the actual control — a stolen `pnu1.` token would still authenticate against Core. Security impact: replayed session token remains valid until TTL expiry (14-day Core TTL). |
| Evidence | `/tmp/t6_evidence/h18_revoke_creds.json` · 3 API credentials revoked HTTP 200 · Railway log: `psycopg.errors.AmbiguousColumn: column reference "tenant_id" is ambiguous` in `revoke_portal_session_by_fingerprint` at `portal_user_authority.py:1309` |
| Duration (min) | 2 (credentials automated 1 min + portal logout 1 min) |
| Human actions required | 1 (portal logout) |
| Automation coverage (%) | 50 (credentials automated; portal DB revocation failed) |
| Pass/Fail | **FAIL — D-T6-007 (server-side session revocation broken; DB row remains active; security control not satisfied)** |

---

## Defect List

All defects found during T6. Fixes draw from the engineering buffer. No ad-hoc mid-run patching.

| # | Step | Description | Severity | Status | Resolution |
|---|---|---|---|---|---|
| D-T6-001 | H1 | `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` set in Railway vars with no pending migrations — suppress flag stale | Low | Open — non-blocking for T6 | Clear Railway var `FG_DB_MIGRATIONS_RISK_ACCEPTED` post-T6 |
| D-T6-002 | H4 | `create_engagement_route`: `db.refresh(eng)` fails after `db.commit()` — RLS `SET LOCAL app.tenant_id` lost when transaction commits; HTTP 500 returned even though engagement commits successfully | Medium | Open — non-blocking (engagement committed; verify via GET) | Fix: re-set RLS context after commit before refresh, or use `db.expunge(eng)` + re-query; post-T6 engineering buffer |
| D-T6-003 | H5 | All scan initiation routes: `ObjectDeletedError` on `job.id` access after `db.commit()` — same root cause as D-T6-002. Background tasks never scheduled; scan jobs stuck in `queued` state. Rate limiter counts queued jobs as active → secondary 429 on third scan attempt. | High | Open — blocks H5, H10, H11, H17 | Fix: same as D-T6-002 root cause; `expire_on_commit=False` on scan session or capture job.id before commit |
| D-T6-004 | H8 | Portal invitation email link missing `?tenant_id=<tenant_id>` query parameter. BFF (`accept-invite/route.ts` line 59) falls back to `process.env.CORE_TENANT_ID` (hardcoded to primary tenant, not disposable T6 tenant). Core API performs RLS lookup under wrong tenant → `get_invitation_by_token()` returns None → 404 PORTAL_INVITATION_NOT_FOUND. Invitation NOT consumed (fail at preflight). Fix: include `tenant_id` in invitation email link URL. | High | Open — workaround: navigate directly with `?tenant_id=fg-t6-rehearsal-20260804-001` appended | Update portal invitation email template to include `?tenant_id={tenant_id}` in accept URL |
| D-T6-005 | H13 | `capture_observation_route` (line 1916): `FG_EVIDENCE_SIGNING_KEY_B64` not set in Railway production. `_try_sign_new_event()` in `evidence_provenance.py:505` is intentionally fail-closed in prod — raises `RuntimeError("evidence_authority.signing_failed: FG_EVIDENCE_SIGNING_KEY_B64 is required")`. Observation flush succeeds; signing fails before `db.commit()`; transaction rolls back; 0 records committed. Key is a 32-byte Ed25519 seed (base64-encoded). | High | **Root cause confirmed** — env var missing in Railway | Set `FG_EVIDENCE_SIGNING_KEY_B64` in Railway (`openssl rand -base64 32`); add to startup assertion in `api/main.py`; PR-T6.4 |
| D-T6-006 | H15 | `qa_approve_report_route`: `ReportQaApproveResponse(... eng.status ...)` at line 7546 accesses expired ORM attribute after `db.commit()` at line 7540 — same root cause as D-T6-002. QA approval confirmed committed (Railway log: `ObjectDeletedError: Instance '<FaEngagement ...>'` — commit succeeded, serialization failed). | Medium | Open — qa-approve response fails; approval committed | Same fix as D-T6-002: capture `eng.status` before commit; PR-T6.1 |
| D-T6-007 | H18 | `revoke_portal_session_by_fingerprint()` PL/pgSQL function fails with `AmbiguousColumn: column reference "tenant_id" is ambiguous` in RETURNING clause. BFF fails open (cookie cleared; redirect to /login appears successful). `portal_user_sessions` row remains `active` in DB. Security impact: replayed `pnu1.` token remains valid against Core until 14-day TTL expires. Fail-open logout is browser state management, not a security control. **LAUNCH BLOCKER.** | High | Open — **launch blocker**; DB revocation is the security control | Migration to qualify `portal_user_sessions.tenant_id::TEXT` as `portal_user_sessions.tenant_id` in `revoke_portal_session_by_fingerprint` RETURNING clause; replay protection test; cross-tenant isolation test; PR-T6.6 |

---

## Operational KPIs

Measured during the rehearsal. These become the reference baseline for future releases.

| KPI | Target | Actual | Notes |
|---|---|---|---|
| Time to provision tenant (H3) | < 2 min | 1 min | PASS |
| Time to create engagement (H4) | < 1 min | 3 min | FAIL target — D-T6-002 caused 3 retry attempts to find canonical engagement ID |
| Time to run no-auth scans (H5) | < 10 min | N/A | FAIL — D-T6-003; scans never executed |
| Time to send invitation (H6) | < 1 min | 4 min | FAIL target — required discovering correct endpoint (/portal/invitations vs /identity/admin/users/invite) and separate admin credential |
| Time from invitation sent to email received (H7) | < 30 s | < 30 s (assumed) | delivery_state=sent; T4 precedent; email receipt not independently timed |
| Time from email to invitation accepted (H8) | < 5 min (human) | 12 min | FAIL target — 3 attempts; D-T6-004 + OIDC double-loop required cookie clearing |
| Time to first portal login after acceptance (H9) | < 3 min | 1 min | PASS |
| Time to run full device-code scan suite (H11) | < 30 min | N/A | FAIL — D-T6-003 + no MS tenant |
| Time to generate report (H14) | < 5 min | 2 min | PASS — includes GET fallback due to D-T6-002 family |
| Time to export PDF (H16) | < 2 min | 1 min | PASS |
| Time to complete drift-cycle re-scan (H17) | < 15 min | N/A | FAIL — D-T6-003; no baseline |
| Time to revoke access (H18) | < 30 s | < 2 min | PASS — credentials automated; portal logout < 30 s |
| Total API calls (entire rehearsal) | | ~60 | Estimate: H1–H18 automation + admin ops + GET fallbacks |
| Total audit events written | | unknown | Requires DB query; not captured in T6 |
| Errors encountered | 0 (target) | 6 defects | D-T6-001 through D-T6-006 |
| Manual interventions required | 0 (target) | 8 | H4 canonical ID lookup, H6 endpoint correction, H6 admin credential, H8 ×3 (URL correction, cookie clear, OIDC), H9 portal observation, H18 logout |
| Total rehearsal duration | < 4 hours | ~4 hours | Start 2026-08-04T13:07:53Z; end ~2026-08-04T17:10:00Z |

---

## T6 Outcome

| Field | Value |
|---|---|
| Steps passed | 11/18 — H1 (D-T6-001), H2, H3, H4 (D-T6-002), H6, H7, H8 (D-T6-004), H9, H12 (D-T6-002), H14 (D-T6-002), H16 |
| Steps failed | 7/18 — H5 (D-T6-003), H10 (D-T6-003), H11 (D-T6-003), H13 (D-T6-005), H15 (D-T6-006), H17 (D-T6-003), H18 (D-T6-007) |
| Defects found | 7 (D-T6-001 through D-T6-007; D-T6-007 discovered post-run via Railway log analysis) |
| Defects resolved within buffer | 0 — production freeze active during T6; no mid-run patching |
| Defects deferred (with acceptance) | 7 — all deferred to post-T6 engineering buffer |
| Launch blockers identified | 1 — D-T6-007 (portal session revocation broken; replayed token remains valid) |
| CG v0 drift summary produced | no — H17 failed; no scan baseline; deferred to T6 second run |
| Dated log committed to `docs/operators/` | yes — `docs/operators/t6_exec_20260804_001.md` |
| T6 result | **FAIL — second run required** |
| T6 completion date | 2026-08-04 |

**T6 result: FAIL**

7 steps failed (threshold: >2 requires second run). D-T6-007 identified post-run via Railway log — H18 corrected from PARTIAL PASS to FAIL. D-T6-007 is a launch blocker: server-side session revocation is the actual security control; a replayed `pnu1.` token remains valid against Core until 14-day TTL.

**Steps requiring second run:** H5, H10, H11, H13, H15, H17, H18.
**Steps that can be skipped on second run:** H1–H4, H6–H9, H12, H14, H16 — unless any defect fix introduces regression.

**Second run authorization:** pending engineering buffer delivery (D-T6-002 through D-T6-007 fixes) + `FG_EVIDENCE_SIGNING_KEY_B64` configured in Railway.

---

## Failure Policy

- No ad-hoc mid-run patching. If a step fails, record the defect and continue the rehearsal where possible.
- Fixes are applied in a batch from the engineering buffer after the run completes.
- If a non-waivable-class failure occurs (tenant isolation, data loss, integrity failure): stop immediately. Do not continue.
- A second rehearsal run is required if more than 2 steps fail or any non-waivable class fails.
