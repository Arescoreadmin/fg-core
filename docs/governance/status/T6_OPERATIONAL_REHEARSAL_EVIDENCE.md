# T6 Operational Rehearsal — H1–H18 Production Dry Run

Status: **PENDING** — begins after Launch Readiness Review GO decision

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
| T5 outcome | _(PASS / PASS WITH ACTION — must be PASS or PASS WITH ACTION before T6 starts)_ |
| LRR decision | _(GO / CONDITIONAL GO — must not be NO-GO)_ |
| Commit SHA | _(must match T5 G1 version fingerprint unless LRR authorized a change)_ |
| Railway deployment ID | |
| Portal deployment ID (Vercel) | |
| Migration version | 0171 (expected) |
| Disposable tenant for dry run | _(create a new disposable tenant; do not use the-wick-network)_ |
| T6 start time (UTC) | |
| T6 operator | |

---

## Chain of Custody (T6)

| Field | Value |
|---|---|
| Executed by | |
| T6 start (UTC) | |
| T6 end (UTC) | |
| Environment | prod |
| Deployment ID | |
| Commit SHA | |
| Tenant | _(disposable)_ |
| Evidence | _(log / screenshot folder reference)_ |

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
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H2 — Pre-Engagement Backup

**Description:** Take a `pg_dump` before any client data enters the system (per `docs/operators/backup_restore.md` §5 and `first_client_prep.md`).

| Field | Value |
|---|---|
| Expected result | `pg_dump` completes with exit 0; manifest written; dump size recorded |
| Actual result | |
| Dump size | |
| Manifest SHA-256 | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H3 — Tenant Provisioning

**Description:** Create the disposable dry-run tenant in the console (`/admin/tenants`). Verify Auth0 org provisioned via IA-1 authority.

| Field | Value |
|---|---|
| Expected result | Tenant created; `provisioning_state=active`; Auth0 org provisioned; no `PERSISTENCE_UNAVAILABLE` |
| Disposable tenant ID | |
| Auth0 org ID | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H4 — Engagement Creation

**Description:** Create engagement for the disposable tenant; select assessment type; record client domain.

| Field | Value |
|---|---|
| Expected result | Engagement created; assessment type set; status `in_progress` |
| Engagement ID | |
| Assessment type | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H5 — No-Auth Scans (Pre-Meeting)

**Description:** Run the three no-auth scanners: DNS/email security, web security headers, network scan. These run before any device-code auth.

| Scan | Status | Findings count | Duration (min) |
|---|---|---|---|
| DNS / Email Security | | | |
| Web Security Headers | | | |
| Network Scan | | | |

| Field | Value |
|---|---|
| Expected result | All three scans complete; findings recorded; no connector crash |
| Actual result | |
| Evidence | |
| Total duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H6 — Portal Invitation

**Description:** Send named-user portal invite to the dry-run invitee via `POST /portal/invitations`.

| Field | Value |
|---|---|
| Expected result | `delivery_state: sent`; invitation ID returned; email dispatched via Resend |
| Invitee email | _(dry-run address)_ |
| Invitation ID | |
| Idempotency key | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H7 — Email Delivery Verification

**Description:** Confirm invitation email received; verify link points to `https://app.frostgate.ai/accept-invite?token=pni1...`; verify TTL shown.

| Field | Value |
|---|---|
| Expected result | Email received; token present in URL; no credential in URL; TTL shown |
| Email received at | |
| Token prefix | pni1. (expected) |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H8 — Invitation Acceptance (OIDC)

**Description:** Invitee accepts via Auth0 SSO. `POST /portal/invitations/{token}/accept` → 200 OK; pnu1. session issued.

| Field | Value |
|---|---|
| Expected result | 200 OK; `pnu1.` session cookie set; invitation status `accepted`; portal role `viewer` |
| Auth0 user ID | |
| Session token prefix | pnu1. (expected) |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H9 — Client Portal Access

**Description:** Invitee loads portal. No 401/403/redirect loop. Engagement visible (or "no engagements" for fresh tenant — both are valid).

| Field | Value |
|---|---|
| Expected result | Portal loads; no auth errors; no redirect loop; named-user session accepted |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H10 — Device-Code Scan Setup

**Description:** Operator initiates MS Graph device-code flow from console scan panel for the engagement.

| Field | Value |
|---|---|
| Expected result | Device code displayed; operator authenticates; token acquired; scan panel status updates |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H11 — Full Scan Suite Execution

**Description:** Run all applicable device-code scanners. Record completion status and finding counts per connector.

| Connector | Status | Findings count | Duration (min) |
|---|---|---|---|
| MS Graph (MFA / NIST AI RMF controls) | | | |
| Endpoint Inventory (Azure AD devices + Intune) | | | |
| OAuth Risk Deep Scan | | | |
| SharePoint / OneDrive Data Exposure | | | |
| Entra ID Governance | | | |

| Field | Value |
|---|---|
| Expected result | All applicable scans complete; findings written to DB; no connector crash |
| Total findings recorded | |
| Actual result | |
| Evidence | |
| Total duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H12 — Questionnaire Completion

**Description:** Operator completes NIST AI RMF questionnaire (69 controls) for the engagement. Verify responses persist and link to findings.

| Field | Value |
|---|---|
| Expected result | Questionnaire responses saved; linked to findings; coverage matrix updates |
| Controls answered | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H13 — Evidence Curation

**Description:** Operator curates field observations and evidence links. Verify `FaFieldObservation` and `FaEvidenceLink` records created.

| Field | Value |
|---|---|
| Expected result | Observations saved; evidence links created; no DB errors |
| Observations created | |
| Evidence links created | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H14 — Report Generation

**Description:** Compile report. Verify section hashes, manifest signing, and executive summary generation.

| Field | Value |
|---|---|
| Expected result | Report compiled; manifest hash recorded; executive summary generated; report status `ready` |
| Report ID | |
| Manifest hash | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H15 — Report QA

**Description:** Run QA checklist against generated report. Verify all sections present; no missing data.

| QA check | Result |
|---|---|
| Executive summary present and coherent | |
| All finding sections present | |
| NIST coverage matrix accurate | |
| Remediation roadmap generated | |
| Evidence appendix populated | |
| Manifest hash matches report content | |
| No placeholder or stub sections | |

| Field | Value |
|---|---|
| Expected result | All QA checks pass; report marked `delivered` |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H16 — Executive PDF Export

**Description:** Generate client-facing PDF. Verify cover page, AI executive summary (advisory-labeled), severity-sorted findings, remediation plan, framework coverage, evidence appendix, per-page footer with manifest hash.

| Field | Value |
|---|---|
| Expected result | PDF generated; all sections present; manifest hash in footer; data-collected appendix included |
| PDF size | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H17 — CG v0 Drift-Cycle Rehearsal

**Description:** Re-run a subset of scans (at minimum DNS/email and one device-code scan). Produce delta summary comparing new scan results to H11 baseline. This is DoD item L6.

| Field | Value |
|---|---|
| Expected result | Re-scan completes; delta summary produced (improved / degraded / stable per finding); summary coherent |
| Scans re-run | |
| Delta summary: improved | |
| Delta summary: degraded | |
| Delta summary: stable | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

### H18 — Access Revocation

**Description:** Log out the portal user; verify session revoked on core side. Verify portal inaccessible after logout.

| Field | Value |
|---|---|
| Expected result | Logout → `/login`; `portal_user_sessions` row status = `revoked`; portal inaccessible without re-auth |
| Session row status post-revocation | |
| Actual result | |
| Evidence | |
| Duration (min) | |
| Human actions required | |
| Automation coverage (%) | |
| Pass/Fail | |

---

## Defect List

All defects found during T6. Fixes draw from the engineering buffer. No ad-hoc mid-run patching.

| # | Step | Description | Severity | Status | Resolution |
|---|---|---|---|---|---|
| | | | | | |

---

## Operational KPIs

Measured during the rehearsal. These become the reference baseline for future releases.

| KPI | Target | Actual | Notes |
|---|---|---|---|
| Time to provision tenant (H3) | < 2 min | | |
| Time to create engagement (H4) | < 1 min | | |
| Time to run no-auth scans (H5) | < 10 min | | |
| Time to send invitation (H6) | < 1 min | | |
| Time from invitation sent to email received (H7) | < 30 s | | |
| Time from email to invitation accepted (H8) | < 5 min (human) | | |
| Time to first portal login after acceptance (H9) | < 3 min | | |
| Time to run full device-code scan suite (H11) | < 30 min | | |
| Time to generate report (H14) | < 5 min | | |
| Time to export PDF (H16) | < 2 min | | |
| Time to complete drift-cycle re-scan (H17) | < 15 min | | |
| Time to revoke access (H18) | < 30 s | | |
| Total API calls (entire rehearsal) | | | |
| Total audit events written | | | |
| Errors encountered | 0 (target) | | |
| Manual interventions required | 0 (target) | | |
| Total rehearsal duration | < 4 hours | | |

---

## T6 Outcome

| Field | Value |
|---|---|
| Steps passed | /18 |
| Steps failed | /18 |
| Defects found | |
| Defects resolved within buffer | |
| Defects deferred (with acceptance) | |
| CG v0 drift summary produced | yes / no |
| Dated log committed to `docs/operators/` | yes / no |
| T6 result | _(PASS / FAIL)_ |
| T6 completion date | |

**T6 result: PENDING**

---

## Failure Policy

- No ad-hoc mid-run patching. If a step fails, record the defect and continue the rehearsal where possible.
- Fixes are applied in a batch from the engineering buffer after the run completes.
- If a non-waivable-class failure occurs (tenant isolation, data loss, integrity failure): stop immediately. Do not continue.
- A second rehearsal run is required if more than 2 steps fail or any non-waivable class fails.
