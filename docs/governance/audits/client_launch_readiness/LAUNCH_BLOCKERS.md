# Launch Blockers (P0)

Five blockers. None require building new product capability — all are verification, hardening, or operationalization of what exists. A paying client should not be onboarded until each is resolved.

**Risk acceptance is not available for this list.** Written founder risk-acceptance exists elsewhere in this audit for two narrow DoD items (L11, L14 — see `LAUNCH_DEFINITION_OF_DONE.md`), but **no written acceptance can waive**: tenant-isolation exposure, backup/restore failure, portal login failure, or audit/evidence-integrity failure. Those four classes end the launch conversation until fixed — the same classes that appear as immediate stop conditions in `STAGGERED_ROLLOUT_PLAN.md`, which never downgrade at any stage.

Cross-reference: structured detail in `audit_findings.json` (FG-LR-001 … FG-LR-005); evidence classes in `EVIDENCE_INDEX.md`.

---

## P0-1 · FG-LR-001 — No verified end-to-end run on the current production stack

**Exact problem.** The only complete dry run (engagement → scans → questionnaire → report → QA → portal → remediation) was recorded 2026-06-01 (ROADMAP Phase 2 row 32). Since then the platform's identity, provisioning, and credential layers were replaced: portal named-user cutover (`portal_users`, migration 0164), credential authority (with production bugs found "during live incident recovery" — ROADMAP R0.2), canonical tenant registry (migration 0156), internal platform authority + service principal (PRs #585/#586, merged the day before this audit). `CLIENT_READINESS.md` §H remains unchecked.

- **Affected workflow:** every client-facing workflow.
- **Customer impact:** live in-meeting failure of login, scan, or report.
- **Likelihood:** medium-high (three of the last four "Platform Recovery" fixes were production-discovered). **Severity:** critical. **Confidence:** high.
- **Recommended action / minimum fix:** repeat H1–H18 in production with the current stack; log every step with timestamps; fix what breaks.
- **Ideal later state:** scripted smoke-test of the golden path runnable on demand.
- **Effort:** 3 days. **Dependencies:** FG-LR-002 (portal user path is part of the run). **Owner type:** founder-operator.
- **Validation / exit criteria:** dated dry-run log committed under `docs/operators/`; all 18 steps pass within 7 days of the first client meeting.
- **Rollback/mitigation:** none — this *is* the mitigation for everything else.
- **ROI:** 10/10.

## P0-2 · FG-LR-002 — Portal named-user login is the only production door and has never carried a real user

**Exact problem.** `apps/portal/app/api/auth/login/route.ts` hard-returns 403 in prod-like environments (fail-closed via `isProdLikeEnv()` — unknown env counts as prod). The surviving path is console invite → Resend email (`apps/console/app/api/email/route.ts`; `apps/console/lib/mailer.ts` throws without `RESEND_API_KEY`) → `/accept-invite` → OIDC (`apps/portal/app/api/auth/oidc/*`) → `pnu1.` session validated server-side by Core. ROADMAP still lists the cutover PRs ("PR B", "PR C") as in-progress even though the code is on main — the release state itself is ambiguous.

- **Affected workflow:** invitation, first login, all portal access, logout.
- **Customer impact:** total portal lockout with no fallback if any link in the chain is misconfigured.
- **Likelihood:** medium. **Severity:** critical. **Confidence:** high.
- **Minimum fix:** one real external test identity completes invite → email → accept → OIDC login → engagement pages → logout, in production; confirm Core-side session revocation on logout; confirm `RESEND_API_KEY`, Auth0 app, `PORTAL_SESSION_SECRET` in Vercel prod.
- **Ideal later state:** synthetic monitor exercising login weekly.
- **Effort:** 2 days. **Owner type:** founder-operator. **Dependencies:** none.
- **Validation / exit criteria:** external-identity portal session created and revoked in prod; documented.
- **Rollback/mitigation:** if OIDC cannot be stabilized in the window, a controlled re-enable of the grant-session path for the design partner only (C7 Argon2id grant model is server-side and auditable) — explicitly time-boxed.
- **ROI:** 10/10.

## P0-3 · FG-LR-003 — No tested database backup or restore

**Exact problem.** No backup/restore runbook exists in the repository (verified absence across `docs/`, `deploy/`, `Makefile`). The ops_governance backup tables (migration 0051) record backups; nothing performs them. Production data lives in Railway Postgres; plan-level automatic backup behavior is unverified (`CLIENT_READINESS` A10 unchecked). A prior internal audit already flagged a no-backup single point (`docs/ai/R1_AUTHORITY_AUDIT.md:119`).

- **Affected workflow:** all persistence; DPA data-handling commitments; the entire tamper-evident evidence story.
- **Customer impact:** irrecoverable loss of a paying client's evidence chain and reports.
- **Likelihood:** low. **Severity:** catastrophic. **Confidence:** high.
- **Minimum fix:** confirm/enable Railway automated backups (upgrade plan if needed); execute one restore into a scratch DB; verify a known engagement's rows; write `docs/operators/backup_restore.md`.
- **Ideal later state:** scheduled logical dumps to independent storage + quarterly restore drill.
- **Effort:** 1.5 days. **Dependencies:** FG-LR-004 (plan decision). **Owner type:** founder-operator.
- **Validation / exit criteria:** dated restore-test log with row-count verification.
- **Rollback/mitigation:** until automated: manual `pg_dump` before every client engagement (add to `first_client_prep.md`).
- **ROI:** 9/10.

## P0-4 · FG-LR-004 — Hobby-tier single instance runs scans and AI report generation in-process

**Exact problem.** Scans and report generation execute via FastAPI `BackgroundTasks` inside the API process (`api/field_assessment.py:3421–3767`); production is a single Railway instance whose headroom has never been checked under engagement load (`CLIENT_READINESS` A10 unchecked; B1 notes the Hobby plan). Durable scan-job records with lease/orphan recovery exist (`services/field_assessment/durable_job_service.py`) and reduce — but do not eliminate — restart blast radius; report generation is not similarly protected.

- **Affected workflow:** in-meeting scans, report generation, API availability.
- **Customer impact:** the highest-visibility failure mode: a stall in front of the client.
- **Likelihood:** medium. **Severity:** high. **Confidence:** high.
- **Minimum fix:** verify/upgrade the Railway plan; run the full scan suite + report generation concurrently once while watching memory/CPU; observe one orphan-recovery cycle; document restart semantics.
- **Ideal later state:** dedicated worker process for scans/reports (ENTERPRISE_PLAN Phase 2 already schedules this — do not pull it forward).
- **Effort:** 1 day. **Owner type:** founder-operator.
- **Validation / exit criteria:** full concurrent run with ≥30% memory headroom, logged.
- **Rollback/mitigation:** pre-meeting execution of no-auth scans (already the runbook's recommendation) shrinks in-meeting load to device-code scans + report.
- **ROI:** 8/10.

## P0-5 · FG-LR-005 — No incident response or rollback procedure

**Exact problem.** July's production incidents (ROADMAP Platform Recovery R0–R7: dangling credentials, masked provisioning errors, credential-authority type bugs) were diagnosed and fixed ad hoc by the founder. There is no written detect→assess→rollback→communicate procedure; deployment is Railway GitHub auto-deploy with no documented rollback step; alert routing (Sentry, UptimeRobot) has no ownership/response contract (see FG-LR-010).

- **Affected workflow:** incident response during a paid engagement; client communications.
- **Customer impact:** extended downtime and unprofessional comms under pressure.
- **Likelihood:** medium (incidents demonstrably occur). **Severity:** high. **Confidence:** high.
- **Minimum fix:** one-page runbook (alert sources → triage steps → Railway rollback-to-previous-deploy procedure → client notification template referencing `docs/operators/letters/`); execute one timed rollback drill.
- **Ideal later state:** staged deploys with health-gated promotion.
- **Effort:** 1 day. **Owner type:** founder-operator.
- **Validation / exit criteria:** drill completes a rollback in <15 minutes; runbook committed.
- **Rollback/mitigation:** n/a — this creates the rollback path.
- **ROI:** 8/10.

---

## Explicitly NOT launch blockers (and why)

- **Tenant isolation / RLS** — implemented with FORCE RLS + parameterized session context + 15 forensic isolation test modules (EVIDENCE E1/E2/E13). Verified strength, not a gap.
- **SSRF in scanners** — centralized 12-layer validator with DNS-rebinding protection (E8). Closed by Phase 0A work.
- **Audit integrity** — HMAC chain + append-only triggers + atomicity service + CI coverage gate (E10/E11). Closed.
- **Retention enforcement (FG-LR-006)** — contractual, not technical, exposure in the first 90 days; a manual purge runbook before client one is an acceptable mitigation, so it is P1, not P0.
- **Console/Portal gating (FG-LR-007/008)** — embarrassing, not unsafe; P1 because it is cheap and protects credibility, but a launch could technically proceed without it.
