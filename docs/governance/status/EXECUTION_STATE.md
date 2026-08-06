# FrostGate Execution State

This is the single canonical execution state for the frozen Launch Readiness Audit.
Update current status fields in place. Preserve historical entries under `Execution History`.

## Current Status

**Date:** 2026-08-06

**Current Branch:** `main`

**Current Commit:** `c11c4300` (ops(c1): restore drill PASS 2026-08-06 — C1 backup hardening COMPLETE)

**Current PR:** None open.

**Overall Status:** YELLOW → GREEN (C1 CLOSED; C4 is the only remaining engineering gate; L14 is founder track)

**Launch Confidence (%):** 97

**Current Critical Path:** ~~C1 backup hardening~~ ✅ → **C4: T8/T9/T10/T13 operator execution** → ~~L14 commercial paper~~ (parallel, founder) → first client onboarding.

**Current Phase:** C4 Operational Validation — T8 / T9 / T10 / T13

**Launch Authorization:** LDR-2026-001 CONDITIONAL GO — 1 constraint outstanding (C4). C1/C2/C3 all DONE.

**Platform Freeze:** ACTIVE — no feature PRs, schema changes, infra changes, or env var additions until first client engagement completes. Exception: production defects discovered during C4 execution.

**Current DoD Progress:** 10/14 Launch DoD items PASS. L7/L8/L9/L11 → READY TO EXECUTE (runbooks committed). L12 IN PROGRESS (accepted risk; rotate before second engagement). L13 CONDITIONAL on L7. L14 FOUNDER TRACK.

**Completed Since Last Update (2026-08-05 → 2026-08-06):**
- C1 CLOSED 2026-08-06: encrypted scheduled backup (02:00 UTC cron, R2 offsite); restore drill PASS (17 tenants / 17 engagements / 101 findings / 346 audit events / migration 0172 / zero mismatches). Evidence: `docs/governance/status/restore_drill_evidence_20260806.md`.
- fix(backup): `fg_backup.sh` migrated from `alembic_version` to `schema_migrations` (commit 2f1d41f4).
- fix(db): migration 0173 — dropped orphaned production function referencing `alembic_version` (commit e82166fa → psycopg3 fix c11c4300 via e82166fa).
- LDR-2026-001 C1 status updated to DONE.

**Current Blockers:**
- **C4 (operational gates):** T8 incident drill (timed Railway rollback, <15 min, recorded), T9 console UX walkthrough (≤9 nav items, operator completes engagement), T10 portal UX walkthrough (every visible page real data, discoveries-first), T13 deletion purge drill (all 3 DPA triggers, execute once on test tenant). All runbooks committed. ~2 days to execute.
- **T9 BLOCKED — identity-critical defect AUTH-001:** Console invitation 403 root cause identified in pre-T9 audit (`docs/audits/console_tenant_ux_authority_audit_20260806.md`). BFF uses tenant portal API key for `POST /workforce/users`; Core correctly rejects (requires `admin:write` + `identity.scim`). T9 cannot pass the invitation step until H0-PR1 ships. T8 and T13 are not blocked and can run now. T10 is conditional (see below).
- **C4 gate status:** T8 — NOT BLOCKED; T9 — BLOCKED on H0-PR1; T10 — CONDITIONAL (can skip portal grant creation using Gold Path grants; blocked on H0-PR3/H0-PR4 if portal access creation is required); T13 — NOT BLOCKED.
- **L12 gap:** FG_SIGNING_SECRET + FG_KEY_PEPPER deferred; written acceptance in L12 manifest. Must rotate before second engagement.
- **L14 (commercial paper):** price card, CG v0 one-pager, Stripe invoice flow, design-partner scheduled. Founder track; 0 engineering days. This is the longest pole.

**Top Three Priorities:**
1. **H0-PR1: Fix console invitation 403 root cause** — BFF authority routing correction for `POST /workforce/users`. 1–2 engineering days. Unblocks T9. This is the critical path. See `docs/plans/tenant_identity_administration_pr_sequence_20260806.md`.
2. **C4: Execute T8+T13 now; T9 after H0-PR1; T10 in parallel or after H0-PR3/H0-PR4** — all runbooks at `docs/operators/`. When all 4 PASS: update LDR-2026-001, tag v1.0.0-rc1, freeze engineering.
3. **L14: Commercial paper + design partner scheduling** — price card, one-pager, Stripe flow, first warm candidate on the calendar. Running in parallel. No engineering dependency.

**Next Required PR:** **H0-PR1** — Fix console invitation 403 root cause. See `docs/plans/tenant_identity_administration_pr_sequence_20260806.md`. Unblocks T9 and C4.

**Post-RC1 — Tenant Identity & Administration Platform stream:**
After RC1 tag: H0-PR2 through H0-PR5 (canonical tenant-context, engagement selector, portal grant ownership, cross-tenant regression). Then H1-PR1 through H1-PR10 (design-partner self-administration surface). Then H2-PR1 (Unified Invitation Authority, P1-01 first PR). Reference: `docs/plans/tenant_identity_administration_platform_roadmap_20260806.md`.

**No feature expansion before RC1:** Platform freeze remains active. H0-PR1 through H0-PR5 are production defects discovered during C4 pre-execution audit — not new features. H1 and beyond do not start until RC1 is tagged.

**Estimated Engineering Days Remaining:** ~2.0 (C4 execution) + ~8–12 days (H0-PR1 through H0-PR5, can begin immediately in parallel with T8/T13).

**Estimated Launch Date:** 2026-08-08 to 2026-08-10 (C4 + LDR update + RC1 tag; first client date depends on L14).

**Roadmap Drift:** PRs #601-608 (IA-1/IA-2, justified), #609-613 (T6 burn-down + CI), backup fix + migration 0173 (C1 defects, on-plan). No scope additions.

**Known Governance Deviation:** GD-2026-001 CLOSED 2026-08-03. See `GOVERNANCE_DEVIATIONS.md`.

**C1 Result:**

| Field | Value |
|---|---|
| C1 status | COMPLETE 2026-08-06 |
| Scheduled backup | PASS — cron 02:00 UTC, encrypted, R2 offsite, run 31073455901 |
| Manual backup (drill source) | FG-BKP-20260806-00001 · `frostgate_20260806_104220_manual.dump.enc` · 1,883,376 bytes · encrypted: true · offsite: true |
| Restore drill | PASS — run 31094275553 · 1m4s |
| Tenants | 17 (expected 17) |
| Engagements | 17 (expected 17) |
| Findings | 101 (expected 101) |
| Audit events | 346 (expected 346) |
| Migration version | 0172 (expected 0172) |
| Mismatches | 0 |
| Evidence file | `docs/governance/status/restore_drill_evidence_20260806.md` |
| Fixes required | migration 0173 (orphaned alembic_version fn); fg_backup.sh schema_migrations; quote_ident() psycopg3 compat |

**Repository Health:** Working tree clean on main. CI green (all gates pass post #613). 1bcddc16 is the launch candidate + 4 stabilization fixes. No open mypy errors. No open gate failures.

**Open Risks:**
- DB startup ordering defect (`_grant_runtime_role_access()` race): accepted; documented; fix tracked pre-Stage 2 concurrent client.
- Orphaned `default` tenant data (7 engagements, 11 scan jobs): P1 data-governance; non-blocking Stage 1; must migrate/archive before commercial use.
- No automated alerting: Railway plan limitation; add 5xx spike alert before engagement start.
- L12 deferred rotation: written acceptance; must close before second engagement.
- `FG_DB_MIGRATIONS_RISK_ACCEPTED=1` still set in Railway (D-T6-001): non-blocking; clear before any schema change.

**Recommended Next Action:** C1 first (backup secrets, 30 min founder action) → C4 execution (2 days) → L14 in parallel. If design partner is warm: schedule before C4 completes — the engagement starts when the date is confirmed, not when the drills close.

**Execution Notes:** T6 passed on second run with 8 defects found and burned down from the buffer. Gold Path 15/15 at 12.9s sets the Stage 2 KPI baseline (target <30s). LDR-2026-001 is immutable. Stage 1 capacity limits: 1 design partner, ≤3 tenants, ≤5 named users, 1 concurrent engagement. PRs #610-613 required same-day CI stabilization after the launch candidate merge — expected, not alarming, and now resolved.

**T4 Result:**

| Field | Value |
|-------|-------|
| T4 status | COMPLETE |
| L2 status | PASS |
| FG-LR-002 status | CLOSED |
| Invitee | jason@frostgate.ai |
| Tenant | the-wick-network |
| Invitation ID | 81b40050-39b2-4a6e-a57b-c830489e7a93 |
| Auth0 user ID | auth0\|6a1a0e50c88714c3166670c3 |
| Auth0 app | cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4 |
| Auth0 tenant | dev-22nn3c7muqjk4tgu.us.auth0.com |
| Session type | pnu1. (named-user) |
| Portal role | viewer |
| G1–G6 | ALL PASS |
| Completion date | 2026-08-04 |
| Evidence file | `docs/governance/status/T4_OPERATIONAL_EVIDENCE.md` |
| Commit | e4d70804 |

**T1 Result:**

| Field | Value |
|-------|-------|
| T1 status | COMPLETE |
| L4 status | PASS |
| FG-LR-003 status | CLOSED |
| Railway plan tier | hobby |
| Automatic Railway backups | None (hobby plan: `maxBackupsCount = 0`) |
| Backup mechanism | Manual `pg_dump` via Docker (`pgvector/pgvector:pg18`) |
| Production DB | PostgreSQL 18.4, migration 0168, 372 tables, 7 engagements |
| Dump size | 1.7 MB (compressed custom format) |
| Restore start | 2026-07-30T20:11:42Z |
| Restore complete | 2026-07-30T20:11:46Z |
| Restore duration | ~4 seconds |
| Scratch target | `frostgate-restore-proof-20260730` (local Docker, isolated) |
| Row-count result | PASS — all tables match exactly |
| ENG-RESTORE-PROOF-01 | PASS — engagement, findings, audit_events, scan_results all match |
| Runbook | `docs/operators/backup_restore.md` |
| Evidence manifest | `docs/governance/status/L04_evidence_manifest.md` |
| Secrets committed | None |
| Production modified | None |

**Plan upgrade note:** Railway Pro is required for automatic backups (`maxBackupsCount > 0`). T5 infra headroom task should include the plan upgrade decision. Until then, pre-engagement manual `pg_dump` is the production backup strategy (see `docs/operators/backup_restore.md` §5 and `first_client_prep.md`).

**Roadmap Drift:** T1 complete on Day 1 as planned. No drift.

**Repository Health:** Working tree clean on main before branching. `docs/operators/backup_restore.md` and `docs/governance/status/L04_evidence_manifest.md` added.

**Open Risks:**
- FG-LR-001, FG-LR-002, FG-LR-004, FG-LR-005 remain open — no durable evidence yet.
- Railway hobby plan confirmed with no automatic backups; manual `pg_dump` is the current backup path; upgrade decision deferred to T5.
- `CLIENT_READINESS.md` is stale relative to the named-user portal cutover.
- `credential_delivery.md` still needs the T14 named-user rewrite.

**Recommended Next Action:** Resolve the remaining L12 rotation gap or record an approved DoD amendment, then execute T4 portal named-user production proof.

**Execution Notes:** The frozen audit is the source of truth. PR #599 merged the T2/T3 operational evidence and runbook updates. PR #600 reconciled L12 evidence manifest header contradictions introduced during external edits. T2 is complete. T3 and L12 remain partially complete until FG_SIGNING_SECRET and FG_KEY_PEPPER are rotated or the frozen DoD is formally amended.

## Execution History (recent, newest first)

### 2026-08-04 — T5 COMPLETE · LRR issued CONDITIONAL GO

**Review Type:** Gate Execution

**Summary:** T5 Infrastructure Headroom executed fully. Execution ID: T5-EXEC-20260804-001. All gates PASS. G1 captured Railway plan limits via CLI (CPU 8 vCPU, memory 8192 MB, Postgres 100 connections, Redis 1024 MB). G1.1 confirmed 71 Railway vars + 19 Vercel vars, all Expected. G2 ran 805 requests against `lace-money-group` tenant (substituted from `default` which does not exist in tenants registry); 100% OK, 0 5xx. G3 7/7 thresholds met: CPU 85.7% headroom, memory 94.4%, DB 97%, Redis 98.8%. G4 `railway redeploy --service api` triggered 8.8s restart-to-health. G4.5 metrics and audit continuous; two known gaps (no OTel, no alerting). G5 all state intact. G6 PASS — hobby plan sufficient; no upgrade required for first-client engagement.

Launch Readiness Review issued CONDITIONAL GO. Pre-T6 backup checkpoint `FG-BKP-20260804-00001` taken. Production freeze lifted for backup reconciliation work.

**Key Finding:** No `tenant_id='default'` in tenants registry. fa_engagements (7 rows) and fa_scan_jobs (11 rows) use orphaned legacy tenant_id. P1 data-governance defect; non-blocking for T6.

**Major Changes:**
- `docs/governance/status/T5_INFRASTRUCTURE_HEADROOM_EVIDENCE.md` — all G1-G6 sections filled PASS
- `docs/governance/status/LAUNCH_READINESS_REVIEW.md` — filled: T5 summary, risks, rollback, decision (CONDITIONAL GO), conditions
- `docs/governance/status/EXECUTION_STATE.md` — updated status, blockers, DoD progress
- `artifacts/t5/T5-EXEC-20260804-001/metrics/G2_load_profile_results.json` — G2 evidence (805 requests)
- `artifacts/t5/T5-EXEC-20260804-001/metrics/G2_railway_peak_metrics.json` — Railway peak metrics
- `artifacts/t5/T5-EXEC-20260804-001/metrics/G4_injection_results.json` — G4 injection results
- `/var/lib/frostgate/backups/frostgate_20260804_122857_pre-engagement.dump` — pre-T6 checkpoint

**Decisions Made:**
- T5 G6: PASS — hobby plan has sufficient first-client headroom; no upgrade required
- LRR: CONDITIONAL GO — conditions 2-5 met; Condition 1 (backup authority reconciliation) required before T6
- G2 tenant substitution: lace-money-group (no default tenant; orphaned engagement data confirmed non-blocking)
- Backup authority: Option B recommended; T1.5 mechanism proven; scheduling + encryption + remote offsite not yet configured (gaps documented)

**Updated Launch Confidence:** 92%

**Next:** Backup authority reconciliation (Condition 1) → T6 H1-H18.

---

### 2026-08-06 — C1 COMPLETE · Backup Hardening Operationally Proven

**Review Type:** Gate Execution

**Summary:** C1 backup hardening closed. Scheduled cron backup PASS (02:00 UTC, encrypted, R2 offsite). Restore drill PASS in 1m4s — 17 tenants / 17 engagements / 101 findings / 346 audit events / migration 0172 / zero mismatches. Three production defects found and fixed during C1 execution: (1) `fg_backup.sh` queried nonexistent `alembic_version` table instead of `schema_migrations`; (2) production database contained an orphaned stored function referencing `alembic_version` that caused `pg_restore --exit-on-error` to abort the restore; (3) migration 0173's initial `format('%I', ...)` syntax was rejected by psycopg3 (`only '%s', '%b', '%t' allowed`) — rewritten with `quote_ident()` concatenation. All three defects found, diagnosed, and resolved in a single session. API remained healthy post-migration. C1 is the last infrastructure constraint. The platform is operationally proven end-to-end.

**Major Changes:**
- `scripts/backup/fg_backup.sh` — replaced `alembic_version`/`version_num` with `schema_migrations`/`version` at lines 552, 1155, 1194 (commit 2f1d41f4)
- `migrations/postgres/0173_drop_alembic_version_fn.sql` — drops orphaned production function; uses `quote_ident()` for psycopg3 compatibility (commits e82166fa, c11c4300 fix, final e82166fa)
- `docs/governance/status/restore_drill_evidence_20260806.md` — PASS evidence committed (commit c11c4300)
- `docs/governance/status/LAUNCH_DECISION_RECORD.md` — C1 status → DONE with full evidence citation
- `docs/governance/status/EXECUTION_STATE.md` — current status updated; confidence 95% → 97%

**Decisions Made:**
- C1 closed on evidence, not on intent. Three real defects found; no shortcuts taken.
- Overall status: YELLOW→GREEN transition. One constraint (C4) remains before full GO.
- Engineering is now the shortest pole. L14 (commercial paper + design partner) is the critical path to first revenue.

**Updated Launch Confidence:** 97%

**Next:** C4 execution (T8/T9/T10/T13) → LDR update → v1.0.0-rc1 tag → L14 design partner scheduling.

---

### 2026-08-05 — Weekly CEO Executive Review · LDR-2026-001 CONDITIONAL GO · Launch Candidate Stabilized

**Review Type:** Weekly CEO Review

**Summary:** Full executive review across ROADMAP.md, THIRTY_DAY_LAUNCH_PLAN.md, LAUNCH_DEFINITION_OF_DONE.md, FIRST_CLIENT_PLAYBOOK.md, TOP_ROI_ACTIONS.md, and repository state. The week delivered the single most consequential gate sequence in the launch plan: T4 COMPLETE (named-user portal proof), T5 COMPLETE (infra headroom, 94.4% memory headroom), T6 COMPLETE (H1-H18 dry run, second run PASS, 8 defects resolved), Stage 1 Gold Path 15/15 PASS (12.9s, 0 interventions), and LDR-2026-001 CONDITIONAL GO issued. 13 PRs merged (#601–613). DoD progress: 3/14 → 10/14. Launch confidence: 92% → 95%. Estimated launch date revised from 2026-08-27 to 2026-08-10. Platform is functionally complete and operationally proven. Remaining work is execution (C4 drills: ~2d) and configuration (C1 backup secrets: founder action) and commercial (L14: price card + design partner scheduling).

**Major Changes:**
- PR #601-608: IA-1 Client Organization Provisioning + 5 prod-critical auth/DB fixes (roadmap drift; T4 prerequisite).
- PR #609 (a19c8f15): T6 PASS; Gold Path 15/15 PASS; LDR-2026-001 CONDITIONAL GO; C2+C3 DONE; runbooks for T8/T9/T10/T13 committed (54 files, 9,455 insertions).
- PR #610-613: CI/gate stabilization post-launch-candidate (mypy, secret scan).
- EXECUTION_STATE.md: current status updated to reflect LDR-2026-001 CONDITIONAL GO, DoD 10/14, launch confidence 95%, launch date 2026-08-10.

**Completed Tasks:**
- T4: Portal named-user proof — COMPLETE (L1/L2 PASS)
- T5: Infrastructure headroom — COMPLETE (L10 PASS)
- T6: H1-H18 production dry run — COMPLETE (L2/L5/L6 PASS; 8 defects burned from buffer)
- Gold Path: 15/15 PASS, 12.9s, 0 interventions
- LDR-2026-001: CONDITIONAL GO issued
- C2 (invitation URL): DONE (commit 5a9440bf)
- C3 (global JSON handler): DONE (commit 98088457)
- Runbooks: T8/T9/T10/T13 committed (docs/operators/)

**New Risks:**
- IA-2 merged before IA-1 COMPLETE (noted gate violation; cannot be unshipped; no impact on DoD).
- 4 post-merge CI fixes required same day as launch candidate — expected defect burn-down; now resolved.
- Orphaned `default` tenant data (7 engagements, 11 scan jobs): P1; must migrate before commercial use.

**Decisions Made:**
- Overall status: YELLOW (C1+C4 outstanding; functional platform GREEN).
- Launch confidence raised from 92% to 95%.
- Estimated launch date: 2026-08-10 (C1+C4 this week + L14 commercial paper).
- T7 PDF content checklist accepted as partially met by Gold Path (Ed25519 + QA-approved); full section-by-section checklist execution deferred to C4 window.
- L12 accepted risk (FG_SIGNING_SECRET + FG_KEY_PEPPER): maintained; rotate before Stage 2.
- No scope additions approved; v1 architecture freeze maintained.
- Commercial acquisition: YES WITH CONDITIONS — C1+C4 must close first; design partner should be scheduled now in parallel.

**Next Week's Three Objectives:**
1. C1: Configure 7 GitHub secrets + run backup/restore-drill workflows (founder action; <1d).
2. C4: Execute T8 (incident drill), T9 (console walkthrough), T10 (portal walkthrough), T13 (deletion purge drill) (~2d).
3. L14: Finalize price card, confirm Stripe invoice flow, schedule design partner (founder commercial track; 0 eng days).

**Updated Launch Confidence:** 95%

**Next:** C1 backup secrets → C4 execution → first client.

---

### 2026-08-04 — T4 COMPLETE · G1–G6 all PASS

**Review Type:** Gate Execution

**Summary:** T4 portal named-user proof executed fully in production. G1–G6 all PASS. A real external user (jason@frostgate.ai) received an invitation email, accepted via Auth0 OIDC SSO, accessed the portal as a viewer, and logged out cleanly. No manual DB writes, no Auth0 dashboard user creation, no RBAC edits — gate policy fully observed.

**Major Changes:**
- `api/notifications/email.py`: added `req.add_header("User-Agent", "FrostGate/1.0")` — Python's default UA (`Python-urllib/3.x`) was blocked by Cloudflare WAF on Resend's CDN with HTTP 403 / error code 1010. Fix committed `470301a4`. Entry P-51 added to `docs/ai/PR_FIX_LOG.md`.
- Auth0 (dev-22nn3c7muqjk4tgu.us.auth0.com): FrostGate Portal app `cvasuyBjdFg4KnidIxKZIFBJFvGdYjF4` created; FrostGate API `https://api.frostgate.ai` (RS256) registered and authorized for the portal app.
- Vercel (portal): `CORE_TENANT_ID=the-wick-network`, `CORE_API_KEY` updated to new portal-bff credential `4921106c-adbc-4488-87d7-6acb0072861a` (scopes: governance:read + governance:write).
- `docs/governance/status/T4_OPERATIONAL_EVIDENCE.md`: all gates filled PASS.
- `ROADMAP.md`: T4 row updated to COMPLETE 2026-08-04.
- Commit `e4d70804` pushed to origin/main.

**Decisions Made:**
- Auth0 tenant `dev-22nn3c7muqjk4tgu` (the management tenant) doubles as the OIDC user auth tenant for portal users — confirmed working; no separate OIDC tenant required.
- No post-T4 cleanup of the portal PRs B/C branches until after T6. They are either superseded or documentation debt; archaeology deferred until after launch.

**Updated Launch Confidence:** 85%

**Next:** T5 G1 — capture Railway plan limits and baseline metrics. No code PR required.

---

### 2026-08-03 — G2-prod PASS · IA-1 COMPLETE · GD-2026-001 CLOSED

**Review Type:** Gate Execution

**Summary:** G2-prod executed and passed. Disposable tenant `fg-ia1-prod-validation-20260803` provisioned in production. Auth0 org `org_ZTxlvEm74W5wG9Q4` created with name `fg-fg-ia1-prod-validation-20260803-5618261f`. `provisioning_state=active` confirmed in DB. Ownership metadata verified in Auth0 (`frostgate_tenant_id=fg-ia1-prod-validation-20260803`, `frostgate_idempotency_key=ia1:fg-ia1-prod-validation-20260803:auth0`). Idempotency proven: retry returned same `binding_id` and `provider_org_id`; event count unchanged; Auth0 org count = 1. Audit trail verified: `security_audit_log` id=43 (`tenant_created`) and id=45 (`tenant_org_provisioned`). IA-1 Final Acceptance block filled. GD-2026-001 closed.

**Major Changes:**
- Auth0 M2M application "FrostGate Identity Authority" (`oyWWKp3DPebUVulQKYP9zRtfLoV74RFB`) created with scopes `read:organizations`, `create:organizations`, `update:organizations`.
- `AUTH0_MANAGEMENT_DOMAIN`, `AUTH0_MANAGEMENT_CLIENT_ID`, `AUTH0_MANAGEMENT_CLIENT_SECRET`, `AUTH0_MANAGEMENT_AUDIENCE` set in Railway production → api → Variables.
- Production API redeployed with working Auth0 credentials.
- `docs/governance/status/IA1_OPERATIONAL_EVIDENCE.md`: G2-prod section filled (PASS), Final Acceptance block completed.
- `docs/governance/status/GOVERNANCE_DEVIATIONS.md`: GD-2026-001 OPEN → CLOSED.
- `docs/governance/status/EXECUTION_STATE.md`: status YELLOW → GREEN, confidence 73% → 79%.

**Decisions Made:** Disposable tenant `fg-ia1-prod-validation-20260803` retained in production DB (no deletion required — row is clean, has valid binding, and documents the gate evidence). Orphan tenant `fg-ia1-prod-validation-20260801` (no binding, no audit rows) can be deleted after T4 if desired.

**Updated Launch Confidence:** 79%

**Next:** T4 portal named-user proof (2.0d, closes FG-LR-002, required for L1/L2). Branch from main.

---

### 2026-08-03 — G1-prod PASS

**Review Type:** Gate Execution

**Summary:** G1-prod executed and passed. `fg_app` restricted role created in production Postgres (NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION). `FG_DB_URL` → `fg_app@postgres.railway.internal`; `FG_DB_MIGRATION_URL` → `postgres@postgres.railway.internal`. Production API redeployed (deployment `82c9eead`, commit `007dd437`). `Application startup complete` confirmed. All role-safety checks verified: rolsuper=false, rolbypassrls=false, rolcreatedb=false, rolcreaterole=false. Table access (tenants, tenant_credentials, schema_migrations) confirmed via fg_app. No permission errors in logs post-startup. Production database now operates under least privilege — the API can no longer bypass RLS policies.

**Major Changes:**
- Production Postgres: `fg_app` role created with full restriction flags.
- Railway production `api` service: `FG_DB_URL` updated to fg_app credential; `FG_DB_MIGRATION_URL` added with postgres superuser credential. Both use `postgres.railway.internal` (Railway internal hostname).
- `docs/governance/status/IA1_OPERATIONAL_EVIDENCE.md`: G1-prod section updated FAIL → PASS with full evidence table; G2-prod updated BLOCKED → PENDING; critical path updated.

**Defect discovered:** `_grant_runtime_role_access()` did not complete before `auth_store` validation on the first startup attempt. Startup reached credential check before table grants were available, causing `auth_store_unreachable:OperationalError`. Root cause: FastAPI's `merged_lifespan` may interleave router startup contexts, allowing the auth store check to execute before `init_db()` completes. Manual pre-application of the 7 grant statements (`GRANT SELECT/INSERT/UPDATE/DELETE ON ALL TABLES`, sequences, functions, `ALTER DEFAULT PRIVILEGES`) unblocked the crash loop. Classified: severity medium, category reliability, component IA startup. Acceptance criterion: no service may issue queries before `_grant_runtime_role_access()` returns successfully.

**Decisions Made:** Manual grant pre-application accepted as a one-time recovery action for G1-prod. The underlying ordering defect is tracked and must be fixed before the next runtime-role promotion (e.g., a new environment). Not patching production manually — the manual run duplicated what `_grant_runtime_role_access()` would have applied; no additional permissions granted beyond what the code intends.

**Updated Launch Confidence:** 73%

**Next:** G2-prod — disposable tenant `fg-ia1-prod-validation-20260801` provisioning proof → close IA-1 → begin T4.

---

### 2026-08-03 — Daily Execution Review

**Review Type:** Daily Execution Review

**Summary:** Executive Delivery Manager audit conducted across ROADMAP.md, THIRTY_DAY_LAUNCH_PLAN.md, LAUNCH_DEFINITION_OF_DONE.md, FIRST_CLIENT_PLAYBOOK.md, TOP_ROI_ACTIONS.md, EXECUTION_STATE.md, and repository state. Seven PRs (#601-607) shipped since last EXECUTION_STATE update — IA-1 Client Org Provisioning feature plus five prod-critical infrastructure fixes. Dev environment repaired: duplicate API-DEV service (UUID-named, wrong FG_ENV=staging) crashed with FG-PROD-003; diagnosed, identified as topology error, deleted. Primary API-DEV verified healthy on all 9 checks. API startup exception visibility hardened: 4 startup paths in api/main.py now log.exception before raise, ensuring Railway log rate limiter cannot eat root exception traceback. Launch confidence revised down from 72% to 68% reflecting unplanned IA-1 engineering time and T4 not yet started.

**Major Changes:**
- PRs #601-607: IA-1 Client Org Provisioning + DB credential separation + assert_migrations fix + schema USAGE grant + RLS context fix (8 credential write-path functions) + migration 0170 SECURITY DEFINER fingerprint lookup function.
- Commit `3d9a742d`: `api/platform_service_principal.py` and `api/internal_platform_authority.py` — set_config RLS context fix for fg_app runtime role.
- Commit `91bff19b`: `api/main.py` — 4 startup paths wrapped with log.exception/raise for Railway log visibility.
- Dev environment: duplicate `API-DEV-48012471` service (service ID `3e227ef4`) deleted via `railway service delete`.
- G1-dev: PASS 7/7 (2nd verification, commit b0f9a22a). G2-dev: BLOCKED (Auth0 dev tenant). G1-prod: FAIL (fg_app role not in prod). G2-prod: BLOCKED on G1-prod.

**Decisions Made:** IA-2 merge before IA-1 close is a gate violation — noted as roadmap drift; cannot be unshipped. Duplicate dev service deleted rather than repaired (topology was wrong by design). Launch confidence reduced to 68% to reflect slip.

**Blockers discovered:** fg_app role missing in production Postgres (G1-prod FAIL). Auth0 dev tenant not yet created (G2-dev BLOCKED). T4 not started due to IA-1 gating.

**Updated Launch Confidence:** 68%

**Next:** G1-prod → redeploy prod API → G2-prod → close IA-1 → begin T4. Parallel: Auth0 dev tenant → G2-dev.

---

### 2026-07-31 — PR #600 Evidence Reconciliation

**Review Type:** Task Execution

**Summary:** PR #600 (b5821f2c) merged — docs-only fix resolving two bot-review contradictions introduced by external edits to L12 evidence files. L12 manifest header now correctly lists FG-LR-012 as open and L12 status as IN PROGRESS, matching the closure section. EXECUTION_STATE priority queue updated to remove stale "merge #599" instruction and add FG-LR-012 gap work. All CI gates green: 496 executed tests, fg-fast, production profile, authority verification, gap audit, RLS verification.

**Major Changes:**
- `docs/governance/status/L12_evidence_manifest.md` — header `Findings closed` corrected to list FG-LR-013 only; `Finding open: FG-LR-012` added; `L12 status` changed from PASS to IN PROGRESS.
- `docs/governance/status/EXECUTION_STATE.md` — priority 1 replaced with L12 gap work; "Next Required PR" tail cleaned.

**Decisions Made:** No DoD amendment. FG_SIGNING_SECRET and FG_KEY_PEPPER remain deferred with written rationale in L12 manifest. Next work order is T4 (portal named-user proof).

**Blockers discovered:** None new. Timing flake (932s vs 930s hard_max) appeared again on docs-only run; resolved with re-run.

**Updated Launch Confidence:** 72%

**Next:** T4 — portal named-user proof with real external identity in production (2.0d, closes FG-LR-002, required for L2).

---

### 2026-07-30 — Executive Delivery Review + T1.5 Merge

**Review Type:** Daily Execution Review

**Summary:** T1.5 merged to main via PR #598 (5f5d4a17). Ring_state_dir Dockerfile fix merged via PR #595 (48f1d30b). Six bot review findings on `fg_backup.sh` corrected in the same PR cycle: retention bucket graduation by age range, offsite_uploaded 3-state exit truth, restore validates against manifest `source_row_counts` not live production, manifest uploaded after verification, encrypted archive discovery via find with `.dump.enc`, backup ID sequence from max manifest scan. Script expanded from 7 to 10 subcommands: added `verify-manifest`, `inventory`, `metrics`. Added HMAC-SHA256 signed manifests, immutable backup IDs (FG-BKP-YYYYMMDD-NNNNN), dry-run mode, backup health dashboard, Prometheus metrics text output. 73 hermetic pytest tests; CI green (all 496 tests pass, fmt-check clean, PR_FIX_LOG entries P-35/P-36/P-37 added).

**Major Changes:**
- `scripts/backup/fg_backup.sh` — 10-subcommand backup CLI (final merged version)
- `scripts/backup/backup_config.sh`, `providers/upload_base.sh`, `providers/upload_local.sh`, `providers/upload_s3_compatible.sh` — provider layer with 3-state exit protocol
- `tests/backup/` — 9 test files, 73 tests covering all subcommands
- `docs/operators/backup_automation.md`, `disaster_recovery.md`, `backup_schedule.md`
- `Dockerfile` — `/app/state` and `/app/models` now created in image (ring_state_dir crash fixed)
- `docs/ai/PR_FIX_LOG.md` — entries P-35, P-36, P-37 added

**Decisions Made:**
- Backup IDs use max-sequence scan of existing manifests (not file count) to survive pruning.
- Restore validation uses `source_row_counts` captured at backup time (not live prod) to avoid false mismatches.
- Provider skip exits 2 (not 0) so callers can distinguish success / failure / skip without touching `offsite_uploaded`.
- Retention bucketing uses age ranges (not global sort position) so each bucket's count is enforced independently.

**Blockers discovered:** None new. FG-LR-001/002/004/005 remain open.

**Updated Launch Confidence:** 68%

**Next:** T2 (Anthropic auto-recharge, 0.1d) and T3 (top-5 secret rotation, 0.5d) are the immediate work order. T4 (portal named-user proof, 2.0d) follows.

---

## T1.5 Execution History

**Date:** 2026-07-30
**Task:** T1.5 Backup Automation & Recovery Hardening
**Status:** COMPLETE

**Summary:** Built the automation layer on top of the T1 proven method. Added `scripts/backup/fg_backup.sh` (production-grade bash) with subcommands `backup / verify / restore / list / prune / drill / status`. Wraps the T1 `pgvector/pgvector:pg18` `pg_dump` recipe verbatim — no change to the proven method itself. Adds SHA-256 manifest per backup, optional AES-256-CBC (pbkdf2 iter=600k) encryption with fail-closed key check, pluggable offsite provider (local / S3 / R2 / B2, all sourced from `scripts/backup/providers/*.sh`), configurable retention with 5 age buckets and a hard "never delete the single newest successful backup" invariant, monthly restore drill that appends evidence to `docs/governance/status/restore_drill_evidence_YYYYMMDD.md`, and a `status` JSON report with RPO/RTO warning thresholds.

**Files added:**
- `scripts/backup/fg_backup.sh` — main script (chmod +x, bash -n clean)
- `scripts/backup/backup_config.sh` — env-driven config with defaults
- `scripts/backup/providers/upload_base.sh` — provider interface
- `scripts/backup/providers/upload_local.sh` — local filesystem provider
- `scripts/backup/providers/upload_s3_compatible.sh` — S3/R2/B2 stub (rclone or aws-cli)
- `docs/operators/backup_automation.md` — automation architecture, config, workflow, failure handling, key rotation, offsite setup
- `docs/operators/disaster_recovery.md` — RTO/RPO targets, full DR procedure, escalation, comms template
- `docs/operators/backup_schedule.md` — one-page schedule reference card
- `tests/backup/conftest.py`, `test_backup_manifest.py`, `test_backup_config.py`, `test_backup_checksum.py`, `test_retention.py`, `test_backup_shell.py`

**Files modified:**
- `docs/operators/backup_restore.md` — added §14 cross-ref to automation docs; updated §13 with T1.5 note
- `docs/operators/first_client_prep.md` — §0 now references `fg_backup.sh backup --type pre-engagement`
- `docs/governance/status/EXECUTION_STATE.md` — this file

**Not changed:**
- The T1 proven method in `docs/operators/backup_restore.md` §1–§13 is unchanged.
- `docs/governance/status/L04_evidence_manifest.md` — frozen evidence, untouched.
- No CI, deployment, auth, or schema files touched.

**Decisions:**
- Full logical dumps only, no true incrementals. Rationale documented in `backup_automation.md §2`: Railway Hobby exposes no WAL/basebackup access; DB is 1.7 MB; incrementals would add complexity with zero benefit at this scale.
- Newest-backup protection is a hard invariant in the pruner (unit-tested) so retention math can never orphan the last recovery point.
- S3 provider intentionally exits 0 with "skipped: credentials not configured" when creds are absent — scheduled backups do not fail because offsite is still being wired up; the manifest records `offsite_uploaded: false` for monitoring.
- `verify` uses `pg_restore --list` where docker is available; on encrypted archives it skips that check (they must be decrypted first) but still verifies SHA-256.

**Launch Confidence:** 65% -> 67%.

**Next:** T2 (Anthropic auto-recharge) and T3 (secret rotation).

## Execution History

### 2026-07-30 — T1 Backup and Restore Proof

**Review Type:** Task Execution

**Summary:** T1 executed fully. Railway plan tier confirmed as hobby (no automatic backups). Production database dumped via `pg_dump` using `pgvector/pgvector:pg18` Docker image (required for PostgreSQL 18.4 server compatibility). Dump restored into isolated local Docker scratch container `frostgate-restore-proof-20260730`. All row counts matched between production and restored database. L4 marked PASS. FG-LR-003 closed.

**Major Changes:**
- Created `docs/operators/backup_restore.md` (operator runbook).
- Created `docs/governance/status/L04_evidence_manifest.md` (sanitized evidence manifest).
- Updated `docs/governance/status/EXECUTION_STATE.md` (this file).

**Completed Tasks:**
- Railway plan tier verified: hobby. `subscriptionPlanLimit.volumes.maxBackupsCount = 0` — no automatic backups.
- Production DB: PostgreSQL 18.4, migration 0168, 372 tables, 7 engagements, 59 findings.
- pg_dump completed: 1.7 MB compressed custom format. Duration: ~2 minutes (including Docker pull and network).
- Scratch container `frostgate-restore-proof-20260730` created: `pgvector/pgvector:pg18` (isolation confirmed).
- Restore: exit code 0. Duration: ~4 seconds.
- Validation: all counts match. ENG-RESTORE-PROOF-01 (June 2026 dry-run engagement): 1/22/0/28/12 — PASS.
- No production writes. No production service pointed at scratch.
- No credentials or dump files committed.
- `make fg-fast` will be run before PR submission.

**Blockers discovered:**
- pg_dump v16 refuses to dump PostgreSQL v18 server. Resolved: use `pgvector/pgvector:pg18` Docker image (pg_dump 18.4).
- Standard `postgres:18` lacks pgvector extension. Resolved: use `pgvector/pgvector:pg18` image for both scratch and pg_restore.
- Railway Hobby plan confirmed to have zero automatic backups. Documented in runbook; upgrade decision deferred to T5.

**New Risks:** None in T1 scope. Railway hobby plan backup gap is documented and a mitigation (pre-engagement `pg_dump`) is in place. T5 will decide on Railway Pro upgrade.

**Decisions Made:** Use `pgvector/pgvector:pg18` as the canonical restore image (matches production schema including vector extension). Evidence manifest placed in `docs/governance/status/` (tracked) rather than `artifacts/launch_evidence/` (git-ignored) to avoid `.gitignore` modification.

**Updated Launch Confidence:** 65%

---

### 2026-07-30 — Initial State (pre-T1)

**Review Type:** Daily Execution Review

**Summary:** Initial execution review after the Launch Readiness Audit was frozen. Repository is on PR #592, which is CI/tooling work and not a launch-plan task. The launch plan remains intact: recovery proof first, then final secrets/auth proof, then full dry run.

**Major Changes:** Created canonical `docs/governance/status/EXECUTION_STATE.md`. Recorded current branch, commit, PR, CI state, blockers, critical path, and launch confidence.

**Completed Tasks:** Frozen Launch Readiness Audit PR #593 merged. Local focused verification passed for platform authority, service principal, portal user authority, and portal tenant registry tests.

**New Risks:** Current active PR #592 may distract from T1 if treated as launch-critical. CI for PR #592 is still pending.

**Decisions Made:** Today's highest-ROI work is T1 backup/restore proof as the primary objective, with T2 Anthropic auto-recharge as the secondary objective if T1 is not blocked. PR #592 should be monitored or merged only if checks pass without consuming launch execution time.

**Updated Launch Confidence:** 60%


Ring State Directory

Status: RESOLVED

Resolution:
- PR #595 deployed successfully.
- Container starts successfully.
- Application startup completed.
- No ring_state_dir errors observed.
- No restart loop detected.
- Repeated /health probes returned HTTP 200.

Production Evidence:
- Docker image creates:
  - /app/state
  - /app/models
  - /var/lib/frostgate/state
- Uvicorn reached "Application startup complete."
- Continuous health checks succeeded after deployment.

Launch Impact:
- Operational blocker cleared.
- This is no longer considered a Launch DoD blocker.

Follow-up (Configuration Hygiene):
Confirm the canonical production value for FG_RING_STATE_DIR.

Preferred:
    /var/lib/frostgate/state

Temporary compatibility:
    /app/state

Until documentation is updated, either path is operational because PR #595 creates both directories during image build.
