# FrostGate Execution State

This is the single canonical execution state for the frozen Launch Readiness Audit.
Update current status fields in place. Preserve historical entries under `Execution History`.

## Current Status

**Date:** 2026-08-10

**Current Branch:** `main`

**Current Commit:** `84296c14` (feat(r4.11): legacy api_keys table retirement - steps 7-16 (#627))

**Current PR:** None open. PR #627 merged to `main` on 2026-08-11 01:54 UTC.

**Overall Status:** YELLOW - launch plan remains valid and H0 hardening is complete, but main is not fully green: `frostgate-release-images` failed the Release Gate on `db-postgres-verify`. Root cause has been reproduced and a local fix is staged; status remains YELLOW until the fix is merged/pushed and release-images reruns green.

**Launch Confidence (%):** 97

**Current Critical Path:** H0-PR1 through H0-PR5 COMPLETE -> R4.11 merged -> restore main release-gate/CI green -> production 0178 proof (`SELECT to_regclass('public.api_keys') IS NULL`) -> L14 design-partner scheduling and commercial paper -> pre-engagement `pg_dump` -> customer one.

**Current Phase:** Post-RC1 customer-one readiness validation; production credential-authority closure and CI/release-gate stabilization.

**Launch Authorization:** LDR-2026-001 CONDITIONAL GO - all 4 launch constraints remain DONE. v1.0.0-rc1 remains the launch candidate baseline. Current work is post-RC1 hardening and release hygiene, not roadmap redesign.

**Platform Freeze:** ACTIVE through first client engagement completion. No new product surface, no refactors, no trust-layer expansion unless repository evidence proves the frozen plan is wrong.

**Current DoD Progress:** 13/14 gates resolved. L1-L13 are PASS/accepted/conditional per Launch Decision Record and prior execution state. L14 remains founder/commercial track. H0 security hardening after RC1 is now complete through H0-PR5.

**Completed Since Last Update (2026-08-07 -> 2026-08-11):**
- **H0-PR4 merged (#618):** Portal grant ownership validation - server-side engagement ownership enforced before grant issuance.
- **H0-PR4 CI repair merged (#620):** Typed portal grant ownership payload fix.
- **H0-PR5 merged (#621):** Cross-tenant regression suite for portal grant/list/revocation and engagement isolation.
- **fg-required always-on merged (#622):** Full required suite no longer skipped by path filters.
- **R4.9 credential authority merged (#623):** Credential authority stream continued.
- **R4.10 merged (#624):** Canonical credential RBAC authority; production RBAC moved to `tenant_credential_roles`.
- **R4.11 steps 1-6 merged (#625):** Canonical SQLite auth and first legacy `api_keys` retirement tranche.
- **Canonical fixture proof merged (#626):** Proved canonical credential plaintext is present in tests.
- **R4.11 steps 7-16 merged (#627):** Legacy `api_keys` table retirement implementation merged; migration `0178_drop_legacy_api_keys.sql` is now on main.

**Current Blockers:**
- **Critical engineering blocker:** `frostgate-release-images` failed on main at Release Gate: `db-postgres-verify` reported failed, even though the standalone `DB Postgres Verify` job in `frostgate-core-ci` passed on the same SHA. Root cause: release-images/Makefile fallback env omitted Compose-required auth secrets, and the migrate service entrypoint host-interpolated `FG_DB_BACKEND` to blank in CI-like environments. Local fix verified in a clean worktree; publication remains blocked until fix is on main and release-images reruns green.
- **CI still running:** `frostgate-core-ci` on `84296c14` is in progress; Guard, migrations replay, DB Postgres Verify, admin, PT, contract, enforcement matrix, and Unit have passed. Hardening/agent/integration follow-on jobs were still running at latest check.
- **R4.11 production proof pending:** apply/verify production migration 0178 and prove `public.api_keys` is absent. This is required to mark R4 Credential Authority closed.
- **L14 founder/commercial track:** design partner scheduling, price card, CG v0 one-pager, Stripe invoice flow, and commercial paper remain the date-setting items for customer one.
- **Known accepted operational risks remain:** D-T8-001 health endpoint DB connectivity gap; D-T9-001 portal key provisioning during onboarding; D-T9-004 verification bundle UI investigation; L12 deferred FG_SIGNING_SECRET/FG_KEY_PEPPER rotation before second engagement.

**Top Three Priorities:**
1. **Restore main release-gate green:** land the release-env/Compose interpolation fix and rerun release-images so release artifacts are publishable from main.
2. **Close R4.11 production proof:** apply migration 0178 where required and capture `to_regclass('public.api_keys') = NULL` evidence.
3. **Advance L14 founder track:** schedule design partner and finalize commercial paper; this remains the direct path to customer one once CI/release health is green.

**Next Required PR:** Release-gate repair for the reproduced workflow/Makefile/Compose env defect, then R4.11 production-proof evidence capture.

**Estimated Engineering Days Remaining:** <1 engineering day for the release-gate repair merge/rerun plus R4.11 production proof. Customer-one timing is otherwise governed by L14 and pre-engagement operations, not feature build.

**Estimated Launch Date:** Platform remains GO for Stage 1 after CI/release-gate is restored and L14 closes. Frozen audit recommended 2026-08-27; current expected date is the earliest scheduled design-partner date after L14, release-gate green, production 0178 proof, and pre-engagement `pg_dump`.

**Roadmap Drift:** None. H0-PR4/H0-PR5 and R4.9-R4.11 are roadmap-tracked hardening/credential-retirement work. No new launch surface is authorized.

**Known Governance Deviation:** GD-2026-001 CLOSED 2026-08-03. No new governance deviation identified in this review.

**Repository Health:** Local checkout is on `main` and matches `origin/main` at `84296c14`. Working tree has pre-existing untracked audit artifacts under `artifacts/audits/`; no tracked code changes at review start. Open PRs: none. Recent merged PRs since the last execution review: #618, #620, #621, #622, #623, #624, #625, #626, #627.

**CI Status:** YELLOW. Latest main CI: `frostgate-docker-ci` PASS; `frostgate-release-images` FAIL at Release Gate (`db-postgres-verify`) on pre-fix SHA; `frostgate-core-ci` in progress with Guard, migration replay, DB Postgres Verify, admin gateway, PT, contract authority, enforcement matrix, and Unit passing at latest check. Local clean-worktree verification of the staged fix: CI-like `make db-postgres-verify` PASS and CI-like aggregate `make release-gate` PASS. Previous local validation from PR #627 included `make fg-security` PASS (1234 passed, 1 skipped), `make required-tests-gate` PASS, and targeted R4.11 tests PASS.

**Open Risks:**
- Release-image publication blocked until the staged release-gate repair is merged/pushed and release-images reruns green.
- R4.11 cannot be called production-closed until migration 0178 proof is captured.
- L14 remains outside engineering but controls first-client date.
- D-T8-001 `/health` can be a false positive for DB outage; hardening before Stage 2 remains prudent.
- D-T9-001 portal key provisioning is an onboarding operational dependency.
- D-T9-004 verification bundle UI failure remains deferred.
- L12 deferred rotation must close before second engagement.

**Recommended Next Action:** Today: commit/push the release-gate env repair, rerun/observe release-images green, then collect R4.11 production proof. In parallel, founder advances L14. Do not start H1 feature work until customer one is scheduled or repository evidence shows a first-client blocker.

**Execution Notes:** The frozen launch plan still says the highest ROI is verification/subtraction, not construction. Since H0-PR4 and H0-PR5 are complete and PR #627 merged, the remaining engineering work is release confidence and production evidence. The current red release gate is the only repository-proven reason to spend engineering time before customer-one operations. L14 remains the largest non-engineering critical path. 2026-08-10 follow-up reproduced the release-images failure in a clean worktree and verified the staged repair with both standalone and aggregate gates passing.

## Execution History

### 2026-08-10 - Daily Execution Review - H0 COMPLETE - R4.11 MERGED - RELEASE GATE YELLOW

**Review Type:** Daily Execution Review

**Summary:** Reviewed ROADMAP.md, THIRTY_DAY_LAUNCH_PLAN.md, LAUNCH_DEFINITION_OF_DONE.md, FIRST_CLIENT_PLAYBOOK.md, TOP_ROI_ACTIONS.md, EXECUTION_STATE.md, current git state, open/merged PRs, recent commits, and current CI. Since the 2026-08-07 execution review, H0-PR4 (#618/#620) and H0-PR5 (#621) merged, completing the post-RC1 tenant-isolation hardening sequence. R4.9-R4.11 credential authority work merged through PR #627, including migration 0178 to drop legacy `api_keys`. Current status is YELLOW because main has a failed `frostgate-release-images` Release Gate on `db-postgres-verify`. Follow-up reproduced the failure in a clean CI-like worktree and staged a release-env/Compose interpolation fix that passes local standalone and aggregate release gates.

**Major Changes:**
- H0-PR4 complete: portal grant creation now enforces tenant-owned engagement validation.
- H0-PR5 complete: cross-tenant portal/engagement regression coverage merged.
- R4.10 complete: canonical credential RBAC authority merged (#624).
- R4.11 implementation merged: legacy `api_keys` retirement steps 1-16 merged (#625/#627), with migration 0178 present on main.
- fg-required workflow hardening merged (#622), forcing required suite execution independent of path filters.
- Release-gate failure root cause identified: missing Compose-required CI auth env plus host interpolation of `FG_DB_BACKEND` in the migrate service entrypoint.

**Completed Tasks:**
- H0 sequence is now 5/5 complete.
- Current branch is main at `84296c14`; no open PRs.
- Recent PR #627 review comments were resolved before merge; local validation included full `make fg-security` PASS.
- Clean CI-like reproduction before fix: aggregate `make release-gate` failed and standalone `make db-postgres-verify` exposed missing `FG_SIGNING_SECRET`; after adding required env, standalone exposed blank `FG_DB_BACKEND`; both issues are now addressed in the staged patch.
- Clean CI-like verification after fix: `make db-postgres-verify` PASS and aggregate `make release-gate` PASS.

**New Risks:**
- Main release gate is red on the pre-fix run: `frostgate-release-images` failed `db-postgres-verify` inside `make release-gate`; staged fix must be committed/pushed and rerun.
- R4.11 production closure proof is pending until migration 0178 is applied/verified in production.
- Core CI was still in progress during this review; final hardening/unit outcome must be checked before declaring repository GREEN.

**Decisions Made:**
- Overall status moved from GREEN to YELLOW due to live release-gate failure on main; remains YELLOW until patched release-images reruns green.
- Primary objective for today is release/CI health, not roadmap expansion.
- Secondary objective remains L14 founder/commercial closure because it is the longest pole to customer one.
- No new product work is authorized; H1 remains deferred until design partner evidence requires it.

**Updated Launch Confidence:** 97%

**Next:** Restore release-gate green -> collect R4.11 production 0178 proof -> close L14/design-partner scheduling -> pre-engagement `pg_dump` -> customer one.

---

### 2026-08-07 — Daily Execution Review · C4 COMPLETE · v1.0.0-rc1 TAGGED · H0-PR1/PR2/PR3 MERGED

**Review Type:** Daily Execution Review

**Summary:** Full executive delivery review across ROADMAP.md, EXECUTION_STATE.md, LDR-2026-001, H0 PR sequence plan, and repository state (commits c11c4300 through 4bf99a3f). All 4 launch constraints (C1–C4) are now DONE. v1.0.0-rc1 tagged at e1f807dd. H0-PR1 (#615), H0-PR2 (#616), H0-PR3 (#617) all merged. LDR-2026-001 is fully satisfied. The platform is in FULL GO state. Engineering is no longer the critical path — L14 (commercial paper + design partner scheduling) is the longest pole. DoD: 13/14 gates resolved (L9 conditional, L12 accepted, L14 founder track). Launch confidence raised from 97% to 99%.

**Major Changes:**
- C4 COMPLETE: T8/T9/T10/T13 all executed 2026-08-06. Evidence files committed. LDR-2026-001 C4 → DONE.
- v1.0.0-rc1 tagged at `e1f807dd` (close C4 commit).
- H0-PR1 merged (#615): AUTH-001 fix — BFF routes workforce mutations through admin gateway; invitation_id RLS fix.
- H0-PR2 merged (#616): `resolve_authoritative_tenant()` — canonical resolver for all mutation routes.
- H0-PR3 merged (#617): `GET /admin/identity/tenants/{tenant_id}/engagements` — tenant-scoped engagement selector API; unblocks H0-PR4.
- C4 session fixes merged to main: D-T9-002 wildcard scope (6299daac), D-T9-003 dark mode (7a2ed2f9), DB RLS/slot fixes (2bbcf90e, 7983afab, c9a63c9a), migration 0174, nav ≤9 items (f3594066).
- EXECUTION_STATE.md updated in place: all current status fields refreshed.

**Completed Tasks:**
- T8: PASS — D-T8-001/002/003 documented; runbooks corrected; rollback proven <15 min.
- T9: PASS — 8 nav items; D-T9-002/003 fixed same session; D-T9-001/004 open (non-blocking).
- T10: CONDITIONAL PASS — portal mechanics proven via T4; data rendering deferred to first engagement.
- T13: CONDITIONAL PASS — core data purged; 2 runbook gaps (Gap 1: locked evidence Step 0; Gap 2: audit ledger non-deletable) patched immediately.
- H0-PR1, H0-PR2, H0-PR3: all merged. H0 is 3/5 complete.
- All 4 LDR constraints: DONE.

**New Risks:**
- D-T8-001: /health does not fail when DATABASE_URL is unreachable — silent false-positive from Railway health probe. Hardening PR needed before Stage 2.
- D-T9-001: Cross-tenant portal access requires Upstash key provisioning on client onboarding — operational gap, not a code change.
- D-T9-004: Verification bundle UI fails silently — root cause not investigated during T9; deferred.

**Decisions Made:**
- Overall status: GREEN. All engineering gates closed. Commercial (L14) is the critical path to first revenue.
- H0-PR4 is today's primary engineering objective. H0-PR5 follows.
- H1 starts when design partner is active; stop H1 when the exit criterion is met (design partner can self-administer), not when all 10 PRs ship.
- T10 data rendering deferral accepted: portal mechanics proven by T4; no live client engagement exists yet to validate data rendering against.
- v1.0.0-rc1 is immutable. Any subsequent hotfixes will be v1.0.0-rc2 or v1.0.1.

**Updated Launch Confidence:** 99%

**Next:** H0-PR4 (portal grant ownership) → H0-PR5 (cross-tenant regression) → first engagement (when L14 closes).

---

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
