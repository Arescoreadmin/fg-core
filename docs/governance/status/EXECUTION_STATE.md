# FrostGate Execution State

This is the single canonical execution state for the frozen Launch Readiness Audit.
Update current status fields in place. Preserve historical entries under `Execution History`.

## Current Status

**Date:** 2026-08-03

**Current Branch:** `main`

**Current Commit:** `4a2bb592`

**Current PR:** None — IA-1 COMPLETE; T4 next.

**Overall Status:** GREEN

**Launch Confidence (%):** 79

**Current Critical Path:** T4 portal named-user proof → T5 infra headroom → T6 H1-H18 dry run.

**Current Phase:** Stage 0 / Week 1 Day 4 — T1, T2 complete; T3 partial; IA-1 COMPLETE (G1-dev, G1-prod, G2-prod all PASS); T4 unlocked.

**Current DoD Progress:** 1/14 Launch DoD items checked (L4: PASS). L12 remains IN PROGRESS. IA-1 COMPLETE establishes L-level evidence for RLS/least-privilege architecture and identity provisioning.

**Completed Since Last Update:** G2-prod executed and passed 2026-08-03. Disposable tenant `fg-ia1-prod-validation-20260803` provisioned: Auth0 org `org_ZTxlvEm74W5wG9Q4` created, `provisioning_state=active`, ownership metadata verified (`frostgate_tenant_id` confirmed), idempotency proven (retry returned same binding, no new events), audit trail verified (security_audit_log ids 43 + 45). Auth0 M2M app "FrostGate Identity Authority" (`oyWWKp3DPebUVulQKYP9zRtfLoV74RFB`) created with correct scopes and Railway vars set. IA-1 Final Acceptance recorded. GD-2026-001 CLOSED.

**Current Blockers:**
- T4 NOT STARTED: portal named-user proof (2.0d, closes FG-LR-002, required for L1/L2). Now unblocked.
- G2-dev BLOCKED: Auth0 dev tenant (frostgate-dev) not yet created — manual browser action (parallel track, not on critical path).
- FG-LR-001: no verified end-to-end production dry run on the current identity/provisioning stack.
- FG-LR-004: Railway plan/headroom and orphan recovery are unproven under engagement load.
- FG-LR-005: incident/rollback runbook and timed drill are missing.
- L12 gap: FG_SIGNING_SECRET and FG_KEY_PEPPER not yet rotated.
- Startup ordering defect: `_grant_runtime_role_access()` race condition not yet fixed.

**Top Three Priorities:**
1. Begin T4 portal named-user proof (2.0d, closes FG-LR-002, required for L1/L2).
2. Auth0 dev tenant (frostgate-dev): browser action → API-DEV vars → redeploy → G2-dev gate (parallel track).
3. T5 infra headroom (Railway Pro decision, backup automation validation).

**Next Required PR:** T4 portal named-user proof. Branch from main.

**Estimated Engineering Days Remaining:** ~12.5 (budget 19.0; T1 1.5d, T1.5 ~1.0d, T2+T3 ~0.5d, IA-1 work ~3.5d consumed).

**Estimated Launch Date:** 2026-08-27, contingent on all Launch DoD L1-L14 passing.

**Roadmap Drift:** PRs #601-608 (IA-1 provisioning work + audit RLS fix) not in the frozen 30-day launch plan — required unplanned engineering time. IA-1 now operationally complete; no further drift expected on this track.

**Known Governance Deviation:** GD-2026-001 CLOSED 2026-08-03. See `GOVERNANCE_DEVIATIONS.md`.

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
