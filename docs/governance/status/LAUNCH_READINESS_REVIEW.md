# Launch Readiness Review

Status: **COMPLETE — CONDITIONAL GO**

**Decision: CONDITIONAL GO | Issued: 2026-08-04**

T6 Status: **READY**
Launch Status: **BLOCKED** — pending backup hardening completion (scheduled backup, encryption, manifest signing, offsite replication)

This document is the executive go/no-go decision record before the full H1-H18 production
dry run (T6). It summarizes all completed gate evidence, classifies remaining risks, and
records the launch decision with named authority.

T6 does not begin until this document is complete and the go/no-go decision is recorded.

---

## Document Control

| Field | Value |
|---|---|
| Prepared by | jcosat |
| Review date (UTC) | 2026-08-04T13:00:00Z |
| T5 close date | 2026-08-04 |
| T5 outcome | PASS — G1–G6 all PASS · G6: PASS (no upgrade required) |
| T4 close date | 2026-08-04 |
| T4 outcome | PASS — G1–G6 all PASS |
| Go/No-Go decision | **CONDITIONAL GO** |
| Decision authority | jcosat |
| T6 authorized to begin | **After backup authority reconciliation (see Go/No-Go § Conditions)** |

---

## Gate Evidence Summary

| Gate | Outcome | Date | Key finding |
|---|---|---|---|
| IA-1: Client Org Provisioning | COMPLETE | 2026-08-03 | Auth0 org provisioned per-tenant; fg_app least-privilege; G1-prod + G2-prod PASS |
| T4: Portal Named-User Proof | COMPLETE | 2026-08-04 | G1–G6 PASS; real user invited, accepted, logged in, accessed portal, logged out |
| T5: Infrastructure Headroom | COMPLETE — PASS | 2026-08-04 | G1–G6 PASS; CPU peak 1.14 vCPU (14%), memory 455 MB (5.6%); 8.8s restart-to-health; no data loss; no upgrade required |

---

## T4 Outcome Summary

Named-user production workflow validated end-to-end.

- **Invitee:** jason@frostgate.ai — the-wick-network tenant
- **G1 (Invitation):** invitation issued via internal admin gateway; delivery_state: sent
- **G2 (Email Delivery):** Resend frostgate.ai domain verified; email received
- **G3 (Acceptance):** `POST /portal/invitations/{token}/accept` → 200 OK; pnu1. session issued
- **G4 (Login):** Auth0 RS256 OIDC; tenant resolved; 8h session
- **G5 (Portal Pages):** portal accessible as viewer; no 401/403/redirect loop
- **G6 (Session):** logout → /login; portal inaccessible after logout
- **Fix landed (P-51):** `User-Agent: FrostGate/1.0` added to Resend client (Cloudflare WAF bypass)
- **Evidence:** `docs/governance/status/T4_OPERATIONAL_EVIDENCE.md`

---

## T5 Outcome Summary

**Decision: PASS**

**Reason:** The Railway hobby plan (8 vCPU / 8192 MB API, 1024 MB Redis, 500 MB Postgres volume) comfortably supports first-client volume. Under the 805-request G2 load profile — which covers dashboard, timeline, evidence, reports, and admin operations for a production customer tenant — CPU peaked at 1.14 vCPU (14.3% of limit, 85.7% headroom) and memory peaked at 455 MB (5.6% of limit, 94.4% headroom). DB connections peaked at 3 of 100. Redis memory at 9.83 MB of 1024 MB. Zero 5xx responses. Server-side p95 latency was 164 ms. After a controlled instance restart (`railway redeploy`), the API recovered to healthy state in 8.8 seconds with no data loss, no session corruption, and no audit event gaps. The plan is sufficient for first-client engagement without upgrade. The single largest risk going into T6 is the absence of automated alerting (Railway plan does not include alert configuration via CLI) and in-memory rate limiting that resets on restart — both known gaps, not blocking.

**Infrastructure limits documented:**

| Metric | Limit | Observed peak | Headroom |
|---|---|---|---|
| API CPU | 8.0 vCPU | 1.14 vCPU (14.3%) | 85.7% |
| API memory | 8192 MB | 455 MB (5.6%) | 94.4% |
| DB connections | 100 | 3 (3%) | 97% |
| Redis memory | 1024 MB | 9.83 MB (0.96%) | 98.8% |

**Failure recovery:** 8.8s restart-to-health (G4 `railway redeploy`; health failure observed then recovered). G5: all audit counts identical pre/post restart; zero data loss; no orphaned sessions; credential state intact.

**Observability:** G4.5 PASS — Railway metrics and audit events continuous post-restart; /health 200 in expected latency window. Two known gaps: (1) no distributed tracing (FG_OTEL_ENDPOINT not set); (2) no automated alerting (Railway plan limitation). Both documented as residual risks.

---

## Remaining Risks

All risks rated before T6 begins. Each must be accepted or have a mitigation in place.

| Risk | Severity | Source gate | Status | Mitigation / Acceptance |
|---|---|---|---|---|
| DB startup ordering defect (`_grant_runtime_role_access()` race) | Medium | IA-1 G1-prod | Open — not on critical path | Manual grant pre-application documented; fix tracked in backlog |
| Backup authority unresolved: T1.5 not reliably scheduled; no encryption; no remote offsite | Medium | T1 / T1.5 | **Open — must resolve before T6** | Option A (Railway Pro upgrade) or Option B (formally accept T1.5 with scheduling + encryption + remote offsite configured). Pre-T6 checkpoint `FG-BKP-20260804-00001` taken; restore path proven via T1. |
| L12 gap: FG_SIGNING_SECRET + FG_KEY_PEPPER not rotated | Medium | T3 partial | Open | Rotation deferred with documented rationale |
| FG-LR-005: incident/rollback runbook not timed-drilled | Low–Medium | T8/T9 | Open | Rollback path documented in T5; timed drill in T8 |
| Portal PRs B/C status (named-user cutover, logout revocation) | Low | post-T4 | Archaeology deferred until after T6 | Reviewed post-T6 |
| No distributed tracing (OTel disabled) | Low | T5 G4.5 | Open — accepted for Stage 1 | FG_OTEL_ENDPOINT not configured; diagnose via structured logs and audit tables; configure before second engagement |
| No automated alerting configured | Medium | T5 G4.5 | Open — accepted for Stage 1 | Railway plan limitation; add 5xx spike alert via dashboard before client engagement start |
| In-memory rate limiting reset on restart | Low | T5 G4.5 | Open — accepted | Rate-limiting state lost on container restart; upgrade to Redis-backed before scale-out |
| Orphaned `default` tenant data | P1 data-governance | T5 G2 | **Defect open; non-blocking for T6** | 7 engagements + 11 scan jobs under unregistered `tenant_id='default'`; not exposed via API; T6 uses new disposable tenant; migrate/archive before commercial use |
| DB startup ordering defect (`_grant_runtime_role_access()` race) | Medium | IA-1 G1-prod | Open — not on critical path | Manual grant pre-application documented; fix tracked in backlog |

---

## Launch Blockers

Items that must be resolved before any client onboarding, regardless of gate outcomes.

| Blocker | Gate | Resolution required by |
|---|---|---|
| T6 H1-H18 dry run not yet executed | T6 | Before client onboarding |
| Launch DoD L1-L14 not fully checked | DoD sweep | Before client onboarding |
| Backup scheduling: produce a successful non-zero automated scheduled backup artifact | T1.5 | Before launch authorization |
| Backup encryption: configure `FG_BACKUP_ENCRYPTION_KEY` and verify encrypted backup roundtrip | T1.5 | Before launch authorization |
| Manifest signing: configure `FG_BACKUP_MANIFEST_HMAC_KEY` and verify HMAC-signed manifests | T1.5 | Before launch authorization |
| Offsite replication: configure S3/R2/B2 destination; verify backup upload and remote restore source | T1.5 | Before launch authorization |

---

## Rollback Strategy

| Field | Value |
|---|---|
| Railway API current deployment | 0da6d286 (post-G4 redeploy; same image as d71a11d2) |
| Railway API rollback target | d71a11d2 → commit `2aaa6ab7`; image `sha256:725b10d7`; or further back to dcd8d311/`cde7cb615b`/`sha256:cd547f84` |
| Estimated rollback time | ~5–10 min via Railway dashboard or `railway redeploy` |
| Rollback verified | YES — G4 controlled restart proved rollback path; T5 G1 rollback evidence section complete |
| DB rollback checkpoint | FG-BKP-20260804-00001 · 2026-08-04T12:28:56Z · SHA-256: `af7ac56d...` · 1.73 MB · local path `/var/lib/frostgate/backups/` |
| DB restore time | ~4 s (T1 proven; `pgvector/pgvector:pg18`; see `docs/operators/backup_restore.md`) |
| Portal rollback method | Vercel — promote previous deployment |
| Auth0 rollback method | Revert app / API configuration manually via Auth0 dashboard |
| Rollback decision authority | jcosat |
| Rollback communication plan | Not formally documented — T8/T9 |

---

## Support Readiness

| Item | Status | Notes |
|---|---|---|
| Operator runbook exists | ✅ | `docs/operators/onboarding_runbook.md` |
| Backup and restore runbook exists | ✅ | `docs/operators/backup_restore.md` (T1 verified 2026-07-30) |
| Disaster recovery runbook exists | ✅ | `docs/operators/disaster_recovery.md` (T1.5 2026-07-30) |
| First client prep checklist exists | ✅ | `docs/operators/first_client_prep.md` (T1.5 2026-07-30) |
| Credential delivery runbook current | ⚠️ Partial | `docs/operators/credential_delivery.md` — named-user path not yet updated post-T4; known gap; update before first invite |
| Incident escalation path documented | ⚠️ Not yet | T8/T9 — not on T6 critical path |
| On-call coverage defined | ⚠️ Not yet | Single operator (jcosat); formal on-call structure post-Stage 1 |

---

## Operational Runbooks Status

| Runbook | Location | Last verified |
|---|---|---|
| Backup and restore | `docs/operators/backup_restore.md` | T1 (2026-07-30) |
| Backup automation | `docs/operators/backup_automation.md` | T1.5 (2026-07-30) |
| Disaster recovery | `docs/operators/disaster_recovery.md` | T1.5 (2026-07-30) |
| Backup schedule | `docs/operators/backup_schedule.md` | T1.5 (2026-07-30) |
| Azure AD app setup | `docs/operators/azure_ad_app_setup.md` | PR 25 |
| Operator onboarding | `docs/operators/onboarding_runbook.md` | PR 20 |
| First client prep | `docs/operators/first_client_prep.md` | T1.5 |
| Incident runbook (timed drill) | | Not yet executed — T8/T9 |

---

## Residual Technical Debt

Items known but not blocking launch. Track in backlog; do not allow to delay T6.

| Item | Severity | Backlog reference |
|---|---|---|
| DB startup ordering barrier (`_grant_runtime_role_access()` race) | Medium | ROADMAP — post-IA-1 backlog |
| Redis rate limiter (portal) — in-memory fallback only if Redis unavailable | Low | P2 backlog — T5 startup warning noted |
| Explanation manifest persistence (DB) | Low | P2 backlog |
| `CLIENT_READINESS.md` stale vs named-user portal cutover | Low | Post-T6 cleanup |
| `credential_delivery.md` needs T4 named-user rewrite | Low | Post-T6 cleanup |
| Portal PRs B/C audit (named-user cutover, logout revocation) | Low | Post-T6 |
| Orphaned `default` tenant: 7 engagements + 11 scan jobs | P1 data-governance | Scoped migration defect; non-blocking for T6 |
| In-memory rate limiting state lost on restart | Low | T5 G4.5 noted; Redis-backed upgrade deferred to scale-out |
| OTel tracing not configured (FG_OTEL_ENDPOINT missing) | Low | T5 startup warning noted; configure before second engagement |

---

## Go/No-Go Decision

| Field | Value |
|---|---|
| Decision | **CONDITIONAL GO** |
| Conditions (if conditional) | See conditions table below |
| T6 authorized | After Condition 1 is resolved |
| T6 authorized start date | As soon as Condition 1 is closed |
| Decision authority | jcosat |
| Rationale | T1–T5 gates all PASS or complete; T4 and T5 prove named-user flow and infrastructure capacity end-to-end. One open governance question (backup authority) must be formally resolved before rehearsal begins. All other T6 prerequisites are met. |

**Basis for CONDITIONAL GO (not NO-GO):** The platform has demonstrated production readiness on all functional and capacity dimensions. The remaining open item is operational posture (backup authority), not a functional or security defect. The pre-T6 backup checkpoint `FG-BKP-20260804-00001` exists and the restore path has been proven (T1). The go/no-go decision would be NO-GO only if the backup checkpoint did not exist — it does.

### Conditions

All conditions must be met before T6 begins. T6 may not start with any condition unresolved.

| # | Condition | Acceptance criteria | Status |
|---|---|---|---|
| 1 | **Backup authority formally reconciled** | Either (A) upgrade Railway to a plan supporting native automatic backups and enable them, OR (B) formally accept T1.5 as production backup authority with documented gaps and a written schedule for configuring encryption + remote offsite + cron. Record the decision in this document below. | **CLOSED (T6 AUTHORIZED)** — Backup authority accepted for operational rehearsal. Launch authorization remains contingent on closure of the four mandatory backup hardening items. |
| 2 | **Pre-T6 backup checkpoint evidenced** | Immutable backup ID, timestamp, SHA-256, and restore instructions recorded. | ✅ DONE — `FG-BKP-20260804-00001` · 2026-08-04T12:28:56Z · SHA-256: `af7ac56d44a5354a7fb2a4cf8af137c4508bc9d60131a96aaa1e4bac2733c41b` · restore: `pgvector/pgvector:pg18` per T1 runbook |
| 3 | **`default` orphan data non-blocking for H1–H18** | Confirm no T6 H1-H18 step depends on data under orphaned `tenant_id='default'`. | ✅ CONFIRMED — T6 creates a fresh disposable tenant (H3); H9 explicitly accepts "no engagements" for fresh tenant; no H1–H18 step reads from `fa_engagements` or `fa_scan_jobs` under `default` |
| 4 | **T6 uses a registered disposable tenant** | T6 platform state table specifies a freshly registered disposable tenant (not `the-wick-network`, not `default`). | ✅ CONFIRMED — T6 evidence doc spec: "create a new disposable tenant; do not use the-wick-network" |
| 5 | **Known observability gaps documented** | No distributed tracing (FG_OTEL_ENDPOINT not set) and no automated alerting are acknowledged as accepted risks for Stage 1 with mitigations noted. | ✅ DONE — documented in T5 G4.5 and LRR Remaining Risks |

### Backup Authority Reconciliation (Condition 1)

**Recommended path: Option B** — accept T1.5 as production backup authority for Stage 1.

**Current T1.5 state:**

| Item | Status | Notes |
|---|---|---|
| Backup mechanism | ✅ PROVEN | T1 restore drill: `pgvector/pgvector:pg18` pg_dump/pg_restore; ~4s restore; 2026-07-30 |
| Script (`fg_backup.sh`) | ✅ EXISTS | 10 subcommands; SHA-256 manifest; immutable backup IDs; 73 passing tests |
| Scheduled automation | ⚠️ FAILED | One cron run on 2026-07-30 produced a 0-byte dump; no subsequent automated runs; `backup_health.json` status=critical |
| Encryption | ⚠️ NOT CONFIGURED | `FG_BACKUP_ENCRYPTION_KEY` not set; all backups `encrypted: false` |
| Manifest signing | ⚠️ NOT CONFIGURED | `FG_BACKUP_MANIFEST_HMAC_KEY` not set; all manifests `manifest_signature: unsigned` |
| Remote offsite | ⚠️ NOT CONFIGURED | `FG_BACKUP_OFFSITE_PROVIDER=local`; copies go to local filesystem only; no S3/R2/B2 |
| Pre-T6 checkpoint | ✅ TAKEN | FG-BKP-20260804-00001 · 1.73 MB · SHA-256 verified · 2026-08-04T12:28:56Z |

**Option B acceptance criteria (for T6 GO):** Operator records a named decision here that T1.5 covers the backup authority role for Stage 1, and documents a completion target for: (a) fix cron scheduling, (b) configure encryption key, (c) configure remote offsite provider. The pre-T6 checkpoint is the T6 rollback baseline regardless.

**Backup Authority:** T1.5 (FrostGate Backup Authority)
**Status:** PROVISIONALLY ACCEPTED FOR T6 / CONDITIONALLY ACCEPTED FOR LAUNCH
**Decision Authority:** Jason
**Decision Date:** 2026-08-04

**Basis:** T1 restore drill previously demonstrated successful restore capability (`pgvector/pgvector:pg18`; ~4s restore; 2026-07-30). A verified pre-T6 checkpoint (`FG-BKP-20260804-00001`, 1.73 MB, SHA-256 verified) exists and rollback is available for the operational rehearsal. Remaining hardening work (scheduling, encryption, manifest signing, offsite replication) does not prevent execution of T6 but does prevent production launch authorization.

**T1.5 is the designated production backup authority for Stage 1**, subject to mandatory completion of scheduling, encryption, manifest signing, and offsite replication before launch authorization is granted.

---

## Next Steps

| Step | Owner | Target date | Status |
|---|---|---|---|
| Condition 1: backup authority reconciliation | jcosat | 2026-08-04 | **CLOSED — T6 AUTHORIZED** |
| T6: Full H1-H18 production dry run | jcosat | Now | **READY** |
| Launch DoD L1-L14 sweep | jcosat | After T6 | Pending |
| Incident runbook timed drill (T8/T9) | jcosat | Before client onboarding | Pending |
| Railway plan upgrade | N/A | N/A | T5 G6: PASS — no upgrade required at Stage 1 volume |
| L12 rotation gap: FG_SIGNING_SECRET + FG_KEY_PEPPER | jcosat | Deferred with written rationale | In progress |
| Orphaned `default` tenant data migration defect | jcosat | Before commercial use of legacy records | Defect open |
| Configure T1.5 scheduling + encryption + remote offsite | jcosat | After T6, before second engagement | Pending — per Option B acceptance |
| Update `credential_delivery.md` for named-user path | jcosat | Before first client invite | Pending |
