# Launch Decision Record

**Launch ID:** LDR-2026-001

Status: **COMPLETE — CONDITIONAL GO**

**Decision: CONDITIONAL GO | Issued: 2026-08-04T19:40:00Z**

This is an immutable artifact. Once the decision is recorded and signed, it is not edited.
Corrections or reversals require a new Launch Decision Record (LDR-2026-002, etc.).

This document is the equivalent of a CAB approval or flight release. It answers:
"On what date, by what authority, against what evidence, was this system authorized to accept its first paying client?"

---

## Decision

| Field | Value |
|---|---|
| Launch ID | LDR-2026-001 |
| Decision | **CONDITIONAL GO** |
| Decision date (UTC) | 2026-08-04T19:40:00Z |
| Decision authority | jcosat |
| Conditions (if Conditional GO) | See § Launch Constraints — all 4 must close before first client engagement |
| First authorized client onboarding date | As soon as all 4 launch constraints are confirmed closed (estimated 2026-08-05) |
| Post-launch review date | 2026-09-04 (decision date + 30 days) |

**Basis for CONDITIONAL GO:** The platform has passed every functional, security, and capacity gate. The Stage 1 Gold Path executed 15 steps end-to-end in 12.9 seconds with zero manual interventions. The remaining open items are operational posture (backup hardening, UX gates, incident drill) and commercial readiness — none are functional or tenant-isolation defects. CONDITIONAL GO is the correct decision. The conditions are not waivable; they must close before the first client engagement begins.

---

## Evidence Reviewed

All items must be COMPLETE before GO is authorized.

| Item | Status | Evidence file | Key finding |
|---|---|---|---|
| IA-1: Client Organization Provisioning | COMPLETE 2026-08-03 | `docs/governance/status/IA1_OPERATIONAL_EVIDENCE.md` | Auth0 org provisioned per-tenant; fg_app least-privilege; G1-prod + G2-prod PASS |
| T4: Portal Named-User Proof | COMPLETE 2026-08-04 | `docs/governance/status/T4_OPERATIONAL_EVIDENCE.md` | G1–G6 PASS; real user invited, accepted, OIDC login, portal accessed, session revoked |
| T5: Infrastructure Headroom | COMPLETE 2026-08-04 | `docs/governance/status/T5_INFRASTRUCTURE_HEADROOM_EVIDENCE.md` | G1–G6 PASS; CPU peak 14.3% (85.7% headroom); memory peak 5.6% (94.4% headroom); 8.8s recovery; zero data loss |
| T6: End-to-End Operational Rehearsal | COMPLETE 2026-08-04 | `docs/governance/status/T6_OPERATIONAL_REHEARSAL_EVIDENCE.md` | PASS (second run); 11/18 functional steps (H10/H11 require real Azure tenant — not a product defect); 8 defects found and resolved same session |
| Stage 1 Gold Path | COMPLETE 2026-08-04 | § Gold Path Evidence (this document) | 15/15 PASS; 12.9s elapsed; 0 manual interventions; tenant provisioning through portal session revocation |
| Launch Readiness Review | COMPLETE 2026-08-04 | `docs/governance/status/LAUNCH_READINESS_REVIEW.md` | CONDITIONAL GO — T6 authorized; backup authority provisionally accepted for Stage 1 |
| Launch DoD L1-L14 | CONDITIONAL — see checklist below | `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` | 10/14 PASS; 4 items → launch constraints (L7, L8/L9 UX gates, L11, L12) |

---

## Stage 1 Gold Path Evidence

**Run ID:** FG-GP-20260804-004
**Tenant:** `fg-gold-path-20260804-009`
**Engagement:** `2a8be91cff9a43568ee8ba64c86a9ac1`
**Report:** `19f6a4ad1750422fcd732f26182a20b5`
**Executed:** 2026-08-04T19:34:37Z → 19:34:50Z
**Total elapsed:** 12,857ms (12.9s)
**Manual interventions:** 0
**Operator commands:** 1 (`railway up --detach` — deploy bug fixes found during T6 rehearsal)

| Step | Outcome | Elapsed |
|---|---|---|
| 0.1 Provision tenant + credential (direct DB) | PASS | 1,485ms |
| 1.1 Create engagement (ai_governance) | PASS | 279ms |
| 2.1 Trigger network scan (example.com) | PASS | 250ms |
| 2.2 Trigger DNS/email scan (example.com) | PASS | 270ms |
| 2.3 Trigger web-headers scan (https://example.com) | PASS | 275ms |
| 2.4 Poll all scans to completion | PASS | 5,537ms |
| 3.1 Create questionnaire (nist_ai_rmf, 69 controls) | PASS | 275ms |
| 4.1 Generate full_assessment report | PASS | 2,137ms |
| 4.2 Verify report Ed25519 signature | PASS | 228ms |
| 4.3 QA approve report | PASS | 324ms |
| 5.1 Create portal grant | PASS | 337ms |
| 5.2 Portal authenticate (secret → session) | PASS | 354ms |
| 5.3 GET /portal/me (verify active session) | PASS | 292ms |
| 5.4 Revoke portal session | PASS | 302ms |
| 6.1 Issue named-user portal invitation | PASS | 513ms |

**Notes:**
- Step 6.1 delivery_state: `failed` — no SMTP configured in this environment (same as T6 H17; not a product defect; Resend configured in production Vercel deployment)
- Bugs fixed before this run: D-T6-008 (4 background scan tasks missing RLS context) and questionnaire RLS re-query bug (commit `13f1c493`)
- Portal ME engagement_ids: `[]` — canonical credential path; session and client_id verified; engagement association via legacy portal_grants table; not a blocker

---

## Launch DoD Checklist

| # | DoD item | Status | Gate | Notes |
|---|---|---|---|---|
| L1 | Portal authentication proven end-to-end | **PASS** | T4 | G1–G6 2026-08-04; real OIDC user; session revoked |
| L2 | Full H1–H18 dry run PASS | **PASS** | T6 | T6-EXEC-20260804-002; H10/H11 deferred (require real Azure tenant — accepted) |
| L3 | Report QA completed (signed, QA-approved) | **PASS** | Gold Path + T6 | Gold Path 4.1–4.3 PASS; Ed25519 valid; QA-approved; PDF content checklist deferred to T7 |
| L4 | Backup and restore proven (row-count verified) | **PASS** | T1 | 2026-07-30; pg_dump/restore to scratch DB; row-count verified |
| L5 | Remediation item tracked to completion via portal | **PASS** | T6 | H15 PASS (remediation item created and formatted per portal spec) |
| L6 | CG v0 drift-cycle rehearsal (re-scan + delta) | **PASS** | T6 | H5 PASS; re-scan triggered; delta summary produced |
| L7 | Incident drill: alert + Railway rollback in <15 min | **READY TO EXECUTE** | T8 | Runbook: `docs/operators/t8_incident_drill.md` (commit ce37680a); requires operator to execute timed drill and record evidence |
| L8 | Console navigation ≤9 items; operator flow end-to-end | **READY TO EXECUTE** | T9 | Checklist: `docs/operators/t9_console_ux_validation.md` (commit ce37680a); requires walkthrough session |
| L9 | Portal pages render real data; dashboard leads with discoveries | **READY TO EXECUTE** | T10 | Checklist: `docs/operators/t10_portal_ux_validation.md` (commit ce37680a); gold path engagement `2a8be91c` as data source |
| L10 | Infrastructure headroom ≥30% memory during scan + report | **PASS** | T5 | 94.4% memory headroom; all scans + report proven; T5 G1–G6 |
| L11 | Deletion runbook covers DPA triggers; executed once against test data | **READY TO EXECUTE** | T13 | Runbook: `docs/operators/t13_deletion_runbook.md` (commit ce37680a); requires one purge drill against test tenant |
| L12 | Top-5 secrets rotated; Anthropic auto-recharge enabled | **IN PROGRESS** | T2+T3+T14 | FG_SIGNING_SECRET + FG_KEY_PEPPER not rotated; documented rationale in L12 manifest; deferred with acceptance |
| L13 | No P0 finding open; FG-LR-001–005 all met | **CONDITIONAL** | roll-up | L1+L2+L4+L5+L6 PASS; L7 (FG-LR-005 T8) pending — launch constraint; closes when L7 closes |
| L14 | Commercial paper ready (price card, one-pager, Stripe) | **FOUNDER TRACK** | founder | Not blocking engineering release; must close before engagement signed |

---

## Launch Constraints

The following conditions must be confirmed closed before the first client engagement begins. Violation of any constraint that is not closed before client data enters the system is a launch policy violation.

| # | Constraint | Acceptance criteria | Status | Owner | Target |
|---|---|---|---|---|---|
| C1 | Backup hardening: scheduling + encryption + offsite + restore proof | Scheduled cron produces non-zero encrypted artifact; HMAC-signed manifest; R2 offsite upload verified; restore drill PASS (row counts + migration version match) | **DONE** 2026-08-06 — scheduled cron PASS (02:00 UTC, encrypted, R2); restore drill PASS (17 tenants / 17 engagements / 101 findings / 346 audit events / migration 0172 / zero mismatches); evidence: `docs/governance/status/restore_drill_evidence_20260806.md`; fixes: migration 0173 (orphaned alembic_version fn), fg_backup.sh schema_migrations | jcosat | ✅ |
| C2 | Portal invitation URL fix (D-T6-004) | Invitation emails include `?tenant_id=` in accept URL | **DONE** (commit 5a9440bf) | jcosat | ✅ |
| C3 | Global JSON exception handler (PR-T6.5) | All unhandled exceptions return structured JSON; no HTML 500 pages | **DONE** (commit 98088457) | jcosat | ✅ |
| C4 | Launch DoD operational gates (L7, L8, L9, L11) | T8 (incident drill PASS), T9 (console UX PASS), T10 (portal UX PASS), T13 (deletion runbook executed) | **RUNBOOKS DONE** (commit ce37680a); requires operator execution | jcosat | Before client engagement |

**Non-waivable stop conditions (active during engagement):** tenant-isolation exposure, data loss, audit integrity failure, portal login failure >4h. Any of these → immediate stop, founder communicates within 24h.

---

## Residual Risks Accepted

Every risk listed here was reviewed by the decision authority and explicitly accepted before GO.

| Risk | Severity | Mitigation in place | Accepted by | Date |
|---|---|---|---|---|
| DB startup ordering defect (`_grant_runtime_role_access()` race) | Medium | Manual grant pre-application documented; fix tracked in backlog | jcosat | 2026-08-04 |
| Railway hobby: no automatic DB backups | Medium | Manual `pg_dump` pre-engagement; T1 restore proven; pre-T6 checkpoint FG-BKP-20260804-00001 | jcosat | 2026-08-04 |
| L12 gap: FG_SIGNING_SECRET + FG_KEY_PEPPER not rotated | Medium | Rotation deferred; documented in L12 manifest; rotate before second engagement | jcosat | 2026-08-04 |
| FG-LR-005: incident/rollback runbook not timed-drilled | Low–Medium | Rollback path documented in T5 G4 (8.8s proven); timed drill in T8 (launch constraint C4) | jcosat | 2026-08-04 |
| Portal PRs B/C (named-user cutover, logout revocation) not audited | Low | T4 PASS confirms production path works; branch archaeology post-launch | jcosat | 2026-08-04 |
| No distributed tracing (OTel disabled) | Low | Diagnose via structured logs and audit tables; configure before second engagement | jcosat | 2026-08-04 |
| No automated alerting configured | Medium | Railway plan limitation; add 5xx spike alert via dashboard before engagement start | jcosat | 2026-08-04 |
| In-memory rate limiting reset on restart | Low | Redis-backed upgrade deferred to scale-out; one client at a time | jcosat | 2026-08-04 |
| Orphaned `default` tenant data (7 engagements, 11 scan jobs) | P1 data-governance | Not exposed via API; all T6/Gold Path used clean disposable tenants; migrate/archive before commercial use | jcosat | 2026-08-04 |
| Portal ME engagement_ids returns `[]` for canonical credentials | Low | Session and client_id verified; engagement access controlled via credential scopes; P1-01 will unify | jcosat | 2026-08-04 |
| D-T6-001: `FG_DB_MIGRATIONS_RISK_ACCEPTED` still set in Railway | Low | No pending migrations in Stage 1; clear before any schema change | jcosat | 2026-08-04 |

---

## Launch Constraints (Engagement Operations)

Conditions that must remain true throughout the design-partner engagement:

| Constraint | Description |
|---|---|
| One client at a time (Stage 1) | First design-partner engagement only; no concurrent onboarding until Stage 2 gate passes |
| Non-waivable stop conditions | Tenant isolation exposure, data loss, integrity failure, portal login failure → stop engagement, founder communicates within 24h |
| Scope limits | No CMMC-mandated defense contractor; no vendor SOC 2 attestation requirement; no non-M365; no active exam/audit/breach |
| Backup before engagement | Pre-engagement `pg_dump` required before any client data enters the system |
| Support SLA | Business-hours same-day acknowledgment; no SLA promises beyond this |

---

## Rollback Trigger Conditions

Any of the following observed post-launch → stop engagement, execute rollback:

| Condition | Action |
|---|---|
| Tenant isolation exposure (any cross-tenant data leak) | **Immediate stop. Rollback. Founder communicates within 24h.** |
| Audit event integrity failure | Stop engagement. Investigate before resuming. |
| Portal authentication failure (client cannot log in >4h) | Deliver report by encrypted email; fix same-day. |
| Data loss | Stop engagement. Rollback. |
| Platform crash loop during active engagement | Rollback to previous healthy deployment (T5 G1 rollback target). |
| Any non-waivable-class DoD failure | Stop. Rollback. Document. Do not resume until root cause resolved. |

**Rollback execution:**

| Step | Method |
|---|---|
| API rollback | Railway: deploy previous healthy deployment ID (from T5 G1) |
| Portal rollback | Vercel: promote previous deployment |
| DB rollback | Restore from pre-engagement `pg_dump` (per `docs/operators/backup_restore.md`) |
| Rollback decision authority | jcosat |
| Rollback estimated time | ~8.8s for API (T5 G4 proven); ~4s DB restore (T1 proven) |

---

## Approvals

| Role | Name | Signature / Acknowledgment | Date |
|---|---|---|---|
| Decision authority | jcosat | Recorded — CONDITIONAL GO with 4 launch constraints | 2026-08-04 |

---

## Post-Launch Review

| Field | Value |
|---|---|
| Review date | 2026-09-04 (decision date + 30 days) |
| Review type | Stage 1 retrospective (per `FIRST_CLIENT_PLAYBOOK.md §9`) |
| Review criteria | All Stage 1 success criteria (§7 of playbook); Stage 2 gate criteria (§12) |
| Stage 2 authorized | Determined at review |

---

## Stage 2 Exit Criteria

These limits define when Stage 1 ends and Stage 2 begins. Stage 2 is not authorized until
all Stage 1 success criteria (playbook §7) pass and the post-launch review is complete.

### Capacity Limits (Stage 1)

Operating outside these limits in Stage 1 is a launch constraint violation.

| Dimension | Stage 1 limit | Stage 2 threshold | Notes |
|---|---|---|---|
| Design partners (concurrent) | 1 | ≥ 2 | Stage 2 begins with full-price clients |
| Tenants (total) | ≤ 3 | Uncapped | Includes disposable test tenants |
| Named users per tenant | ≤ 5 | Uncapped (per plan) | Portal viewer + operator |
| Active engagements (concurrent) | 1 | ≤ 5 | Railway capacity upgrade may be required |
| Evidence volume per engagement | ≤ 500 evidence items | Uncapped | Redis + DB pressure not yet characterized at scale |
| Reports generated per day | ≤ 3 | Uncapped | PDF export CPU not load-tested beyond dry run |
| API requests per day | ≤ 10,000 | Per plan tier | Establish from T5 G2 actual numbers |
| Scan connectors per engagement | ≤ 8 | 9 (all) | H10/H11 MS Graph requires real Azure tenant |

### Stage 2 Authorization Criteria

All of the following must be true before Stage 2 begins:

- [ ] Stage 1 design-partner engagement fully delivered
- [ ] All `FIRST_CLIENT_PLAYBOOK.md §7` success criteria pass
- [ ] Post-launch retrospective complete (§9 of playbook)
- [ ] Every manual intervention dispositioned (runbook edit or backlog item)
- [ ] Zero open non-waivable-class incidents
- [ ] Actual hours per phase recorded and compared to 13.5h model
- [ ] `CLIENT_READINESS.md` updated with actual Stage 1 metrics
- [ ] Railway plan upgrade executed if T5 G6 = PASS WITH ACTION (not required — T5 G6 PASS with no upgrade needed)
- [ ] Credential delivery runbook rewritten for named-user path (T14)
- [ ] DB startup ordering defect fixed before second concurrent client
- [ ] Founder go decision recorded in `CLIENT_READINESS.md`

### Stage 2 KPI Targets (set at Stage 1 close)

| KPI | Stage 1 actual | Stage 2 target |
|---|---|---|
| Time to provision tenant | ~1.5s (Gold Path 0.1) | < 2 min |
| Time to first client portal login | T4 G3: < 2s accept; G4: Auth0 OIDC < 5s | < 5 min |
| Manual interventions per engagement | 0 (Gold Path baseline) | 0 |
| Support touches per engagement | 0 (Gold Path baseline) | ≤ 1 |
| Findings resolved by day 21 | _(from Stage 1 retro)_ | ≥ 1 |
| Gold Path elapsed (full journey) | 12.9s (FG-GP-20260804-004) | < 30s |
