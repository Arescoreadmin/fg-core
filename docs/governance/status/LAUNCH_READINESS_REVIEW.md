# Launch Readiness Review

Status: **PENDING** — produced after T5 closes, before T6 begins

This document is the executive go/no-go decision record before the full H1-H18 production
dry run (T6). It summarizes all completed gate evidence, classifies remaining risks, and
records the launch decision with named authority.

T6 does not begin until this document is complete and the go/no-go decision is recorded.

---

## Document Control

| Field | Value |
|---|---|
| Prepared by | |
| Review date (UTC) | |
| T5 close date | |
| T5 outcome | _(PASS / PASS WITH ACTION / FAIL)_ |
| T4 close date | 2026-08-04 |
| T4 outcome | PASS — G1–G6 all PASS |
| Go/No-Go decision | _(GO / NO-GO / CONDITIONAL GO)_ |
| Decision authority | |
| T6 authorized to begin | _(yes / no)_ |

---

## Gate Evidence Summary

| Gate | Outcome | Date | Key finding |
|---|---|---|---|
| IA-1: Client Org Provisioning | COMPLETE | 2026-08-03 | Auth0 org provisioned per-tenant; fg_app least-privilege; G1-prod + G2-prod PASS |
| T4: Portal Named-User Proof | COMPLETE | 2026-08-04 | G1–G6 PASS; real user invited, accepted, logged in, accessed portal, logged out |
| T5: Infrastructure Headroom | _(fill)_ | _(fill)_ | _(fill from G6 reason)_ |

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

_(Fill after T5 G6 decision. Copy the Reason paragraph and key findings from T5_INFRASTRUCTURE_HEADROOM_EVIDENCE.md § G6.)_

**Decision:** _(PASS / PASS WITH ACTION / FAIL)_

**Reason:**

**Infrastructure limits documented:**

| Metric | Limit | Observed peak | Headroom |
|---|---|---|---|
| API CPU | | | |
| API memory | | | |
| DB connections | | | |
| Redis memory | | | |

**Failure recovery:** _(G4 restart-to-health time; G5 state integrity outcome)_

**Observability:** _(G4.5 result summary)_

---

## Remaining Risks

All risks rated before T6 begins. Each must be accepted or have a mitigation in place.

| Risk | Severity | Source gate | Status | Mitigation / Acceptance |
|---|---|---|---|---|
| DB startup ordering defect (`_grant_runtime_role_access()` race) | Medium | IA-1 G1-prod | Open — not on critical path | Manual grant pre-application documented; fix tracked in backlog |
| Railway hobby: no automatic DB backups | Medium | T1 | Open — mitigation in place | Manual `pg_dump` pre-engagement; T5 G6 decides upgrade |
| L12 gap: FG_SIGNING_SECRET + FG_KEY_PEPPER not rotated | Medium | T3 partial | Open | Rotation deferred with documented rationale |
| FG-LR-005: incident/rollback runbook not timed-drilled | Low–Medium | T8/T9 | Open | Rollback path documented in T5; timed drill in T8 |
| Portal PRs B/C status (named-user cutover, logout revocation) | Low | post-T4 | Archaeology deferred until after T6 | Reviewed post-T6 |
| _(fill from T5 G6 Residual Risks)_ | | T5 G6 | | |

---

## Launch Blockers

Items that must be resolved before any client onboarding, regardless of gate outcomes.

| Blocker | Gate | Resolution required by |
|---|---|---|
| T6 H1-H18 dry run not yet executed | T6 | Before client onboarding |
| Launch DoD L1-L14 not fully checked | DoD sweep | Before client onboarding |
| _(any T5 G6 mandatory actions)_ | T5 G6 | _(date from T5 G6 table)_ |

---

## Rollback Strategy

| Field | Value |
|---|---|
| Railway previous healthy deployment | _(from T5 G1 Rollback Evidence)_ |
| Estimated rollback time | _(from T5 G1 Rollback Evidence)_ |
| Rollback verified | _(YES / NO — from T5 G1)_ |
| Portal rollback method | Vercel — promote previous deployment |
| DB rollback method | Restore from most recent `pg_dump` (see `docs/operators/backup_restore.md`) |
| Auth0 rollback method | Revert app / API configuration manually |
| Rollback decision authority | |
| Rollback communication plan | |

---

## Support Readiness

| Item | Status | Notes |
|---|---|---|
| Operator runbook exists | | `docs/operators/onboarding_runbook.md` |
| Backup and restore runbook exists | | `docs/operators/backup_restore.md` |
| Disaster recovery runbook exists | | `docs/operators/disaster_recovery.md` |
| First client prep checklist exists | | `docs/operators/first_client_prep.md` |
| Credential delivery runbook current | | Review post-T4 for named-user path |
| Incident escalation path documented | | |
| On-call coverage defined | | |

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
| Redis rate limiter (portal) — in-memory fallback only if Redis unavailable | Low | P2 backlog |
| Explanation manifest persistence (DB) | Low | P2 backlog |
| `CLIENT_READINESS.md` stale vs named-user portal cutover | Low | Post-T6 cleanup |
| `credential_delivery.md` needs T4 named-user rewrite | Low | Post-T6 cleanup |
| Portal PRs B/C audit (named-user cutover, logout revocation) | Low | Post-T6 |

---

## Go/No-Go Decision

| Field | Value |
|---|---|
| Decision | _(GO / NO-GO / CONDITIONAL GO)_ |
| Conditions (if conditional) | |
| T6 authorized | _(yes / no)_ |
| T6 authorized start date | |
| Decision authority | |
| Rationale | |

**If NO-GO:** list the specific blockers that must be resolved before this review is re-run.

**If CONDITIONAL GO:** list the conditions and their acceptance criteria. T6 proceeds only if all conditions are met before first client contact.

---

## Next Steps

| Step | Owner | Target date |
|---|---|---|
| T6: Full H1-H18 production dry run | | |
| Launch DoD L1-L14 sweep | | |
| Incident runbook timed drill (T8/T9) | | |
| Railway plan upgrade (if T5 G6 = PASS WITH ACTION) | | |
| L12 rotation gap resolution | | |
