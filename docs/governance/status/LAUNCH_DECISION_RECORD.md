# Launch Decision Record

**Launch ID:** LDR-2026-001

Status: **PENDING** — produced after Launch Readiness Review; authorizes production launch

This is an immutable artifact. Once the decision is recorded and signed, it is not edited.
Corrections or reversals require a new Launch Decision Record (LDR-2026-002, etc.).

This document is the equivalent of a CAB approval or flight release. It answers:
"On what date, by what authority, against what evidence, was this system authorized to accept its first paying client?"

---

## Decision

| Field | Value |
|---|---|
| Launch ID | LDR-2026-001 |
| Decision | _(GO / CONDITIONAL GO / NO-GO)_ |
| Decision date (UTC) | |
| Decision authority | |
| Conditions (if Conditional GO) | |
| First authorized client onboarding date | |
| Post-launch review date | |

---

## Evidence Reviewed

All items must be COMPLETE before GO is authorized.

| Item | Status | Evidence file | Key finding |
|---|---|---|---|
| IA-1: Client Organization Provisioning | COMPLETE 2026-08-03 | `docs/governance/status/IA1_OPERATIONAL_EVIDENCE.md` | Auth0 org provisioned per-tenant; fg_app least-privilege; G1-prod + G2-prod PASS |
| T4: Portal Named-User Proof | COMPLETE 2026-08-04 | `docs/governance/status/T4_OPERATIONAL_EVIDENCE.md` | G1–G6 PASS; real user invited, accepted, logged in, accessed portal, revoked |
| T5: Infrastructure Headroom | _(fill)_ | `docs/governance/status/T5_INFRASTRUCTURE_HEADROOM_EVIDENCE.md` | _(fill from T5 G6 decision)_ |
| T6: End-to-End Operational Rehearsal | _(fill)_ | `docs/governance/status/T6_OPERATIONAL_REHEARSAL_EVIDENCE.md` | _(fill from T6 outcome)_ |
| Launch Readiness Review | _(fill)_ | `docs/governance/status/LAUNCH_READINESS_REVIEW.md` | _(GO / NO-GO / CONDITIONAL GO from LRR)_ |
| Launch DoD L1-L14 | _(fill)_ | `docs/governance/audits/client_launch_readiness/LAUNCH_DEFINITION_OF_DONE.md` | _(X/14 items PASS)_ |

---

## Launch DoD Checklist

All 14 items must be PASS before GO is authorized. No partial passes.

| # | DoD item | Status | Gate | Notes |
|---|---|---|---|---|
| L1 | Portal authentication proven end-to-end | _(fill)_ | T4 | |
| L2 | Named-user production workflow proven | PASS | T4 | G1–G6 2026-08-04 |
| L3 | Report QA completed | _(fill)_ | T7 | |
| L4 | Backup and restore proven (row-count verified) | PASS | T1 | 2026-07-30; pg_dump/restore to isolated scratch DB |
| L5 | Secret rotation completed | _(fill)_ | T3 | FG_SIGNING_SECRET + FG_KEY_PEPPER pending |
| L6 | CG v0 drift-cycle rehearsal completed | _(fill)_ | T6 | Re-scan + delta summary |
| L7 | _(fill from DoD document)_ | _(fill)_ | | |
| L8 | _(fill from DoD document)_ | _(fill)_ | | |
| L9 | _(fill from DoD document)_ | _(fill)_ | | |
| L10 | Infrastructure headroom proven (≥30% memory headroom; orphan recovery observed) | _(fill)_ | T5 | |
| L11 | _(fill from DoD document)_ | _(fill)_ | | |
| L12 | FG_SIGNING_SECRET + FG_KEY_PEPPER rotated | IN PROGRESS | T3 | Deferred with documented rationale |
| L13 | Roll-up: T1, T4, T5, T6, T8 all PASS | _(fill)_ | — | |
| L14 | _(fill from DoD document)_ | _(fill)_ | | |

---

## Residual Risks Accepted

Every risk listed here was reviewed by the decision authority and explicitly accepted before GO.

| Risk | Severity | Mitigation in place | Accepted by | Date |
|---|---|---|---|---|
| DB startup ordering defect (`_grant_runtime_role_access()` race) | Medium | Manual grant pre-application documented; fix tracked in backlog | | |
| Railway hobby: no automatic DB backups | Medium | Manual `pg_dump` pre-engagement; upgrade decision from T5 G6 | | |
| L12 gap: FG_SIGNING_SECRET + FG_KEY_PEPPER not rotated | Medium | Deferred with documented rationale in L12 manifest | | |
| FG-LR-005: incident/rollback runbook not timed-drilled | Low–Medium | Rollback path documented in T5; manual drill in T8/T9 | | |
| Portal PRs B/C (named-user cutover, logout revocation) — not yet audited | Low | T4 PASS confirms production path works; branch archaeology post-launch | | |
| _(fill from T5 G6 Residual Risks)_ | | | | |
| _(fill from LRR Remaining Risks)_ | | | | |

---

## Launch Constraints

Conditions that must remain true during and after launch. Violation triggers the rollback policy.

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
| Rollback decision authority | _(fill)_ |
| Rollback estimated time | _(from T5 G1)_ |

---

## Approvals

| Role | Name | Signature / Acknowledgment | Date |
|---|---|---|---|
| Decision authority | | | |

---

## Post-Launch Review

| Field | Value |
|---|---|
| Review date | _(Decision date + 30 days)_ |
| Review type | Stage 1 retrospective (per `FIRST_CLIENT_PLAYBOOK.md §9`) |
| Review criteria | All Stage 1 success criteria (§7 of playbook); Stage 2 gate criteria (§12) |
| Stage 2 authorized | _(yes / no — determined at review)_ |

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
| Scan connectors per engagement | ≤ 8 | 9 (all) | All 9 connectors validated in T6 H11 |

### Stage 2 Authorization Criteria

All of the following must be true before Stage 2 begins:

- [ ] Stage 1 design-partner engagement fully delivered
- [ ] All `FIRST_CLIENT_PLAYBOOK.md §7` success criteria pass
- [ ] Post-launch retrospective complete (§9 of playbook)
- [ ] Every manual intervention dispositioned (runbook edit or backlog item)
- [ ] Zero open non-waivable-class incidents
- [ ] Actual hours per phase recorded and compared to 13.5h model
- [ ] `CLIENT_READINESS.md` updated with actual Stage 1 metrics
- [ ] Railway plan upgrade executed if T5 G6 = PASS WITH ACTION (required before multi-client load)
- [ ] Credential delivery runbook rewritten for named-user path (T14)
- [ ] DB startup ordering defect fixed before second concurrent client
- [ ] Founder go decision recorded in `CLIENT_READINESS.md`

### Stage 2 KPI Targets (set at Stage 1 close)

| KPI | Stage 1 actual | Stage 2 target |
|---|---|---|
| Time to provision tenant | _(from T6 H3)_ | < 2 min |
| Time to first client portal login | _(from T6 H9)_ | < 5 min |
| Manual interventions per engagement | _(from T6 KPIs)_ | 0 |
| Support touches per engagement | _(from Stage 1 retro)_ | ≤ 1 |
| Findings resolved by day 21 | _(from Stage 1)_ | ≥ 1 |
