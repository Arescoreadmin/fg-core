# Definition of Done for Launch

**Purpose:** a binary checkpoint. Not tasks — outcomes. Every item is pass/fail with a named verification method and a durable evidence artifact. The design partner is not onboarded until **every Launch DoD item is checked**; the first full-price cohort (Stage 2) is not onboarded until every Stage 2 DoD item is checked.

Scope note: the founder's review draft of this checklist included "Portal journey is driven by `journeyState`." The full state-machine stepper is budgeted in the Stage 2→3 package (2.5d; putting it pre-launch would exceed the 20-day cap), so it appears here in the **Stage 2 DoD**, with a defined v0 next-action requirement in the Launch DoD. This is a deliberate trade, recorded so it can be overruled deliberately.

---

## Launch DoD — gate to Stage 1 (design partner)

| # | Outcome (binary) | Verified by | Evidence artifact | Findings closed |
|---|------------------|-------------|-------------------|-----------------|
| L1 | A real external identity completes a full engagement journey in production — invite → email → accept → OIDC login → engagement pages → evidence view → logout with Core-side session revocation — **without engineering intervention** | Cold external mailbox test during dry run | Dry-run log §portal, session + revocation records | FG-LR-002 |
| L2 | The full H1–H18 flow passes on the current production stack, including `migration_status` clean against prod and the client-access-code delivery rehearsal | Timed dry run | Dated H1–H18 log in `docs/operators/` | FG-LR-001 |
| L3 | A report is generated, Ed25519-signed, QA-approved (SoD-gated), delivered, and the PDF passes the section QA checklist (no placeholders, advisory language, manifest hash, data-collected appendix populated) | Human QA against checklist on dry-run artifact | Signed-off checklist stored with dry-run log | FG-LR-011 |
| L4 | A production database backup has been restored successfully into a scratch database with row-count verification of a known engagement | Restore drill | `docs/operators/backup_restore.md` + dated restore log | FG-LR-003 |
| L5 | A remediation item has been tracked to completion through the portal: client marks resolved with evidence note → observation + evidence link created → NIST response updated → roadmap re-phased | Dry-run step H15–H16 | Finding history + audit events for the test item | (part of L2) |
| L6 | One monthly governance review (CG v0 drift cycle) has been performed manually on the dry-run engagement: re-scan → delta identified → templated delta summary produced | Manual CG v0 rehearsal | Delta summary document + re-scan results | FG-LR-020 (v0 proven) |
| L7 | An incident drill has been executed: test alert fired and acknowledged within target, and a Railway rollback to the previous deploy completed in under 15 minutes | Timed drill | Incident runbook + drill timing log | FG-LR-005, FG-LR-010 |
| L8 | Console navigation equals the launch IA: ≤9 items, one dashboard; an operator completes an engagement end-to-end using only visible navigation | Scripted click-through | Nav registry diff + walkthrough note | FG-LR-007 |
| L9 | Every visible portal page renders real data (no permanent empty states); the dashboard leads with concrete discoveries before charts; every screen state presents one obvious next action (v0: Immediate Actions card) | Click-through of every visible nav item on the dry-run engagement | Walkthrough note + screenshots | FG-LR-008, FG-LR-028 (min) |
| L10 | Infrastructure headroom is proven: full scan suite + report generation concurrently with ≥30% memory headroom; one orphan-recovery cycle observed | Load check on prod plan | Metrics capture in dry-run log | FG-LR-004 |
| L11 | The retention purge runbook has been executed once against test data, respecting lifecycle locks and legal holds; DPA language matches actual practice | Purge rehearsal in staging | Purge runbook + execution log | FG-LR-006 |
| L12 | Top-5 blast-radius secrets rotated; rotation procedure documented; Anthropic auto-recharge enabled | Config review | `docs/operators/secret_rotation.md`; billing console screenshot | FG-LR-012, FG-LR-013 |
| L13 | **No P0 finding remains open** — FG-LR-001…005 exit criteria all met (this row is the roll-up assertion) | Audit findings review | Updated `audit_findings.json` statuses | FG-LR-001–005 |
| L14 | Commercial paper ready: price card ($3.5k–5.5k anchor), CG v0 one-pager, response-time expectation in letter #1, Stripe invoice flow confirmed | Founder review | Updated letters + proposal template | founder track |

**Rule:** any unchecked item on the day the design partner is scheduled pushes the date, not the item — with two exceptions that may be explicitly risk-accepted in writing by the founder: L11 (if the purge rehearsal slips, the calendar control + day-90 buffer covers the first engagement) and L14 (commercial paper can trail signature by days, not the engagement itself).

**Non-waivable classes.** No written risk acceptance — founder or otherwise — exists for failures in these four classes: **tenant-isolation exposure · backup/restore failure · portal login failure · audit/evidence-integrity failure.** L1, L2, L4, and L13 therefore have no override path of any kind. This mirrors the never-downgrading stop conditions in `STAGGERED_ROLLOUT_PLAN.md`.

### Traceability: every Launch DoD item → its executable step in the 30-day plan

Task IDs follow execution order v2 (T1–T14, per `IMPLEMENTATION_SANITY_PASS.md`).

| DoD | Plan task (THIRTY_DAY_LAUNCH_PLAN.md) | DoD | Plan task |
|-----|----------------------------------------|-----|-----------|
| L1 | T4 (portal named-user proof) | L8 | T9 (console gating) |
| L2 | T6 (H1–H18 dry run) | L9 | T10 (portal gating + discoveries hero) |
| L3 | T7 (report/PDF QA) | L10 | T5 (infra headroom) |
| L4 | T1 (backup + restore drill, Day 1) | L11 | T13 (retention purge rehearsal) |
| L5 | T6 (dry-run steps H15–H16) | L12 | T2 + T3 + T14 (auto-recharge; rotation act; rotation doc) |
| L6 | T6 (CG v0 drift rehearsal) | L13 | Roll-up of T1, T4, T5, T6, T8 |
| L7 | T8 (incident/rollback drill) | L14 | Founder commercial track |

## Stage 2 DoD — gate to first full-price cohort

| # | Outcome (binary) | Verified by | Findings closed |
|---|------------------|-------------|-----------------|
| S1 | Portal journey is driven by the formal `journeyState` machine (PORTAL_UX_AUDIT §5.1a): persistent stepper, table-driven transition tests passing, fail-safe unknown-state resolution | Unit test suite + design-partner walkthrough | FG-LR-028 |
| S2 | Operator Home v1 replaces the interim dashboard and meets all five acceptance criteria (≤3 clicks, single owner, explicit aging, no invisible engagements, exceptions on one screen) | Scripted walkthrough against seeded tenant | FG-LR-027 |
| S3 | Report v2 spine delivered: business-risk chapter, categorized financial impact (six categories, cited ranges only), Top-10 actions page — methodology reviewed before first client-facing use | Chapter review against spec | FG-LR-026 |
| S4 | ≥1 CG v0 subscription signed and one live monthly cycle delivered to a real client | Contract + delta email on file | FG-LR-020 |
| S5 | Design-partner retro complete: actual hours-per-engagement recorded (replacing the 13.5 h estimate), every manual intervention listed, operating-model assumptions re-checked | Retro doc | — |
| S6 | Any stack change since the Stage-1 dry run has re-passed the golden-path smoke | Smoke log | rollout rule 1 |

---

**Relationship to the other deliverables:** the 30-day plan (`THIRTY_DAY_LAUNCH_PLAN.md`) is the *work*; this document is the *gate*. The plan can flex task order and days; the gate does not flex. If the plan completes but a DoD item fails, the launch date moves.
