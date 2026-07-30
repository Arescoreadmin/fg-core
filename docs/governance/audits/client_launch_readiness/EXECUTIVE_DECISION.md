# FrostGate Launch Readiness — Executive Decision

**Audit date:** 2026-07-30 · **Revision 1.3 — FROZEN AS CANONICAL.** Further refinement of this audit is lower ROI than execution; changes from here are recorded as execution learnings (Stage-1 retro, DoD check-offs), not audit revisions.
**Launch gate:** `LAUNCH_DEFINITION_OF_DONE.md` — 14 binary outcomes gate the design partner; 6 more (Stage 2 Exit DoD) gate scaling into Stage 3. The plan flexes; the gate does not. Four failure classes are non-waivable by anyone: tenant-isolation exposure, backup/restore failure, portal login failure, audit/evidence-integrity failure.

**Canonical sequence from here:**
`freeze audit (done) → implementation PR plan for the 14 plan tasks → execute Launch DoD → run design partner → capture actual friction (hours, interventions, support calls) → adjust Stage 2 package from evidence`
**Scope:** Entire `fg-core` repository at `cd79f1f` (main lineage), production topology per `CLIENT_READINESS.md`
**Method:** Direct repository inspection with code-level evidence (see `EVIDENCE_INDEX.md`). Documentation claims were verified against implementation, not trusted.
**Constraint applied:** 20 effective engineering days pre-launch.

---

## VERDICT: READY WITH CONDITIONS

**CONFIDENCE: MEDIUM**
**PRE-LAUNCH EFFORT: 19.0 engineering days** (plan in `THIRTY_DAY_LAUNCH_PLAN.md`; 16.6 committed + 2.4 buffer)
**RECOMMENDED FIRST CLIENT DATE: 2026-08-27, contingent on passing the Launch DoD gate** — the date is earned by L1–L14 all checking, not by the calendar plan completing. Stage 1 design partner; first *full-price* clients (Stage 2) ~2 weeks after a clean design-partner engagement **and** S1–S6.

### TOP FIVE NON-NEGOTIABLE ACTIONS

1. **Re-run the full production dry run (H1–H18) on the current stack.** The last complete dry run was 2026-06-01; the entire identity, provisioning, and credential layer was rebuilt after it, with production incidents in July (`ROADMAP.md` Platform Recovery R0–R7). Nothing else in this audit matters if this fails. *(FG-LR-001, 3 days)*
2. **Prove the portal named-user path with a real external user in production.** Password login is hard-disabled in prod (`apps/portal/app/api/auth/login/route.ts` returns 403); invite → OIDC is the only door, and it has never carried a real client. *(FG-LR-002, 2 days)*
3. **Verify backups and perform one tested restore of production Postgres.** No backup/restore runbook exists anywhere in the repository; the ops_governance "backup records" tables record backups, they don't make them. *(FG-LR-003, 1.5 days)*
4. **Gate the Console and Portal down to the launch surface.** Hide the four overlapping dashboards, the decision-engine legacy pages, and portal stub pages (`/changes` renders a permanently empty list). What a client or operator can click must work. *(FG-LR-007/008, 3 days)*
5. **Write and drill the incident/rollback runbook + alert triage.** July's incidents were recovered ad hoc; a paying client removes that luxury. *(FG-LR-005/010, 1.5 days)*

---

## Answers to the thirteen decision questions

**1. Is FrostGate ready to accept a paying client in 30 days?**
Yes, conditionally. The product surface for an assessor-led field assessment is genuinely built and deep: 13 scan types, NIST AI RMF questionnaire, findings with plain-language explanations, remediation closed loop, signed reports with PDF export, evidence lifecycle locks, append-only audit ledgers, RLS-enforced tenant isolation — all verified in code, not just docs. What is missing is *proof the assembled system works end-to-end on today's production stack*, plus baseline operational safety (backups, incident response, retention). Those fit in 19 days.

**2. What are the true launch blockers?**
Five (full detail in `LAUNCH_BLOCKERS.md`): unverified current-stack E2E flow (FG-LR-001); unproven portal named-user login in prod (FG-LR-002); no tested DB backup/restore (FG-LR-003); unverified hobby-tier infrastructure headroom with in-process background work (FG-LR-004); no incident/rollback runbook (FG-LR-005). None require building new product. All are verification and operationalization.

**3. What must be completed before client one?**
The five blockers, plus: manual deletion runbook honoring all three DPA commitments — day-90 expiry, 5-business-day early request, 10-business-day termination (FG-LR-006), launch-mode UI gating (FG-LR-007/008), report/PDF QA on real dry-run data (FG-LR-011), alert triage doc (FG-LR-010), Anthropic auto-recharge (FG-LR-013), and the discoveries-first portal dashboard reorder (FG-LR-028 minimum). Total: 16.6 days.

**4. What can safely wait until after client three?**
Docs reconciliation beyond the security-relevant corrections (FG-LR-009 remainder), secret rotation full inventory (FG-LR-012 beyond top-5), automated retention purge, admin_gateway topology decision (FG-LR-019), removal of legacy `/remediation` routes (FG-LR-025).

**5. What should wait until after client ten?**
Client email digests/scheduled re-scans/snapshot deltas as *automation* (manual versions earlier — FG-LR-014), Prometheus/Grafana observability and SLOs (FG-LR-017), multi-instance scaling work (FG-LR-016), `field_assessment.py` decomposition (FG-LR-015), repo hygiene sweep (FG-LR-018), SOC 2 Type II program.

**6. What should be removed, hidden, merged, or deferred?**
See `DEFER_REMOVE_MERGE.md`. Headlines: hide 10+ console legacy pages and merge four dashboards into one; hide portal `/changes` and unavailable export options; park the self-serve Tier-1 funnel and Stripe checkout; freeze the trust-layer expansion arc and enterprise KMS stubs; defer subscription/billing v2 completion and invoice manually.

**7. Is the Console usable enough for internal operators?**
Marginally, for a founder-operator who built it — no, for anyone else. The engagement workspace itself (guided gates, scan panels, QA approve, readiness) is task-complete and verified. The problem is everything around it: ~22 nav items in 6 groups, four dashboard-class pages with overlapping claims, and a legacy decision-engine wing unrelated to the launch offering. Launch-gate it to ≤9 items (`CONSOLE_UX_AUDIT.md`).

**8. Is the Portal simple and credible enough for customers?**
Close. The core client journey (login → engagement → risk dashboard → findings → remediation → reports → attestation) is real, wired to live data, and better than what Big-4 deliverables offer. It is undermined by stub pages, a 12-item nav for a 6-task user, and an untested invite path. One day of gating plus the dry run fixes the credibility risk (`PORTAL_UX_AUDIT.md`).

**9. What is the safest initial customer profile?**
A Central Florida SMB/mid-market org (25–500 employees) on Microsoft 365, in a *pressure-aware but not examiner-imminent* regulated segment (medical group, law firm, community bank without an active exam), with a friendly relationship, engaged via the Stage 1 design-partner terms: discounted, explicit pilot framing, operator-led delivery. Avoid for now: CMMC-mandated defense contractors (highest stakes), orgs requiring SOC 2 of vendors, orgs off Microsoft 365 (connector coverage collapses to the 3 no-auth scans).

**10. What rollout conditions would require an immediate stop?**
Cross-tenant data exposure of any kind; evidence/audit-chain integrity failure (verification bundle tamper flag on untampered data); loss of client data with no restore path; portal lockout affecting a paying client >24h; AI-generated report content presenting fabricated compliance claims. Full stop/rollback matrix in `STAGGERED_ROLLOUT_PLAN.md`.

**11. What is the total pre-launch engineering effort?**
19.0 days against a 20-day budget: 8.5 (P0 blockers) + 8.1 (P1 pre-client-one) + 2.4 buffer for dry-run-discovered defects. Arithmetic in `THIRTY_DAY_LAUNCH_PLAN.md`.

**12. What are the 10 highest-ROI actions?**
See `TOP_ROI_ACTIONS.md`. Top three: production dry run (10), named-user portal proof (10), Anthropic auto-recharge (9 — trivial cost, prevents an in-meeting failure).

**13. Final launch verdict?**
Below.

---

## Scoring model (0–10, deliberately uninflated)

Scores judge readiness for the *first clients*, not against absent future features. "Min action" = minimum required for launch; blank = none required.

| Area | Score | Evidence (EVIDENCE_INDEX) | Conf. | Why not higher | Min action for launch |
|------|-------|---------------------------|-------|----------------|----------------------|
| Production readiness | 5 | E16–E24 | High | Unverified current-stack E2E; hobby-tier single instance; no rollback drill | FG-LR-001/004/005 |
| Security maturity | 7 | E1–E15 | High | No rotation procedure; portal chain unproven in prod; migration risk-flag set | FG-LR-002/012 |
| Tenant safety | 7 | E1/E2/E13 | High | FORCE RLS + param context + forensic tests; held back only by lack of a current-prod verification pass | inside FG-LR-001 |
| Operational readiness | 4 | E21–E28 | High | No backups/restore, no incident process, no alert ownership | FG-LR-003/005/010 |
| Customer readiness | 6 | E39–E45 | Med | Deliverables complete; invite path + PDF quality unverified on current stack | FG-LR-002/011 |
| Console usability | 4 | E29–E31 | High | 22 nav items, 4 dashboards, legacy wing; engagement workspace itself is a 7 | FG-LR-007 |
| Portal usability | 6 | E32–E36 | High | Stub pages, 12-item nav, jargon; core journey is strong | FG-LR-008 |
| E2E workflow completeness | 6 | END_TO_END_FLOW_AUDIT | High | Retention/offboarding missing; reassessment manual; invitation handoff unproven | FG-LR-006 runbook |
| Assessment quality | 7 | E44; PRs 26/28/29 | Med | 13 scan types + 69-control fusion; depth validated only at June dry run | re-validate in FG-LR-001 |
| Evidence quality | 8 | E10–E12/E15/E46 | High | Strongest dimension; only current-stack verification pending | — |
| Reporting quality | 6 | E39; TC-7 | Med | Engine + signing + quality inputs real; human QA on current output pending | FG-LR-011 |
| Remediation readiness | 6 | E45 | High | Closed loop works; no owner assignment, no reminders (accepted stage 1) | — |
| Continuous governance readiness | 4 | FG-LR-020 | High | Machinery without a motion; correct sequencing, so not penalized further | — (post-launch) |
| Enterprise readiness | 4 | Phase 4 gates unstarted | High | No SOC 2, no SLAs, single operator — irrelevant to first 3 clients by design | — |
| Support readiness | 4 | E35; ops audit | Med | Founder white-glove only; fine ≤3 clients, unscalable | FG-LR-010 |
| Commercial readiness | 5 | E40/E47/E48 | Med | Paper + invoicing adequate; pricing informal; billing automation absent (deferred deliberately) | founder track |
| Maintainability | 3 | E25; 91 svc pkgs; 168 migrations | High | 12.7k-line module, 222 routers, doc drift, duplicate trees — biggest long-term tax | — (post-launch) |
| Developer experience | 5 | E19; Makefile lanes | Med | Excellent CI discipline offsets surface sprawl; onboarding a second engineer would be slow | — |
| Competitive moat | 7 | MOAT_ASSESSMENT | Med | Architecture 9/10; accrued data 1/10 — compounding starts at client one | launch itself |
| Confidence in 30-day launch | 6 | this plan | Med | 18d plan fits 20d budget with thin buffer; single-operator schedule risk | hold the ops floor, flex the date |

---

## Moat contribution of this launch (FOUNDER_DIRECTIVE alignment)

The moat thesis — deterministic evidence chain + assessor-led field evidence + governed workflow — is *implemented*, and more deeply than any of the four competitor classes offers (`MOAT_ASSESSMENT.md`). But the compounding mechanisms (institutional memory, longitudinal drift, benchmarks) all require **client engagements flowing through the system**. Every pre-launch day spent adding trust-layer depth delays the only input the moat cannot be built without. Launching — even at Stage 1 scale — is itself the highest-leverage moat action available. This is a **[MOAT-WIDENING]** decision: the first client's evidence graph is the first entry in an asset no competitor can backfill.

---

VERDICT: **READY WITH CONDITIONS**
CONFIDENCE: **MEDIUM**
PRE-LAUNCH EFFORT: **19.0 engineering days**
RECOMMENDED FIRST CLIENT DATE: **2026-08-27 — contingent on all Launch DoD items (L1–L14) passing, not on plan completion**

TOP FIVE NON-NEGOTIABLE ACTIONS:
1. Full production dry run (H1–H18) on the current stack — FG-LR-001
2. Real external-user portal invite→OIDC→session proof in production — FG-LR-002
3. Verified Postgres backup + one tested restore + runbook — FG-LR-003
4. Launch-mode gating of Console and Portal surfaces — FG-LR-007/008
5. Incident/rollback runbook drilled once + alert triage ownership — FG-LR-005/010

---

## Addendum — Revision 1.1 (founder review response)

Founder review of revision 1.0 identified six areas where the audit critiqued without prescribing. This revision adds the prescriptions in place; **verdict unchanged, budget 18.5 → 19.0 days** (one 0.5-day launch item absorbed: the discoveries-first portal dashboard reorder).

1. **Console target design** — `CONSOLE_UX_AUDIT.md` §5 now specifies the destination: a 7-zone **Operator Home** work-queue (today's engagements · waiting on client · evidence needing review · reports pending approval · high-risk findings · governance alerts · system health), each zone mapped to an existing endpoint, plus a 6-destination target screen map. New finding FG-LR-027 (3d, Stage 2→3).
2. **Portal continuous journey** — `PORTAL_UX_AUDIT.md` §5 specifies the 9-step carried journey (Login → Welcome → … → Schedule follow-up) with a BFF-computed `journeyState` stepper over existing pages. New finding FG-LR-028 (2.5d, Stage 2→3; 0.5d minimum in launch).
3. **Customer psychology** — `PORTAL_UX_AUDIT.md` §5.2 maps the confidence curve, including the minute-five "worth paying for" moment; its cheapest fix (lead the dashboard with concrete discoveries, not charts) moved *into* the launch plan.
4. **Executive report specification** — `CUSTOMER_COMMERCIAL_READINESS.md` now specifies the 7-chapter enterprise spine (Exec Summary → Business Risk → Financial Impact → Top-10 Actions → Roadmap → Technical Appendix → Evidence) mapped against the current PDF. New finding FG-LR-026 (Report v2, 3d, Stage 2).
5. **Operating-model math** — `CUSTOMER_COMMERCIAL_READINESS.md` now quantifies: ~13.5 operator-hours/engagement, 1–2 engagements/week capacity (independently confirming the rollout caps), $3.5k–5.5k pricing floor, ~2-week delivery cycle, support-load ceiling at 10 clients, and calendar-anchored renewal/upsell triggers (delivery, day-30, day-90 retention decision, quarterly).
6. **Continuous governance repositioned** — revision 1.0 wrongly filed CG under "later." FG-LR-020 is re-cut: the *scheduler* stays deferred, but **CG v0 launches at Stage 1 with zero engineering days** — baseline (delivered report + verification bundle) → monthly manual drift re-scan + delta email → quarterly review call + report regeneration → renewal at the day-90 retention touchpoint. Priced $750–1,500/mo against ~2–3 operator-hours/mo, pitched at report delivery. It starts the longitudinal drift history — the non-backfillable moat asset — from client one. Stage-3 automation (FG-LR-014 + the `/changes` delta view) replaces the manual steps once real CG clients define what to automate first.

The Stage 2→3 investment package (Operator Home 3d + journey shell 2.5d + Report v2 3d ≈ 8.5d) is sequenced in `STAGGERED_ROLLOUT_PLAN.md` and deliberately kept out of the pre-launch window.

## Addendum — Revision 1.2 (founder refinements + launch gate)

Five refinements and one new deliverable, applied in place. Verdict and 19.0-day budget unchanged.

1. **Operator Home now has acceptance criteria, not aspirations** (`CONSOLE_UX_AUDIT.md` §5.1): ≤3 clicks to active work · single owner on every item · explicit aging with amber/red thresholds per queue · no non-closed engagement absent from all zones (testable predicate) · all exceptions on one screen. These gate FG-LR-027 (Stage 2 Exit DoD S2).
2. **`journeyState` is now a formal state machine** (`PORTAL_UX_AUDIT.md` §5.1a): 10 states, explicit allowed-transition table, derivation-not-storage, two sanctioned reverse edges only, fail-safe unknown-state resolution, one CTA per state, table-driven transition tests (Stage 2 Exit DoD S1).
3. **Financial impact is categorized, not predicted** (`CUSTOMER_COMMERCIAL_READINESS.md` report spec ch. 3): every finding maps deterministically to Regulatory Exposure / Operational Risk / Productivity / AI Governance / Data Protection / Business Continuity; dollar ranges only where a citable benchmark exists; never "estimated savings."
4. **Capacity numbers carry explicit assumptions** (one founder, no subcontractors, M365 clients, current automation level, current scope, travel excluded) so they can be revised honestly when any assumption changes.
5. **The moat's deepest layer is named: decision history as institutional memory** (`MOAT_ASSESSMENT.md`): what accumulates is not just observations but *choices with attributed rationale* — governance decisions, accepted risks, exceptions, reviewer reasoning — already flowing into shipped append-only ledgers. Internally: it cannot be reconstructed by a competitor or by the client, and it appreciates on the client's side of the ledger. **Externally, only the approved framing is used** (MOAT_ASSESSMENT framing rule): FrostGate preserves a continuously verified institutional record that would otherwise be fragmented or lost over time.
6. **New deliverable: `LAUNCH_DEFINITION_OF_DONE.md`** — the binary checkpoint this audit previously lacked. 14 Launch DoD outcomes (external client completes engagement unassisted; report signed and delivered; backup restored; remediation tracked to completion; manual governance review performed; incident drill executed; console at launch IA; portal next-action v0; no open P0s; …) gate Stage 1. Full `journeyState`, Operator Home, and Report v2 sit in the Stage 2 Exit DoD (gate semantics settled in the PR #593 review dispositions below) — a recorded, deliberate trade to hold the 20-day cap.

## Addendum — Revision 1.3 (freeze + final consistency validation)

Five cross-artifact checks were executed before freezing; two required fixes, which were applied:

1. **Every Launch DoD item → executable verification step:** PASS. Each L-item carries a verification method, and a traceability table in the DoD now maps L1–L14 to their 30-day-plan tasks.
2. **Every P0 → Launch DoD item:** PASS (FG-LR-001→L2, 002→L1, 003→L4, 004→L10, 005→L7; L13 is the roll-up).
3. **Stage-2 features absent from committed effort:** PASS. Only FG-LR-028's 0.5-day minimum is in the 16.6; the 8.5-day package (026/027/028 remainders) is outside the window.
4. **Risk acceptance impossible for the four fatal classes:** **FAILED, fixed.** `LAUNCH_BLOCKERS.md` previously allowed written founder acceptance for any blocker. Both it and the DoD now state that no written acceptance — founder or otherwise — exists for tenant-isolation exposure, backup/restore failure, portal login failure, or audit/evidence-integrity failure (L1, L2, L4, L13 have no override path).
5. **Date contingent on the gate:** **PARTIAL, fixed.** Both date statements in this document now read as contingent on L1–L14 passing, not on plan completion.

Also in 1.3: the institutional-memory claim is split into internal analysis vs. approved external framing ("FrostGate preserves a continuously verified institutional record of evidence, decisions, exceptions, remediation, and reviewer rationale that would otherwise be fragmented or lost over time") — recorded in `MOAT_ASSESSMENT.md` (framing rule) and `CUSTOMER_COMMERCIAL_READINESS.md` (sales language), paired with the genuine portability story so procurement never reads lock-in.

## Addendum — PR #593 review dispositions (RFC process, pre-merge)

Four review findings from the Codex reviewer, each verified against the repository and dispositioned intentionally per the RFC posture. All four **accepted**; two change launch criteria and are marked accordingly.

| # | Review finding | Verification | Disposition | Launch-criteria change |
|---|---------------|--------------|-------------|------------------------|
| R1 (P1) | `credential_delivery.md` delivers only `PORTAL_PASSWORD` — a credential production rejects; the post-QA client access code's consumption is undocumented | **Confirmed, and worse:** `client_access_code` (FaEngagement) is displayed in console but consumed by **no** portal or core auth path — it is vestigial to the named-user cutover | Accepted. E2E handoff #2 corrected; `credential_delivery.md` rewrite + access-code disposition added to T14; real-handoff rehearsal added to T6/L2; playbook Day-9 and comms rows corrected; folded into FG-LR-009 evidence | Yes — L2 wording strengthened |
| R2 (P1) | DPA also requires deletion within 5 business days of early request (§5) and 10 business days of termination (§10) — day-90-only modeling leaves mid-engagement breach exposure | **Confirmed verbatim** in `contracts/dpa_template.md` lines 67 and 112 | Accepted. FG-LR-006 retitled and rescoped to all three triggers; L11 requires named trigger/owner/deadline per trigger; T13 and E2E stage 15 updated | Yes — L11 strengthened |
| R3 (P2) | S1–S3 gate Stage 2 entry per the DoD, but the rollout schedules that same work *during* Stage 2 — contradiction | Confirmed — an ambiguity this audit created in rev 1.2 | Accepted, resolved by clarifying gate semantics: the S-tier is the **Stage 2 Exit DoD**, gating Stage 2 → Stage 3. Preserves the recorded rev-1.1 intent (build shaped by real client feedback; revenue not stalled behind an 8.5-day build) while keeping a hard gate before scaling to 10 clients. The alternative (pre-Stage-2 gate work) was considered and rejected for contradicting that intent | Yes — gate semantics clarified; founder may overrule to the stricter reading |
| R4 (P2) | FG-LR-020 (CG v0, 0 days, Stage 1) declared FG-LR-014 (Stage 3 automation) as a dependency — canonical JSON would block L6/S4 behind deferred work | Confirmed — dependency-semantics error | Accepted. Dependency removed; FG-LR-014 noted as the CG v1 automation successor, not a v0 prerequisite | No |
