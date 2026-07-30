# Implementation Sanity Pass — Feasibility Review of the 14 Launch Tasks

**Status:** executed 2026-07-30, pre-merge. This is an implementation-layer artifact, not an audit revision — the audit is frozen at 1.3. Its job: confirm every launch task can be completed independently, with no hidden dependencies discovered mid-Week-2.
**Result: PASS after two structural fixes (S-1, S-2 below), both applied to `THIRTY_DAY_LAUNCH_PLAN.md` in the same commit.**

---

## Structural findings (the reason this pass existed)

| # | Finding | Class | Fix applied |
|---|---------|-------|-------------|
| S-1 | **Secret rotation (old Task 13) was sequenced in Week 4 — *after* the dry run.** Rotating `FG_SIGNING_SECRET`, `PORTAL_SESSION_SECRET`, etc. after L2 passes mutates the exact production configuration the dry run validated, silently invalidating the gate. | Structural — would have surfaced as a mystery failure at the design-partner engagement | Task split: **13a "rotate top-5 secrets" (0.5d) moved to Week 1, before the dry run**; 13b "rotation runbook doc" (0.5d) stays Week 4. New rule added to the plan: *any production config change after the dry run requires a golden-path smoke re-run before the client date* (extends rollout cross-stage rule 1 into the pre-launch window). |
| S-2 | **The Railway plan decision is a shared upstream input to three tasks** (backup availability → Task 3; headroom → Task 4; the stack the dry run validates → Task 5) but was owned by none of them. Deciding it late would re-open all three. | Structural — hidden shared dependency | **Day-1 decision point added:** the plan-tier check/upgrade is the first action inside Task 3 (backup validation), and Tasks 4–5 explicitly consume its output. If the plan changes after Day 1, Tasks 4–5 restart. |
| S-3 | UI gating (Tasks 8/9/10) lands *after* the dry run — hiding nav can't break validated flows, but it does change what the client/operator sees post-validation. | Minor — already mitigated | No plan change: DoD L8/L9 already require post-gating click-throughs as their own validation, and the S-1 smoke rule covers the merges. Recorded so nobody "optimizes" the click-throughs away. |
| S-4 | The rollback drill (Task 7) temporarily reverts production to a previous deploy. Run adjacent to the dry run, it could strand prod on old code. | Minor — procedural | Drill definition amended: it ends only when the *current* deploy is restored and `/health` + golden-path smoke pass; scheduled in a low-traffic window, never same-day as dry-run steps. |

**Week-1 reorder (founder-directed, adopted):** recovery is verified *before* anything else touches production — backup/restore Day 1, portal proof Days 2–3, dry run starting Day 4–5, defect capture closing the week. Testing then runs against verified recovery, verified authentication, and the final plan tier. The old plan had the dry run in Week 2 regardless; the new order pulls it earlier and gives every subsequent production-touching task a known-good restore path.

## Per-task feasibility table

Acceptance criteria live in `LAUNCH_DEFINITION_OF_DONE.md` (DoD column); this table adds what the DoD doesn't carry: rollback-if-partial and merge order. Effort re-checked against task content — all estimates confirmed realistic (basis noted where non-obvious).

| Task (new order) | Objective (one line) | DoD | Effort ✓ | Dependencies | Rollback if partially completed | Validation | Merge order / code? |
|------------------|---------------------|-----|----------|--------------|--------------------------------|------------|--------------------|
| **T1** Backup validation + restore rehearsal + runbook *(was Task 3)* | Prove recovery works before anything else touches prod; settle Railway plan tier (S-2 decision point) | L4 | 1.5d ✓ | None — deliberately first | Nothing to roll back (read-only vs prod; restore goes to scratch DB) | Restore log w/ row counts | No code. Runbook doc merges anytime |
| **T2** Anthropic auto-recharge | Eliminate the trivial in-meeting failure | L12 (part) | 0.1d ✓ | None | N/A | Billing console screenshot | No code |
| **T3** Rotate top-5 secrets *(new 13a, moved per S-1)* | Rotate before validation so the dry run tests final config | L12 (part) | 0.5d ✓ | T1 (restore path exists first — rotation is the first prod mutation) | Keep prior secret until new one validated; revert env var if any service fails health | Post-rotation health + login checks | No code |
| **T4** Portal named-user proof *(was Task 1)* | One real external identity through invite→OIDC→session→logout-revocation in prod | L1 | 2.0d ✓ (incl. Auth0 debug allowance) | T1, T3 (tests final secrets) | Config-only changes; revert Auth0/Vercel settings. If OIDC unfixable in window: time-boxed grant-session fallback for design partner only (documented in FG-LR-002) | Session + revocation records | No code expected; if code fix needed, merges before T5 |
| **T5** Infra headroom load check *(was Task 4)* | Prove concurrent scan suite + report gen on the Day-1 plan tier | L10 | 1.0d ✓ | T1 (plan tier fixed) | N/A (observational) | Metrics capture, ≥30% headroom | No code |
| **T6** Full H1–H18 dry run + CG v0 rehearsal *(was Task 5)* | Validate every launch workflow on the final stack | L2, L5, L6 | 3.0d ✓ (June run + defect margin) | T1–T5 **all** — this is why they precede it | Dry run is on a test engagement; defects go to the buffer, not ad-hoc patching mid-run | Dated H-step log | No code itself; defect fixes merge under the S-1 smoke rule |
| **T7** Report/PDF QA | Human sign-off on the artifact that carries the fee | L3 | 1.0d ✓ | T6 (needs its artifact) | N/A | Signed checklist | Content/prompt fixes possible — merge + smoke |
| **T8** Incident/rollback runbook + timed drill | Practiced recovery before a client is watching | L7 | 1.0d ✓ | T6 complete (S-4: never same-day); low-traffic window | Drill *is* the rollback; ends restored to current + smoke | <15 min timing log | No code |
| **T9** Console launch gating *(was Task 8)* | ≤9 nav items, one dashboard | L8 | 2.0d ✓ (registry predicates exist) | None hard; after T6 by design (S-3) | Feature-flag/registry revert — single commit | Post-gating operator click-through | **Code PR #1** (with T10/T11 if convenient) + smoke |
| **T10** Portal gating + discoveries-first hero *(was Task 9)* | Hide stubs, trim nav, concrete discoveries lead the dashboard | L9 | 1.5d ✓ | None hard; after T6 (S-3) | Registry revert; hero reorder is one component | Post-gating client-view click-through | **Code PR #2** + smoke |
| **T11** Hide self-serve funnel | No public path to unstaffed checkout | (L9 adjunct) | 0.5d ✓ | None | Link restore | No public route to checkout | Rides Code PR #1 or #2 |
| **T12** Alert triage doc + Sentry rule | Alert → named action → owner | L7 adjunct, FG-LR-010 | 0.5d ✓ | None | N/A | Test alert acknowledged | No code |
| **T13** Retention purge runbook + rehearsal | Execute purge once on dry-run data, respecting locks/holds | L11 | 0.5d ✓ | T6 (needs the test engagement's data) | Rehearsal runs on test data only | Purge execution log | No code (SQL script committed as tooling) |
| **T14** Secret-rotation runbook *(13b)* + docs truth pass *(was 13/14)* | Rotation procedure written; SYSTEM.md security claims match code; CLIENT_READINESS re-dated | L12 (part), FG-LR-009 | 1.5d ✓ | T1–T8 outcomes (docs record what was proven) | N/A | Spot-check claims vs code | Docs only, merges last |

Totals unchanged: 16.6 committed + 2.4 buffer = **19.0** (T3+T14 = the old Task 13's 1.0, split 0.5/0.5).

## Independence verdict

After S-1/S-2: every task has (a) a single owner (founder-operator), (b) no undeclared upstream design decisions, (c) a rollback story where partial completion could leave prod dirty (T3, T4, T8, T9, T10), and (d) validation that doesn't depend on a later task. The one intentional serialization is T1→T3→T4→T6: recovery, then final config, then auth proof, then full validation — which is the point, not a hidden coupling. Tasks T2, T5, T9–T13 can flex in order without cross-effects (T5 only after the Day-1 plan decision; T9–T11 and T13 only after T6).

**Conclusion: no unresolved structural issues. The audit is clear to merge.**
