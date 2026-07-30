# 30-Day Launch Plan (20 engineering-day budget)

**Window:** 2026-07-31 → 2026-08-27 (recommended first Stage-1 client date).
**Budget:** 20 effective engineering days. **Committed: 16.6 · Buffer: 2.4 · Total: 19.0 ≤ 20.** Founder-only commercial tasks are listed separately and cost no engineering days.

Rule for the window: **no new product surface, no refactors, no trust-layer PRs.** Verification, gating, and operationalization only.

**Execution order v2** — resequenced per `IMPLEMENTATION_SANITY_PASS.md` (structural fixes S-1: secrets rotate *before* the dry run; S-2: Railway plan tier decided Day 1; founder-directed Week-1 reorder: recovery verified before anything else touches production). Task IDs are now T1–T14 and match the sanity-pass table and the DoD traceability map.

**Config-freeze rule (S-1) — permanent invariant, not launch-scoped:** any production configuration change after a validation gate passes (T6 now; any dry run or smoke thereafter) requires a golden-path smoke re-run before the next client-facing use. Validated-config-is-launched-config, forever. Codified as rollout cross-stage rule 1 (`STAGGERED_ROLLOUT_PLAN.md`), which survives this plan.

---

## Week 1 — Recovery first, then the front door (days 1–5)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| T1 | **Day 1.** Backup posture: **decide Railway plan tier first (S-2 — Tasks T5/T6 consume this)**; confirm/enable backups, one restore into scratch DB, row-count verify, write `docs/operators/backup_restore.md`; add pre-engagement `pg_dump` to first_client_prep | FG-LR-003 | 1.5 | Dated restore log committed; plan tier fixed |
| T2 | Anthropic auto-recharge + balance check | FG-LR-013 | 0.1 | Auto-recharge on |
| T3 | Rotate top-5 blast-radius secrets (incl. anything handled during July incidents) — **before validation, so the dry run tests final config (S-1)**; keep prior secret until new one passes health checks | FG-LR-012 (act) | 0.5 | Secrets rotated; services healthy |
| T4 | **Days 2–3.** Portal named-user proof in prod: real external mailbox, invite → Resend → accept → OIDC → engagement pages → logout revocation; verify RESEND_API_KEY/Auth0/PORTAL_SESSION_SECRET; resolve PR B/C status ambiguity in ROADMAP | FG-LR-002 | 2.0 | External identity session created + revoked, logged |
| T5 | **Day 4.** Infra headroom on the Day-1 plan tier: concurrent full-scan-suite + report load check; observe orphan recovery once; document restart semantics | FG-LR-004 | 1.0 | ≥30% memory headroom logged |

**Week 1 subtotal: 5.1** — dry run begins Day 5 against verified recovery, verified auth, final secrets, final plan tier.

## Week 2 — Full dry run + defect capture (days 5–10)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| T6 | Full H1–H18 production dry run on the final stack (includes `migration_status` check against prod, then clear `FG_DB_MIGRATIONS_RISK_ACCEPTED`; rehearsal of the **real** portal-access handoff — named-user invite, not the vestigial access code (PR #593 review); **one manual CG v0 drift-cycle rehearsal** — re-scan + delta summary, DoD item L6). **Closes with a written defect list; fixes draw from the buffer, never ad-hoc mid-run patching** | FG-LR-001, FG-LR-020 (v0) | 3.0 | All 18 steps pass; dated log in docs/operators/; delta summary produced; defect list captured |
| T7 | Report/PDF QA on dry-run artifact: section checklist (no placeholders, advisory language, manifest hash, data-collected appendix); fix defects | FG-LR-011 | 1.0 | Checklist signed off |
| T8 | Incident/rollback runbook + one timed Railway rollback drill + client-comms template. **Drill ends only when the current deploy is restored and health + golden-path smoke pass; low-traffic window, never same-day as dry-run steps (S-4)** | FG-LR-005 | 1.0 | Rollback < 15 min, documented, prod restored |

**Week 2 subtotal: 5.0**

## Week 3 — Gate the surface (days 11–15)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| T9 | Console launch-mode nav gating (≤9 items; hide legacy decision-engine wing + 3 of 4 dashboards); post-gating operator click-through (S-3) | FG-LR-007 | 2.0 | Operator completes engagement using visible nav only |
| T10 | Portal launch-mode gating: hide `/changes`, unavailable export options, trim nav to 6 (+conditional Assistant); NIST tooltip lines; friendly fallback for hidden URLs; **discoveries-first dashboard hero** (FG-LR-028 minimum); post-gating client-view click-through (S-3) | FG-LR-008 (+028 min) | 1.5 | Every visible portal item shows real data; dashboard leads with named discoveries |
| T11 | Hide self-serve funnel links + Stripe checkout path | FG-LR-023 | 0.5 | No public path to checkout |
| T12 | Alert triage doc + Sentry notification rule + test alert acknowledged | FG-LR-010 | 0.5 | Documented triage path, alert received on phone |
| T13 | Manual deletion runbook covering **all three DPA triggers** — day-90 expiry, early request (5 business days, DPA §5), termination (10 business days, DPA §10) — + tested script on dry-run engagement data (respect lifecycle locks/legal hold); calendar control for day-90, on-request procedure for the other two | FG-LR-006 | 0.5 | Runbook covers all 3 triggers; purge executed once on test data |

**Week 3 subtotal: 5.0**

## Week 4 — Truth + margin (days 16–20)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| T14 | Secret-rotation runbook (documenting T3's procedure) + docs truth pass: SYSTEM.md v1.3 security-relevant corrections (auth model, migration count, tenant-context mechanism, prod topology incl. admin_gateway decision one-paragraph), CLIENT_READINESS re-dated, **`credential_delivery.md` rewritten for the named-user flow** (its PORTAL_PASSWORD instructions are rejected by production — PR #593 review) + access-code disposition decided (wire it or remove it from console display) | FG-LR-012 (doc), FG-LR-009 (+019 min) | 1.5 | Rotation doc exists; doc claims match code spot-checks; credential doc matches production auth |
| — | **Buffer** for dry-run-discovered defects (July incident base-rate says expect 2–3) | — | 2.4 | Burn-down logged |

**Week 4 subtotal: 3.9**

## Arithmetic

| Bucket | Days |
|--------|------|
| P0 blockers (T1, T4, T5, T6, T8) | 8.5 |
| P1 pre-client-one (T2, T3, T7, T9–T14) | 8.1 |
| Buffer | 2.4 |
| **Total** | **19.0 / 20** |

Check: week subtotals 5.1 + 5.0 + 5.0 + 3.9 = 19.0 ✓; buckets 8.5 + 8.1 + 2.4 = 19.0 ✓.

## Stage 2→3 investment package (post-launch, NOT in this budget)

The prescriptive designs added in revision 1.1 (Operator Home, portal journey shell, Report v2) are deliberately **excluded** from the pre-launch window — they are the first post-launch build package (~8.5 days: FG-LR-027 3.0 + FG-LR-028 remainder 2.5 + FG-LR-026 3.0), sequenced in `STAGGERED_ROLLOUT_PLAN.md` Stage 2→3. CG v0 (FG-LR-020) costs 0 engineering days and runs from Stage 1 as a founder motion.

Deliberately **not** in the plan (competed and lost): automated retention job (manual runbook suffices — stage 3), email digests/re-scan automation (FG-LR-014), Prometheus dashboards (FG-LR-017), field_assessment.py split (FG-LR-015), repo hygiene (FG-LR-018), open trust-layer/billing PRs (FG-LR-021/022/024), legacy route removal (FG-LR-025), global search, accessibility pass. Rationale per item in `DEFER_REMOVE_MERGE.md`.

## Founder commercial track (parallel, 0 engineering days)

Price card in proposal · response-time sentence in letter #1 · DPA cross-check after tasks 7/12 · Stripe invoice flow confirmation · design-partner selection + scheduling for week of 2026-08-24.

## Stop condition for the plan itself

If the Week-2 dry run surfaces defects consuming more than the 2.4-day buffer, **push the client date rather than cutting tasks 7, 11, or 12** — the ops floor is not negotiable; the date is.

## The gate

This plan is the *work*; **`LAUNCH_DEFINITION_OF_DONE.md` is the *gate*** — 14 binary Launch DoD outcomes (L1–L14) that must all be checked before the design partner is onboarded, and 6 Stage 2 Exit DoD outcomes (S1–S6) before scaling past Stage 2 into Stage 3. The plan can flex task order and days; the gate does not flex. Plan complete + DoD item failing = the date moves.
