# 30-Day Launch Plan (20 engineering-day budget)

**Window:** 2026-07-31 → 2026-08-27 (recommended first Stage-1 client date).
**Budget:** 20 effective engineering days. **Committed: 16.6 · Buffer: 2.4 · Total: 19.0 ≤ 20.** Founder-only commercial tasks are listed separately and cost no engineering days.

Rule for the window: **no new product surface, no refactors, no trust-layer PRs.** Verification, gating, and operationalization only.

---

## Week 1 — Prove the system (days 1–5)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| 1 | Portal named-user proof in prod: real external mailbox, invite → Resend → accept → OIDC → engagement pages → logout revocation; verify RESEND_API_KEY/Auth0/PORTAL_SESSION_SECRET; resolve PR B/C status ambiguity in ROADMAP | FG-LR-002 | 2.0 | External identity session created + revoked, logged |
| 2 | Anthropic auto-recharge + balance check | FG-LR-013 | 0.1 | Auto-recharge on |
| 3 | Backup posture: confirm/enable Railway backups (upgrade plan if needed), one restore into scratch DB, row-count verify, write `docs/operators/backup_restore.md`; add pre-engagement `pg_dump` to first_client_prep | FG-LR-003 | 1.5 | Dated restore log committed |
| 4 | Infra headroom: concurrent full-scan-suite + report load check on prod plan; observe orphan recovery once; document restart semantics | FG-LR-004 | 1.0 | ≥30% memory headroom logged |

**Week 1 subtotal: 4.6**

## Week 2 — Full dry run + fix (days 6–10)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| 5 | Full H1–H18 production dry run on current stack (includes `migration_status` check against prod, then clear `FG_DB_MIGRATIONS_RISK_ACCEPTED`; includes client-access-code delivery rehearsal) | FG-LR-001 | 3.0 | All 18 steps pass; dated log in docs/operators/ |
| 6 | Report/PDF QA on dry-run artifact: section checklist (no placeholders, advisory language, manifest hash, data-collected appendix); fix defects | FG-LR-011 | 1.0 | Checklist signed off |
| 7 | Incident/rollback runbook + one timed Railway rollback drill + client-comms template | FG-LR-005 | 1.0 | Rollback < 15 min, documented |

**Week 2 subtotal: 5.0**

## Week 3 — Gate the surface (days 11–15)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| 8 | Console launch-mode nav gating (≤9 items; hide legacy decision-engine wing + 3 of 4 dashboards); smoke click-through | FG-LR-007 | 2.0 | Operator completes engagement using visible nav only |
| 9 | Portal launch-mode gating: hide `/changes`, unavailable export options, trim nav to 6 (+conditional Assistant); NIST tooltip lines on coverage; friendly fallback for hidden URLs; **discoveries-first dashboard hero** (lead with 2–3 concrete plain-language findings before charts — the minute-five confidence fix, FG-LR-028 minimum) | FG-LR-008 (+028 min) | 1.5 | Every visible portal item shows real data; dashboard leads with named discoveries |
| 10 | Hide self-serve funnel links + Stripe checkout path | FG-LR-023 | 0.5 | No public path to checkout |
| 11 | Alert triage doc + Sentry notification rule + test alert acknowledged | FG-LR-010 | 0.5 | Documented triage path, alert received on phone |
| 12 | Manual retention purge runbook + tested script on dry-run engagement (respect lifecycle locks/legal hold); calendar control | FG-LR-006 | 0.5 | Purge executed once on test data |

**Week 3 subtotal: 5.0**

## Week 4 — Truth + hardening margin (days 16–20)

| # | Task | Finding | Days | Exit criteria |
|---|------|---------|------|---------------|
| 13 | Secret inventory + rotation doc; rotate top-5 blast-radius secrets (incl. anything handled during July incidents) | FG-LR-012 | 1.0 | Rotation doc; suspect secrets rotated |
| 14 | Docs truth pass: SYSTEM.md v1.3 security-relevant corrections (auth model, migration count, tenant-context mechanism, prod topology incl. admin_gateway decision one-paragraph), CLIENT_READINESS re-dated | FG-LR-009 (+019 min) | 1.0 | Doc claims match code spot-checks |
| 15 | **Buffer** for dry-run-discovered defects (July incident base-rate says expect 2–3) | — | 2.4 | Burn-down logged |

**Week 4 subtotal: 4.4**

## Arithmetic

| Bucket | Days |
|--------|------|
| P0 blockers (tasks 1,3,4,5,7) | 8.5 |
| P1 pre-client-one (tasks 2,6,8,9,10,11,12,13,14) | 8.1 |
| Buffer | 2.4 |
| **Total** | **19.0 / 20** |

Check: week subtotals 4.6 + 5.0 + 5.0 + 4.4 = 19.0 ✓; buckets 8.5 + 8.1 + 2.4 = 19.0 ✓.

## Stage 2→3 investment package (post-launch, NOT in this budget)

The prescriptive designs added in revision 1.1 (Operator Home, portal journey shell, Report v2) are deliberately **excluded** from the pre-launch window — they are the first post-launch build package (~8.5 days: FG-LR-027 3.0 + FG-LR-028 remainder 2.5 + FG-LR-026 3.0), sequenced in `STAGGERED_ROLLOUT_PLAN.md` Stage 2→3. CG v0 (FG-LR-020) costs 0 engineering days and runs from Stage 1 as a founder motion.

Deliberately **not** in the plan (competed and lost): automated retention job (manual runbook suffices — stage 3), email digests/re-scan automation (FG-LR-014), Prometheus dashboards (FG-LR-017), field_assessment.py split (FG-LR-015), repo hygiene (FG-LR-018), open trust-layer/billing PRs (FG-LR-021/022/024), legacy route removal (FG-LR-025), global search, accessibility pass. Rationale per item in `DEFER_REMOVE_MERGE.md`.

## Founder commercial track (parallel, 0 engineering days)

Price card in proposal · response-time sentence in letter #1 · DPA cross-check after tasks 7/12 · Stripe invoice flow confirmation · design-partner selection + scheduling for week of 2026-08-24.

## Stop condition for the plan itself

If the Week-2 dry run surfaces defects consuming more than the 2.4-day buffer, **push the client date rather than cutting tasks 7, 11, or 12** — the ops floor is not negotiable; the date is.
