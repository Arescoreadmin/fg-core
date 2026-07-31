# Launch DoD L12 — Secret Rotation & Anthropic Auto-Recharge Evidence Manifest

**DoD item:** L12  
**Findings closed:** FG-LR-012 (secret rotation), FG-LR-013 (Anthropic auto-recharge)  
**Runbook:** `docs/operators/secret_rotation.md`

---

## Current Status

**L12 status:** OPEN — operator action required.

**Blocking items:**
1. Anthropic auto-recharge must be enabled (T2 — 10 minutes, billing dashboard).
2. Top-5 blast-radius secrets must be rotated (T3 — follow `secret_rotation.md`).
3. This manifest must be completed and committed after rotation.

---

## Evidence Record Template

Fill in one row per rotation event. Copy the block for additional rotation cycles.

### Rotation Cycle 1

**Date (UTC):** _(e.g. 2026-07-31)_  
**Operator:** _(email)_  
**Pre-rotation backup:** _(fg_backup.sh backup ID, e.g. FG-BKP-20260731-00001)_

| Secret | Rotated? | Railway/Vercel updated | Health check | Notes |
|--------|----------|----------------------|--------------|-------|
| `PORTAL_SESSION_SECRET` | ☐ | ☐ Vercel portal | ☐ Portal login OK | |
| `FG_REPORT_SIGNING_KEY` | ☐ | ☐ Railway API | ☐ Report generated OK | Old key archived offline |
| `FG_INTERNAL_GATEWAY_SECRET` + `FG_INTERNAL_AUTH_SECRET` | ☐ | ☐ Railway API ☐ Railway Console ☐ Vercel portal | ☐ Console login OK ☐ Portal renders OK | R6 Deploy 2 |
| `FG_SIGNING_SECRET` | ☐ | ☐ Railway API | ☐ `/health` 200 | Re-enroll agents if needed |
| `FG_KEY_PEPPER` | ☐ | ☐ Railway API | ☐ Credential auth OK | Defer unless exposed |

**Post-rotation checklist:**
- [ ] `GET /health` → 200
- [ ] Console login → dashboard loads
- [ ] Portal login page renders
- [ ] Test engagement created in console
- [ ] Report generation on test engagement: AI executive summary generated
- [ ] No Railway restart loops

**Anthropic Auto-Recharge:**
- [ ] Auto-recharge enabled in `console.anthropic.com`
- [ ] Trigger threshold: $10
- [ ] Recharge amount: $50
- [ ] Monthly cap: $200
- [ ] Current balance at time of check: $______
- [ ] Balance check added to `first_client_prep.md` §1: ☐ confirmed

**Overall result:** _(PASS / PARTIAL — list any deferred items)_

---

## DoD Closure Criteria

L12 can be marked PASS when:
1. Anthropic auto-recharge is enabled (screenshot referenced above).
2. `PORTAL_SESSION_SECRET`, `FG_REPORT_SIGNING_KEY`, and `FG_INTERNAL_GATEWAY_SECRET` are rotated (highest-urgency three of the five; `FG_SIGNING_SECRET` and `FG_KEY_PEPPER` may be deferred with written rationale if no evidence of exposure).
3. `docs/operators/secret_rotation.md` is committed (done — in this PR).
4. This manifest is completed and committed.

---

## Next Scheduled Rotation

**Required by:** 2026-10-31 (90 days for `PORTAL_SESSION_SECRET` and `FG_INTERNAL_GATEWAY_SECRET`).

**Trigger for unscheduled rotation:**
- Any secret shared in a chat, email, or ticket during incident response.
- Any team member offboarding.
- Any suspected credential exposure.
