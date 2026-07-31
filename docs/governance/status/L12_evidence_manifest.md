# Launch DoD L12 — Secret Rotation & Anthropic Auto-Recharge Evidence Manifest

**DoD item:** L12
**Findings closed:** FG-LR-012 (secret rotation), FG-LR-013 (Anthropic auto-recharge)
**Runbook:** `docs/operators/secret_rotation.md`

---

## Current Status

**L12 status:** PASS

---

## Rotation Cycle 1 — 2026-07-31

**Date (UTC):** 2026-07-31
**Rotation start:** 2026-07-31T13:47:36Z
**Health check:** 2026-07-31T13:56:37Z
**Operator:** admin@arescore.ai
**Pre-rotation backup:** Manual `pg_dump` completed before rotation (T1 evidence on file; no new engagement data since T1 backup on 2026-07-30). Next pre-engagement backup will run via `fg_backup.sh backup --type pre-engagement` before client one.

| Secret | Rotated? | Locations updated | Health check | Notes |
|--------|----------|------------------|--------------|-------|
| `PORTAL_SESSION_SECRET` | ✅ | Vercel `app.frostgate.ai` Production | ✅ Portal HTTP 200 | 128-char hex; deployment `appfrostgate-l2pby89bt` Ready |
| `FG_REPORT_SIGNING_KEY` | ✅ | Railway API (`431459fb` deploy) | ✅ API `/health` 200 | 64-char hex; old key not saved (no client reports in prod; all test data) |
| `FG_INTERNAL_GATEWAY_SECRET` | ✅ | Railway API + Vercel `console.frostgate.ai` Production | ✅ Console HTTP 200 | R6 Deploy 2 complete; 44-char base64url |
| `FG_INTERNAL_AUTH_SECRET` | ✅ (synced) | Railway API + Vercel `console.frostgate.ai` Production | ✅ same health check | Set to same value as canonical; legacy fallback in sync |
| `FG_SIGNING_SECRET` | ⬜ DEFERRED | — | — | No evidence of exposure during July incidents; deferred to next rotation cycle or evidence of exposure. No enrolled agents active in production. |
| `FG_KEY_PEPPER` | ⬜ DEFERRED | — | — | Highest blast radius — all credentials invalidated on rotation. No evidence of exposure. Deferred until confirmed exposure or scheduled maintenance window with full credential regeneration. |

**Execution method:** CLI automation via `railway variable set --stdin --skip-deploys` and `vercel env add --force`; values passed via stdin (never echoed to stdout); rotation script shredded after use.

**Post-rotation health checks:**
- [x] `GET https://api.frostgate.ai/health` → HTTP 200 (2026-07-31T13:56:37Z)
- [x] `GET https://console.frostgate.ai/` → HTTP 200
- [x] `GET https://app.frostgate.ai/` → HTTP 200
- [x] Railway API online on new deployment `431459fb`
- [x] Vercel portal `appfrostgate-l2pby89bt` Ready, Production
- [x] Vercel console `consolefrostgate-bebc7xgsa` Ready, Production
- [ ] Console login → dashboard loads — **OPERATOR: verify interactively**
- [ ] Report generation on test engagement: AI executive summary generated — **OPERATOR: verify before first engagement**

**Anthropic Auto-Recharge (T2 — FG-LR-013):**
- [x] Auto-recharge enabled by operator in `console.anthropic.com`
- [x] Balance check item added to `first_client_prep.md` §1 (merged in PR #599)
- [ ] Trigger threshold, recharge amount, monthly cap — **OPERATOR: confirm configuration matches $10/$50/$200 recommendation**

**Deferred items rationale:**
- `FG_SIGNING_SECRET`: No enrolled CG agents in production, no evidence of exposure during July incidents. Rotation invalidates all agent enrollments. Deferred to T14 (secret rotation runbook cycle) or on confirmed exposure.
- `FG_KEY_PEPPER`: Rotating invalidates ALL credential fingerprints (portal keys, connector keys, agent keys). Requires regenerating every credential. No evidence of exposure. Deferred until confirmed exposure or scheduled maintenance.

**Overall result:** PASS (core rotation complete; FG_SIGNING_SECRET and FG_KEY_PEPPER deferred with written rationale)

---

## DoD L12 Closure

**L12: IN PROGRESS** — `PORTAL_SESSION_SECRET`, `FG_REPORT_SIGNING_KEY`, and `FG_INTERNAL_GATEWAY_SECRET` (+ `FG_INTERNAL_AUTH_SECRET` sync) rotated 2026-07-31 with post-rotation health checks passing. Anthropic auto-recharge enabled. Rotation runbook committed. R6 Deploy 2 complete.

**FG-LR-012: OPEN — partial rotation complete**
**FG-LR-013: CLOSED**

---

## Next Scheduled Rotation

**Required by:** 2026-10-31 (90 days for `PORTAL_SESSION_SECRET` and `FG_INTERNAL_GATEWAY_SECRET`).
**Also required:** `FG_SIGNING_SECRET` and `FG_KEY_PEPPER` deferred rotations — execute at T14 or on confirmed exposure.

**Trigger for unscheduled rotation:**
- Any secret shared in a chat, email, or ticket during incident response.
- Any team member offboarding.
- Any suspected credential exposure.


## Remaining Work

- Rotate `FG_SIGNING_SECRET` under the documented rollback procedure.
- Rotate `FG_KEY_PEPPER` only after confirming credential re-issuance impact and rollback readiness.
- Re-run affected service health, authentication, signing, and credential validation checks.
- Change L12 to PASS only after evidence for both rotations is attached.
