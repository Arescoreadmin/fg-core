# Launch DoD L1 — Portal Named-User Production Proof Evidence Manifest

**DoD item:** L1
**Finding closed:** FG-LR-002 (portal named-user login never carried a real user)
**Runbook:** `docs/operators/portal_named_user_proof.md`

---

## Current Status

**L1 status:** IN PROGRESS — awaiting operator execution of T4 proof.

---

## DoD L1 Requirement

> A real external identity completes a full engagement journey in production — invite → accept → OIDC login → engagement pages → logout with Core-side session revocation — **without engineering intervention**.

**Exit criteria:**
- `pni1.` invitation created via `POST /portal/invitations`.
- External identity authenticates via Auth0 OIDC on `app.frostgate.ai`.
- `pnu1.` session created in `portal_user_sessions` (Core DB).
- Portal engagement page loads without error.
- Logout triggers `DELETE /portal/named-sessions/self` on Core.
- Old `pnu1.` token rejected (HTTP 401) or `portal_session_revoked` audit event confirmed.

---

## T4 Execution — [DATE TBD]

**Date (UTC):** _(fill in)_
**Operator:** _(fill in)_
**External test identity:** `***@_____.___` _(domain only — do not record full email)_

### Pre-flight

| Check | Result | Notes |
|-------|--------|-------|
| `GET /health` → 200 | ⬜ | |
| Portal renders OIDC-only login (no password field) | ⬜ | |
| `RESEND_API_KEY` set in Railway Console service | ⬜ | |
| `PORTAL_SESSION_SECRET` set in Vercel portal production | ⬜ | Rotated 2026-07-31 |
| `CORE_TENANT_ID` is client tenant ID (not default/frostgate-internal) | ⬜ | |
| Auth0 callback URL includes `https://app.frostgate.ai/api/auth/oidc/callback` | ⬜ | |

### Step 2 — Invitation

**Invitation ID:** _(fill in)_  
**Issued at:** _(fill in)_  
**Expires at:** _(fill in)_  
**Portal role:** viewer  
**Engagement ID:** _(fill in)_

### Step 4 — OIDC Acceptance

**Acceptance time (UTC):** _(fill in)_  
**OIDC provider used:** _(Google / Microsoft / other)_  
**Portal user ID:** _(fill in)_  
**Membership ID:** _(fill in)_

| Check | Result | Notes |
|-------|--------|-------|
| Accept-invite page renders "Sign in to accept" button | ⬜ | |
| Auth0 OIDC flow completes without error | ⬜ | |
| Portal home page loads after OIDC callback | ⬜ | |
| Engagement pages load (findings / questionnaire tab) | ⬜ | |

### Step 6–7 — Logout and Revocation

**Logout time (UTC):** _(fill in)_  
**Revocation confirmation method:** _(401 rejection / audit event)_

| Check | Result | Notes |
|-------|--------|-------|
| Logout redirects to portal login page | ⬜ | |
| Old `pnu1.` token rejected (HTTP 401 / SESSION_REVOKED) | ⬜ | |
| `portal_session_revoked` audit event present (if checked) | ⬜ | |

---

## DoD L1 Closure

**L1: IN PROGRESS** — awaiting T4 execution.

**FG-LR-002: OPEN**

---

## Next Steps

1. Operator executes T4 proof using `docs/operators/portal_named_user_proof.md`.
2. Fill in all fields above.
3. Change `L1 status` to `PASS` and `FG-LR-002` to `CLOSED` once all checks are confirmed.
4. Commit to main — L1 is a non-waivable DoD gate (no override path).
