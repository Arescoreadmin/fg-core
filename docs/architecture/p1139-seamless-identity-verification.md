# P-113.9 — Seamless Identity Verification + Recovery

**Status:** PLAN — branch `feat/p1139-seamless-identity-verification` created 2026-09-05  
**Date:** 2026-09-05  
**Depends on:** P-113.8 merged (PR #680)  
**Scope:** Two sub-streams — P-113.9A (verification UX + error contract) and P-113.9B (bootstrap retirement from normal operations)

## Mandatory Invariants

These were added after initial audit review and are non-negotiable constraints on the implementation:

**I-1: Explicit error code allowlist in BFF (applies to PR-9A-1)**  
The BFF must not blindly proxy arbitrary `detail.code` values from Core to the browser. Define a closed public contract. Any Core code not on the allowlist collapses to a generic safe error. This prevents future Core internals from accidentally becoming externally observable when new error codes are added.

**Public invitation error contract (exhaustive):**
```
INVITATION_EMAIL_MISMATCH  — signed-in email does not match invitation
IDENTITY_UNVERIFIED        — email_verified is false at acceptance time
INVITATION_EXPIRED         — token is past expiry
INVITATION_CONSUMED        — invitation already accepted/bound
INVITATION_NOT_FOUND       — token invalid, not found, or unknown state
SESSION_EXPIRED            — BFF-generated; no Core call made
```
Any other code from Core → normalize to `INVITATION_NOT_FOUND` (generic safe).  
Core `message` / `detail.message` / stack → never forwarded.

**I-2: Canonical state-derived tenant readiness (applies to PR-9B-1)**  
`invite-initial-admin` is not merely a renamed bootstrap. The endpoint must derive its behavior from canonical state, not from an explicit lifecycle flag, so that every possible call is safe:

```
invite-initial-admin(tenant_id, email, display_name?):
  existing bound admin for email   → { status: "already_ready", ... }
  existing pending invitation      → rotate token + resend + { status: "invitation_rotated", ... }
  no active admin row              → create row + create invitation + send email + { status: "invited", ... }
```

Callers (operators, CI, recovery jobs, autonomous agents) must be able to call this operation safely without knowing the current state in advance. The endpoint reads canonical state and does the right thing.

---

## Problem Statement

P-113.8 proved that the canonical invitation acceptance flow works. It also exposed three production bugs (body/415, email_verified/id_token, post-commit RLS) that required DB surgery and multiple deployment cycles to resolve. The flow is **functionally secure but operationally brittle**: verification success depends on one fragile id_token shape, error codes are swallowed by the BFF proxy, session expiry during acceptance causes a confusing dead-end, and seating the first admin for a new tenant requires two separate manual operations ("bootstrap" then "invite").

The goal is to make the happy path automatic and every failure path recoverable in one click, without exposing implementation folklore to the user.

---

## Audit Findings (grounded in current code)

### A. Email Verified Propagation Map

```
Auth0 id_token
  → auth.config.ts jwt() : account.id_token decoded via atob()  [CORRECT — P-113.8 fix]
  → token.emailVerified : boolean | undefined persisted in NextAuth JWT
  → auth.config.ts session() : defaults to false if absent     [CORRECT — fail-closed]
  → session.emailVerified : boolean guaranteed by type          [CORRECT]
  → route.ts L645: header "X-FG-Named-User-Email-Verified"     [CORRECT — ternary === true]
  → identity_acceptance.py L90-92: string "true"/"false" → bool [CORRECT]
  → L195: gate — 403 IDENTITY_UNVERIFIED if false              [CORRECT]
```

**D-1 (Low): Token refresh does not re-derive emailVerified** — correct by design (JWT retains value), but if email_verified changes in Auth0 after the initial sign-in (user verifies email), the session will remain `emailVerified: false` until the user signs out and back in. Currently no signal to the user that re-auth will unblock them.

**D-2 (Medium): ActorContext does not capture email_verified during acceptance** — `identity_acceptance.py` gates on `named_email_verified` (L195) but does not store it on the ActorContext passed to principal resolution. The audit trail cannot assert email verification was enforced at acceptance time.

**D-3 (High): No recovery path when email_verified=false at accept time** — the console page (L50-51) shows a static message "Verify your email with your identity provider and try again." No re-auth link. No automatic retry after re-auth. User must manually sign out, verify email in Auth0, sign back in, navigate to invitation URL again.

---

### B. BFF Error Contract — the core defect

**D-4 (High): BFF proxy normalizes all Core 403 responses to `CORE_ACCESS_DENIED`**

`route.ts` L719-723:
```typescript
if (response.status === 403) {
  // ...
  return credentialError('CORE_ACCESS_DENIED', 403, requestId, tenantId);
}
```

Core returns `{ "detail": { "code": "INVITATION_EMAIL_MISMATCH" } }` or `{ "detail": { "code": "IDENTITY_UNVERIFIED" } }`. The BFF discards the detail object. The console receives only `{ "error": "CORE_ACCESS_DENIED" }`.

**Consequence:** `page.tsx` L48-51 has dead code:
```typescript
if (body.error === 'CORE_ACCESS_DENIED' || body.code === 'INVITATION_EMAIL_MISMATCH') {
  // branch 1 is always taken when Core returns 403
  // body.code is never set — CORE_ACCESS_DENIED wins first
```
Both IDENTITY_UNVERIFIED and INVITATION_EMAIL_MISMATCH render the same error message ("sent to a different email address"). The console cannot distinguish them.

**Security note:** The 403 normalization exists to prevent leaking internal auth details on *credential* paths. The invitation acceptance path is *not* a credential path — it is a named-user delegation path with a public token. The Core error codes for this path (`INVITATION_EMAIL_MISMATCH`, `IDENTITY_UNVERIFIED`, `TENANT_NOT_AVAILABLE`) are safe to pass through because they reveal only what the user's own invitation state is, not internal system structure.

---

### C. Session Expiry During Acceptance

**D-5 (High): Session expiry between preflight and accept causes a misleading dead-end**

Flow:
1. User loads invitation page → preflight succeeds (session is fresh)
2. User waits (session age ≤ 8h default, but: stale tab, mobile background, etc.)
3. User clicks "Accept" → `POST /api/core/identity/invitations/{token}/accept`
4. `route.ts` L638: `const session = await auth()` → returns null (expired)
5. L648: No session, no headers set → Core receives no `X-FG-Named-User-Email` header
6. `identity_acceptance.py` L197: `if not named_email` → 403 IDENTITY_UNVERIFIED
7. BFF normalizes → 403 CORE_ACCESS_DENIED
8. Console page L48: reads as "sent to different email" — wrong message, no recovery path

The session expiry case hits the same BFF normalization as email mismatch. The user sees "sent to different email address" when the actual problem is "please sign in again."

There is also a BFF-level null-session case that should be caught earlier: at L638, if `auth()` returns null and the path is an invitation POST, the BFF could detect the expired session immediately (before sending to Core) and return a signal the console can act on.

---

### D. Console Invitation Page — Current State Machine

`apps/console/app/identity/invitations/[token]/page.tsx`

Current states (implicit, via `useState<string | null>(null)` for `error`):
- Loading (session status check)
- Preflight loading (after authenticated)
- Error: one generic message covers {invalid token, expired, consumed, revoked, wrong account, unverified email, tenant suspended, session expired}
- Ready (preflight loaded)
- Accepting (POST in flight)

**D-6 (Medium): Preflight errors are not granular** — `identity_acceptance.py` L105-127 returns `404 INVITATION_NOT_FOUND` for all invalid states (malformed token, expired, status≠pending). The console cannot distinguish "expired" (recoverable via resend) from "consumed" (no action needed) from "malformed" (user probably copied URL incorrectly).

The security concern is minimal: the token format (`fgwi1.*`) already reveals whether it was a real token. Returning `INVITATION_EXPIRED` vs `INVITATION_NOT_FOUND` in the detail does not create a new oracle.

**D-7 (Medium): No "sign in with different account" path** — when email mismatch occurs, the user sees the error and has no affordance to switch accounts. They must manually sign out, switch, sign back in, and navigate to the invitation URL again.

**D-8 (Low): No email showing before accept** — the page shows only a masked email (`j***@frostgate.ai`). The user cannot see which Auth0 account they are signed in as until they attempt accept and get an error. The session object has `session.user.email` available; showing it on the ready state prevents the error in the first place.

---

### E. Bootstrap Dependency Map

`api/client_lifecycle.py` lifecycle state `admin_unset` emits `ACTION_BOOTSTRAP_ADMIN`. This triggers the console (via `GET /admin/tenants/{id}/lifecycle`) to show "Bootstrap admin" form.

**Current flow for seating first admin (two manual steps):**
```
POST /tenants → admin_unset
  ↓ Operator: form in console
POST /admin/tenants/{id}/bootstrap-admin → creates unbound row → admin_unbound
  ↓ Operator: separate invitation flow (workforce/users/invite or admin/identity/invitations)
invitation sent → user accepts → admin_unbound → operational
```

**The gap:** `bootstrap-admin` creates the unbound row but does NOT create an invitation or send any email. A second operator action is required. This two-step ceremony is the user-visible "bootstrap ritual" being complained about.

**Bootstrap endpoint classification:**

| Usage | Tag | Notes |
|---|---|---|
| `POST /bootstrap-admin` for new tenant | OPERATIONAL (problematic) | Should be collapsed into invitation creation |
| `POST /bootstrap-admin` to promote existing user (idempotent path 2) | INSTALL/RECOVERY | Legitimate for break-glass |
| `FG_CONSOLE_BOOTSTRAP_ADMIN_SUBJECTS` env var | INSTALL only | One-time operator setup; not user-facing |

The `bootstrap-admin` endpoint is correctly implemented and audited. The problem is that it is the primary user-facing action when it should be a lower-level primitive not visible during ordinary tenant onboarding.

**BIND_ADMIN_IDENTITY action:** After bootstrap, the lifecycle shows `ACTION_BIND_ADMIN_IDENTITY` but the console renders this as a button with no clear affordance — the operator must separately navigate to the invitation flow. This is a UX gap, not a security gap.

---

## P-113.9A: Seamless Verification & Identity Binding

### Objective

Make verification automatic when the IdP already proves it, make every failure recoverable in one click, and make the page state machine explicit and deterministic.

---

### 9A.1 — BFF Invitation Error Contract (with allowlist)

**Files:** `apps/console/app/api/core/[...path]/route.ts`

**Change:** On the invitation acceptance path only, extract `detail.code` from Core 403 responses and map it through an explicit closed allowlist before returning to the browser. The general 403 normalization (`CORE_ACCESS_DENIED`) continues to apply to all credential paths.

**The allowlist is the contract.** Any code not on it collapses to `INVITATION_NOT_FOUND`. Core `message`, `detail.message`, or any other field is never forwarded.

```typescript
// Exhaustive public invitation error contract — add to route.ts
const INVITATION_ERROR_ALLOWLIST = new Set([
  'INVITATION_EMAIL_MISMATCH',
  'IDENTITY_UNVERIFIED',
  'TENANT_NOT_AVAILABLE',
] as const);

type AllowedInvitationCode = typeof INVITATION_ERROR_ALLOWLIST extends Set<infer T> ? T : never;
```

**BFF response shape for invitation 403:**
```json
{
  "error": "INVITATION_DENIED",
  "detail_code": "INVITATION_EMAIL_MISMATCH",
  "request_id": "..."
}
```

**Implementation sketch:**
```typescript
// route.ts — BEFORE the existing general 403 handler
if (response.status === 403 && isInvitationPath) {
  let detailCode: string = 'INVITATION_NOT_FOUND'; // safe default
  try {
    const body403 = await response.json() as { detail?: { code?: string } };
    const raw = body403?.detail?.code ?? '';
    if (INVITATION_ERROR_ALLOWLIST.has(raw as AllowedInvitationCode)) {
      detailCode = raw;
    }
    // unknown code: fall through to safe default — not logged (prevents Core internals leaking via log aggregation)
  } catch { /* ignore parse failure */ }
  console.warn(
    `[core-proxy] INVITATION_DENIED request_id=${requestId} detail_code=${detailCode}`,
  );
  return NextResponse.json(
    { error: 'INVITATION_DENIED', detail_code: detailCode, request_id: requestId },
    { status: 403, headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } },
  );
}
// existing general 403 handler: credential paths still return CORE_ACCESS_DENIED
```

**Why not log unknown codes?** If an unknown Core code were logged by name in BFF log aggregation, it becomes externally observable to anyone with log access. The safe default absorbs it silently; the Core-side log (where the code originates) remains the authoritative diagnostic source.

**Contract tests required (see 9A Test Requirements):**
- Known allowlisted code → preserved in `detail_code`
- Unknown Core code → `detail_code === 'INVITATION_NOT_FOUND'`
- Core `message` field → absent from BFF response
- Non-invitation 403 → `error === 'CORE_ACCESS_DENIED'` (regression guard)

---

### 9A.2 — Session Expiry Signal

**Files:** `apps/console/app/api/core/[...path]/route.ts`

**Change:** When `auth()` returns null on the invitation POST path, return a specific signal the console can act on before the request reaches Core.

```typescript
// route.ts L638 area — in the isInvitationPath POST branch
const session = await auth();
if (!session && isInvitationPath && request.method === 'POST') {
  return NextResponse.json(
    { error: 'SESSION_EXPIRED', request_id: requestId },
    { status: 401, headers: { 'Cache-Control': 'no-store', 'x-request-id': requestId } }
  );
}
```

This is caught by the console before Core is called. No Core request is made, no Core error is normalized.

---

### 9A.3 — Canonical Email Verified State in ActorContext

**Files:** `api/identity_acceptance.py`

**Change:** Pass `named_email_verified` into the resolved ActorContext or audit event details so that governance records can assert verification was enforced at binding time.

Currently, line 195 gates on `named_email_verified` but the value is not recorded. The audit event at `_store.transition_invitation()` does not capture this. After binding, there is no durable record of _when_ and _how_ email verification was established.

**Minimal change:** include `"email_verified_at_acceptance": True` in the `details` dict passed to `emit_identity_audit_event()` during the binding transition.

**Larger change (if ActorContext is the right layer):** add `email_verified: bool = False` as a field to `ActorContext` and populate it from `named_email_verified` during the invitation acceptance code path. This gives downstream consumers access to the verified state without re-reading headers.

---

### 9A.4 — Console Invitation Page State Machine

**Files:** `apps/console/app/identity/invitations/[token]/page.tsx`

**Rewrite this file completely.** The current implementation uses a single `error: string | null` state, which collapses all failure modes into one branch. A proper state machine makes recovery paths explicit and eliminates the dead-code error-mapping issue.

**Proposed state type:**
```typescript
type InvitationState =
  | { phase: 'redirect_to_auth' }        // unauthenticated — sign-in in progress
  | { phase: 'preflight_loading' }        // authenticated, fetching preflight
  | { phase: 'preflight_error'; code: 'EXPIRED' | 'CONSUMED' | 'INVALID' | 'UNKNOWN' }
  | { phase: 'ready'; preflight: PreflightData; userEmail: string }
  | { phase: 'accepting' }
  | { phase: 'email_mismatch'; signedInAs: string; invitedEmail: string }
  | { phase: 'email_unverified' }
  | { phase: 'session_expired' }          // new — re-auth signal from BFF
  | { phase: 'tenant_unavailable' }
  | { phase: 'accepted'; tenantId: string }
  | { phase: 'error'; message: string }
```

**State transitions:**
```
sessionStatus='unauthenticated' → redirect_to_auth (trigger signIn with callbackUrl=current path)
sessionStatus='loading'         → preflight_loading (wait)
sessionStatus='authenticated'   → preflight_loading → {preflight_error | ready}
ready + click accept            → accepting
accepting + ok response         → accepted → redirect
accepting + SESSION_EXPIRED     → session_expired
accepting + INVITATION_DENIED/INVITATION_EMAIL_MISMATCH → email_mismatch
accepting + INVITATION_DENIED/IDENTITY_UNVERIFIED       → email_unverified
accepting + other 4xx           → preflight_error.CONSUMED (or INVALID)
accepted                        → router.push(/admin/tenants/{id})
```

**Preflight error codes** (requires 9A.5 backend change):
- `EXPIRED` → "This invitation has expired. Contact your workspace admin to resend it."
- `CONSUMED` → "This invitation has already been accepted."
- `INVALID` → "This invitation link is not valid. Check that you copied the full URL."
- `UNKNOWN` → generic fallback

**UX requirements for each state:**

`ready`:
- Show: tenant name, role, invitation email (masked), expiry date
- Show: "You are signed in as {session.user.email}" — critical for catching mismatch before the attempt
- Show: "Accept Invitation" button
- If session.email does not pattern-match the masked invitation email, show a soft warning: "Note: make sure this matches the email address your invitation was sent to."

`email_mismatch`:
- Show: "You are signed in as {signedInAs}. This invitation was sent to {invitedEmail}."
- Show: "Sign in with a different account" button → triggers `signOut()` then `signIn('auth0', { callbackUrl: current path })`
- Show: "Go back" link

`email_unverified`:
- Show: "Your email address is not verified yet."
- Show: "Re-authenticate to check verification status" button → triggers `signIn('auth0', { callbackUrl: current path, prompt: 'login' })` — forces Auth0 fresh auth which re-evaluates email_verified
- Show: link to Auth0 email verification (if user knows they already clicked the verify email link)
- On return from re-auth: page automatically re-attempts accept (state machine detects authenticated → auto-accept if was_in_unverified_state)

`session_expired`:
- Show: "Your session expired while viewing this invitation."
- Show: "Sign in again" button → `signIn('auth0', { callbackUrl: current path })`
- On return: page automatically re-attempts accept

`accepted`:
- Brief "Accepted! Redirecting…" before router.push

**Auto-continuation on return from re-auth:**

Store the intent in `sessionStorage` before triggering re-auth:
```typescript
sessionStorage.setItem(`invitation-intent-${token}`, 'accept');
signIn('auth0', { callbackUrl: `/identity/invitations/${token}` });
```

On page load after re-auth:
```typescript
const intent = sessionStorage.getItem(`invitation-intent-${token}`);
if (intent === 'accept' && sessionStatus === 'authenticated') {
  sessionStorage.removeItem(`invitation-intent-${token}`);
  // auto-attempt accept (skip showing 'ready' state briefly)
}
```

This gives the "return to invitation → continue automatically" behavior without a second button click.

---

### 9A.5 — Preflight Granular Error Codes (Backend)

**Files:** `api/identity_acceptance.py`

**Change:** Return distinguishable detail codes in the 404 response body for the GET preflight so the console can show specific messages.

Current (L105-127): all invalid states → `404 {"detail": {"code": "INVITATION_NOT_FOUND"}}`

Proposed:
```python
# Token not found or fingerprint failure → INVITATION_NOT_FOUND (no oracle)
# Status != 'pending' (consumed/bound/revoked) → INVITATION_CONSUMED
# Status == 'pending' but expired → INVITATION_EXPIRED
```

**Security rationale:** The token is a 256-bit HMAC token (`fgwi1.*`). Knowing it was valid at some point (INVITATION_EXPIRED or INVITATION_CONSUMED vs INVITATION_NOT_FOUND) is low-risk because token possession proves prior legitimate delivery. The granular response helps the user take the right action without leaking information about tenants or other users.

**Note on expired tokens:** Core currently normalizes expired to `INVITATION_NOT_FOUND` (L125-127). This makes sense for the security model (no oracle for when a token was valid) but prevents good UX. The trade-off is acceptable to expose EXPIRED vs NOT_FOUND since the token format itself already proves the token structure.

---

### 9A.6 — Email Verified Refresh Path

**Files:** `apps/console/auth.config.ts`

Currently, `emailVerified` is set only on initial sign-in (when `account.id_token` is present) and falls back to `false` on subsequent session refreshes if the token renewal does not carry a new id_token. This is correct (fail-closed) but means a user who verifies their email after initial sign-in remains blocked until they sign out and back in.

**Change:** When the console triggers re-auth via `signIn('auth0', { callbackUrl: ..., prompt: 'login' })`, Auth0 will issue a fresh id_token with the current `email_verified` state. The JWT callback will pick it up via `account.id_token`. No change needed in `auth.config.ts` for this case — re-auth naturally refreshes.

**What to document and test:**
- `prompt: 'login'` forces fresh Auth0 login, ensuring a fresh id_token is issued
- `prompt: 'none'` (silent SSO) does NOT issue a new id_token in all Auth0 tenants; avoid it on the unverified re-auth path
- A test should verify that post-re-auth, `token.emailVerified` is correctly updated

---

### 9A.7 — Resend Surface

**Files:** `api/identity_acceptance.py` (new endpoint), `apps/console/app/identity/invitations/[token]/page.tsx`

**Scope:** Workforce invitation resend. Currently, resend requires admin access (`POST /admin/identity/invitations/{id}/resend`). An invited user cannot self-serve.

**Design decision — no unauthenticated resend:** Token possession alone is not sufficient authority to generate a new token. Resend must require that the requesting user's authenticated email matches the invitation email.

**Proposed endpoint:** `POST /identity/invitations/{token}/request-resend`

```
Auth: gateway auth + named-user identity headers (same as accept)
Checks:
  1. Token fingerprint resolves to a valid invitation (same pre-context lookup)
  2. Invitation status is {pending, expired, failed} (not consumed/bound)
  3. Named user email matches invitation email
Action:
  Rotates the acceptance token (new token, old token 404s immediately)
  Sends invitation email with new token URL (same delivery as original invite)
  Returns: { sent: true }
```

This reuses the full authority chain from accept but only rotates the token and resends the email, without performing the binding.

**Console:** On the `preflight_error.EXPIRED` state, show "Request a new invitation link" button if the user is authenticated. This calls the new endpoint. On success, shows "A new invitation link has been sent to {masked_email}."

**If user is unauthenticated on EXPIRED:** show "Sign in to request a new invitation link" — the re-auth path brings them to the page authenticated, where the resend button is available.

---

### 9A.8 — Observability (Internal)

**Requirement:** Every stage of the invitation acceptance flow should be observable internally without leaking sensitive claims.

**Add structured log events in `identity_acceptance.py`:**
```python
# At each gate:
_log.info("invitation_acceptance.gate", extra={
  "gate": "email_verified",
  "passed": named_email_verified,
  "request_id": request.headers.get("X-Request-ID"),
  "tenant_id": pre_tenant_id,  # available after pre-context lookup
  # never log: email, sub, fingerprint
})
```

Log gates to add:
- `fingerprint_computed` (token prefix valid / invalid)
- `pre_context_lookup` (found / not found)
- `email_verified` (gate passed / failed)
- `email_match` (gate passed / failed — log result only, not the emails)
- `tenant_active` (gate passed / failed)
- `principal_resolved` (success / failure)
- `tenant_user_bound` (rowcount=1 success / binding_conflict)

---

### P-113.9A Test Requirements

**Backend (pytest):**
- GET preflight returns `INVITATION_EXPIRED` (not `INVITATION_NOT_FOUND`) for expired pending invitations
- GET preflight returns `INVITATION_CONSUMED` for bound/accepted invitations
- POST accept with no session headers returns 403 IDENTITY_UNVERIFIED (existing — should pass)
- Audit event details include `email_verified_at_acceptance: true`
- POST request-resend with matching email rotates token and returns sent:true
- POST request-resend with non-matching email returns 403 INVITATION_EMAIL_MISMATCH
- POST request-resend on bound invitation returns 404 INVITATION_NOT_FOUND

**BFF (Jest/unit) — contract tests (mandatory per I-1):**
- Known allowlisted code (`INVITATION_EMAIL_MISMATCH`) → `{ error: 'INVITATION_DENIED', detail_code: 'INVITATION_EMAIL_MISMATCH' }`
- Unknown Core code (e.g. `INTERNAL_VALIDATION_FAILED`) → `{ error: 'INVITATION_DENIED', detail_code: 'INVITATION_NOT_FOUND' }` — not the raw code
- Core `message` field present → absent from BFF response body
- Null session on invitation POST → `{ error: 'SESSION_EXPIRED' }` with 401, Core not called
- Non-invitation 403 → `{ error: 'CORE_ACCESS_DENIED' }` (regression guard — allowlist not applied)

**Console (React Testing Library or E2E):**
- `email_mismatch` state renders "Sign in with a different account" button
- `session_expired` state renders "Sign in again" button
- `email_unverified` state renders re-auth button
- `preflight_error.EXPIRED` state renders resend button (when authenticated)
- Auto-continuation: if `sessionStorage` contains `invitation-intent-${token}`, accept is called automatically on authenticated load
- `ready` state shows `session.user.email` alongside masked invitation email

---

## P-113.9B: Bootstrap Retirement from Normal Operations

### Objective

Eliminate "bootstrap" as a concept in normal tenant onboarding. Bootstrap survives only as a platform installation and disaster recovery primitive. Normal operations use a single canonical path: create tenant → invite initial admin → wait for binding → tenant ready.

The semantic distinction is explicit:

| Concept | When | Who | Visible to tenants? |
|---|---|---|---|
| **Platform bootstrap** | Installation, DR only | FrostGate operator | Never |
| **Tenant initialization** | Every new tenant | Platform admin via Console | Yes (invitation email) |

---

### 9B.1 — Canonical State-Derived `invite-initial-admin`

**Files:** `api/tenant_admin.py` (new endpoint), `api/identity/store.py` (reuse token generation)

**Endpoint:** `POST /admin/tenants/{tenant_id}/invite-initial-admin`

**Authority:** `platform.admin`

**Mandatory invariant (I-2): the endpoint reads canonical state and does the right thing. Callers do not need to know the current state in advance.**

```
invite-initial-admin(tenant_id, email, display_name?):

  CASE: active + bound admin already exists for email
    → return { status: "already_ready", tenant_id, user_id }
    → no write, no email
    → HTTP 200

  CASE: active + unbound admin row exists for email with pending invitation
    → rotate acceptance token (old token 404s immediately)
    → resend invitation email with new token
    → return { status: "invitation_rotated", tenant_id, user_id, invitation_url, expires_at }
    → HTTP 200

  CASE: active + unbound admin row exists for email, no valid pending invitation
    (invitation expired, consumed, or absent)
    → generate new acceptance token + invitation row
    → send invitation email
    → return { status: "invitation_sent", tenant_id, user_id, invitation_url, expires_at }
    → HTTP 200

  CASE: no active admin row exists for email (admin_unset state)
    → upsert tenant_user row (create or promote, same logic as bootstrap-admin)
    → generate acceptance token + invitation row
    → send invitation email
    → emit tenant.admin.invite_initial audit event
    → commit (single transaction)
    → return { status: "invited", tenant_id, user_id, invitation_url, expires_at }
    → HTTP 201

  CASE: tenant is suspended or not found
    → HTTP 404 / 403 as appropriate, no write
```

**The only disallowed call:** `invite-initial-admin` when a *different* email already has an active bound admin (tenant is operational with a different admin). This returns 409 `TENANT_ALREADY_HAS_ADMIN`. The caller must know which admin they're inviting; the endpoint does not reassign admins.

**Idempotency:** same caller, same email, called N times → always safe. No duplicate rows created. Email rotated on each call (user gets a fresh token, old URLs 404). This is correct for automation and recovery jobs.

**What this enables:**
- Operators can safely call from a CI job or autonomous agent without checking state first
- Recovery: if the invited admin's token expired, calling again rotates and resends without manual DB intervention
- Console: one form, one submit, one confirmation: "Invitation sent to {email}"

**Tenant lifecycle after `invite-initial-admin`:**
```
INITIALIZING (admin_unset)
     ↓ invite-initial-admin()
ADMIN_INVITED (admin_unbound, pending invitation exists)
     ↓ admin follows invitation → accept → canonical binding
ADMIN_BOUND (admin_unbound → operational transition)
     ↓ evaluate_client_lifecycle()
READY (operational)
```

These are conceptual labels; the underlying `client_lifecycle.py` states (`admin_unset`, `admin_unbound`, `operational`) do not change. The console maps them to user-readable labels. No lifecycle state machine changes are required for this semantic model — the readiness is already derived from canonical DB state by `evaluate_client_lifecycle()`.

---

### 9B.2 — Lifecycle Action Rename

**Files:** `api/client_lifecycle.py`, `apps/console/app/admin/tenants/[tenantId]/page.tsx`

**Change in `client_lifecycle.py`:**
```python
# Replace (internal constant, versioned machine contract)
ACTION_BOOTSTRAP_ADMIN = "BOOTSTRAP_ADMIN"
# With
ACTION_INVITE_INITIAL_ADMIN = "INVITE_INITIAL_ADMIN"
```

This is a **machine contract change** — bump `LIFECYCLE_VERSION` to 2 and update all consumers.

Consumers to audit:
- `apps/console/app/admin/tenants/[tenantId]/page.tsx` — replace `'BOOTSTRAP_ADMIN'` check
- `tests/test_client_lifecycle_001.py` — update action code assertions
- Any other test or automation that checks for `BOOTSTRAP_ADMIN`

**Console UI change:** Replace "Bootstrap admin" button label + form title with "Invite initial admin". Call `POST /admin/tenants/{id}/invite-initial-admin` instead of `POST /admin/tenants/{id}/bootstrap-admin`.

---

### 9B.3 — Deprecate Standalone `bootstrap-admin` for New Tenants

**Files:** `api/tenant_admin.py`, `apps/console/app/admin/tenants/[tenantId]/page.tsx`

Keep the `POST /bootstrap-admin` endpoint but:
1. Add a deprecation notice in the API docs and endpoint docstring
2. Mark it as break-glass only (emergency admin promotion for existing users, not initial tenant setup)
3. Remove it from the console normal flow (the INVITE_INITIAL_ADMIN CTA replaces it)
4. Leave it callable by platform.admin for disaster recovery scenarios

**Retire condition:** After `invite-initial-admin` is proven in production and no operational runbook references `bootstrap-admin` for new tenant setup.

---

### 9B.4 — BIND_ADMIN_IDENTITY → Automatic After invite-initial-admin

Currently, `admin_unbound` → `ACTION_BIND_ADMIN_IDENTITY` shows a button in the console that does nothing concrete (the operator has to separately trigger the invitation flow). 

With `invite-initial-admin`, the invitation is already sent when the unbound row is created. The `BIND_ADMIN_IDENTITY` state and action still exist (for cases where the invitation expired before acceptance), but the console should clarify what it means:

**Console UI for `admin_unbound`:**
- Banner: "An admin invitation has been sent to {masked_email}. Waiting for acceptance."
- Secondary action: "Resend invitation" (if admin is already in unbound state with an existing pending invitation → calls the resend endpoint)
- No ambiguous "Bind admin identity" button — that implies operator action when it's actually user action

---

### 9B.5 — Startup Readiness Validation

**Files:** `api/main.py` or startup validation module

**Change:** Add a startup check for platform authority prerequisites. If the platform is in a state where it cannot process invitation acceptances (e.g., `FG_INTERNAL_GATEWAY_SECRET` absent, `FG_KEY_PEPPER` absent), log `[STARTUP_FATAL]` and fail-closed.

The console already has `[STARTUP_FATAL]` for `FG_GATEWAY_DELEGATION_SECRET_CURRENT` (route.ts L611-615). The API should have equivalent.

Existing: `api/config/internal_gateway_secret.py` has `resolve_internal_gateway_secret()`. Audit whether this raises at startup or only at first request.

**Proposed check at startup:**
```python
# In api/main.py startup event
from api.identity.workforce_token import _get_pepper  # or equivalent
from api.config.internal_gateway_secret import resolve_internal_gateway_secret

if not resolve_internal_gateway_secret():
    _log.critical("[STARTUP_FATAL] FG_INTERNAL_GATEWAY_SECRET not configured — invitation acceptance will fail at runtime")
if not _get_pepper():
    _log.critical("[STARTUP_FATAL] FG_KEY_PEPPER not configured — invitation token generation will fail")
```

These do not crash the server (acceptance is not the only function) but they make the missing configuration observable at startup rather than at the first acceptance attempt.

---

### 9B.6 — Console Bootstrap Env Var Documentation

**Files:** `apps/console/auth.config.ts` docstring, deployment runbook

`FG_CONSOLE_BOOTSTRAP_ADMIN_SUBJECTS` and `FG_CONSOLE_BOOTSTRAP_ADMIN_EMAILS` are installation-only controls. Document explicitly:
- Should be set only during initial platform setup
- Should be removed from production env after canonical platform admin credential is established
- Their continued presence in production is a security smell (JWT role override without DB authority)
- Add a startup warning log if either var is set in a non-development environment

---

### P-113.9B Test Requirements

**Backend (pytest) — mandatory I-2 state cases:**
- `admin_unset` → creates row + invitation → `{ status: "invited" }` (HTTP 201)
- `admin_unbound` with pending invitation → rotates token + resends → `{ status: "invitation_rotated" }` (HTTP 200)
- `admin_unbound` with no valid invitation → creates new invitation → `{ status: "invitation_sent" }` (HTTP 200)
- Existing bound admin for same email → no write, no email → `{ status: "already_ready" }` (HTTP 200)
- Operational tenant with *different* bound admin → 409 `TENANT_ALREADY_HAS_ADMIN` (no write)
- All state transitions are atomic (rollback on email send failure if possible; invitation not created if row upsert fails)
- `POST /invite-initial-admin` called N times with same email → N-1 token rotations, 0 duplicate rows
- `LIFECYCLE_VERSION=2` returned by lifecycle endpoint after action rename
- `POST /bootstrap-admin` still works and audits correctly (break-glass regression)

**Console:**
- INVITE_INITIAL_ADMIN action renders "Invite initial admin" form (not "Bootstrap admin")
- Form submits to `/invite-initial-admin` endpoint
- `admin_unbound` state shows "Invitation sent — waiting for acceptance" banner + "Resend" button
- "Bind admin identity" button absent from `admin_unbound` state

---

## Implementation Sequence

Execute in strict order within each sub-stream. Both sub-streams can be started in parallel after planning is complete.

### P-113.9A Order

```
1. route.ts: BFF 403 passthrough for invitation path (9A.1)
2. route.ts: session expiry signal (9A.2)
3. identity_acceptance.py: preflight granular error codes (9A.5)
4. page.tsx: full state machine rewrite (9A.4) — depends on 1, 2, 3
5. identity_acceptance.py: audit trail for email_verified (9A.3)
6. identity_acceptance.py: POST /request-resend endpoint (9A.7)
7. page.tsx: resend CTA on EXPIRED state (9A.7 — depends on 6)
8. identity_acceptance.py: structured observability log events (9A.8)
```

### P-113.9B Order

```
1. tenant_admin.py: POST /invite-initial-admin endpoint (9B.1)
2. client_lifecycle.py: rename ACTION_BOOTSTRAP_ADMIN (9B.2) — bump LIFECYCLE_VERSION
3. page.tsx (tenant detail): replace bootstrap CTA with invite-initial-admin (9B.2)
4. page.tsx (tenant detail): admin_unbound state UX (9B.4)
5. api/main.py: startup readiness check (9B.5)
6. Documentation: bootstrap env var deprecation (9B.6)
```

### PR Sequence

| PR | Label | Scope |
|---|---|---|
| PR-9A-1 | `fix: bff-invitation-error-contract` | 9A.1 + 9A.2 (BFF only — safe, backward compatible) |
| PR-9A-2 | `fix: invitation-preflight-granular-errors` | 9A.5 (backend only) |
| PR-9A-3 | `feat: seamless-invitation-ux` | 9A.4 + 9A.3 + 9A.8 (console page rewrite + audit) |
| PR-9A-4 | `feat: invitation-resend-surface` | 9A.6 + 9A.7 (new endpoint + console CTA) |
| PR-9B-1 | `feat: invite-initial-admin` | 9B.1 + 9B.2 + 9B.3 + 9B.4 + 9B.5 |

---

## Security Invariants (unchanged from P-113.8)

1. Authority chain: `fgwi1.* token → fingerprint → locked invitation → email match → verified email → canonical principal → tenant_user binding → COMMIT`
2. Named-user headers are transport only — authority derives from locked invitation + canonical identity provider
3. `email_verified` defaults to false (fail-closed) at every layer
4. All accepting state changes are in a single transaction with `WITH FOR UPDATE` on the invitation row
5. Token fingerprint (HMAC-SHA256) is never stored in plain form; raw token is never logged
6. Cross-tenant access is impossible: the invitation's `tenant_id` sets the RLS context before any tenant-scoped query

**New invariant for 9A.7 (resend):** resend can only be triggered by an authenticated user whose email matches the invitation email. Token possession alone is not sufficient. The full named-user delegation chain (gateway auth + email match) is required.

---

## Files Impacted

### P-113.9A

| File | Change |
|---|---|
| `apps/console/app/api/core/[...path]/route.ts` | 403 passthrough + session expiry signal |
| `apps/console/app/identity/invitations/[token]/page.tsx` | Full rewrite — explicit state machine |
| `api/identity_acceptance.py` | Preflight granular codes + audit trail + request-resend endpoint |
| `tests/test_p1138_invitation_acceptance.py` | Extend for new codes and resend endpoint |
| `apps/console/tests/` | New invitation page tests |

### P-113.9B

| File | Change |
|---|---|
| `api/tenant_admin.py` | New `POST /invite-initial-admin` endpoint |
| `api/client_lifecycle.py` | Rename `ACTION_BOOTSTRAP_ADMIN`, bump `LIFECYCLE_VERSION` |
| `api/main.py` | Startup readiness check |
| `apps/console/app/admin/tenants/[tenantId]/page.tsx` | Bootstrap CTA → invite-initial-admin, admin_unbound banner |
| `tests/test_client_lifecycle_001.py` | Update action code assertions |
| `tests/test_tenant_admin_001.py` | New endpoint tests |
| `contracts/core/openapi.json` | New route for `invite-initial-admin` |

### No Migration Required

None of these changes require a new database migration. The `tenant_invitations` table (migration 0186) already supports the data model for `invite-initial-admin`. The lifecycle state names (`admin_unset`, `admin_unbound`, `operational`) are not changing — only the `next_actions` action code changes.

---

## Canonical Identity Normalization Contract (Final State)

After P-113.9A ships, the `email_verified` contract is:

```
Auth0 ID token (signed, server-to-server)
  │
  ↓ auth.config.ts jwt() — decoded once, stored in JWT
  │   Primary: account.id_token base64 decode (initial sign-in + every re-auth)
  │   Fallback: profile['email_verified'] (for non-Auth0 providers, if ever added)
  │   Default: false (fail-closed on absent)
  │
  ↓ NextAuth JWT: token.emailVerified: boolean (persisted across refreshes)
  │
  ↓ auth.config.ts session() — session.emailVerified: boolean (guaranteed)
  │
  ↓ BFF route.ts — invitation POST only
  │   X-FG-Named-User-Email-Verified: 'true' | 'false'
  │
  ↓ identity_acceptance.py
  │   Gate: 403 IDENTITY_UNVERIFIED if false
  │   Stored: email_verified_at_acceptance in audit event details
  │
  ↓ ActorContext (augmented)
      email_verified: bool
```

Every layer consumes from the previous; no layer re-derives from Auth0 raw claims. The only source-of-truth derivation point is the id_token decode in `auth.config.ts`.

---

## Success Criterion

**P-113.9 is not complete when five PRs merge. It is complete when this test passes.**

Create a synthetic tenant from the Console. Provide only the initial administrator's name and email address. From that point forward, the following are prohibited:

- No operator CLI commands
- No database operations
- No secret manipulation
- No bootstrap commands
- No manual lifecycle transitions
- No FrostGate engineer intervention of any kind

The invited administrator must be able to:

1. Receive the invitation email
2. Follow the invitation link to the Console
3. Authenticate via Auth0
4. If verification or account problems occur — recover in one click without operator involvement
5. Accept the invitation
6. Reach their tenant workspace

If the administrator successfully binds and the tenant reaches `operational` state via this path — and only this path — then bootstrap has been eliminated from normal operations rather than given a nicer name.

**Target flow:**

```
Console operator:
  Create tenant → Invite initial admin (name + email)

System:
  Invitation email dispatched

Admin:
  Click link
    → Sign in if required
    → wrong account?    → switch account → automatically resume
    → unverified email? → re-auth        → automatically resume
    → session expired?  → sign in again  → automatically resume
    → Accept
    → Redirect to tenant workspace

System:
  Tenant → READY (operational)
  No operator action taken after initial invite
```
