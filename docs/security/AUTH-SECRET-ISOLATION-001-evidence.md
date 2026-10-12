# AUTH-SECRET-ISOLATION-001 — Security Evidence Record

**Date:** 2026-10-12
**Priority:** P1 — Production Security and Availability
**Status:** CODE_HOTFIX_READY | PRODUCTION_AUTH_NOT_VERIFIED
**Baseline commit:** d25b66c8 (PR #764 merged)
**Hotfix branch:** fix/auth-secret-isolation-001

---

## 1. Initial Defect

**Location:** `apps/console/auth.ts:7`

**Defective code (baseline d25b66c8):**
```typescript
secret: process.env.AUTH_SECRET ?? process.env.FG_INTERNAL_AUTH_SECRET,
```

**Problem:** The `??` fallback silently allows `FG_INTERNAL_AUTH_SECRET` — a service-to-service
gateway credential — to serve as the browser-facing session signing/encryption secret for Auth.js.
This crosses an explicit trust boundary: gateway credentials authenticate console→API requests;
session secrets sign browser JWT session cookies. These must remain completely isolated.

**Observed production symptom:**
```
[auth][error] MissingSecret
GET /api/auth/session 500
```
Logged from `api.frostgate.ai` deployment. The `api.frostgate.ai` domain is NOT the console
deployment — this indicates the MissingSecret error originated from a different application or
misrouted request (see Section 5 for deployment ownership analysis).

**Introduced in:** PR #764 (CUSTOMER-ZERO-RUN3-PRICING-COST-INTEGRATION-001 merge train).

---

## 2. Affected Authentication Boundaries

| Boundary | Role | Status |
|---|---|---|
| Browser session JWT (Auth.js) | Signs/encrypts NextAuth session cookies | AFFECTED — secret could be FG_INTERNAL_AUTH_SECRET if AUTH_SECRET absent |
| Gateway credential (FG_INTERNAL_AUTH_SECRET) | Console→Core API service-to-service auth | NOT AFFECTED — gateway path unchanged |
| Auth0 OIDC (AUTH0_CLIENT_SECRET) | Identity provider | NOT AFFECTED — unchanged |
| Middleware edge verification | Validates session cookies at edge | AFFECTED — shared secret with route handler |

---

## 3. Root Cause Analysis

### Confirmed findings

**C1: Unsafe secret fallback in auth.ts**
File: `apps/console/auth.ts:7`
The `??` operator means: if `process.env.AUTH_SECRET` is undefined (unset in Vercel), use
`process.env.FG_INTERNAL_AUTH_SECRET`. This is a security violation (AUTH-002) and an operational
hazard — the same credential would sign both gateway tokens and browser session cookies, allowing
any party with knowledge of one to potentially forge the other.

**C2: startup-validation.ts did not validate AUTH_SECRET presence**
File: `apps/console/lib/startup-validation.ts`
The production config validator checked `FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK` (correctly)
but did NOT check that `AUTH_SECRET` itself was set. A deployment with `AUTH_SECRET` absent would
pass startup validation silently and fall back to the gateway secret.

**C3: vercel.json ignoreCommand did not watch package-lock.json**
File: `apps/console/vercel.json`
The `ignoreCommand` watched `apps/console packages/navigation packages/ui` but not
`package-lock.json`. Lockfile changes (dependency version changes) would not trigger a
console rebuild.

### Unverified production hypotheses

**H1: api.frostgate.ai is a separate Vercel project from console.frostgate.ai**
The `MissingSecret` error was logged from `api.frostgate.ai`. The repository has no `apps/api`
directory with a vercel.json. This may be the Python/FastAPI backend deployed on Railway, not
a Next.js console deployment. The exact origin application is NOT VERIFIED from repository
files alone — requires human operator to confirm via Vercel/Railway dashboard.

**H2: AUTH_SECRET may not be set in the Vercel console project Production scope**
If `AUTH_SECRET` was absent from the Vercel Production environment at the time of the
`MissingSecret` error, the fallback to `FG_INTERNAL_AUTH_SECRET` would have silently activated.
Or: `FG_INTERNAL_AUTH_SECRET` was also absent, causing the MissingSecret error. The exact
Vercel environment variable state is NOT VERIFIED — requires human operator to check.

**H3: The MissingSecret error may predate PR #764**
The fallback was introduced in PR #764. If the error predates that PR, it may have originated
from a missing `AUTH_SECRET` with no fallback. The timeline is NOT VERIFIED.

---

## 4. Code Changes

### 4.1 apps/console/auth.ts — Remove unsafe fallback

**Before:**
```typescript
secret: process.env.AUTH_SECRET ?? process.env.FG_INTERNAL_AUTH_SECRET,
```

**After:**
```typescript
secret: process.env.AUTH_SECRET,
```

With a block comment documenting the invariants AUTH-001, AUTH-002, AUTH-004, AUTH-008.

**Security rationale:** Removes the cross-boundary fallback. NextAuth will throw `[auth][error] MissingSecret`
if `AUTH_SECRET` is absent, making the misconfiguration visible rather than silent.
`startup-validation.ts` will abort the process before any request is served in production.

**Compatibility:** No functional change when `AUTH_SECRET` is correctly set (which it must be).
Auth0 provider, JWT strategy, session lifetime, callbacks — all unchanged.

### 4.2 apps/console/lib/startup-validation.ts — Add AUTH_SECRET presence check

Adds a new validation condition that pushes an error if `AUTH_SECRET` is absent or whitespace-only:
```typescript
const authSecret = (process.env.AUTH_SECRET || '').trim();
if (!authSecret) {
  errors.push(
    '  AUTH_SECRET is not configured. Set a dedicated session-signing secret for Auth.js. ' +
      'Do not reuse FG_INTERNAL_AUTH_SECRET or any internal gateway credential for this purpose.',
  );
}
```

The check is positioned before the gateway secret check and inside the `isProdLike()` guard.
Error message explicitly warns against reusing the gateway credential.

**Security rationale:** Fail-fast at boot rather than serving requests with a misconfigured
or cross-boundary session secret. Consolidated error pattern: all problems are reported at once.

### 4.3 apps/console/vercel.json — Watch package-lock.json

**Before:** `"ignoreCommand": "git diff HEAD^ HEAD --quiet -- apps/console packages/navigation packages/ui"`
**After:** `"ignoreCommand": "git diff HEAD^ HEAD --quiet -- apps/console packages/navigation packages/ui package-lock.json"`

**Rationale:** Dependency version changes (auth library upgrades, lockfile bumps) must trigger
a rebuild of the console application. The previous command would skip builds when only the
lockfile changed.

---

## 5. Deployment Ownership Matrix

| Application | Source path | vercel.json | Domains | Verified |
|---|---|---|---|---|
| Console (Next.js) | `apps/console/` | `apps/console/vercel.json` | `console.frostgate.ai` (presumed) | NOT VERIFIED — Vercel dashboard required |
| Portal (Next.js) | `apps/portal/` | `apps/portal/vercel.json` | `app.frostgate.ai` (presumed) | NOT VERIFIED |
| Web/Marketing | `apps/web/` | `apps/web/vercel.json` | `frostgate.ai` (presumed) | NOT VERIFIED |
| API (Python/FastAPI) | `api/` | Not found in repo | `api.frostgate.ai` (presumed) | NOT VERIFIED — may be Railway, not Vercel |
| Admin Gateway | `admin_gateway/` | Not found in repo | Internal | NOT VERIFIED |

**Note on `api.frostgate.ai`:** The `MissingSecret` error was logged from this domain. This domain
does not correspond to any Next.js application found in the repository. It likely maps to the
Python/FastAPI backend or a proxy deployment. The console Next.js Auth.js code is NOT expected
to run at `api.frostgate.ai`. If Auth.js `MissingSecret` errors are appearing from that domain,
the cause is different from the `auth.ts` fallback and requires separate investigation.

---

## 6. Secret Isolation Proof

| Credential | Purpose | Used in auth.ts | Acceptable |
|---|---|---|---|
| `AUTH_SECRET` | Auth.js session JWT signing/encryption | YES — `secret: process.env.AUTH_SECRET` | YES — dedicated |
| `FG_INTERNAL_AUTH_SECRET` | Legacy alias for gateway secret | NO — removed from auth.ts | N/A — removed |
| `FG_INTERNAL_GATEWAY_SECRET` | Console→Core service auth | NO — only in internal-gateway-secret.ts | CORRECT |
| `FG_ADMIN_GATEWAY_TOKEN` | Legacy gateway alias | NO | CORRECT |
| `FG_INTERNAL_TOKEN` | Legacy gateway alias | NO | CORRECT |
| `AUTH0_CLIENT_SECRET` | Auth0 OIDC app secret | NO — in providers config only | CORRECT |

---

## 7. Middleware Consistency Proof

Auth.js v5 (next-auth ^5.0.0-beta.31) architecture:

- `middleware.ts` calls `NextAuth(authConfig)` — no explicit `secret` argument.
  In next-auth v5 beta, this automatically reads `AUTH_SECRET` from `process.env`.
- `apps/console/app/api/auth/[...nextauth]/route.ts` re-exports `handlers` from `auth.ts`.
  `auth.ts` calls `NextAuth({ ...authConfig, secret: process.env.AUTH_SECRET, ... })`.

Both paths ultimately use `process.env.AUTH_SECRET`. The middleware edge config (`authConfig`)
uses empty providers (no OIDC dependencies) for Edge compatibility. The route handler adds
the Auth0 provider. The session strategy (JWT), maxAge, callbacks, and pages are shared via
`authConfig` spread.

---

## 8. Regression Test Results

**Command:** `cd apps/console && node --test tests/auth-secret-isolation.test.js`
**Exit code:** 0
**Tests:** 27 pass, 0 fail

**Command:** `cd apps/console && node --test tests/*.test.js`
**Exit code:** 0
**Tests:** 2361 pass, 0 fail (all pre-existing tests preserved)

**Command:** `make fg-fast`
**Exit code:** 0
**Duration:** ~396 seconds
**Result:** All checks passed

**Test coverage matrix:**

| ID | Scenario | Result |
|---|---|---|
| AUTH-T01 | Dedicated secret configured, no fallback | PASS (static) |
| AUTH-T02 | Secret missing — startup-validation catches it | PASS (static) |
| AUTH-T03 | Secret empty — fail closed | PASS (behavioral) |
| AUTH-T04 | Secret whitespace-only — fail closed | PASS (behavioral) |
| AUTH-T05 | Gateway secret present, session secret missing — no fallback | PASS (behavioral + static) |
| AUTH-T06 | Valid session token — JWT strategy preserved | PASS (static) |
| AUTH-T07 | Single secret source — wrong secret deterministically rejected | PASS (static) |
| AUTH-T08 | Session expiry — maxAge enforced | PASS (static) |
| AUTH-T09 | Middleware and handler secret consistency | PASS (static) |
| AUTH-T10 | Unauthenticated protected route — denied | PASS (static) |
| AUTH-T11 | Unsupported experience class — denied | PASS (static) |
| AUTH-T12 | Cross-tenant request — denied | PASS (static) |
| AUTH-T13 | Role escalation — server-signed token only | PASS (static) |
| AUTH-T14 | Auth0 callback — preserved | PASS (static) |
| AUTH-T15 | Logout — signOut exported, route exists | PASS (static) |
| AUTH-T16 | Public auth routes — accessible | PASS (static) |
| AUTH-T17 | Secret leakage — none in logs/errors | PASS (static) |
| AUTH-T18 | Edge runtime compatibility | PASS (static) |
| AUTH-T19 | Node runtime compatibility | PASS (static) |
| AUTH-T20 | Auth file change triggers deployment | PASS (static) |
| AUTH-T21 | Unrelated governance change may skip build | PASS (static) |
| AUTH-T22 | Shared auth dependency change triggers deployment | PASS (static) |
| AUTH-003 | Credential boundary — gateway secret not imported in auth.ts | PASS (static) |
| AUTH-007 | No hardcoded secret literals in auth.ts | PASS (static) |
| AUTH-002-ordering | AUTH_SECRET validated independently from gateway secret | PASS (static) |

---

## 9. Residual Risks

| Risk | Severity | Mitigation | Owner |
|---|---|---|---|
| AUTH_SECRET not set in Vercel Production scope | CRITICAL | Must be verified and set by operator before/after deploy | Human operator |
| FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK not set to "false" | HIGH | Must be set in Vercel Production; startup-validation will abort if missing | Human operator |
| api.frostgate.ai MissingSecret origin unknown | MEDIUM | Separate investigation required; not fixed by this PR | Human operator |
| Production deployment not yet executed | HIGH | Hotfix PR must be merged and deployed; this is CODE_HOTFIX_READY only | Human operator |
| next-auth v5 beta middleware secret resolution behavior | LOW | Documented in Section 7; both paths confirmed to use AUTH_SECRET env var | Accepted |

---

## 10. Required Operator Actions

Before production recovery:

1. **REQUIRED — Vercel console project:** Confirm `AUTH_SECRET` is set in the Production environment scope.
   - Do NOT set it to the value of `FG_INTERNAL_AUTH_SECRET` or `FG_INTERNAL_GATEWAY_SECRET`.
   - Generate a fresh random value (e.g., `openssl rand -base64 32`) locally and set it via the Vercel dashboard.
   - Never share the value in chat, logs, or commit messages.

2. **REQUIRED — Vercel console project:** Confirm `FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK=false` is set in Production.

3. **REQUIRED — Deployment:** Merge this PR and trigger a fresh Vercel deployment for the console project only.

4. **REQUIRED — Verification:** After deployment, verify:
   - No `MissingSecret` errors in Vercel function logs.
   - `/api/auth/session` returns 200 with an unauthenticated body (not 500).
   - Interactive Auth0 login completes successfully.
   - Protected routes deny unauthenticated access.

5. **SEPARATE INVESTIGATION:** Determine why `api.frostgate.ai` was logging `MissingSecret`.
   That domain is not the console Next.js application. It may require separate remediation.

---

## 11. Production Recovery Runbook

### Environment verification (operator, before deployment)

- [ ] Confirm Vercel project for the console is `frostgate-console` (or equivalent).
- [ ] Open Vercel dashboard > Project > Settings > Environment Variables > Production.
- [ ] Confirm `AUTH_SECRET` exists, is non-empty, and is scoped to Production. Do NOT reveal the value.
- [ ] Confirm `AUTH_SECRET` value is NOT the same as `FG_INTERNAL_AUTH_SECRET` or `FG_INTERNAL_GATEWAY_SECRET`.
- [ ] Confirm `FG_CONSOLE_ALLOW_LEGACY_INTERNAL_FALLBACK` is set to `false`.
- [ ] Confirm `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, `AUTH0_ISSUER_BASE_URL` are set.
- [ ] Confirm `CORE_API_URL` and `CORE_TENANT_ID` are set.
- [ ] Confirm at least one of `FG_INTERNAL_GATEWAY_SECRET`/`FG_ADMIN_GATEWAY_TOKEN`/`FG_INTERNAL_AUTH_SECRET` is set.

If `AUTH_SECRET` is absent or incorrectly set:
- Generate a new value: `openssl rand -base64 32` (run locally, do not paste output into chat)
- Set it in the Vercel dashboard. Discard the terminal session after setting.

### Deployment (operator)

- [ ] Merge the hotfix PR to `main`.
- [ ] Confirm Vercel auto-deployment triggers for the console project.
- [ ] Wait for deployment to reach "Ready" state.
- [ ] Note the deployed Git SHA and confirm it matches the merged hotfix commit.

### Authentication verification (operator)

- [ ] `curl -I https://console.frostgate.ai/api/auth/session` — expect 200, no `MissingSecret`.
- [ ] Open `https://console.frostgate.ai/api/auth/session` in browser — expect JSON with `user: null` (unauthenticated).
- [ ] Navigate to a protected route — expect redirect to `/login`.
- [ ] Complete interactive Auth0 login with `jcosat0211@gmail.com`.
- [ ] Confirm session is established (protected route accessible).
- [ ] Sign out — confirm session is cleared.

### Rollback criteria

Rollback if after deployment:
- [ ] `MissingSecret` errors continue.
- [ ] Auth0 callback fails with a 500.
- [ ] Sessions are not established after successful Auth0 login.
- [ ] Any regression in protected-route behavior.

**Rollback procedure:**
- In Vercel, redeploy the previous known-good commit via the deployments list.
- Do NOT restore the `FG_INTERNAL_AUTH_SECRET` fallback as a permanent fix.
- Preserve Vercel function logs as incident evidence before rollback.

---

*This evidence record was created as part of AUTH-SECRET-ISOLATION-001. Production incident closure
requires separate live verification by a human operator.*
