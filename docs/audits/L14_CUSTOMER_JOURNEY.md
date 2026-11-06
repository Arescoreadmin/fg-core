# L14 Customer Journey Trace

**Date:** 2026-11-05
**Audit:** L14-UNIFIED-EXPERIENCE-001
**Scope:** Self-service customer journey — marketing visit → assessment purchase → portal activation → ongoing access

---

## Journey Overview

```
frostgate.ai → app.frostgate.ai/assessment → Stripe Checkout → /assessment/activate → Auth0 OIDC → portal access
```

---

## Step-by-Step Trace

### Step 1: Marketing Discovery

| Field | Value |
|---|---|
| Source URL | https://frostgate.ai/ |
| Implementation file | `apps/web/app/page.tsx` |
| Status | IMPLEMENTED |
| Verification | CODE (live status NOT_VERIFIED) |

**What the code does:**
- Renders a full static marketing homepage: hero, features (4 cards), "How it works" (3 steps), CTA section, footer
- Three CTAs all link to `https://app.frostgate.ai/assessment`
- Nav: "Operator sign in" → `https://console.frostgate.ai`, "Get started" → `https://app.frostgate.ai/assessment`
- No pricing disclosure on this page

**Gaps:**
- No pricing page at all
- No `/pricing` route exists in `apps/web/app/`
- Customer has no price visibility before clicking through to the portal

---

### Step 2: Assessment Intake Form

| Field | Value |
|---|---|
| Source URL | https://app.frostgate.ai/assessment |
| Implementation file | `apps/portal/app/assessment/page.tsx` |
| Status | IMPLEMENTED |
| Verification | CODE (live status NOT_VERIFIED) |

**What the code does:**
- Renders a form collecting: Organization name (required), Work email (required), Industry (dropdown), Employee count (dropdown)
- On submit: `POST /api/assessment/start` (BFF)
- BFF calls Core API `POST /ingest/assessment/orgs` → org + assessment_id
- BFF calls Core API `POST /ingest/assessment/{id}/checkout` → Stripe checkout URL
- Browser is redirected to Stripe-hosted checkout

**Gaps:**
- No price shown on this page ("Secure payment by Stripe. One-time payment · No subscription required." — but no amount)
- Rate limit: 5 submissions per IP per minute (adequate for low-volume)
- `CORE_API_KEY` required in env — if absent, returns 503 (fail-closed, correct)

---

### Step 3: Stripe Checkout

| Field | Value |
|---|---|
| Source URL | Stripe-hosted (stripe.com) |
| Implementation file | `api/assessments.py:546–575` |
| Status | PARTIALLY_IMPLEMENTED |
| Verification | CODE (Stripe live flow NOT_PROVEN — requires live Stripe keys) |

**What the code does:**
- Amount is computed server-side from `profile_type` (classified from org profile):
  - `smb_basic`/`smb_growth`: $299 (cents: 29900)
  - `midmarket`/`enterprise`: $599 (cents: 59900)
  - `regulated`/`govcon`: $999 (cents: 99900)
- Generates HMAC-SHA256 activation token (pepper-keyed, 32 random bytes)
- Records `AssessmentActivation` row (pending, 24h TTL)
- Sets `success_url` = `{CONSOLE_BASE_URL}/assessment/activate?id={id}&at={token}`
- Sets `cancel_url` = `{CONSOLE_BASE_URL}/onboarding`
- Returns `checkout_url` to BFF

**Gaps:**
- `cancel_url` points to `/onboarding` — this route does not exist in `apps/portal/`. This will return a 404 for cancelled checkout users. FINDING: broken cancel URL.
- `CONSOLE_BASE_URL` env var defaults to `https://app.frostgate.ai` — correct for portal.
- Stripe live flow not tested (requires `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, live CLI — documented in operator runbook)

---

### Step 4: Post-Payment Redirect — Activation Landing

| Field | Value |
|---|---|
| Source URL | https://app.frostgate.ai/assessment/activate?id=...&at=... |
| Implementation file | `apps/portal/app/assessment/activate/page.tsx` |
| Status | IMPLEMENTED |
| Verification | CODE (live Stripe flow NOT_PROVEN) |

**What the code does:**
1. Extracts `id` (assessment_id) and `at` (raw activation token) from URL params
2. Stashes `at` in `sessionStorage` as `fg_activation_token`
3. Removes `at` from URL via `window.history.replaceState` (prevents referrer leakage)
4. Polls `GET /api/assessment/payment-status/{id}` to confirm payment
5. If `payment_status === 'paid'`: shows "Continue with SSO to activate" button
6. If status is `unpaid`: shows "Payment still being processed" message
7. On button click: redirects to `/api/auth/oidc?mode=activate&assessmentId={id}`

**Security notes:**
- Token in initial HTTP request is visible to Vercel/CDN logs until replaceState runs (documented P2 finding)
- `/assessment` prefix added to `PUBLIC_PREFIXES` in portal middleware — no session required to reach this page

---

### Step 5: OIDC Identity Verification (Auth0)

| Field | Value |
|---|---|
| Source URL | /api/auth/oidc → Auth0 → /api/auth/oidc/callback |
| Implementation file | `apps/portal/app/api/auth/oidc/route.ts`, `apps/portal/app/api/auth/oidc/callback/route.ts` |
| Status | IMPLEMENTED |
| Verification | CODE (live Auth0 NOT_PROVEN — requires PORTAL_AUTH0_DOMAIN, PORTAL_AUTH0_CLIENT_ID, PORTAL_AUTH0_CALLBACK_URL) |

**What the code does:**
- Generates PKCE code_verifier + code_challenge
- Sets CSRF state
- Stores `{state, codeVerifier, returnTo, mode: 'activate', assessmentId}` in `fg_oidc_state` HttpOnly cookie (10min TTL)
- Redirects to Auth0 authorize endpoint
- On callback: validates state, exchanges code for token, extracts OIDC claims
- Sets `fg_oidc_bootstrap` HttpOnly cookie with access_token
- Redirects back to `/assessment/activate?id={id}&from=oidc`

---

### Step 6: Account Activation

| Field | Value |
|---|---|
| Source URL | app.frostgate.ai/assessment/activate?id=...&from=oidc |
| Implementation file | `apps/portal/app/assessment/activate/page.tsx`, `apps/portal/app/api/auth/activate/route.ts`, `api/assessments.py:693` |
| Status | IMPLEMENTED |
| Verification | CODE (live flow NOT_PROVEN) |

**What the code does:**
- Retrieves activation token from `sessionStorage`
- `POST /api/auth/activate` with `{assessment_id, activation_token}`
- BFF reads `fg_oidc_bootstrap` cookie (access_token)
- BFF calls Core API `POST /ingest/assessment/{id}/activate` with `{access_token, activation_token, oidc_provider: 'auth0'}`
- Core API: validates activation token (HMAC verify, single-use, expiry check), validates OIDC token (Auth0), creates tenant + portal user + membership, migrates assessment from `lead:` namespace, issues `pnu1.` session token
- BFF sets `fg_portal_session` HttpOnly cookie, clears `fg_oidc_bootstrap`
- Client: clears `sessionStorage`, redirects to `/`

**Security controls verified in code:**
- Activation token: HMAC-SHA256-keyed with pepper, stored as hash only, single-use (atomic state → 'claimed'), 24h TTL
- Payment re-verified server-side before activation (payment_status must be 'paid')
- OIDC token validated server-side (not trusted from client)
- Existing tenant claim rejected (409) — prevents double-activation
- Session token prefix `pnu1.` validated before setting cookie

---

### Step 7: Portal Access

| Field | Value |
|---|---|
| Source URL | https://app.frostgate.ai/ |
| Implementation file | `apps/portal/app/page.tsx`, `apps/portal/app/layout.tsx` |
| Status | IMPLEMENTED |
| Verification | CODE (live flow NOT_PROVEN) |

**What the code does:**
- Portal home shows: engagement list, risk posture panel (NIST coverage, findings, function heatmap, immediate actions), remediation status, attestation health
- Navigation: Overview, Assessment, Findings, Reports, Coverage, Attestation, Remediation, Continuity, AI Assistant
- All routes protected by middleware session gate

---

## Journey Status Matrix

| Step | Status | Blockers |
|---|---|---|
| 1. Marketing discovery | IMPLEMENTED | No pricing disclosure |
| 2. Assessment intake form | IMPLEMENTED | No price shown before checkout |
| 3. Stripe checkout | PARTIALLY_IMPLEMENTED | Broken cancel_url (`/onboarding` → 404); live flow NOT_PROVEN |
| 4. Activation landing | IMPLEMENTED | Activation token in CDN logs (P2) |
| 5. Auth0 OIDC | IMPLEMENTED | Live flow NOT_PROVEN (requires env vars) |
| 6. Account activation | IMPLEMENTED | Live flow NOT_PROVEN (requires Stripe + Auth0) |
| 7. Portal access | IMPLEMENTED | Engagement `/engagement` route may be missing |

---

## Conversion Risk Analysis

| Risk | Severity | Description |
|---|---|---|
| Price surprise at checkout | P2 | Customer doesn't see price until Stripe-hosted page — potential drop-off at checkout |
| Broken cancel URL | P1 | Cancelled checkout redirects to 404 — customer is stranded |
| "No engagements available" state | P3 | New portal user post-activation sees empty dashboard until operator creates an engagement |
| Auth0 configuration gap | P1 | If PORTAL_AUTH0_DOMAIN/CLIENT_ID are not set, entire OIDC flow returns 503 |
