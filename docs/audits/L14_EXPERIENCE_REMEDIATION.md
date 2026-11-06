# L14 Experience Remediation Backlog

**Date:** 2026-11-05
**Audit:** L14-UNIFIED-EXPERIENCE-001
**Sorted by:** Severity, then effort (smallest first)

---

## L14-UX-001

**Title:** Fix broken Stripe cancel_url — `/onboarding` does not exist in portal
**Severity:** P1 — Broken user flow
**Affected property:** api/assessments.py (Core API), apps/portal (no /onboarding route)
**Description:**
`create_checkout_session` sets `cancel_url=f"{base_url}/onboarding"`. The `base_url` defaults to `https://app.frostgate.ai`. There is no `/onboarding` page in `apps/portal/app/`. A customer who cancels checkout is redirected to a 404.
**Root cause:**
The `cancel_url` was written before the portal's self-service intake flow existed. The `/onboarding` path is a console-side legacy wizard — it lives at `console.frostgate.ai/onboarding`, not `app.frostgate.ai/onboarding`.
**Recommended fix:**
Change `cancel_url` to point to the assessment intake form:
```python
cancel_url=f"{base_url}/assessment",
```
This sends the customer back to the intake form where they can restart without being stranded.
**Effort:** S
**Dependencies:** None — single-line change in `api/assessments.py:566`
**Acceptance criteria:** A customer who cancels Stripe checkout is returned to `app.frostgate.ai/assessment` (the intake form), not a 404.

---

## L14-UX-002

**Title:** Add fail-closed CORE_API_KEY guard to BFF activate route
**Severity:** P1 — Operational correctness
**Affected property:** apps/portal/app/api/auth/activate/route.ts
**Description:**
`/api/auth/activate` does not check whether `CORE_API_KEY` is set before forwarding the request. If `CORE_API_KEY` is absent in a production deployment, the route silently sends an empty key to the Core API. The Core API activation endpoint is on a `public_router` (bypasses `require_scopes`), so the missing key may not trigger an auth error — but the behavior is undefined and inconsistent with the `start/route.ts` pattern which explicitly fails with 503 when the key is absent.
**Root cause:**
The activate route was written as a "public" flow that doesn't need an API key to reach the public endpoint, but this assumption isn't documented and breaks deployment hygiene.
**Recommended fix:**
Add at the top of the POST handler:
```typescript
const CORE_API_KEY = process.env.CORE_API_KEY || '';
if (!CORE_API_KEY) {
  return NextResponse.json({ error: 'Service not configured' }, { status: 503 });
}
```
And add the `'X-API-Key': CORE_API_KEY` header to the upstream fetch call.
**Effort:** S
**Dependencies:** None
**Acceptance criteria:** Missing `CORE_API_KEY` returns HTTP 503 from `/api/auth/activate`, not a silent forward with empty key.

---

## L14-UX-003

**Title:** Correct console landing Snapshot price from flat $299 to "$299–999"
**Severity:** P1 — Commercial accuracy
**Affected property:** apps/console/app/page.tsx
**Description:**
The console landing page TIERS array shows `price: '$299'` for the Snapshot tier. The API charges $299, $599, or $999 based on `profile_type`. FrostGate's primary target market (community banking, healthcare, legal, defense) classifies as `regulated` or `govcon` and pays $999. The displayed price undersells the revenue-per-customer and misrepresents the price to operators quoting prospects.
**Root cause:**
The TIERS constant predates the tiered pricing implementation in `api/assessments.py`.
**Recommended fix:**
Change line 26 of `apps/console/app/page.tsx`:
```tsx
price: '$299–999',
period: 'one-time',
```
Add a footnote: "Price depends on organization profile (industry, size, regulatory exposure)."
**Effort:** S
**Dependencies:** None
**Acceptance criteria:** Console landing shows "$299–999 one-time" for Snapshot tier with a profile-based pricing note.

---

## L14-UX-004

**Title:** Add pricing disclosure to marketing website (frostgate.ai)
**Severity:** P2 — Conversion
**Affected property:** apps/web/app/page.tsx
**Description:**
The marketing homepage has no pricing section and no `/pricing` page. B2B buyers in regulated industries (banks, healthcare) routinely require pricing visibility before engaging with a vendor. The current funnel sends customers from frostgate.ai → Stripe checkout without any price anchor.
**Root cause:**
The web app was built as a pure awareness page. Commercial details were placed on the console landing.
**Recommended fix:**
Add a `#pricing` section to `apps/web/app/page.tsx` with the tiered pricing table (Snapshot at $299–999, Intelligence at $5K/yr CTA). Keep it simple: two tiers with "Talk to Sales" for Control/Autonomous. This does not require backend changes.
**Effort:** M
**Dependencies:** None — static content addition
**Acceptance criteria:** `frostgate.ai/#pricing` exists, shows Snapshot price range, links to `app.frostgate.ai/assessment`.

---

## L14-UX-005

**Title:** Console landing page — redirect authenticated operators to dashboard
**Severity:** P2 — Wrong UX for operator domain
**Affected property:** apps/console/app/page.tsx
**Description:**
`console.frostgate.ai/` renders a public marketing pitch with pricing and feature lists. Authenticated console operators navigating to the root URL see this page instead of their dashboard. The expected behavior for a logged-in operator is an automatic redirect to `/dashboard`.
**Root cause:**
The console `page.tsx` is a landing page that was designed for operator discovery, before `next-auth` authentication was added.
**Recommended fix:**
Two changes:
1. Add middleware logic: if `console.frostgate.ai/` is accessed with a valid session, redirect to `/dashboard`.
2. The marketing content should ideally move to `frostgate.ai` (longer term).
**Effort:** S
**Dependencies:** Console middleware/auth setup
**Acceptance criteria:** Authenticated operator who navigates to `console.frostgate.ai/` is redirected to `/dashboard`.

---

## L14-UX-006

**Title:** Fix console landing CTA to point to portal assessment, not legacy onboarding wizard
**Severity:** P1 — Wrong audience / broken funnel
**Affected property:** apps/console/app/page.tsx (TIERS const, hrefs)
**Description:**
Console landing CTAs for "Start Assessment" and "Get Intelligence" point to `/onboarding` and `/onboarding?tier=intelligence`. These are console-local legacy flows, not the customer self-service portal. Operators who share the console URL with prospects land those prospects in an operator wizard, not the customer portal.
**Root cause:**
The console landing predates the self-service portal (`app.frostgate.ai/assessment`).
**Recommended fix:**
Change the CTA hrefs to point to the portal:
```tsx
href: 'https://app.frostgate.ai/assessment',  // Snapshot
href: 'https://app.frostgate.ai/assessment',  // Intelligence (same intake, different tier resolved by profile)
```
**Effort:** S
**Dependencies:** None
**Acceptance criteria:** "Start Assessment" and "Get Intelligence" CTAs on `console.frostgate.ai` link to `https://app.frostgate.ai/assessment`.

---

## L14-UX-007

**Title:** Verify and repair portal /engagement route
**Severity:** P2 — Potential broken navigation
**Affected property:** apps/portal/app/engagement/ (may be missing)
**Description:**
The `PORTAL_REGISTRY` lists `/engagement` as a primary visible navigation item with `sourceOfTruth: apps/portal/app/engagement/page.tsx`. The portal navigation header renders this as "Assessment" in the nav bar. The top-level `apps/portal/app/` directory listing did not include an `engagement/` subdirectory. If the route doesn't exist, portal users will navigate to a 404 from the main nav.
**Root cause:**
Registry and filesystem may be out of sync.
**Recommended fix:**
1. Verify: `ls apps/portal/app/engagement/`
2. If missing: either create a stub page at `apps/portal/app/engagement/page.tsx` that redirects to the engagement detail flow, or remove `/engagement` from the registry (set `visibility: 'hidden'`).
**Effort:** S
**Dependencies:** Confirm whether this route exists in deployment
**Acceptance criteria:** Clicking "Assessment" in the portal nav either renders content or is hidden from the nav.

---

## L14-UX-008

**Title:** Add CDN log scrubbing for activation token query parameter
**Severity:** P2 — Security / data minimization
**Affected property:** Vercel/CDN configuration (not in this repo — operator action required)
**Description:**
The `at=` query parameter containing the raw HMAC activation token appears in Vercel access logs for the initial GET request to `/assessment/activate`. The token is single-use and 24h TTL, but Vercel log retention (typically 7 days) means the token persists in logs longer than its validity window. Any Vercel administrator with log access can see the raw token.
**Root cause:**
URL-embedded secrets are architecturally visible in access logs regardless of client-side scrubbing.
**Recommended fix:**
Add a Vercel log drain filter or Vercel Edge Middleware rule that redacts query parameters matching `at=*` for the `/assessment/activate` path before writing to log storage. This is a Vercel project-level configuration, not a code change.
**Effort:** S (operator action)
**Dependencies:** Vercel project access; operator runbook entry
**Acceptance criteria:** Vercel access logs for `/assessment/activate` do not contain the `at=` parameter value.

---

## L14-UX-009

**Title:** Add empty-state guidance for new portal users post-activation
**Severity:** P3 — Conversion / onboarding experience
**Affected property:** apps/portal/app/page.tsx
**Description:**
After a customer completes the activation flow, they land on the portal dashboard. The current "No engagements available" state reads: "Your assessor will create an engagement and notify you when it is ready." This may be confusing for a customer who just paid for a Snapshot — they expect immediate access to something.
**Root cause:**
The portal is designed for operator-managed assessments. The self-service Snapshot flow creates an assessment but does not automatically surface it as an engagement in the portal.
**Recommended fix:**
Post-activation, the portal should show a personalized onboarding state: "Welcome to FrostGate. Your AI governance assessment is being processed — you'll receive an email within 24 hours with next steps." This requires detecting the `assessment_id` tied to the portal session and showing a custom empty state rather than the generic "No engagements available" message.
**Effort:** M
**Dependencies:** Portal session stores `assessment_id`; Core API engagement link to assessment
**Acceptance criteria:** A newly activated portal user sees a meaningful onboarding message rather than a generic "no engagements" state.
