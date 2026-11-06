# L14 Navigation Matrix

**Date:** 2026-11-05
**Audit:** L14-UNIFIED-EXPERIENCE-001
**Method:** Code inspection only. All "Actual Destination" entries are CODE (source-verified) or NOT_VERIFIED (live status unknown).

---

## Legend

| Column | Meaning |
|---|---|
| Source URL | Property where the link appears |
| Element | Link text / component |
| Expected Destination | What the href claims |
| Actual Destination | CODE = verified in source; NOT_VERIFIED = not live-tested |
| Auth Required | Whether the destination requires authentication |
| Result | PASS / WARNING / FAIL / NOT_VERIFIED |
| Severity | P0–P3 |

---

## A. Marketing Website (frostgate.ai)

| Source URL | Element | Expected Destination | Actual Destination | Auth Required | Result | Severity |
|---|---|---|---|---|---|---|
| frostgate.ai/ | Nav: "Operator sign in" | https://console.frostgate.ai | CODE: `href="https://console.frostgate.ai"` | Yes (console) | PASS | — |
| frostgate.ai/ | Nav: "Get started" CTA | https://app.frostgate.ai/assessment | CODE: `href="https://app.frostgate.ai/assessment"` | No | PASS | — |
| frostgate.ai/ | Hero: "Start your assessment" | https://app.frostgate.ai/assessment | CODE: `href="https://app.frostgate.ai/assessment"` | No | PASS | — |
| frostgate.ai/ | Hero: "See how it works" | #how-it-works (anchor) | CODE: `href="#how-it-works"` — anchor section exists in page | No | PASS | — |
| frostgate.ai/ | Nav: "Features" | #features (anchor) | CODE: `href="#features"` — anchor section exists in page | No | PASS | — |
| frostgate.ai/ | Nav: "How it works" | #how-it-works (anchor) | CODE: `href="#how-it-works"` — anchor section exists in page | No | PASS | — |
| frostgate.ai/ | CTA section: "Start your assessment" | https://app.frostgate.ai/assessment | CODE: `href="https://app.frostgate.ai/assessment"` | No | PASS | — |
| frostgate.ai/ | Footer: "Console" | https://console.frostgate.ai | CODE: `href="https://console.frostgate.ai"` | Yes (console) | PASS | — |
| frostgate.ai/ | Footer: "Client Portal" | https://app.frostgate.ai | CODE: `href="https://app.frostgate.ai"` | Yes (portal) | PASS | — |
| frostgate.ai/pricing | (no pricing page) | — | 404 expected (no route in `apps/web/app/`) | No | WARNING | P2 |

**Web navigation summary:** All outbound links in the web homepage are correct per source code. No internal routes exist other than `/` — no `/pricing`, `/features`, `/blog`, `/contact` pages found.

---

## B. Customer Portal (app.frostgate.ai)

Navigation is driven by `PORTAL_REGISTRY` filtered to `visibility: visible` items, sorted by tier (primary first). Based on the registry:

| Source URL | Element | Expected Destination | Actual Destination | Auth Required | Result | Severity |
|---|---|---|---|---|---|---|
| app.frostgate.ai/ | Nav: "Overview" | / (portal root) | CODE: route `/` (PortalHome page exists at `apps/portal/app/page.tsx`) | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Assessment" | /engagement | CODE: route `/engagement` (registry `sourceOfTruth`: `apps/portal/app/engagement/page.tsx`) | Yes | WARNING — page directory not confirmed | P2 |
| app.frostgate.ai/ | Nav: "Findings" | /findings | CODE: route `/findings` (registry `sourceOfTruth`: `apps/portal/app/findings/page.tsx`) | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Reports" | /reports | CODE: route `/reports` | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Coverage" | /coverage | CODE: route `/coverage` | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Attestation" | /attestation | CODE: route `/attestation` | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Remediation" | /remediation | CODE: route `/remediation` | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "Continuity" | /continuity | CODE: route `/continuity` | Yes | PASS | — |
| app.frostgate.ai/ | Nav: "AI Assistant" (secondary) | /assistant | CODE: route `/assistant` | Yes | PASS | — |
| app.frostgate.ai/ | Home logo link | / | CODE: `href="/"` in layout | Yes | PASS | — |
| app.frostgate.ai/assessment | Form submit | /api/assessment/start (POST) → Stripe URL | CODE: BFF route at `apps/portal/app/api/assessment/start/route.ts` | No | PASS | — |
| app.frostgate.ai/assessment/activate | Activation flow | /api/auth/oidc → Auth0 → /api/auth/oidc/callback | CODE: verified in `activate/page.tsx` and `oidc/route.ts` | Partial (OIDC required) | PASS | — |
| app.frostgate.ai/login | (login page) | OIDC flow or password | CODE: `apps/portal/app/login/` (exists in listing) | No | PASS | — |
| app.frostgate.ai/api/assessment/payment-status/[id] | (API endpoint) | JSON: payment_status | CODE: Returns JSON error (not 500) for bad IDs — input validation present | No | PASS | — |

**Portal navigation note:** The portal header is generated from `PORTAL_REGISTRY` server-side. The `/engagement` route appears in the registry with `maturity: strong` and `lifecycle: core` but the `apps/portal/app/` directory listing did not show an `engagement/` subdirectory in the top-level scan. This should be verified.

---

## C. Enterprise Console (console.frostgate.ai)

Console navigation is driven by `CONSOLE_REGISTRY` filtered to `visibility: visible` items. Visible items:

| Source URL | Element | Expected Destination | Actual Destination | Auth Required | Result | Severity |
|---|---|---|---|---|---|---|
| console.frostgate.ai/ | CTA: "Start Assessment" | /onboarding | CODE: `href="/onboarding"` (console-local legacy flow) | No (public) | WARNING — wrong audience | P1 |
| console.frostgate.ai/ | CTA: "Get Intelligence" | /onboarding?tier=intelligence | CODE: `href="/onboarding?tier=intelligence"` | No | WARNING — wrong audience | P1 |
| console.frostgate.ai/ | CTA: "Talk to Sales" (Control) | mailto:sales@frostgate.ai | CODE: `href="mailto:sales@frostgate.ai"` | No | PASS | — |
| console.frostgate.ai/ | CTA: "Talk to Sales" (Autonomous) | mailto:sales@frostgate.ai | CODE: `href="mailto:sales@frostgate.ai"` | No | PASS | — |
| console.frostgate.ai/ | Nav: "Sign In" | /login | CODE: `href="/login"` (console login page — `apps/console/app/login/page.tsx`) | No | PASS | — |
| console.frostgate.ai/ | Nav: "Get Started" | /onboarding | CODE: `href="/onboarding"` (legacy) | No | WARNING — wrong audience | P1 |
| console.frostgate.ai/login | Auth: "Sign in with Auth0" | Auth0 authorize endpoint via next-auth | CODE: `signIn('auth0', { callbackUrl: '/dashboard' })` | No | PASS | — |
| console.frostgate.ai/dashboard | Sidebar: "Command Center" | /dashboard | CODE: route `/dashboard` exists | Yes | PASS | — |
| console.frostgate.ai/dashboard | Sidebar: "Readiness" | /dashboard/readiness | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/field-assessment | Sidebar: "Field Assessments" | /field-assessment | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/dashboard/workforce | Sidebar: "Workforce Intel" | /dashboard/workforce | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/dashboard/forensics | Sidebar: "Audit & Forensics" | /dashboard/forensics | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/admin/tenants | Sidebar: "Clients" | /admin/tenants | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/keys | Sidebar: "Keys" | /keys | CODE: route exists | Yes | PASS | — |
| console.frostgate.ai/dashboard/settings | Sidebar: "Settings" | /dashboard/settings | CODE: route exists | Yes | PASS | — |

---

## Cross-Domain Links Summary

| From | To | Purpose | Status |
|---|---|---|---|
| frostgate.ai → app.frostgate.ai/assessment | Multiple CTAs | Drive new customer signups | PASS (code correct) |
| frostgate.ai → console.frostgate.ai | "Operator sign in" | Operator access | PASS (code correct) |
| frostgate.ai → app.frostgate.ai | Footer "Client Portal" | Portal access | PASS (code correct) |
| console.frostgate.ai → frostgate.ai | No link | None | WARNING — console landing has no "back to marketing" link |
| app.frostgate.ai → frostgate.ai | No link found | None | WARNING — portal has no link back to marketing site |
| Stripe success_url → app.frostgate.ai/assessment/activate | Post-payment | Activation | PASS (code correct) |
| Stripe cancel_url → app.frostgate.ai/onboarding | Cancelled checkout | Re-entry | WARNING — `/onboarding` route is at `console.frostgate.ai`, not `app.frostgate.ai`. The cancel_url in `api/assessments.py:566` sends cancelled customers to `{CONSOLE_BASE_URL}/onboarding` where `CONSOLE_BASE_URL` defaults to `https://app.frostgate.ai`. There is no `/onboarding` page in `apps/portal/`. This is a **broken cancel URL** — cancelled checkout users will land on a 404. |
