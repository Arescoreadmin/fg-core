# L14 Unified Experience Audit

**Date:** 2026-11-05
**Branch:** audit/l14-unified-experience-001
**Commit:** 083308c7
**Auditor:** Automated — Claude agent (claude-sonnet-4-6)
**Scope:** Three FrostGate digital properties — marketing site (frostgate.ai), customer portal (app.frostgate.ai), enterprise console (console.frostgate.ai)

---

## Methodology

This audit used two techniques only:

| Technique | Coverage |
|---|---|
| **CODE_INSPECTION** | All three `apps/` directories read in full: layout, page, tailwind config, globals.css, navigation packages, API routes, shared packages |
| **LIVE_OBSERVED** | NOT_AVAILABLE — network access was blocked by the execution environment. All live-site rows in the evidence manifest carry `NOT_VERIFIED` |

The audit cannot confirm any live HTTP status, final redirect destination, or rendered HTML. All findings derive from the source tree at commit 083308c7 on branch `audit/l14-unified-experience-001` (identical to `main` at the time of branching).

---

## Scope and Limitations

**What was inspected:**
- `apps/web/app/page.tsx`, `layout.tsx`, `globals.css`, `tailwind.config.ts`
- `apps/portal/app/page.tsx`, `layout.tsx`, `globals.css`, `tailwind.config.ts`, assessment intake page, activation page, all BFF API routes
- `apps/console/app/page.tsx`, `layout.tsx`, `globals.css`, `tailwind.config.ts`, `dashboard/layout.tsx`, `login/page.tsx`, `onboarding/page.tsx`
- `packages/navigation/src/registrations/portal.ts`, `console.ts`
- `api/assessments.py` (checkout creation, activation token, tier pricing)
- `SYSTEM.md` (authoritative architecture and pricing)

**What could NOT be verified:**
- Live HTTP responses from frostgate.ai, app.frostgate.ai, console.frostgate.ai
- Actual Stripe checkout session creation (requires STRIPE_SECRET_KEY in env)
- Auth0 OIDC flow (requires PORTAL_AUTH0_DOMAIN, PORTAL_AUTH0_CLIENT_ID)
- CDN/proxy log exposure of activation tokens
- Vercel deployment configuration
- Environment variable correctness in production

---

## Executive Summary — Top 5 Findings

### Finding 1 — P1: Console Landing Page Serves as Marketing Site (Wrong Property)
**Severity:** P1 — Commercial confusion risk

The enterprise console (`apps/console/app/page.tsx`) renders a full public marketing and pricing page with CTAs to `/onboarding`. This page is served at `console.frostgate.ai/` — an operator-only property. The marketing function belongs at `frostgate.ai`. Operators who navigate to the console land on a marketing pitch rather than their dashboard. The correct entry point for new customers should be `frostgate.ai`, not `console.frostgate.ai`.

Additionally, the console onboarding wizard (`/onboarding`) appears to be a legacy flow for operator-assisted tenant creation, but the console landing page CTA targets it with "Start Free Assessment" language aimed at end customers. This creates a confused audience (operator vs. customer).

### Finding 2 — P1: Pricing Contradiction Between Console Landing and API Tier Prices
**Severity:** P1 — Commercial accuracy

| Source | Snapshot price |
|---|---|
| `apps/console/app/page.tsx` (TIERS const) | $299 one-time |
| `api/assessments.py` (_TIER_PRICES) | $299 for `smb_basic`/`smb_growth` |
| `apps/console/app/onboarding/page.tsx` (tierPrice()) | $299, $599, $999 depending on profile |
| `SYSTEM.md` | "$299–999" range |

The console landing page shows a flat "$299" Snapshot price. The API has three distinct amounts ($299, $599, $999) based on `profile_type`. The console onboarding `tierPrice()` function replicates the tiered logic, returning $299, $599, or $999. However it uses a **different classification logic** from the server-side `_TIER_PRICES`: the UI computes pricing based on `isDodContractor`, `handlesCui`, `handlesPhi`, and `employeeCount`, while the server classifies based on `profile_type` derived from `classify_profile()`. The two are not provably aligned — a user classified as `midmarket` on the server ($599) might see "$299" in the client UI during the onboarding wizard if the client-side `tierPrice()` logic produces a different result for the same inputs.

The marketing web (`frostgate.ai`) has **no pricing page at all**. All three CTAs on `frostgate.ai` point to `https://app.frostgate.ai/assessment` which also shows no pricing — the customer doesn't see the price until Stripe checkout.

### Finding 3 — P2: Brand Token Split — Web vs Portal/Console
**Severity:** P2 — Brand consistency

The marketing site (`apps/web`) uses a custom `steel`/`rust` color palette in Tailwind. The portal and console use CSS variable-based tokens (`--primary: #FF5A1F`, `--background`, `--foreground`, etc.) and semantic Tailwind classes (`text-primary`, `bg-background`). These are fundamentally different token systems with no shared authority. The result:

- `frostgate.ai` renders a dark navy/slate hero with orange-rust accents and the FrostGate shield logo
- `app.frostgate.ai` and `console.frostgate.ai` render in a light/dark mode toggle system with orange primary (#FF5A1F)

The orange primary (#FF5A1F) in portal/console does not map cleanly to the web's `rust-500` (#9b3830) or `steel-600` (#2e5878). This is a visual discontinuity at the domain boundary that every user crossing from frostgate.ai to app.frostgate.ai will notice.

Additionally, the web app uses `font-family: Inter` (Google Fonts import) while portal/console use system-ui (`-apple-system, BlinkMacSystemFont, Segoe UI, Roboto...`). These are different typefaces.

### Finding 4 — P2: Web App Has No Pricing Page; CTA Sends to Stripe Without Price Disclosure
**Severity:** P2 — Conversion and trust risk

`frostgate.ai` has three CTAs pointing to `https://app.frostgate.ai/assessment`. The assessment intake form at that URL collects org name, email, industry, and employee count — then proceeds to Stripe checkout. The customer does not see the price before clicking "Continue to payment." The price is computed server-side at checkout creation and is only visible at the Stripe-hosted checkout page. While this is not an error, it is a friction point: B2B customers in regulated industries are accustomed to seeing prices before entering a purchase flow.

There is no `/pricing` page on `frostgate.ai`, no anchor-linked pricing section, and no price disclosure in the web homepage content.

### Finding 5 — P2: Activation Token Referrer Leakage Window
**Severity:** P2 — Security / data exposure (window is bounded)

The Stripe `success_url` embeds a raw HMAC-keyed activation token in the URL:
```
/assessment/activate?id=<assessment_id>&at=<raw_activation_token>
```

The `activate/page.tsx` correctly scrubs `at` from the URL using `window.history.replaceState` and stores it in `sessionStorage`. However the token still appears in:
1. The initial HTTP GET request to the Next.js server (Vercel access logs, CDN edge logs)
2. The Stripe-hosted checkout success redirect response (Stripe's server logs carry the success_url)
3. The browser's initial navigation before the client-side React effect runs and scrubs it

This is a known and documented partial mitigation. The token is HMAC-SHA256-keyed with a pepper, single-use (enforced atomically server-side), and 24h TTL. The exposure window between HTTP server receipt and `replaceState` is milliseconds under normal operation. The activation endpoint requires both a valid activation token AND a valid OIDC access token from Auth0 — so the activation token alone is insufficient for exploitation without also completing the Auth0 OIDC flow for that specific assessment.

**Classification:** ACCEPTABLE MITIGATION given the two-factor requirement (token + OIDC). But classified P2 because Vercel/CDN log exposure means the raw token is visible to platform operators with log access for 24 hours.

---

## Launch Readiness Matrix

| Property | URL | Status | Notes |
|---|---|---|---|
| Marketing website | frostgate.ai | PARTIALLY_PROVEN | Present in source; live status NOT_VERIFIED. No pricing page. Dark-theme brand diverges from portal. |
| Customer portal | app.frostgate.ai | PARTIALLY_PROVEN | Assessment intake + activation flow implemented (PR #804). Live Stripe/Auth0 NOT_PROVEN. |
| Enterprise console | console.frostgate.ai | PARTIALLY_PROVEN | Operator dashboard implemented. Landing page serves marketing content — wrong audience for console domain. |

---

## Security Findings

### SEC-001: Activation Token in URL (Bounded Exposure)

| Field | Value |
|---|---|
| Severity | P2 |
| Location | `api/assessments.py:565`, `apps/portal/app/assessment/activate/page.tsx:50` |
| Description | Raw HMAC token in Stripe success_url appears in CDN/Vercel access logs until client-side `replaceState` executes |
| Mitigations | Token is single-use (atomic DB claim); HMAC-SHA256 with pepper; 24h TTL; second factor (OIDC) required to complete activation |
| Residual risk | Vercel/CDN logs readable by platform operators for 24h window |
| Classification | ACCEPTABLE — two-factor requirement makes raw token insufficient for exploitation |
| Recommended fix | Log-scrubbing rule at Vercel edge to redact `at=` parameter from access logs; reduces residual from 24h to 0 |

### SEC-002: Console Landing Page Accessible Without Auth

| Field | Value |
|---|---|
| Severity | P1 |
| Location | `apps/console/app/page.tsx` |
| Description | The console landing page at `console.frostgate.ai/` renders without authentication, exposing the full commercial pricing and feature list to unauthenticated visitors |
| Impact | Minor — marketing content is publicly intended. Larger issue is audience confusion: operators expect to land at their dashboard |
| Recommended fix | Add auth middleware redirect on `console.frostgate.ai/` → `/login` for unauthenticated users; move marketing content to frostgate.ai |

### SEC-003: BFF activation route missing CORE_API_KEY check

| Field | Value |
|---|---|
| Severity | P1 |
| Location | `apps/portal/app/api/auth/activate/route.ts` |
| Description | The `/api/auth/activate` route does not check for `CORE_API_KEY` before forwarding to the Core API, unlike `/api/assessment/start` which fails closed with 503 when `CORE_API_KEY` is absent. If `CORE_API_KEY` is not set in production, the activate route forwards an empty `X-API-Key` header. The Core API endpoint `/ingest/assessment/{id}/activate` is on a `public_router` (bypasses `require_scopes`) so this may not be a live security gap, but it is an operational misconfiguration risk. |
| Recommended fix | Add an env check for `CORE_API_KEY` at the top of the activate route handler, mirroring the pattern in `start/route.ts` |

---

## Commercial Accuracy Findings

### COM-001: Pricing Mismatch — Console Landing vs API Tier Prices

| Property | Displayed | Server Amount (cents) | Match |
|---|---|---|---|
| Console landing Snapshot | $299 | $299 (smb), $599 (midmarket/enterprise), $999 (regulated/govcon) | Partial — only SMB matches |
| Console onboarding tierPrice() | $299 / $599 / $999 | Same tiers | Logic diverges from server classify_profile() |
| Marketing web | None | N/A | No disclosure |

The console landing shows a flat "$299" CTA. Under the hood, customers in regulated industries or defense will be charged $599 or $999 at checkout. The disclosed price at the top of the page does not represent the actual price for most of FrostGate's target market (community banking, healthcare, legal, defense — all in the $599–999 tier).

**Recommended fix:** Replace the flat "$299 one-time" display with the documented range "$299–999 one-time" per SYSTEM.md, or implement a dynamic pricing preview in the onboarding wizard before checkout.

### COM-002: No Public Pricing on Marketing Site

The marketing site (frostgate.ai) has no pricing section, no `/pricing` page, and no price anchor on the homepage. The console landing (at console.frostgate.ai) has a detailed 4-tier pricing section. These are on two separate domains with separate audiences. B2B buyers typically research pricing before entering a demo/purchase funnel.

---

## Brand Consistency Summary

### Web (frostgate.ai)
- **Framework:** Next.js 14.2.35 (older than portal/console 14.2.5 — minor version mismatch)
- **Colors:** Custom Tailwind palette — `steel-*` (blue-grey) and `rust-*` (red-brown)
- **Background:** `bg-gray-950` hardcoded in `body` class (pure dark site, no dark mode toggle)
- **Font:** Inter (Google Fonts import)
- **Logo:** PNG image (`logo-original.png`)
- **No shared package dependency** (no `@fg/ui`, no `@fg/navigation`)

### Portal (app.frostgate.ai)
- **Framework:** Next.js 14.2.5
- **Colors:** CSS variable tokens (`--primary: #FF5A1F`, `--background: #FFFFFF` / `#05070A` dark)
- **Dark mode:** Yes (class-based, `localStorage` persistence)
- **Font:** System-UI stack
- **Logo:** Text ("FrostGate" with "Client Portal" subtitle)
- **Shared packages:** `@fg/ui`, `@fg/navigation`

### Console (console.frostgate.ai)
- **Framework:** Next.js 14.2.35
- **Colors:** Same CSS variable tokens as portal (identical `globals.css`)
- **Dark mode:** Yes (class-based, identical script)
- **Font:** System-UI stack
- **Logo:** `FrostGateShield` SVG component (`@/components/governance/FrostGateShield`)
- **Shared packages:** `@fg/ui`, `@fg/navigation`

### Divergences Identified
| Token | Web | Portal | Console | Impact |
|---|---|---|---|---|
| Primary color | steel-600 `#2e5878` | `#FF5A1F` orange | `#FF5A1F` orange | High — different hue family |
| Background | `gray-950` (always dark) | CSS var (light/dark toggle) | CSS var (light/dark toggle) | Medium — dark vs adaptive |
| Font | Inter (Google) | System-UI | System-UI | Low |
| Logo treatment | PNG file | Text + "Client Portal" label | SVG shield component | Medium — inconsistent |
| Next.js version | 14.2.35 | 14.2.5 | 14.2.35 | Low |

**Canonical authority:** The portal and console share `globals.css` with identical CSS variable definitions — these are the design system authority. The web app does not participate in this system.

---

## Navigation Findings

### NAV-001: Web footer links are correct
`frostgate.ai` footer links to `console.frostgate.ai` and `app.frostgate.ai` — both correct.

### NAV-002: Web nav links to console and portal correctly
Header links to `https://console.frostgate.ai` ("Operator sign in") and `https://app.frostgate.ai/assessment` ("Get started") — correct.

### NAV-003: Console landing CTAs point to `/onboarding` (console-local, not portal)
All "Start Assessment" CTAs on `console.frostgate.ai/` point to `/onboarding` (console-local). The correct self-service customer entry point is `app.frostgate.ai/assessment`. Operators using the console's onboarding wizard are using a legacy flow.

### NAV-004: Portal navigation derived from PORTAL_REGISTRY — includes `/engagement` route (CONFIRMED PRESENT)
The portal layout nav derives from `PORTAL_REGISTRY.getAllItems()` filtered to `visible` tier. The registry includes `/engagement` (Assessment). The `apps/portal/app/engagement/` directory was confirmed present in the filesystem. No finding.

### NAV-005: Console sidebar nav derived from CONSOLE_REGISTRY
Visible console pages include: Command Center (`/dashboard`), Readiness (`/dashboard/readiness`), Field Assessments (`/field-assessment`), Workforce Intel (`/dashboard/workforce`), Audit & Forensics (`/dashboard/forensics`), Clients (`/admin/tenants`), Keys (`/keys`), Settings (`/dashboard/settings`). These match pages confirmed to exist in `apps/console/app/`.

---

## Remediation Priority Table

| Priority | ID | Finding | Effort |
|---|---|---|---|
| P1 | COM-001 | Console landing "$299" flat price misrepresents tiered pricing for target market | S |
| P1 | SEC-002 | Console landing accessible without auth — wrong UX for operator domain | S |
| P1 | SEC-003 | BFF activate route missing CORE_API_KEY fail-closed guard | S |
| P1 | NAV-003 | Console CTA targets `/onboarding` (legacy flow) instead of `app.frostgate.ai/assessment` | S |
| P2 | COM-002 | No pricing page on marketing site — B2B buyers expect price before funnel entry | M |
| P2 | SEC-001 | Activation token in URL visible in CDN logs for 24h window | M |
| — | NAV-004 | Portal `/engagement` route confirmed present in filesystem | CLOSED |
| P2 | BRAND-001 | Web uses steel/rust tokens; portal/console use orange primary — domain-boundary visual discontinuity | L |
| P2 | BRAND-002 | Web uses Inter font; portal/console use system-UI | S |
| P3 | BRAND-003 | Web logo is PNG; console uses SVG component; portal uses text — no unified logo treatment | M |
