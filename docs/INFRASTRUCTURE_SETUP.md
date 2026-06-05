# FrostGate — Infrastructure Setup & Vendor Configuration

**Owner:** Jason Cosat  
**Last updated:** 2026-05-29  
**Scope:** Production deployment as of PR 34. Documents every vendor, service, and configuration required to run `console.frostgate.ai` and the FrostGate backend API end-to-end.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Vendor Inventory](#2-vendor-inventory)
3. [Vercel — Console Frontend](#3-vercel--console-frontend)
4. [Railway — Python Backend API](#4-railway--python-backend-api)
5. [Railway — Managed PostgreSQL](#5-railway--managed-postgresql)
6. [Railway — Managed Redis](#6-railway--managed-redis)
7. [Auth0 — Authentication](#7-auth0--authentication)
8. [GitHub — Source Control & CI/CD Trigger](#8-github--source-control--cicd-trigger)
9. [Anthropic — AI Report Generation](#9-anthropic--ai-report-generation)
10. [How a Login Request Flows End-to-End](#10-how-a-login-request-flows-end-to-end)
11. [How an API Request Flows End-to-End](#11-how-an-api-request-flows-end-to-end)
12. [Environment Variable Reference](#12-environment-variable-reference)
13. [Key Files by Concern](#13-key-files-by-concern)

---

## 1. Architecture Overview

```
Browser
  │
  │  HTTPS — console.frostgate.ai
  ▼
┌────────────────────────────────────────────────┐
│  Vercel (Next.js 14 App Router)                 │
│  apps/console/                                  │
│                                                 │
│  Auth:  next-auth v5 + Auth0 OIDC               │
│  BFF:   /api/core/[...path]/route.ts            │
│         — injects X-API-Key + X-Tenant-ID       │
│         — enforces proxy allowlist              │
└────────────────┬───────────────────────────────┘
                 │
                 │  HTTPS — api-production-6d47.up.railway.app
                 │  Headers: X-API-Key, X-Tenant-ID, X-Request-ID
                 ▼
┌────────────────────────────────────────────────┐
│  Railway — FastAPI (Python 3.12)                │
│  api/main.py                                    │
│                                                 │
│  Auth gate: api/middleware/auth_gate.py         │
│  Field assessment: api/field_assessment.py      │
│  AI reports: api/reports_engine.py              │
│  Decision engine: engine/evaluate.py            │
│  OPA policy: policy/rego/                       │
└──────┬──────────────────────┬──────────────────┘
       │                      │
       ▼                      ▼
┌─────────────┐     ┌─────────────────────┐
│  Railway    │     │  Railway            │
│  PostgreSQL │     │  Redis              │
│  (managed)  │     │  (managed)          │
│  72 migs    │     │  rate limiting,     │
│  applied    │     │  session cache      │
└─────────────┘     └─────────────────────┘
```

---

## 2. Vendor Inventory

| Vendor | Role | Plan | URL/Region |
|--------|------|------|------------|
| **Vercel** | Console frontend hosting | Hobby (upgradeable) | `console.frostgate.ai` — iad1 region |
| **Railway** | Python API hosting | Hobby | `api-production-6d47.up.railway.app` |
| **Railway** | Managed PostgreSQL | Hobby add-on | `zephyr.proxy.rlwy.net:26619` (public proxy) |
| **Railway** | Managed Redis | Hobby add-on | Internal `redis.railway.internal` |
| **Auth0** | OIDC identity provider | Free tier | `dev-22nn3c7muqjk4tgu.us.auth0.com` |
| **GitHub** | Source control + deploy trigger | Free | `github.com/Arescoreadmin/fg-core` |
| **Anthropic** | AI model (report generation) | API pay-as-you-go | `api.anthropic.com` |

---

## 3. Vercel — Console Frontend

### What it hosts
The operator-facing Next.js 14 application (`apps/console/`). This is the dashboard, field assessment console, governance UI, and all admin surfaces.

### Project settings
- **Framework:** Next.js (auto-detected)
- **Root directory:** `apps/console`
- **Build command:** `next build` (default)
- **Node.js version:** 22 LTS
- **Production domain:** `console.frostgate.ai`
- **Git repository:** `Arescoreadmin/fg-core` — deploys on push to `main`

### How deployments work
Every `git push origin main` triggers an automatic Vercel build. Vercel detects the monorepo root (`apps/console`) from `.vercel/project.json`. No manual deploy step is needed.

### Authentication layer (`apps/console/`)

Auth is handled by **next-auth v5 beta.31** with the Auth0 OIDC provider.

Two config files are required because Auth0's OIDC provider uses Node.js crypto APIs which are not compatible with Vercel's Edge runtime (where middleware runs):

**`auth.config.ts`** — Edge-safe, used by middleware only:
```typescript
// Empty providers array — OIDC providers cannot run in Edge runtime
export const authConfig = {
  providers: [],
  pages: { signIn: '/login' },
} satisfies NextAuthConfig;
```

**`auth.ts`** — Full server-side config with Auth0 provider:
```typescript
export const { handlers, auth, signIn, signOut } = NextAuth({
  providers: [
    Auth0({
      clientId: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      issuer: process.env.AUTH0_ISSUER_BASE_URL,
    }),
  ],
  pages: { signIn: '/login' },
});
```

**`middleware.ts`** — Protects all routes except `/login` and `/api/auth/*`:
```typescript
const { auth } = NextAuth(authConfig);  // Uses Edge-safe config

export default auth(function middleware(req) {
  const isAuthenticated = !!(req as { auth?: unknown }).auth;
  const { pathname } = req.nextUrl;

  if (pathname.startsWith('/api/auth') || pathname === '/login')
    return NextResponse.next();  // Always allow login page

  if (!isAuthenticated) {
    const loginUrl = new URL('/login', req.url);
    loginUrl.searchParams.set('callbackUrl', req.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
});
```

### BFF Proxy (`apps/console/app/api/core/[...path]/route.ts`)

The console never calls the backend API directly from the browser. Every API call goes through the BFF (Backend For Frontend) proxy which runs server-side on Vercel and:

1. Validates the requested path against an allowlist (`PROXY_RULES`)
2. Injects `X-API-Key: <CORE_API_KEY>` for the default tenant, or an allowlisted demo tenant key from `FG_CONSOLE_DEMO_TENANT_KEYS` / `FG_DEMO_TENANT_API_KEYS`
3. Injects `X-Tenant-ID: <CORE_TENANT_ID>` by default, or a tenant ID from `FG_CONSOLE_DEMO_TENANTS` when explicitly selected
4. Enforces rate limiting (in-memory store in dev; Redis protocol or Upstash REST in prod)
5. Forwards the request to `CORE_API_URL` (Railway backend)

This means the API key never touches the browser — it lives only in Vercel environment variables, server-side.

### Required Vercel environment variables

| Variable | Value | Description |
|----------|-------|-------------|
| `CORE_API_URL` | `https://api-production-6d47.up.railway.app` | Backend base URL |
| `CORE_API_KEY` | `<governance key>` | API key injected into every backend request |
| `CORE_TENANT_ID` | `default` | Default tenant context injected into backend requests |
| `FG_CONSOLE_DEMO_TENANTS` | optional | Comma-separated allowlist for demo tenant query selection |
| `FG_CONSOLE_DEMO_TENANT_KEYS` or `FG_DEMO_TENANT_API_KEYS` | optional | JSON map of allowlisted demo tenant IDs to tenant-bound API keys |
| `AUTH0_CLIENT_ID` | `JPIiVXP8fKKSYblWegdN7BrnzwboWVUS` | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | `<secret>` | Auth0 application client secret |
| `AUTH0_ISSUER_BASE_URL` | `https://dev-22nn3c7muqjk4tgu.us.auth0.com` | Auth0 domain |
| `AUTH_SECRET` | `<random 32+ char string>` | next-auth session signing secret (generate with `openssl rand -base64 32`) |
| `NEXTAUTH_URL` | `https://console.frostgate.ai` | Must match the production domain |

---

## 4. Railway — Python Backend API

### What it hosts
The FastAPI backend (`api/`, `services/`, `engine/`). This is the auth gate, field assessment engine, AI report generation, decision engine, OPA policy evaluation, and all governance APIs.

### Deployment setup
- **Service type:** Docker (Railway builds from `Dockerfile` in repo root)
- **Repository:** `Arescoreadmin/fg-core` — auto-deploys on push to `main`
- **Public URL:** `https://api-production-6d47.up.railway.app`
- **Internal port:** `8080` (set via `PORT` env var)

### How the Docker build works
Railway detects the `Dockerfile` at the repo root, builds the Python image, and runs the API via Uvicorn. Migrations run automatically on startup when `FG_DB_MIGRATIONS_REQUIRED=1`.

### Database URL normalization
Railway provides Postgres connection strings in the format `postgresql://...`. The psycopg3 driver requires `postgresql+psycopg://...`. This is handled automatically in `api/db.py`:

```python
# Normalizes Railway's bare URL to psycopg3 format
if db_url.startswith("postgresql://"):
    db_url = "postgresql+psycopg://" + db_url[len("postgresql://"):]
```

### Auth gate logic (`api/middleware/auth_gate.py`)

Every non-public request must carry an `X-API-Key` header. The gate:

1. Extracts the key from the header
2. Calls `verify_api_key_detailed()` — checks the key against the `api_keys` Postgres table
3. For global key bypass (`FG_ENV=development`): allows any request carrying `FG_API_KEY`
4. Sets `request.state.tenant_id` from the key's bound tenant — OR from the `X-Tenant-ID` header when the key has no bound tenant (global key fallback, added 2026-05-29)
5. Enforces scope requirements per route prefix

### Required Railway environment variables

| Variable | Value | Description |
|----------|-------|-------------|
| `FG_ENV` | `development` | Enables global key bypass, disables prod invariants |
| `FG_API_KEY` | `<governance key>` | Global API key; matches `CORE_API_KEY` in Vercel |
| `FG_DB_URL` | `postgresql://postgres:...@zephyr.proxy.rlwy.net:26619/railway` | Public Postgres proxy URL |
| `FG_DB_MIGRATIONS_REQUIRED` | `0` | Skip migration check on startup (migrations already applied) |
| `FG_ANTHROPIC_API_KEY` | `sk-ant-...` | Anthropic API key for report generation |
| `FG_AI_PLANE_ENABLED` | `1` | Enable AI services |
| `FG_AI_DEFAULT_PROVIDER` | `anthropic` | Default AI provider |
| `FG_REDIS_URL` | `redis://...` | Railway Redis internal URL |
| `PORT` | `8080` | Port Uvicorn binds to |

---

## 5. Railway — Managed PostgreSQL

### What it stores
All persistent application state: API keys, tenants, field assessment engagements, findings, evidence, questionnaire responses, reports, audit ledger, governance assets, workforce data, and all 72 applied migrations.

### Setup
Added as a Railway add-on to the same project as the Python API service. Railway automatically injects `DATABASE_URL` into the service; this is mapped to `FG_DB_URL`.

### Connection details
- **Internal (from Railway service):** `postgres.railway.internal:5432/railway`
- **Public proxy (for external access/migrations):** `zephyr.proxy.rlwy.net:26619/railway`
- **Database:** `railway`
- **User:** `postgres`

> The internal URL is only reachable from within the Railway project. Use the public proxy URL for `FG_DB_URL` to ensure the API can reach the database regardless of how Railway resolves internal hostnames.

### Migration state
72 migrations (0001–0072) have been applied. The migration files live in `migrations/postgres/`. They are applied in numeric order on startup when `FG_DB_MIGRATIONS_REQUIRED=1`.

### Key tables

| Table | Purpose |
|-------|---------|
| `api_keys` | API key store — hashed keys, tenant binding, scopes |
| `fa_engagements` | Field assessment engagement sessions |
| `fa_findings` | Assessment findings per engagement |
| `fa_evidence_links` | Evidence artifacts attached to findings |
| `fa_field_observations` | Field observations (manual + scan-derived) |
| `fa_questionnaires` | NIST AI RMF questionnaire responses |
| `audit_ledger_record` | HMAC-chained append-only audit log |
| `decisions` | Policy decision records |
| `tenant_users` | Per-tenant user registry (workforce intelligence) |
| `ai_query_log` | AI query attribution log |

---

## 6. Railway — Managed Redis

### What it stores
Rate limiting counters (BFF proxy), session cache, and explanation cache (finding explainer LRU).

### Setup
Added as a Railway add-on to the same project. Railway injects `REDIS_URL` automatically; this is mapped to `FG_REDIS_URL` in the API service.

### Note on current state
The console BFF uses an in-memory rate limit store in development mode. In production-like Vercel environments it requires either Redis protocol config (`BFF_REDIS_URL` or `REDIS_URL`) or Upstash/Vercel KV REST config (`UPSTASH_REDIS_REST_URL` plus `UPSTASH_REDIS_REST_TOKEN`, or `KV_REST_API_URL` plus `KV_REST_API_TOKEN`). The Python backend uses Redis for rate limiting and caching when `FG_REDIS_URL` is set.

---

## 7. Auth0 — Authentication

### What it does
Auth0 acts as the OIDC (OpenID Connect) identity provider for the console. When a user navigates to `console.frostgate.ai` without a session, they are redirected to the Auth0 Universal Login page. After successful login, Auth0 redirects back to Vercel with an authorization code that next-auth exchanges for a session.

### Account details
- **Tenant domain:** `dev-22nn3c7muqjk4tgu.us.auth0.com`
- **Plan:** Free
- **Application type:** Regular Web Application (required — not SPA, not Machine-to-Machine)
- **Client ID:** `JPIiVXP8fKKSYblWegdN7BrnzwboWVUS`

### Required Auth0 application settings

Navigate to **Auth0 Dashboard → Applications → FrostGate Console → Settings**:

| Setting | Value |
|---------|-------|
| Application Type | Regular Web Application |
| Allowed Callback URLs | `https://console.frostgate.ai/api/auth/callback/auth0` |
| Allowed Logout URLs | `https://console.frostgate.ai` |
| Allowed Web Origins | `https://console.frostgate.ai` |

> For local development also add: `http://localhost:3000/api/auth/callback/auth0`, `http://localhost:3000`

### Creating users
Auth0 Free uses the **Username-Password-Authentication** database connection by default. Users must be manually created in **Auth0 Dashboard → User Management → Users → Create User**. Social logins (Google, etc.) can be enabled later as connections on the application.

### How next-auth v5 reads Auth0 credentials
next-auth v5 changed its env var convention from `AUTH0_CLIENT_ID` to `AUTH_AUTH0_ID`. To avoid confusion, credentials are passed explicitly in `auth.ts`:

```typescript
Auth0({
  clientId: process.env.AUTH0_CLIENT_ID,     // explicitly passed
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  issuer: process.env.AUTH0_ISSUER_BASE_URL,
})
```

The env vars `AUTH0_CLIENT_ID`, `AUTH0_CLIENT_SECRET`, and `AUTH0_ISSUER_BASE_URL` must be set in Vercel (not in any local `.env` committed to the repo).

---

## 8. GitHub — Source Control & CI/CD Trigger

### Repository
`github.com/Arescoreadmin/fg-core` (private)

### Deployment triggers
Both Vercel and Railway watch the `main` branch. A `git push origin main` simultaneously triggers:
1. A Vercel build for the console frontend
2. A Railway build for the Python backend

There is no separate CI/CD pipeline file required — both platforms poll GitHub directly.

### Branch strategy
All work happens on feature branches and merges to `main` via PRs. The `main` branch is what is deployed to production.

---

## 9. Anthropic — AI Report Generation

### What it does
The FrostGate report engine calls the Anthropic API to generate:
- Field assessment executive summaries (in-report narrative sections)
- AI advisory reports (executive, technical, compliance variants)
- Finding plain-language explanations (finding explainer service)

### Configuration
- **API key env var:** `FG_ANTHROPIC_API_KEY` (set in Railway, never committed to repo)
- **Default model:** `claude-haiku-4-5-20251001` (fast, lower cost)
- **Report generation model:** `claude-sonnet-4-20250514` (recommended for quality reports)
- **Call boundary:** All model calls go through `services/ai/dispatch.py → call_provider("anthropic", ...)`

### Usage
The Anthropic API is called from the Railway backend. The Vercel frontend never calls Anthropic directly.

---

## 10. How a Login Request Flows End-to-End

```
1. User navigates to https://console.frostgate.ai/field-assessment/engagements

2. Vercel middleware.ts runs (Edge runtime)
   - Uses NextAuth(authConfig) — empty providers, Edge-safe
   - No session cookie found → redirect to /login

3. User arrives at /login page
   - Clicks "Sign in with Auth0" (or is auto-redirected)

4. next-auth initiates OIDC flow
   - Redirects browser to Auth0 Universal Login:
     https://dev-22nn3c7muqjk4tgu.us.auth0.com/authorize?...

5. User enters credentials on Auth0's login page

6. Auth0 redirects back to Vercel:
   https://console.frostgate.ai/api/auth/callback/auth0?code=...

7. next-auth /api/auth route handler (Node.js runtime, uses full auth.ts config)
   - Exchanges authorization code for tokens with Auth0
   - Creates encrypted session cookie
   - Redirects to original callbackUrl

8. User arrives at /field-assessment/engagements with valid session
```

---

## 11. How an API Request Flows End-to-End

```
1. Console page component calls fieldAssessmentApi.listEngagements()
   (apps/console/lib/fieldAssessmentApi.ts)

2. fetch() hits /api/core/field-assessment/engagements
   (runs server-side in Vercel Node.js runtime)

3. BFF proxy route.ts runs:
   - Checks path against PROXY_RULES allowlist ✓
   - Applies rate limiting
   - Builds request to Railway:
     URL:     https://api-production-6d47.up.railway.app/field-assessment/engagements
     Headers: X-API-Key: <CORE_API_KEY>
              X-Tenant-ID: default
              X-Request-ID: <uuid>

4. Railway FastAPI receives request

5. AuthGateMiddleware.dispatch() runs:
   - Extracts X-API-Key from header
   - Calls verify_api_key_detailed()
     → FG_ENV=development + key matches FG_API_KEY → global_key bypass
   - result.tenant_id = None (global key, not bound to a tenant)
   - Falls back to X-Tenant-ID header: "default"
   - Sets request.state.tenant_id = "default"

6. field_assessment.list_engagements() runs:
   - Uses request.state.tenant_id = "default" for DB query
   - Returns engagements for tenant "default"

7. Response flows back: Railway → Vercel BFF → Browser
```

---

## 12. Environment Variable Reference

### Vercel (`apps/console/`) — full list

| Variable | Required | Description |
|----------|----------|-------------|
| `CORE_API_URL` | Yes | Railway backend URL |
| `CORE_API_KEY` | Yes | API key injected into every backend request |
| `CORE_TENANT_ID` | Yes | Default tenant ID injected into backend requests |
| `FG_CONSOLE_DEMO_TENANTS` | No | Comma-separated allowlist for console demo tenant selection |
| `FG_CONSOLE_DEMO_TENANT_KEYS` or `FG_DEMO_TENANT_API_KEYS` | No | JSON map of demo tenant IDs to tenant-bound API keys |
| `AUTH0_CLIENT_ID` | Yes | Auth0 application client ID |
| `AUTH0_CLIENT_SECRET` | Yes | Auth0 application client secret |
| `AUTH0_ISSUER_BASE_URL` | Yes | Auth0 tenant URL (e.g. `https://dev-22nn3c7muqjk4tgu.us.auth0.com`) |
| `AUTH_SECRET` | Yes | Session signing key — generate: `openssl rand -base64 32` |
| `AUTH_SESSION_MAX_AGE_SECONDS` | No | Local console session lifetime, default 28800 seconds / 8 hours |
| `AUTH_SESSION_UPDATE_AGE_SECONDS` | No | Session refresh cadence, default 900 seconds / 15 minutes |
| `NEXTAUTH_URL` | Yes | Must be `https://console.frostgate.ai` in production |
| `BFF_REDIS_URL` or `REDIS_URL` | Prod only* | Redis protocol URL for BFF rate limiting |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | Prod only* | Upstash REST rate-limit store for Vercel/serverless |
| `KV_REST_API_URL` + `KV_REST_API_TOKEN` | Prod only* | Vercel KV/Upstash REST alias for rate limiting |
| `BFF_RATE_LIMIT_WINDOW_S` | No | Rate limit window (default: 60) |
| `BFF_RATE_LIMIT_MAX_REQUESTS` | No | Max requests per window (default: 100) |

*One production rate-limit store is required: Redis protocol, Upstash REST, or Vercel KV REST.

### Vercel (`apps/portal/`) — demo tenant variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CORE_API_URL` | Yes | Railway backend URL |
| `CORE_API_KEY` | Yes | Default portal API key |
| `CORE_TENANT_ID` | Yes | Default portal tenant |
| `PORTAL_SESSION_SECRET` | Yes | HMAC secret for signed portal session cookies |
| `FG_PORTAL_DEMO_TENANTS` | No | Comma-separated allowlist for portal demo tenant selection |
| `FG_PORTAL_DEMO_TENANT_KEYS` or `FG_DEMO_TENANT_API_KEYS` | No | JSON map of demo tenant IDs to tenant-bound API keys |
| `NEXT_PUBLIC_PORTAL_DEMO_TENANTS` | No | Public tenant ID list rendered in the login selector; contains no secrets |

### Railway API service — full list

| Variable | Required | Description |
|----------|----------|-------------|
| `FG_ENV` | Yes | `development` — enables global key bypass |
| `FG_API_KEY` | Yes | Global API key — must match `CORE_API_KEY` in Vercel |
| `FG_DB_URL` | Yes | PostgreSQL connection string (public proxy URL) |
| `FG_DB_MIGRATIONS_REQUIRED` | Yes | `0` — migrations already applied; set `1` to re-run |
| `FG_ANTHROPIC_API_KEY` | Yes | Anthropic API key |
| `FG_AI_PLANE_ENABLED` | Yes | `1` — enables AI services |
| `FG_AI_DEFAULT_PROVIDER` | Yes | `anthropic` |
| `FG_REDIS_URL` | Recommended | Railway Redis internal URL for caching |
| `PORT` | Yes | `8080` — Uvicorn bind port |
| `FG_REPORT_VERIFY_URL` | No | Override for report verification URL in MS Graph reports |
| `FG_MSAL_CLIENT_ID` | MS Graph only | Azure AD app client ID for MS Graph scans |
| `FG_MSAL_TENANT_ID` | MS Graph only | Azure AD tenant ID |

---

## 13. Key Files by Concern

| Concern | File |
|---------|------|
| Console auth config (Edge-safe) | `apps/console/auth.config.ts` |
| Console auth config (full, with Auth0) | `apps/console/auth.ts` |
| Console route protection middleware | `apps/console/middleware.ts` |
| BFF proxy (injects key + tenant, allowlist) | `apps/console/app/api/core/[...path]/route.ts` |
| Backend auth gate (key verification, tenant) | `api/middleware/auth_gate.py` |
| API key verification logic | `api/auth_scopes/resolution.py` |
| Database URL normalization (psycopg3) | `api/db.py` |
| Field assessment endpoints | `api/field_assessment.py` |
| AI report generation | `api/reports_engine.py` |
| Finding plain-language explanations | `services/field_assessment/finding_explainer.py` |
| MS Graph connector (MSAL, NIST checks) | `services/connectors/msgraph/` |
| AI dispatch (Anthropic call boundary) | `services/ai/dispatch.py` |
| Migration files | `migrations/postgres/0001–0072` |
| Docker build (Railway) | `Dockerfile` |
| Local infrastructure (dev only) | `docker-compose.yml` |
| All env vars documented | `.env.example` |

---

*FrostGate — AI Governance for Regulated Industries*  
*Deltona, Florida*
