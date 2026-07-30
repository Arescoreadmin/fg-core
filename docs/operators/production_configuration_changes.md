# Production Configuration Changes — PRs #585–#587

**Effective:** 2026-07-29
**Applies to:** Railway `api` service (backend), Vercel `apps/console`, Vercel `apps/portal`

PRs #585 (Internal Platform Authority Bootstrap), #586 (Platform Service Principal), and #587 (Console Production Stabilization) introduced new required production configuration. This document is the single operator-facing checklist for what changed — see the individual `ROADMAP.md` entries for the full PR content.

## Required variables

**`CORE_TENANT_ID` does not take the same value on every service.** The backend and console anchor to the canonical internal platform authority tenant; the portal must anchor to the actual client tenant it serves. See the dedicated section below before setting this anywhere — getting it wrong on the portal fails client sessions, not the deployment.

| Variable | Required value | Where it's set | Enforced by |
|---|---|---|---|
| `CORE_TENANT_ID` (Railway `api`, Vercel `apps/console`) | `frostgate-internal` | Railway `api` service, Vercel `apps/console` | `api/internal_platform_authority.py` (backend, hard-fail); `apps/console/lib/startup-validation.ts` (console, hard-fail at startup) |
| `CORE_TENANT_ID` (Vercel `apps/portal`) | **The specific client tenant ID this portal deployment serves** — **not** `frostgate-internal`, **not** `default` | Vercel `apps/portal` | `apps/portal/app/api/core/[...path]/route.ts` (portal, fails per-request if unset — does not reject `default` specifically, but a wrong value silently 403s every legitimate client session — see below) |
| `CORE_API_URL` | `<production API URL>` (the Railway `api` service's public URL) | Vercel `apps/console`, Vercel `apps/portal` | `apps/console/lib/startup-validation.ts`; portal BFF proxy fails per-request if unset |
| `FG_INTERNAL_AUTH_SECRET` | `<matching internal secret>` — must be the **same value** across the Railway `api` service and Vercel `apps/console` | Railway `api` service, Vercel `apps/console` | `api/config/required_env.py` (backend, hard-fail); `apps/console/lib/internal-gateway-secret.ts` → `internalGatewaySecret()` (console, checks `FG_INTERNAL_GATEWAY_SECRET` / `FG_ADMIN_GATEWAY_TOKEN` / `FG_INTERNAL_AUTH_SECRET` / `FG_INTERNAL_TOKEN` in that order — `FG_INTERNAL_AUTH_SECRET` is the name actually set in Docker and CI environments today) |

Do not print or commit the actual secret values for `FG_INTERNAL_AUTH_SECRET` anywhere, including in this document.

## The portal's `CORE_TENANT_ID` must be the client tenant, never `frostgate-internal`

`frostgate-internal` is the internal platform authority tenant — FrostGate's own machine-identity anchor, used by the **backend** and **console** because those are FrostGate's internal operator surfaces. The **portal is client-facing**: portal sessions, memberships, and grants are created and stored under the specific client's own tenant (`tenant_users`, `portal_grants`, etc., all scoped by `tenant_id`).

`apps/portal/app/api/core/[...path]/route.ts` → `resolveAuth()` forwards `CORE_TENANT_ID` as `X-Tenant-ID` on every backend request in production (demo-tenant steering via env allowlist or Edge Config is disabled outside dev/test — see `isProdLikeEnv()` in that file). The backend's `PortalClientScopeMiddleware` (`api/middleware/portal_scope.py`) then validates the portal session's membership **against that exact `tenant_id`**. If `CORE_TENANT_ID` is set to `frostgate-internal` (or any tenant other than the one the client's memberships actually belong to), every legitimate client session fails validation with `403` (`MEMBERSHIP_NOT_BOUND` or equivalent) — the deployment itself stays up, but no client can use the portal.

Set the portal's `CORE_TENANT_ID` to the tenant ID the console's tenant-provisioning flow created for that specific client engagement — the comment in `resolveAuth()` calls this "the console-provisioned default tenant" for the deployment. If you don't know the value, check the console's tenant record for the engagement rather than guessing or reusing another deployment's value.

## `CORE_TENANT_ID=default` is invalid in production

`default` was the legacy placeholder value used before PR #585 established `frostgate-internal` as the canonical internal platform authority tenant. It is **no longer valid** in production or strict mode:

- **Backend (`api` service):** `api/internal_platform_authority.py` → `validate_configured_core_tenant_id()` raises `InternalPlatformAuthorityError` (`CORE_TENANT_ID_INVALID` or `CORE_TENANT_ID_MISSING`) during FastAPI startup. This is a **hard failure that crashes the container** — the process will not start and Railway will crash-loop the deployment until the variable is corrected.
- **Console:** `apps/console/lib/startup-validation.ts` → `validateProductionConfig()` throws during the Next.js `instrumentation.ts` startup hook, before any request is served, if `CORE_TENANT_ID` is missing, `default`, or fails the tenant-ID format check.
- **Portal:** the BFF proxy (`apps/portal/app/api/core/[...path]/route.ts`) only checks that `CORE_TENANT_ID` is *present* — it does not reject `default` specifically. A stale `default` value here fails differently and later: individual field-assessment requests will fail (a nonexistent/invalid tenant lookup) rather than the app failing to start.

If the backend `api` service crash-loops after a deploy touching PRs #585–#587, check `CORE_TENANT_ID` first:

```
railway variable set CORE_TENANT_ID=frostgate-internal --service api
```

Setting a variable via `railway variable set` triggers an automatic redeploy.

## Related documents

- [`onboarding_runbook.md`](onboarding_runbook.md) — first-client setup checklist and troubleshooting table
- [`first_client_prep.md`](first_client_prep.md) — pre-engagement Railway/Vercel env var checklist
- [`../INFRASTRUCTURE_SETUP.md`](../INFRASTRUCTURE_SETUP.md) — full environment variable reference for console, portal, and backend
