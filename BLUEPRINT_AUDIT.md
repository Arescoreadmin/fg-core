# Blueprint Audit Report

## Executive Summary
- **Overall Status:** PASS (with documented tripwires and follow-ups)
- **Confidence Score:** 90

This audit covers Stage 0/1/2, key lifecycle, and the new Audit Search/Export feature across core, admin-gateway, and console. The primary gaps are noted as tripwires (e.g., legacy fallbacks and test-only placeholder secrets). Audit search/export is now enforced with tenant scoping, and exports redact sensitive fields.

---

## Stage 0 Checklist
- **Services exist:** core, admin-gateway, console, postgres, redis, agent profiles, and healthchecks are wired in `docker-compose.yml`.  
- **Compose wiring:** core depends on postgres + redis; admin-gateway depends on core; console depends on admin-gateway.  
- **Makefile targets:** CI lanes and contract targets defined (`fg-fast`, `ci`, `ci-admin`, `ci-console`, etc.).  
- **Contracts generation:** `make contracts-gen` + `make fg-contract` clean after updates.  
- **Healthchecks:** redis, postgres, core, admin-gateway, and console healthchecks present.

## Stage 1 Checklist
- **OIDC config:** OIDC environment keys and validation logic present (dev bypass blocked in prod).  
- **Session cookie security:** HttpOnly + Secure (prod) + SameSite=Strict cookies.  
- **CSRF protection:** double-submit cookie pattern enforced for state-changing methods.  
- **RBAC scopes:** scope definitions in admin-gateway and enforcement in routers.  
- **Tenant enforcement:** admin-gateway validates tenant access for product + admin endpoints; write paths require explicit tenant.  
- **Audit middleware:** request-level audit middleware logs admin-gateway requests; audit logger redacts sensitive fields.

## Stage 2 Checklist
- **Postgres wiring:** postgres service, FG_DB_URL, and healthchecks are configured in compose.  
- **Migrations:** admin-gateway has Alembic migrations for product tables.  
- **Products CRUD + connection test:** admin-gateway product router supports CRUD and test connection; console includes products list/detail/new views.  
- **RBAC/tenant enforcement + negative tests:** admin-gateway tests cover tenant access; product write paths require explicit tenant header.

## Key Lifecycle Checklist (core + gateway + console)
- **Expiry enforced:** auth layer checks token expiration and DB expiration.  
- **Usage tracking:** `last_used_at` and `use_count` updated atomically on successful auth.  
- **Rotate/revoke behavior:** API routes for rotate/revoke with audit logging.  
- **Tenant scoping:** API key endpoints require tenant_id for writes in admin-gateway and core; console requires tenant input for key + product writes.  
- **Audit on success/fail:** key create/revoke/rotate events are audited in core; auth failures/successes logged.  
- **Proxy redaction:** audit search/export redacts sensitive fields; admin-gateway audit logger redacts before logging/forwarding.

## Audit Search + Export Feature (New)
- **Core API:** `/admin/audit` search and `/admin/audit/export` implemented with tenant scoping and redaction.  
- **Admin Gateway:** `/admin/audit` and `/admin/audit/export` proxy to core with tenant access validation.  
- **Console:** New Audit Search UI with filtering and CSV/JSONL export actions.

## Drift Checks
- **Makefile vs workflows:** workflows call Makefile lanes; workflows now use secrets for FG_API_KEY rather than defaults.  
- **Release workflow uses Makefile:** (manual verification required—release workflow uses Makefile targets where applicable).  
- **Contracts present:** admin OpenAPI contracts updated for new audit endpoints.

## Repo-Wide Static Checks (Audit Findings)
1. **Placeholder secrets:** No default secrets remain in Makefile, `.env.example`, workflows, or docker-compose. Tests and scripts require explicit FG_API_KEY values.  
2. **Query-param API keys:** No production code accepts API keys via query parameters; only headers/cookies are used.  
3. **Tenant defaulting:** Write/export endpoints require explicit tenant scoping in admin-gateway and core.  
4. **Core bypass risk:** admin-gateway enforces tenant access before proxying to core for tenant-specific endpoints.  
5. **Header logging:** No direct logging of sensitive headers found; audit responses redact sensitive fields.

## Tripwires (Risky Patterns to Monitor)
- **Fallback auth in compose:** `FG_AUTH_ALLOW_FALLBACK` defaults to true in docker-compose for MVP environments; should be disabled for production hardening.  
- **Test placeholders:** Ensure test fixtures do not reintroduce default secrets.  
- **Audit forwarder:** admin-gateway audit forwarder is disabled by default; if enabled, ensure core endpoint and scopes are aligned.

---

## Follow-ups Recommended
1. Add explicit core audit ingestion endpoint if admin-gateway forwarding is enabled in production.
2. Consider a UI tenant selector shared across products/keys/audit to prevent UX mistakes.
3. Review release workflow for Makefile enforcement (if release pipeline changes).
