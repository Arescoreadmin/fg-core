# SOC Audit Stage 0 — Inventory + Threat Model

## Scope and method (evidence-first)
- Enumerated repository files and module surfaces with `find . -maxdepth 3 -type f` and `rg --files api jobs scripts .github tools tests`.
- Enumerated risky keywords with `rg -n "TODO|FIXME|allow|bypass|debug|insecure|fallback|dev|test only" ...`.
- Enumerated dangerous primitives/egress with `rg -n "requests\.|httpx|aiohttp|urllib|subprocess|eval\(|exec\(|yaml\.load|pickle|mktemp|os\.system" ...`.

## Repository surfaces
- **Core API service:** `api/` (FastAPI app, middleware, auth scopes, DB pathing, webhook/tripwire delivery).
- **Aux jobs:** `jobs/` (`sim_validator`, `merkle_anchor`, `chaos`).
- **Agent transport:** `agent/` (HTTP client, TLS pinning, transport policy).
- **CI/pipeline:** `.github/workflows/*.yml`, `.github/actions/*`.
- **Security/tooling:** `tools/ci/*.py`, `scripts/*.py`, `scripts/*.sh`.
- **Policy/contracts/schemas:** `policy/`, `contracts/`, `schemas/`, `migrations/`.

## Entrypoints
- API server startup: `api/main.py` (`build_app`, middleware assembly, route mounting).
- Auth gate middleware: `api/middleware/auth_gate.py`.
- CI entrypoints: `.github/workflows/ci.yml`, `.github/workflows/docker-ci.yml`.
- Release gate: `scripts/release_gate.py`.
- Job entrypoints: `jobs/*/job.py`.

## Network boundaries
- **Inbound HTTP:** FastAPI routes in `api/main.py` + routers in `api/*.py`.
- **Outbound webhooks/alerts:** `api/security_alerts.py` and `api/tripwires.py`.
- **Agent outbound calls:** `agent/core_client.py`, `agent/agent_main.py`.
- **State/data boundaries:** SQLite/Postgres via `api/db.py`, migration scripts, tenant context setters.

## Secrets surfaces
- Env-driven secrets/keys: `FG_API_KEY`, `FG_WEBHOOK_SECRET`, DB credentials in config and compose.
- Dev/prod toggles: `FG_ENV`, `FG_AUTH_DB_FAIL_OPEN`, `FG_DEV_AUTH_BYPASS`-style controls in tests/checkers.
- Compose/environment defaults in `docker-compose.yml` + generated `.env` patterns in `Makefile` targets.

## Spine controls and enforcement locations
- **AuthN/AuthZ:** `api/auth.py`, `api/auth_scopes/*`, `api/middleware/auth_gate.py`.
- **Tenant isolation:** `api/auth_scopes/resolution.py` (`bind_tenant_id`, tenant context application).
- **Startup invariants:** `api/config/startup_validation.py`, runtime checks in middleware.
- **Audit/forensics:** `api/forensics.py`, `api/evidence_chain.py`, `scripts/verify_audit_chain.py`.
- **Key handling/hashing:** `api/auth_scopes/helpers.py`, `api/auth_scopes/resolution.py` (hash upgrades, lookup hash).

---

## One-page threat model

### Assets
1. Tenant-scoped security events and decisions.
2. API keys (global and scoped), webhook secrets.
3. Audit/event integrity chain and governance artifacts.
4. CI/release trust path (contract generation, production gates).

### Attackers
- External attacker with API access and malformed inputs.
- Internal operator misconfiguration (unsafe env toggles, dev overrides in prod-like infra).
- Supply-chain attacker leveraging weak dependency constraints.
- CI bypass actor exploiting skipped or non-deterministic checks.

### Trust boundaries
1. Client -> API ingress boundary (headers, keys, tenant IDs).
2. API -> DB boundary (tenant context + policy constraints).
3. API -> outbound webhook boundary (potential SSRF/egress abuse).
4. Git commit -> CI -> release artifact boundary.

### Critical flows
1. Request auth and tenant binding.
2. Decision persistence and audit-chain emission.
3. Alert/tripwire outbound delivery.
4. Startup invariant enforcement for production-like envs.

### Top abuse cases
1. **Unsigned webhook acceptance** allows forged webhook events when secret absent.
2. **SSRF on alert/webhook endpoints** to internal network targets.
3. **Tenant confusion in non-prod default paths** (`unknown` tenant assignment) leaking test/dev data across boundaries.
4. **Auth bypass by route mismatch behavior** on unmatched routing paths.
5. **Pipeline weakening via optional/skip flags** causing release gate dilution.
