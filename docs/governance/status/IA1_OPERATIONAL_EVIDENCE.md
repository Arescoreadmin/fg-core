# IA-1 Operational Evidence

Status: G1-dev PASS · G1-prod PASS (2026-08-03) — G2-prod BLOCKED (AUTH0_MANAGEMENT_* not in prod Railway) · G2-dev BLOCKED (Auth0 dev tenant)

Gate sequence: G1-dev → G2-dev → G1-prod → G2-prod

Critical path:
1. ~~Create Railway dev environment~~ ✓ DONE
2. ~~Create restricted dev runtime role (fg_app)~~ ✓ DONE
3. ~~Run G1-dev~~ ✓ PASS
4. ~~Tighten dev isolation~~ ✓ DONE (2026-08-01)
5. ~~Merge PR #602 (credential separation)~~ ✓ MERGED (a3dc65b8)
6. ~~Merge PR #604 (assert_migrations_applied CREATE fix)~~ ✓ MERGED (06ee0038)
7. ~~Merge PR #605 (GRANT USAGE ON SCHEMA public to fg_app)~~ ✓ MERGED (cb053181)
8. ~~Merge PR #606 (RLS tenant context in credential write paths)~~ ✓ MERGED (b0f9a22a)
9. ~~Redeploy API-DEV from merged main — clean startup confirmed~~ ✓ DONE (2026-08-02)
10. ~~Merge PR #608 (audit RLS tenant context + brute-force tenant propagation)~~ ✓ MERGED (901c1c51)
11. Create Auth0 dev tenant (frostgate-dev) — MANUAL BLOCKER (G2-dev parallel track)
12. ~~Create restricted prod runtime role (fg_app)~~ ✓ DONE (2026-08-03)
13. ~~Run G1-prod~~ ✓ PASS (2026-08-03)
14. Rotate Auth0 M2M client secret → set AUTH0_MANAGEMENT_* in Railway prod → redeploy — MANUAL BLOCKER (G2-prod)
15. Run G2-prod
16. Run G2-dev (parallel — Auth0 dev tenant required)
17. IA-1 operationally complete → IA-2 deployment unlocked

Dev isolation status (2026-08-01):
- FG_JWT_SECRET, FG_ENCRYPTION_KEY, FG_KEY_PEPPER, FG_SIGNING_SECRET,
  FG_REPORT_SIGNING_KEY, FG_BILLING_EVIDENCE_HMAC_KEY, FG_ACKNOWLEDGMENT_KEY,
  FG_INTERNAL_AUTH_SECRET, FG_INTERNAL_GATEWAY_SECRET, FG_WEBHOOK_SECRET:
  replaced with dev-specific random values ✓
- FG_CORS_ORIGINS: restricted to dev origins ✓
- Stripe: already in test mode ✓
- Auth0 (FG_OIDC_ISSUER): PENDING DECISION — G2-dev will create Auth0 orgs
  in the shared production Auth0 tenant. Options:
  (a) Accept disposable test orgs + manual cleanup after G2-dev
  (b) Create a separate Auth0 dev tenant with its own Management API credentials

---

## G1-dev — Migration 0169, Dev Environment

**Status: PASS**

Infrastructure created this session:
- Railway dev environment provisioned (Postgres-dUxF, Redis-89wp, API-DEV services)
- `fg_app` restricted role created on dev Postgres
- `FG_DB_MIGRATION_URL` added to API-DEV (elevated postgres for DDL)
- `FG_DB_URL` set to fg_app (restricted runtime credential)
- Code change: `api/db.py` + `api/db_migrations.py` — added `FG_DB_MIGRATION_URL` support to decouple migration engine from runtime engine

| Field | Value |
|---|---|
| Environment | dev |
| Date/time (UTC) | 2026-08-01T16:13:40Z |
| Operator | jcosat |
| Railway deploy/run ID | 7c0daa93-36d6-4022-8742-ea2c9879f493 |
| Migration service exit status | 0 (169 migrations applied) |
| `SELECT version FROM schema_migrations WHERE version = '0169'` | **0169 — PASS** |
| `SELECT to_regclass('public.tenant_identity_bindings')` | **tenant_identity_bindings — PASS** |
| `SELECT to_regclass('public.tenant_identity_binding_events')` | **tenant_identity_binding_events — PASS** |
| `/health` HTTP status | **200 OK — PASS** |
| API runtime role (`current_user`) | **fg_app — PASS** |
| `rolsuper` | **false — PASS** |
| `rolbypassrls` | **false — PASS** |
| `rolcreatedb` | **false — PASS** |
| `rolcreaterole` | **false — PASS** |

**G1-dev result: PASS**

---

## G2-dev — E2E Proof, Dev Environment

**Status: PENDING — G1-dev complete, G2-dev not yet executed**

Disposable tenant: `fg-ia1-dev-validation-20260801`

| Field | Value |
|---|---|
| Environment | dev |
| Date/time (UTC) | |
| Operator | |
| Tenant ID | |
| Request ID | |
| `provisioning_state` | |
| `provider_org_id` | |
| `provider_org_name` | |
| Ownership metadata: `frostgate_tenant_id` matches tenant | |
| Audit event ID | |
| Audit event type | |
| Auth0 org count for this org name | |
| Retry: same `provider_org_id` returned | |
| Retry: no second `org_provisioning_started` event | |
| Retry: duplicate-org count in Auth0 | |
| Console UI binding state visible | (skip if not rendered) |

**G2-dev result: PENDING — execution required**

---

## G1-prod — Migration 0169 + Runtime Role Safety, Production Environment

**Status: PASS**

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | 2026-08-03 |
| Operator | jcosat |
| Railway deployment ID | 82c9eead-4506-4a1a-8bb5-ef3e541bd32d |
| Commit | 007dd437 |
| `SELECT MAX(version) FROM schema_migrations` | **0170 — PASS** |
| `SELECT to_regclass('public.tenant_identity_bindings')` | **tenant_identity_bindings — PASS** |
| `SELECT to_regclass('public.tenant_identity_binding_events')` | **tenant_identity_binding_events — PASS** |
| Application startup | **`INFO: Application startup complete.` — PASS** |
| API runtime role (`current_user` via fg_app connection) | **fg_app — PASS** |
| `rolsuper` | **false — PASS** |
| `rolbypassrls` | **false — PASS** |
| `rolcreatedb` | **false — PASS** |
| `rolcreaterole` | **false — PASS** |
| `rolreplication` | **false — PASS** |
| `SELECT COUNT(*) FROM schema_migrations` via fg_app | **PASS** |
| `SELECT COUNT(*) FROM tenants` via fg_app | **6 rows — PASS** |
| `SELECT COUNT(*) FROM tenant_credentials` via fg_app | **PASS** |
| Permission errors in logs post-startup | **None — PASS** |
| `FG_DB_URL` user | **fg_app** |
| `FG_DB_MIGRATION_URL` user | **postgres** |
| `FG_DB_URL` host | **postgres.railway.internal** |
| `FG_DB_MIGRATION_URL` host | **postgres.railway.internal** |

**G1-prod result: PASS**

**Actions taken (2026-08-03):**
1. `CREATE ROLE fg_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS LOGIN` in prod Postgres
2. `GRANT CONNECT ON DATABASE railway TO fg_app`
3. `GRANT USAGE ON SCHEMA public TO fg_app`
4. Pre-applied `_grant_runtime_role_access()` grants manually (see defect note below)
5. `FG_DB_URL` updated to `postgresql://fg_app@postgres.railway.internal:5432/railway`
6. `FG_DB_MIGRATION_URL` set to `postgresql://postgres@postgres.railway.internal:5432/railway`
7. Production API redeployed — `Application startup complete` confirmed

**Defect recorded:** `_grant_runtime_role_access()` did not complete before `auth_store` validation during the first startup attempt. Runtime credential check reached `api_keys` before grants were available, producing `auth_store_unreachable:OperationalError`. Manual pre-application of the 7 grant statements unblocked the crash loop. Classified as a startup ordering / initialization race (severity: medium). Acceptance criterion: no service capable of issuing queries may initialize before `_grant_runtime_role_access()` completes. To be tracked and fixed before next production deployment of the runtime role pattern.

---

## G2-prod — E2E Proof, Production Environment

**Status: BLOCKED — AUTH0_MANAGEMENT_* env vars not set in production Railway**

Blocker (2026-08-03): `AUTH0_MANAGEMENT_DOMAIN`, `AUTH0_MANAGEMENT_CLIENT_ID`,
`AUTH0_MANAGEMENT_CLIENT_SECRET`, `AUTH0_MANAGEMENT_AUDIENCE` are absent from the
production Railway environment. The implementation is correct (PR #608 verified);
this is a missing production prerequisite, not an implementation defect.

Pre-execution actions required:
1. Rotate M2M client secret in Auth0 production tenant (any prior secret treated as exposed)
2. Set all four `AUTH0_MANAGEMENT_*` variables in Railway production → api → Variables
3. Redeploy production API
4. Verify preflight: all four vars present, /health 200, no Auth0 config error in logs, fg_app role unchanged

Disposable tenant: `fg-ia1-prod-validation-20260803`

Note: `fg-ia1-prod-validation-20260803` was created 2026-08-03T17:52:38Z during the
blocked attempt. No identity binding was created. No Auth0 org was created. The tenant
row is valid and may be reused for the gate run.

| Field | Value |
|---|---|
| Environment | prod |
| Date/time (UTC) | |
| Operator | |
| Tenant ID | |
| Request ID (tenant creation) | |
| Request ID (identity-binding) | |
| `provisioning_state` | |
| `provider_org_id` | |
| `provider_org_name` | |
| Ownership metadata: `frostgate_tenant_id` matches tenant | |
| Audit event ID | |
| Audit event type | |
| Auth0 org count for this org name | |
| Retry: same `provider_org_id` returned | |
| Retry: no second `org_provisioning_started` event | |
| Retry: duplicate-org count in Auth0 | |
| Console UI binding state visible | (skip if not rendered) |

**G2-prod result: PENDING — Auth0 M2M configuration required before execution**

---

## Final Acceptance

_To be completed only after all four gates pass._

```
IA-1: OPERATIONALLY COMPLETE

Evidence:
- G1-dev PASS
- G2-dev PASS
- G1-prod PASS
- G2-prod PASS
- Migration 0169 verified in dev and prod
- One FrostGate tenant maps to one Auth0 Organization
- Retry proven idempotent
- Ownership metadata verified
- Audit trail verified
- Runtime DB role non-elevated

Next:
IA-2 unlocked
```

| Field | Value |
|---|---|
| Closed by | |
| Date/time (UTC) | |
