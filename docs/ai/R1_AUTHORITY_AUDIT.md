# R1: Authority and Persistence Audit

**Date**: 2026-07-17
**Scope**: Tenant creation, credential management, API key lifecycle, internal gateway tokens, persistence locations
**Status**: Complete — input to R7, R3, R4, R6

---

## Critical Finding: Tenant Identity Lives on Filesystem, Not Postgres

There is no `tenants` table in Postgres. Tenant identity is stored in `state/tenants.json` via `tools/tenants/registry.py` with a threading lock. `api_keys.tenant_id` is a string column, not a foreign key to any tenant table. This makes R7 larger than anticipated — it must create a `tenants` Postgres table from scratch and migrate the JSON file.

---

## 1. Tenant Creation Paths

| File | Function | Route | HTTP Method | Persistence Targets | Auth Required |
|------|----------|-------|-------------|---------------------|---------------|
| `api/admin.py` | `create_tenant()` | `/admin/tenants` | POST | `tools/tenants/registry.py` → `state/tenants.json` | Yes: `admin:write` + `require_internal_admin_gateway` |
| `apps/console/app/api/admin/provision-tenant/route.ts` | `POST()` | `/api/admin/provision-tenant` | POST | 1. Core API `/admin/tenants`; 2. Core API `/admin/keys`; 3. Redis/Upstash `portal:tenant:{id}:key`; 4. Edge Config (metadata only) | Yes: NextJS `auth()` + `canAccessConsoleRoute()` |

### Notes
- Console BFF is a multi-step orchestrator, not an authority. It calls Core API for the tenant record and key, then writes the portal key to Redis/Upstash independently.
- `state/tenants.json` contains plaintext `api_key` values. If the file is readable beyond the API process, all tenant keys are exposed.
- No foreign-key or uniqueness constraint links `api_keys.tenant_id` to any verified tenant record.

---

## 2. Credential Paths

### A. API Key Operations

| Operation | File | Function | Route | Storage | Notes |
|-----------|------|----------|-------|---------|-------|
| Create (user) | `api/keys.py` | `create_key()` | `POST /keys` | Postgres or SQLite `api_keys` | Via `mint_key()` → `insert_key_row()` |
| Create (admin) | `api/admin.py` | `admin_create_key()` | `POST /admin/keys` | Same | Via `mint_key()` → `insert_api_key()` |
| Create (BFF) | `provision-tenant/route.ts` | `POST()` | Indirect via Core API | Same | HTTP call to `/admin/keys` with admin headers |
| List | `api/keys.py` | `get_keys()` | `GET /keys` | Reads Postgres/SQLite | Filters by bound tenant |
| Revoke | `api/keys.py` | `revoke_key()` | `POST /keys/revoke` or `DELETE /keys/{prefix}` | Updates `enabled=0` | Via `revoke_api_key()` |
| Revoke (admin) | `api/admin.py` | `admin_revoke_key()` | `POST /admin/keys/{prefix}/revoke` | Same | Tenant-scoped |
| Rotate | `api/keys.py` | `rotate_key()` | `POST /keys/rotate` | Creates new row, marks old revoked | |
| Rotate (mgmt) | `api/key_rotation.py` | `KeyRotationManager.rotate_key()` | Internal | Same | Independent implementation |

### B. api/credentials.py — DEAD CODE

**Finding: `api/credentials.py` is not reachable from any production route.**

- Only imported by: `tests/security/test_credentials.py`, `tests/test_usage_attribution.py`
- Functions `create_credential`, `validate_credential`, `rotate_credential`, `revoke_credential` are never called outside tests
- Safe to remove in R4 with no migration needed

### C. Key Storage and Hash Paths

| Path | File | Input | Hash | Storage |
|------|------|-------|------|---------|
| Auth-scoped write | `api/auth_scopes/store.py::insert_key_row()` | Pre-computed `key_hash`, `key_lookup`, `hash_alg`, `hash_params` | Argon2id (pre-computed by `mint_key()`) | Postgres `api_keys` |
| Admin write | `api/db/api_keys_store.py::insert_api_key()` | Raw key string | Argon2id (re-hashes internally) | Postgres `api_keys` |
| SQLite write | `api/auth_scopes/mapping.py` | Raw key | Argon2id | SQLite `api_keys` |

**Why two writers for Postgres**: `auth_scopes/store.py` documents (lines 20–27) that `api_keys_store.py` would re-hash an already-hashed key, creating a double-hash bug. The two paths are acknowledged, intentional, and write to the same table without conflict.

---

## 3. Internal Gateway Token Usage

| Env Var | Priority | Validated By | Validated Via |
|---------|----------|-------------|---------------|
| `FG_ADMIN_GATEWAY_TOKEN` | 1 (highest) | `api/admin.py::require_internal_admin_gateway()`, `provision-tenant/route.ts::internalToken()` | `hmac.compare_digest()` |
| `FG_INTERNAL_AUTH_SECRET` | 2 | Same | Same |
| `FG_INTERNAL_TOKEN` | 3 (legacy) | Same | Same |

### Behavior When Missing
- **Dev/local (non-prod)**: Admin routes ungated if no token configured
- **Prod/staging**: Returns 403 — blocks all admin operations
- **Console BFF**: Returns 503 "not configured" if `internalToken()` returns empty string

### Note
The three-name fallback chain in both Python and TypeScript is identical and in the same order. No observed priority conflict. Consolidation (R6) is cleanup, not a correctness fix.

---

## 4. Persistence Locations

| System | Actively Written (Prod) | Data | Write Path |
|--------|------------------------|------|-----------|
| **Postgres `api_keys`** | YES | API keys, tenant binding, scopes, hash, expiry | `auth_scopes/store.py` (auth path), `db/api_keys_store.py` (admin path) |
| **Filesystem `state/tenants.json`** | YES | Tenant registry: id, name, plaintext api_key, status | `tools/tenants/registry.py::create_tenant_exclusive()` |
| **Redis (ioredis)** | YES (if `REDIS_URL` set) | `portal:tenant:{id}:key` (1-year TTL) | `provision-tenant/route.ts::writeKeyToRedis()` |
| **Upstash REST** | YES (if `UPSTASH_REDIS_REST_URL` set) | Same key + `console:tenant-registry` metadata | `provision-tenant/route.ts::writeKeyToUpstash()` + `upsertTenantInUpstash()` |
| **Vercel Edge Config** | YES (metadata only) | Tenant label, created_at — **no credentials** | `lib/tenant-registry.ts::upsertTenantInRegistry()` |
| **SQLite `api_keys`** | In dev/test only | Same as Postgres | `auth_scopes/mapping.py` (gated off when `FG_DB_BACKEND=postgres`) |
| **Postgres `security_audit_log`** | YES | Key operations, auth events, admin actions | `api/security_audit.py` |
| **Env vars** | NO | Configuration only (tokens used for validation, not stored) | N/A |
| **Local filesystem (other)** | NO | None identified | N/A |

### SQLite Production Status
`_ensure_api_keys_sqlite()` in `api/main.py` only runs when `FG_DB_BACKEND != "postgres"`. Production with `FG_DB_BACKEND=postgres` never touches SQLite. Confirmed gated correctly.

---

## 5. Duplicate System Matrix

| Operation | Handler 1 | Handler 2 | Handler 3 |
|-----------|-----------|-----------|-----------|
| Tenant creation | `api/admin.py::create_tenant()` | `tools/tenants/registry.py` (called by admin.py) | `provision-tenant/route.ts` (BFF wrapper) |
| API key creation | `api/keys.py::create_key()` | `api/admin.py::admin_create_key()` | `provision-tenant/route.ts` (indirect via admin route) |
| API key validation | `api/auth_scopes/resolution.py::verify_api_key_detailed()` | `api/credentials.py::validate_credential()` (test-only) | — |
| API key revocation | `api/keys.py::revoke_key()` | `api/admin.py::admin_revoke_key()` | `api/auth_scopes/mapping.py::revoke_api_key()` (called by both) |
| API key rotation | `api/keys.py::rotate_key()` | `api/key_rotation.py::KeyRotationManager.rotate_key()` | — |
| Internal token validation | `api/admin.py::require_internal_admin_gateway()` | `provision-tenant/route.ts::internalToken()` | `api/auth_scopes/resolution.py` |
| Portal key write | `provision-tenant/route.ts::writeKeyToRedis()` | `provision-tenant/route.ts::writeKeyToUpstash()` | — |

---

## 6. Migration Risk Register

### High — Data loss or availability impact

1. **Filesystem registry has no backup**: `state/tenants.json` is a single file on the API server. Container restart preserves it; container replacement loses it. R7 must migrate before any infrastructure change.

2. **Plaintext keys in `state/tenants.json`**: The `api_key` field is stored as plaintext. The API keys table stores only hashes. If the JSON file is readable outside the process, all tenant keys are compromised. R7 migration must not copy plaintext keys into Postgres — the Postgres table should store the binding only (tenant_id → key prefix), not the raw key.

3. **Portal key is the only credential the portal has**: `portal:tenant:{id}:key` in Redis/Upstash is not backed by Postgres. If Redis expires or Upstash is unreachable, the portal cannot authenticate. R0 addresses provisioning; R7 must add Postgres-backed credential resolution as a cache-miss fallback.

4. **No foreign key from `api_keys.tenant_id` to any tenant table**: Keys can exist for tenant IDs that don't exist in the registry. R7 must add referential integrity as part of creating the `tenants` table.

5. **Dual-write race in provision-tenant**: Between step 1 (create tenant in Core API → JSON file) and step 2 (create key in Core API → Postgres), any failure leaves a partial state. R0 handles the Redis/Upstash failure; the tenant-exists-but-key-missing case has no recovery path today.

### Medium — Cross-system state

6. **Two key rotation implementations**: `api/keys.py::rotate_key()` and `api/key_rotation.py::KeyRotationManager` both write to the same `api_keys` table but independently. If their rotation logic diverges, the same key could be rotated differently depending on which path is invoked. R4 must consolidate.

7. **TTL fragmented across three locations**: `api/auth_scopes/__init__.py` (DEFAULT_TTL_SECONDS), `api/key_rotation.py` (env-configured), `provision-tenant/route.ts` (hardcoded ONE_YEAR_SECONDS). No single source of truth. R4 must canonicalize.

8. **`security_audit_log` absent in SQLite mode**: SQLite deployments have no queryable audit trail. Key operations only logged to container stdout. R7 migration must ensure prod is always in Postgres mode before R4 touches key paths.

### Low — Cleanup opportunities

9. **`api/credentials.py` dead code**: Zero production imports. Remove in R4 after confirming test coverage is replaced.

10. **Three env var names for one secret**: Functional but creates confusion about which is "real." R6 addresses this.

11. **Rotation chain orphaning**: `rotated_from` column links new key to old prefix but old keys accumulate without cleanup. Low risk, minor debt.

---

## 7. Recommended Canonical Targets

| Concern | Current | Target (post-recovery) |
|---------|---------|----------------------|
| Tenant identity | `state/tenants.json` (filesystem) | Postgres `tenants` table (new, R7) |
| API keys | Postgres `api_keys` (already) | Same — no change needed |
| Portal credential lookup | Redis/Upstash (cache only) | Postgres `tenant_credential_bindings` → Redis as read-through cache |
| Audit trail | Postgres `security_audit_log` (already) | Same |
| Tenant metadata (UI) | Vercel Edge Config + Upstash console registry | Keep — metadata-only, no credentials |
| Internal gateway token | Three env var aliases | One: `FG_INTERNAL_GATEWAY_SECRET` (R6) |
| Key hash authority | Dual writer (auth-scopes + admin) | Single `CredentialAuthority.insert()` (R4) |

---

## 8. Answers to Specific Questions

**Is `api/credentials.py` reachable in production?**
No. Zero imports outside `tests/`. Dead code, no migration needed, safe to remove in R4.

**Is `_ensure_api_keys_sqlite` active in production?**
No. Gated by `FG_DB_BACKEND != "postgres"`. Production with `FG_DB_BACKEND=postgres` never touches SQLite.

**How many Postgres tables hold tenant identity?**
Zero — there is no tenant table in Postgres. `api_keys.tenant_id` is a string column with no foreign key. `state/tenants.json` is the only authoritative record of which tenants exist.

**Does `auth_scopes/store.py` bypass `api_keys_store.py` in the production key write path?**
Yes, intentionally. `auth_scopes/store.py` inserts with pre-computed hashes (to avoid double-hashing). `api_keys_store.py` takes raw keys and re-hashes. Both write to the same table, no conflict. Documented in `store.py` lines 20–27.
