# Credential Migration Decisions

**Date**: 2026-07-19
**Scope**: Legacy module disposition, migration strategy, compatibility contracts
**Status**: R4.1 — Locked decisions. No implementation may deviate without updating this document.

---

## 1. api/credentials.py — Export Classification

| Export | Classification | Reason |
|--------|---------------|--------|
| `create_credential(tenant_id)` | **replace** | Replaced by `issue_credential()` in `credential_authority.py`. Not called in production (zero non-test imports). |
| `validate_credential(raw_key, *, expected_tenant_id)` | **replace** | Replaced by `validate_credential()` in authority. Currently returns `str` (tenant_id only) — authority returns `CredentialPrincipal`. All callers must be updated. |
| `revoke_credential(credential_id, tenant_id)` | **replace** | Replaced by `revoke_credential()` in authority. |
| `rotate_credential(credential_id, tenant_id)` | **replace** | Non-atomic (revoke then issue in sequence). Replaced by atomic `rotate_credential()` in authority. |
| `hash_credential(secret)` | **delete** | Exposes internal hash function publicly. Documented as "for transparency" — no production caller. Dangerous to keep as public API. Tests that use it must patch at the verification layer instead. |
| `CredentialRecord` | **migrate_test_coverage** | Shape referenced in `test_credentials.py` tests 1, 3, 8, 9. Superseded by `CredentialPrincipal` and issuance response type. Tests must be rewritten against new response shape. |
| Error constants (`ERR_AUTH_REQUIRED`, `ERR_AUTH_INVALID`, `ERR_AUTH_REVOKED`, `ERR_TENANT_DENIED`, `ERR_NOT_FOUND`) | **retain** | Published API error codes. Tests 4–7 verify by string value. Must remain stable. New authority must emit the same code strings. |
| `_CREDENTIAL_SCOPE = "credential:use"` | **retain** | Scope name is a published contract. `validate_credential` enforces it. New authority must enforce `required_scopes={"credential:use"}`. |
| `_CREDENTIAL_TTL_SECONDS = 365 * 24 * 3600` | **retain as policy** | One-year TTL is a product contract. Moved to `credential_authority.py` as `DEFAULT_CREDENTIAL_TTL_SECONDS`. |
| Internal helpers (`_db_path`, `_emit`, `_lookup_row`, `_revoke_by_db_id`) | **delete** | All replaced by authority internals. `_lookup_row` has a SQLite-only direct connection path that must not survive. |

**Module removal target:** R4.8 (after dual-read migration and consumer cutover in R4.7).

---

## 2. api/key_rotation.py — KeyRotationManager

**Disposition: retire in R4.8.**

Critical gaps found in audit:

1. **No tenant enforcement on old key lookup.** `rotate_key()` accepts `tenant_id` but does not verify the key being rotated belongs to that tenant. This is a tenant isolation gap.
2. **Deferred revocation semantics.** Old key is not revoked immediately — `expire_old_keys()` must run after the grace period. This conflicts with the locked decision that immediate cutover is the default. Bounded overlap requires an explicit flag and audit event.
3. **`rotated_from` writes the prefix string**, not a stable `credential_id`. Incompatible with the canonical `replaced_by_credential_id` FK.
4. **Duplicate route.** `POST /admin/keys/{prefix}/rotate` is registered twice in `admin.py`. The second registration (line ~1719) uses `KeyRotationManager` with no tenant enforcement. FastAPI uses the last-registered handler — this is the active bug. R4.6 must fix the route duplication and replace with the canonical authority route.

**Test coverage:** `KeyRotationManager` tests test the deferred-revocation behavior. These tests must be rewritten against `rotate_credential()` semantics (immediate cutover, explicit overlap opt-in).

---

## 3. api/db/api_keys_store.py

**Disposition: delete in R4.8.**

- Uses `_`-delimited prefix scheme (e.g., `abc123_`) incompatible with `fgk.<payload>.<secret>` format.
- Does not set `tenant_id` on insert — would violate NOT NULL constraint in Postgres mode.
- Has no tenant enforcement.
- Should not be called in Postgres mode. Confirmed by `store.py` header comment (lines 20–27) which acknowledges this as an intentional divergent path.
- No production callers. Safe to delete with no migration.

---

## 4. Rotation Semantic Decision

**Chosen:** Immediate cutover is the default. Bounded overlap requires explicit request, explicit `rotation_policy = 'bounded_overlap'` on the slot, bounded duration, and an audit event.

**Retired:** `KeyRotationManager`'s deferred-revocation / grace-period model. It introduces complexity (in-memory state, `expire_old_keys()` sweep dependency) with no corresponding security benefit when immediate cutover is available.

**Rotation history link:** `replaced_by_credential_id` is a FK to `tenant_credentials.credential_id`. This is a stable, unique identifier — unlike the current inconsistency where `KeyRotationManager` writes the prefix string and `rotate_api_key_by_prefix` writes the Argon2id hash.

---

## 5. validate_credential Return Type Migration

**Current:** Returns `str` (tenant_id only).
**Target:** Returns `CredentialPrincipal`.

**Migration strategy:** R4.3 introduces `authenticate_credential()` returning `CredentialPrincipal`. The existing `validate_credential()` in `credentials.py` is kept as a shim during R4.7 dual-read phase that calls `authenticate_credential()` and returns `principal.tenant_id` for backward compatibility. The shim is removed in R4.8.

All call sites that consume only `tenant_id` from the validation result must be updated to consume `CredentialPrincipal.tenant_id` before the shim is removed. Usage attribution must be updated to consume the full principal.

---

## 6. Test Contracts That Must Survive Migration

These contracts are encoded in `tests/security/test_credentials.py` and must not be broken silently:

| Contract | Test(s) | Notes |
|----------|---------|-------|
| `"fgk."` prefix in issued key | 1 | New `issue_credential()` must produce keys with this prefix |
| `"$argon2"` in stored `key_hash` | 2 | Argon2id PHC string format; if algorithm changes, test must be updated explicitly |
| `.` separator; secret is last dot-segment | 2, 10 | Format `fgk.<payload>.<secret>` — cannot change without updating all parsers and tests |
| Five error code strings by value | 4–7 | `ERR_AUTH_REQUIRED`, `ERR_AUTH_INVALID`, `ERR_AUTH_REVOKED`, `ERR_TENANT_DENIED`, `ERR_NOT_FOUND` |
| `rotated_from` linkage on issuance response | 9 | New issuance response must include `replaced_by_credential_id` or an equivalent `rotated_from` field |
| `"credential:use"` scope enforced on validation | 13 | Must remain enforced; scope name must not change |
| Trusted tenant always from validated credential, never from payload | 14 | Architectural invariant; usage attribution must consume `CredentialPrincipal.tenant_id` |

**`AuthResult` compatibility:**
Tests 13–14 patch `verify_api_key_detailed` and assert against `AuthResult(valid, reason, tenant_id, scopes)`. During R4.7 dual-read, the legacy path still uses `AuthResult`. After R4.8, these tests must be rewritten against `CredentialPrincipal` and the new authority's validation path.

---

## 7. lookup_fingerprint Migration

**Finding:** Existing keys already have `key_lookup = HMAC-SHA256(secret_part, FG_KEY_PEPPER)` stored in `api_keys`. This is exactly the `lookup_fingerprint` value. No existing key holder needs to re-present their raw secret.

**Migration:** R4.2 adds `lookup_fingerprint` to `tenant_credentials`. R4.7 (dual-read migration) backfills `lookup_fingerprint` from `api_keys.key_lookup` for migrated keys. The values are identical.

**`lookup_key_version`:** Current pepper is version 1. When `FG_KEY_PEPPER` is rotated, increment `lookup_key_version` and re-derive fingerprints in a separate migration. Lookup during pepper rotation: try current version fingerprint first, fall back to prior version if not found, re-derive and store new fingerprint on successful auth.

**`secret_prefix`:** First 8 characters of `key_lookup` hex. Matches the existing `credential_id[:8]` pattern already used in audit logs (`_emit` in `credentials.py`).

---

## 8. api_keys Table — Migration Mapping

Columns in `api_keys` and their disposition when `tenant_credentials` is authoritative:

| api_keys column | Disposition | Maps to tenant_credentials |
|----------------|-------------|---------------------------|
| `id` | Retire | Not needed — `credential_id` UUID replaces serial PK |
| `name` | Retire | `credential_slot` replaces human label |
| `prefix` | Retire | `secret_prefix` (stored explicitly; derived from key_lookup[:8]) |
| `key_hash` | Migrate | `secret_hash` |
| `key_lookup` | Migrate | `lookup_fingerprint` |
| `hash_alg` | Migrate | `hash_algorithm` |
| `hash_params` | Migrate | `hash_params` |
| `scopes_csv` | Migrate | `scopes_csv` (same column, same format) |
| `enabled` | Retire | `status` with `revoked` replaces boolean flag |
| `created_at` | Migrate | `issued_at` |
| `version` | Retire | `schema_version` replaces; starts at 1 |
| `expires_at` | Migrate | `expires_at` |
| `rotated_from` | Discard | Value is inconsistent (prefix string vs hash). Use `replaced_by_credential_id` going forward. |
| `last_used_at` | Migrate | `last_used_at` |
| `use_count` | Migrate as approximate | `approximate_use_count`; semantics change from exact-synchronous to best-effort |
| `tenant_id` | Migrate | `tenant_id` (NOT NULL, same value) |
| `created_by` | Migrate | `created_by_actor_id` |
| `description` | Retire | `metadata` JSONB replaces |
| `role` | Migrate | Part of `metadata` JSONB for `tenant_api_key` if needed; not a first-class field |

**Keys that cannot be migrated without rotation:** None — all required hash material (`key_hash`, `key_lookup`, `hash_alg`, `hash_params`) is already stored. Backfill from `api_keys` to `tenant_credentials` is mechanical. Users do not need to re-present credentials for the migration.

---

## 9. Deploy Sequence

### Deploy 1 (R4.7)
- `tenant_credentials` table exists and is populated for new issuances.
- `validate_credential()` prefers `tenant_credentials`; falls back to `api_keys` on miss.
- Successful legacy fallback emits `legacy_credential_validated` telemetry event.
- New issuance goes to `tenant_credentials` only.
- Old issuance paths (`credentials.py`, `keys.py`, `admin.py` direct key creation) remain as fallback consumers.

### Deploy 2 (R4.8 — Phase A)
- Backfill: migrate all `api_keys` rows to `tenant_credentials` via a reconciliation script.
- Rotate any keys that could not be safely migrated (none expected — all hash material is present).
- New legacy issuance is disabled (raise `DeprecationError` in old paths).
- Validation still has legacy fallback during observation window.

### Deploy 3 (R4.8 — Phase B)
- Legacy fallback removed from `validate_credential()`.
- `api/credentials.py`, `api/key_rotation.py`, `api/db/api_keys_store.py` removed.
- `api_keys` table retained as read-only audit history (not dropped).
- CI authority gate active: direct writes to `tenant_credentials` outside `credential_authority.py` fail CI.
- Operational documentation updated with new key management procedures.

---

## 10. Ownership Boundaries Summary

| Concern | Owner |
|---------|-------|
| Tenant API key lifecycle | `api/credential_authority.py` (R4) |
| Tenant lifecycle state | `api/tenant_lifecycle.py` (R3) |
| Internal gateway secret | `api/config/internal_gateway_secret.py` (R6) |
| Portal key (Redis/Upstash) | `apps/console/app/api/admin/provision-tenant` (deferred to R4.9) |
| Agent/device credentials | `api/identity_governance/` (deferred to R4.9+) |
| Connector credentials | Connector subsystem (deferred to R4.9+) |
