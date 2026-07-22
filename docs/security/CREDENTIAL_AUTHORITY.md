# Credential Authority

**Date**: 2026-07-19
**Scope**: Tenant credential lifecycle — issuance, validation, rotation, revocation, expiration
**Status**: R4.1 — Authority contract established. Implementation begins R4.2.
**Authority**: This document is the authoritative reference for all credential lifecycle decisions. R4.2–R4.9 must not deviate from the contracts defined here without updating this document first.

---

## 1. Scope and Boundaries

### In scope for R4 (initial delivery)

| Credential class | Description |
|-----------------|-------------|
| `tenant_api_key` | API keys issued to tenants for programmatic access to the Core API. Currently stored in `api_keys` table. |

### In scope — R4.9 addition

| Credential class | Description |
|-----------------|-------------|
| `portal_access` | Portal grants issued to clients for time-limited portal authentication. Absorbed from legacy `portal_grants` table. 14-day TTL. Raw opaque token format (no `fgk.` prefix). |

### Explicitly deferred

| Credential class | Deferred to | Reason |
|-----------------|-------------|--------|
| `connector_credentials` | R4.9 or later | Connector auth has its own encryption and rotation requirements; boarding with `tenant_api_key` would underspecify it. |
| `agent_device_credentials` | R4.9 or later | Device trust lifecycle has distinct FSM requirements (see `api/identity_governance/`). |
| `service_identity` | R4.9 or later | No confirmed current issuer or consumer found in audit. Candidate class only — not promoted into scope without evidence. |
| `internal_gateway_secret` | R6 | Gateway secret convergence is R6's authority. R4 references R6 boundary but does not absorb it. |

---

## 2. Credential Lifecycle

```
issued → pending → active → rotated (terminal for that generation)
                          → revoked (terminal)
                          → expired (terminal)
         pending → expired (if activation deadline passes)
```

**State semantics:**

| Status | Meaning |
|--------|---------|
| `pending` | Issued but not yet activated. `expires_at` is the activation deadline. Validation always rejects. |
| `active` | Valid for authentication. `expires_at` is the credential validity deadline (NULL = no expiry). |
| `rotated` | Superseded by a newer generation. `replaced_by_credential_id` points to successor. Terminal — cannot reactivate. |
| `revoked` | Explicitly disabled. Terminal — cannot reactivate. |
| `expired` | Passed `expires_at` without being rotated or revoked. Terminal. |

**Expiration enforcement — hybrid model:**

At validation time, effective expiration is enforced regardless of row status:
```sql
status = 'active'
AND (expires_at IS NULL OR expires_at > now())
```

The scheduled `expire_credentials()` sweep normalizes row status and emits authoritative expiration events. It is for audit completeness, not for primary security enforcement. The scheduled job is not trusted for authentication correctness.

**Pending credential cleanup:**
- `expires_at` on a `pending` row is the activation deadline (short TTL, configurable per credential type).
- If `pending` rows are never activated, the sweep marks them `expired` and emits `expired` events.
- If a credential class does not require an activation step, issue directly as `active`.

**Plaintext secret:**
- Returned exactly once at issuance.
- Never stored.
- Never returned on idempotency replay — replay returns record metadata only with a clear indicator that the secret is no longer available.
- Never appears in logs, exceptions, audit records, or request traces.

---

## 3. Credential Model

### tenant_api_key format

```
fgk.<base64url-json-payload>.<secret>
```

- `fgk` — hardcoded prefix; identifies key class in logs and display.
- `<base64url-json-payload>` — non-secret metadata (tenant_id_hint for RLS, expiry hint). Not a security boundary — hint only.
- `<secret>` — `secrets.token_urlsafe(32)`, cryptographically random. The only security-bearing component.

This format is a published contract. Tests encode it explicitly. Any new issuance path must produce keys in this format or all parsers and tests must be updated simultaneously.

### portal_access format

```
<raw_secret>
```

- No prefix, no structure. A single `secrets.token_urlsafe(32)` value (~43 URL-safe base64 characters).
- The entire value is the secret input to `HMAC-SHA256(secret, FG_KEY_PEPPER)` for fingerprint derivation.
- No tenant-hint encoding — portal tokens do not carry metadata in the token itself.
- The entire value is passed to Argon2id for verification.

**Contract invariants:**

- No `fgk.` prefix. Any incoming token that begins with `fgk.` is rejected with `absent=True` (safe fallthrough — wrong type, not a portal credential).
- Raw secret is returned exactly once at issuance. It is never stored, never returned on idempotency replay, and never logged.
- Minimum 20 chars, maximum 128 chars. Tokens outside this range are rejected with `absent=True`.

### Schema fields

| Field | Type | Notes |
|-------|------|-------|
| `credential_id` | UUID | Stable identifier for the credential record. Not derived from the secret. |
| `tenant_id` | VARCHAR(128) NOT NULL | FK to `tenants.tenant_id`. |
| `credential_type` | VARCHAR(64) NOT NULL | `tenant_api_key` for initial scope. |
| `credential_slot` | VARCHAR(128) NOT NULL | Named logical position (e.g., `production-primary`). Stable across rotation generations. |
| `generation` | INTEGER NOT NULL DEFAULT 1 | Increments with each rotation within a slot. |
| `lookup_fingerprint` | VARCHAR(64) NOT NULL | HMAC-SHA256(secret_part, pepper). Used for indexed candidate lookup. Deterministic, not secret. |
| `lookup_key_version` | INTEGER NOT NULL DEFAULT 1 | HMAC key version — allows pepper rotation without invalidating all fingerprints. |
| `secret_prefix` | VARCHAR(16) NOT NULL | First 8 chars of `key_lookup` hex. Display-only; never used as lookup key. Collisions safe. |
| `secret_hash` | TEXT NOT NULL | Argon2id hash of `"{secret}:{pepper}"`. The verification proof. |
| `hash_algorithm` | VARCHAR(32) NOT NULL | `argon2id`. Versioned for future algorithm migration. |
| `hash_params` | JSONB NOT NULL | `{time_cost, memory_cost, parallelism, hash_len, salt_len}`. Required for verification. |
| `status` | VARCHAR(16) NOT NULL | `pending`, `active`, `rotated`, `revoked`, `expired`. |
| `expires_at` | TIMESTAMPTZ | NULL = no expiry. Meaning depends on status (activation deadline when pending; validity deadline when active). |
| `issued_at` | TIMESTAMPTZ NOT NULL | When the credential was created. |
| `activated_at` | TIMESTAMPTZ | When status changed to active. NULL for directly-issued active credentials means issued_at is the effective activation time. |
| `rotated_at` | TIMESTAMPTZ | When superseded by the next generation. |
| `revoked_at` | TIMESTAMPTZ | When explicitly revoked. |
| `replaced_by_credential_id` | UUID | FK to `tenant_credentials.credential_id` of successor. NULL unless rotated. |
| `created_by_actor_id` | VARCHAR(256) | Actor who issued the credential. |
| `request_id` | VARCHAR(128) | Request that triggered issuance. |
| `idempotency_key` | VARCHAR(256) | Caller-supplied idempotency token. Scoped to `(tenant_id, idempotency_key)`. |
| `last_used_at` | TIMESTAMPTZ | Updated out-of-band, at most once per configurable interval. Best-effort. |
| `approximate_use_count` | INTEGER NOT NULL DEFAULT 0 | Accumulated asynchronously. Not exact. Never used for authorization. |
| `scopes_csv` | TEXT | Comma-separated scopes. For `tenant_api_key`: always includes `credential:use`. |
| `metadata` | JSONB | Per-type validated payload. See Section 4. Unknown keys rejected. |
| `schema_version` | INTEGER NOT NULL DEFAULT 1 | Bumped when hash input fields change. |
| `record_hash` | VARCHAR(64) | SHA-256 of immutable fields. Tamper-detection. Same pattern as `transition_hash` in R3. |

### Indexes and constraints

```sql
UNIQUE (credential_id)
UNIQUE (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
UNIQUE (tenant_id, credential_type, credential_slot, generation)
INDEX (tenant_id, status)
INDEX (lookup_fingerprint)
INDEX (expires_at) WHERE status IN ('pending', 'active')
```

No partial unique index on `(tenant_id, credential_type, credential_slot) WHERE status = 'active'`.
Uniqueness across active generations is enforced by authority logic via the `credential_slots` table, not a DB constraint — this preserves the option for bounded-overlap rotation without a destructive constraint change.

### credential_slots table

```sql
CREATE TABLE credential_slots (
    tenant_id         VARCHAR(128)  NOT NULL REFERENCES tenants(tenant_id),
    credential_type   VARCHAR(64)   NOT NULL,
    credential_slot   VARCHAR(128)  NOT NULL,
    current_generation INTEGER      NOT NULL DEFAULT 0,
    rotation_policy   VARCHAR(32)   NOT NULL DEFAULT 'immediate',
    max_overlap_count INTEGER       NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ   NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, credential_type, credential_slot)
);
```

`rotation_policy` values: `immediate` (old valid_until = now()), `bounded_overlap` (old valid_until = now() + grace, requires explicit request and audit event).
`max_overlap_count`: maximum simultaneously valid generations. Default 1 (immediate cutover). Max 2 for bounded overlap. Authority enforces this transactionally via conditional UPDATE on `current_generation`.

---

## 4. Per-Type Metadata Schemas

Metadata is validated at authority boundaries via Pydantic discriminated unions. Unknown keys are rejected.

### tenant_api_key

```python
class TenantApiKeyMetadata(BaseModel):
    allowed_scopes: list[str]      # must be subset of permitted scopes for credential:use
    environment: str               # "production" | "staging" | "development"
    owner_label: str | None = None # human display label, max 128 chars
```

### portal_access

```python
class PortalAccessMetadata(BaseModel):
    client_id: str           # client the grant authorizes access for; max 128 chars
    engagement_id: str       # engagement scope for this grant; max 128 chars
    portal_grant_id: str | None = None  # populated for sentinel migration records only
```

`portal_grant_id` is set on sentinel rows (copied from `portal_grants.id`) to allow traceability back to the originating legacy record during the transition window. It is `None` on new canonical grants.

**Sentinel migration records** (created by `migrations/postgres/0161_portal_access_migration.sql`):

These rows copy existing `portal_grants` into `tenant_credentials` with a non-authenticating sentinel fingerprint. They exist to give every pre-migration grant a `credential_id` before the transition window closes.

| Field | Sentinel value |
|-------|---------------|
| `credential_slot` | `legacy:{client_id}:{engagement_id}:{portal_grant_id}` |
| `lookup_fingerprint` | `legacy:{portal_grant_id}` |
| `metadata.validation_mode` | `"legacy_fallback_only"` |
| `metadata.source` | `"legacy_portal_grant"` |

A real HMAC-SHA256 fingerprint is a 64-character lowercase hex string (`[0-9a-f]{64}`). The `legacy:` prefix can never be produced by HMAC, so sentinel rows are completely invisible to the canonical fingerprint index lookup. `validate_credential()` will never match a sentinel row through fingerprint lookup.

**Sentinel rows must not be used for authentication.** Authentication for legacy grants during the transition window is handled by the `_authenticate_legacy_portal_grant` fallback path in `portal_grant_service.py`.

**Removal condition:** Remove `_authenticate_legacy_portal_grant` and drop the `portal_grants` table 15 days after the migration deployment date (14-day maximum grant TTL + 1 day buffer). Track in ROADMAP.md `Legacy fallback removal date` column.

---

## 5. Validation Path

### tenant_api_key

```
presented raw key (fgk.<payload>.<secret>)
        ↓
parse: prefix, payload, secret_part = key.rsplit(".", 1)[-1]
        ↓
compute: lookup_fingerprint = HMAC-SHA256(secret_part, FG_KEY_PEPPER)
        ↓
indexed lookup:
    SELECT c.*, t.lifecycle_state
    FROM tenant_credentials c
    JOIN tenants t ON t.tenant_id = c.tenant_id
    WHERE c.lookup_fingerprint = :fingerprint
      AND c.credential_type = 'tenant_api_key'
        ↓
verify: Argon2id hash (constant-time)
        ↓
enforce: status = 'active'
         AND (expires_at IS NULL OR expires_at > now())
         AND tenant lifecycle permits validation
        ↓
return: CredentialPrincipal (never the raw row)
```

### portal_access

```
presented raw token (opaque, ~43 chars, no prefix)
        ↓
parse: reject if starts with "fgk." → CredentialNotFoundError(absent=True)
       reject if len < 20 or len > 128 → CredentialNotFoundError(absent=True)
       secret_part = stripped token
        ↓
compute: lookup_fingerprint = HMAC-SHA256(secret_part, FG_KEY_PEPPER)
        ↓
indexed lookup:
    SELECT c.*, t.lifecycle_state
    FROM tenant_credentials c
    JOIN tenants t ON t.tenant_id = c.tenant_id
    WHERE c.lookup_fingerprint = :fingerprint
      AND c.credential_type = 'portal_access'
        ↓
  (sentinel rows are invisible — their fingerprint 'legacy:...' can never match)
        ↓
verify: Argon2id hash (constant-time)
        ↓
enforce: status = 'active'
         AND (expires_at IS NULL OR expires_at > now())
         AND tenant lifecycle permits validation
        ↓
return: CredentialPrincipal with metadata = {client_id, engagement_id}
```

**Canonical-first authentication with legacy fallback (portal_grant_service):**

```
validate_credential(raw_secret, credential_type="portal_access")
        ↓
success → check principal.tenant_id matches expected tenant → return session
        ↓
CredentialNotFoundError(absent=True)  → try legacy Argon2id scan (portal_grants)
CredentialNotFoundError(absent=False) → FAIL CLOSED — do not fall through
any other exception                   → FAIL CLOSED — do not fall through
```

`absent=True` means nothing matched in the canonical index — safe to check legacy.
`absent=False` means a canonical record was found but is revoked, expired, or has a hash mismatch — this must never fall through to a less-strict legacy check.

**Tenant lifecycle policy at validation:**

| Tenant state | validate existing | issue | rotate | revoke |
|-------------|-------------------|-------|--------|--------|
| `active` | yes | yes | yes | yes |
| `suspended` | no | no | emergency only (explicit flag required) | yes |
| `archived` | no | no | no | yes |
| `deleted` | no | no | no | idempotent only |

No cache for lifecycle state. The JOIN to `tenants` is authoritative. Cache may be added if benchmarks prove necessity, with a mandatory short TTL and active invalidation from R3 events.

**CredentialPrincipal:**

```python
@dataclass(frozen=True)
class CredentialPrincipal:
    tenant_id: str
    credential_id: str
    credential_type: str
    credential_slot: str
    generation: int
    scopes: frozenset[str]
    issued_at: datetime
    authentication_method: str = "api_key"
    metadata: dict | None = None  # per-type binding info; see Section 4
```

For `portal_access`, `metadata` contains `client_id` and `engagement_id` from `PortalAccessMetadata`. Callers must use `principal.metadata` to read binding info — they must not re-query the credential table.

Usage attribution must consume `CredentialPrincipal`, not parse raw credential material.

---

## 6. Rotation Semantics

Rotation is slot-level and serialized via the `credential_slots` parent table.

**Atomic rotation sequence (inside one transaction):**
1. `SELECT ... FROM credential_slots WHERE ... FOR UPDATE` — lock the slot.
2. Recheck idempotency key against existing credential records.
3. Read `current_generation`.
4. Validate overlap policy (max 1 simultaneous active generation for `immediate`; max 2 for `bounded_overlap`).
5. Insert new credential row at `generation = current_generation + 1`, status `active`.
6. Set old generation's `valid_until` (= now() for `immediate`; = now() + grace_period for `bounded_overlap`).
7. Mark old generation `rotated`, set `replaced_by_credential_id`.
8. Conditional UPDATE: `UPDATE credential_slots SET current_generation = current_generation + 1, updated_at = now() WHERE ... AND current_generation = :expected_generation`.
9. `rowcount == 0` → concurrent rotation won; raise `CredentialConflictError`. Caller retries.
10. Emit `rotated` audit event (includes both old and new `credential_id`).
11. Commit.

**Empty slot race:** The `credential_slots` row is inserted at first issuance. Concurrent issuance into a new slot is serialized by the `PRIMARY KEY (tenant_id, credential_type, credential_slot)` insert constraint — one writer gets the row, the other gets an `IntegrityError` and retries.

---

## 7. Revocation

- Idempotent: revoking an already-revoked credential is a no-op that returns success.
- Reasoned: `reason` is required, logged in the audit event.
- Actor-attributed: `actor_id` required.
- Timestamped: `revoked_at` set to now().
- Irreversible: no transition from `revoked` to any other status.
- `revoke_all_for_tenant(tenant_id)` bulk operation must be atomic and emit one event per credential revoked.

---

## 8. Audit Events

Two-layer model:

**Authoritative lifecycle events** (`tenant_credential_events` table):

| Event type | Written for |
|-----------|-------------|
| `issued` | Every new credential |
| `activated` | pending → active |
| `rotated` | Old generation superseded |
| `revoked` | Explicit revocation |
| `expired` | Sweep marks row expired |
| `denied_tenant_state` | Validation rejected due to tenant lifecycle state |

Not written for every validation attempt — high-volume validation telemetry goes to the structured security telemetry layer, not the authoritative audit table.

**Security telemetry** (structured logs / telemetry pipeline):

| Event type | Written for |
|-----------|-------------|
| `validated` | Successful authentication |
| `validation_failed` | Failed authentication (wrong secret, wrong tenant, etc.) |

Telemetry events must never include `secret_hash`, `lookup_fingerprint`, or any portion of the raw credential.

**Audit event fields:**

```
event_id, credential_id, tenant_id, event_type, actor_id, request_id,
reason, occurred_at, schema_version, event_hash
```

`event_hash`: SHA-256 of `(event_id, credential_id, tenant_id, event_type, occurred_at)`. Same tamper-detection pattern as R3 `transition_hash`.

---

## 9. Authority Boundary

`api/credential_authority.py` is the **only** module permitted to:
- INSERT into `tenant_credentials`
- INSERT into `credential_slots`
- UPDATE `tenant_credentials.status`, `revoked_at`, `rotated_at`, `replaced_by_credential_id`, `valid_until`
- INSERT into `tenant_credential_events`

Exception: migration files may INSERT/UPDATE during schema setup only.

A CI gate (`tools/ci/check_credential_authority.py`) will scan for SQL containing `INSERT INTO tenant_credentials` or `UPDATE tenant_credentials` outside `api/credential_authority.py` and migration files. This prevents authority bypass from accumulating silently.

---

## 10. Boundary with R6

`internal_gateway_secret` is R6's authority. R4 does not issue, validate, rotate, or revoke gateway secrets. The `FG_INTERNAL_GATEWAY_SECRET` resolver in `api/config/internal_gateway_secret.py` is R6's and is consumed but not modified by R4.

---

## 11. Legacy Module Disposition

See `docs/security/CREDENTIAL_MIGRATION_DECISIONS.md` for the full per-export classification and migration plan.

| Module | Disposition | Target |
|--------|-------------|--------|
| `api/credentials.py` | Retire in R4.8 | Replaced by `api/credential_authority.py` |
| `api/key_rotation.py` (KeyRotationManager) | Retire in R4.8 | Replaced by `rotate_credential()` in authority |
| `api/db/api_keys_store.py` | Delete in R4.8 | Not used in Postgres mode; uses incompatible prefix scheme |
| `api/auth_scopes/mapping.py::rotate_api_key_by_prefix` | Retire in R4.8 | Replaced by `rotate_credential()` |
| `api/auth_scopes/mapping.py::revoke_api_key` | Retire in R4.8 | Replaced by `revoke_credential()` |
| `api/auth_scopes/store.py::insert_key_row` | Retire in R4.8 | Replaced by `issue_credential()` |
| `api/auth_scopes/resolution.py::verify_api_key_detailed` | Retain during R4.7 dual-read; retire in R4.8 | Replaced by `validate_credential()` |
