# R4.9 — Canonical Credential Authority Consolidation

**Branch:** `feat/r4.9-credential-authority`
**Status:** PLAN — not yet implemented

---

## Context

The canonical authority (`api/credential_authority.py`) is complete. All routes go through it.
`tenant_credentials` writes are authority-only and CI-gated. `api/credentials.py` and
`api/key_rotation.py` are already retired. TTL definitions are centralized.

**The only remaining debt is the legacy `api_keys` path:**

- `auth_scopes/resolution.py` falls back to `api_keys` when canonical lookup fails
- `api/keys.py` and `auth_scopes/mapping.py` still write to `api_keys`
- The CI gate has an explicit carve-out for those two files

**Phase 0 measurement (2026-08-08, production Railway DB):**

| Query | Result |
|---|---|
| `unmigrated_total` (identity-correlated by `lookup_fingerprint = key_lookup`) | **28** |
| `unmigrated_live` | **> 0** (live orphans confirmed: `default`, `demo-bank`, `demo-healthcare`) |
| Decision | **Option A — R4.9a backfill required before R4.9b retirement** |

Removing the fallback without backfill would silently break authentication for all tenants
with live orphaned credentials.

---

## Locked Sequence

```
R4.9a: Backfill legacy api_keys → tenant_credentials
         ↓
       Prove unmigrated_live = 0
       Preferably unmigrated_total = 0
         ↓
R4.9b: Remove fallback + legacy writers + CI carve-outs
```

Do not invert this sequence.

---

## R4.9a — Authority-Owned Backfill

### Invariants

For every `api_keys` row the backfill must:

- Preserve tenant binding (`tenant_id`)
- Preserve lookup/key hash material exactly (`key_lookup` → `lookup_fingerprint`, `key_hash` → `secret_hash`)
- Create a canonical `tenant_credentials` row if and only if one does not already exist for that `(tenant_id, lookup_fingerprint)` pair
- Emit a `backfill_migrated` audit event to `tenant_credential_events` (not `issued` — preserves semantic distinction)
- Remain fully idempotent — safe to run multiple times; subsequent runs are no-ops
- Never duplicate an already-migrated credential
- Never broaden scope or privilege — status derived strictly from source row state

### Status mapping

| `api_keys` state | `tenant_credentials.status` |
|---|---|
| `enabled = true` AND (`expires_at IS NULL` OR `expires_at > now()`) | `active` |
| `enabled = false` | `revoked` |
| `enabled = true` AND `expires_at <= now()` | `expired` |

### Scope

Backfill **all 28 rows** (live and dead) to achieve `unmigrated_total = 0`.
This gives complete historical record in `tenant_credential_events` and avoids
any future ambiguity about whether unmigrated_total > 0 means "intentional" or "forgotten."

If dead rows are intentionally excluded from a future run, that policy must be documented
explicitly at that time. The default here is full backfill.

### Implementation location

The backfill function lives inside `api/credential_authority.py` — never outside the authority
boundary. It is **not** exposed as a route; it is called only from the migration script.

### It must NOT use `issue_credential()`

Normal issuance generates new secret material, advances slot generation, enforces tenant
lifecycle transitions, and emits `issued` events. All of those are wrong for a migration.
The backfill path accepts existing hash/fingerprint material and preserves lifecycle metadata.

### Gate before R4.9b

Re-run the Phase 0 fingerprint-correlated queries against production.
**Both must read 0 before R4.9b begins:**

```sql
SELECT COUNT(*) AS unmigrated_live
FROM api_keys ak
WHERE ak.enabled = true
  AND (ak.expires_at IS NULL OR ak.expires_at > now())
  AND NOT EXISTS (
      SELECT 1 FROM tenant_credentials tc
      WHERE tc.tenant_id = ak.tenant_id
        AND tc.credential_type = 'tenant_api_key'
        AND tc.lookup_fingerprint = ak.key_lookup
  );

SELECT COUNT(*) AS unmigrated_total
FROM api_keys ak
WHERE NOT EXISTS (
    SELECT 1 FROM tenant_credentials tc
    WHERE tc.tenant_id = ak.tenant_id
      AND tc.credential_type = 'tenant_api_key'
      AND tc.lookup_fingerprint = ak.key_lookup
);
```

**`unmigrated_live = 0` is the hard gate. `unmigrated_total = 0` is the target.**
"Migration script ran successfully" is not the gate.

---

## R4.9b — Legacy Path Retirement

### Acceptance bar (all required)

- [ ] `auth_scopes/resolution.py` — `api_keys` fallback removed; canonical path only
- [ ] `api/keys.py` — legacy writer disabled or file deleted (confirm mount status first)
- [ ] `auth_scopes/mapping.py` — legacy `api_keys` write path removed
- [ ] `tools/ci/check_credential_authority.py` — grandfathered file carve-outs for `api_keys` writes removed; `api_keys` writes added to blocked list
- [ ] Regression test: credential that exists only in `api_keys` (not in `tenant_credentials`) returns 401 after fallback removal
- [ ] Regression test: canonical credential still authenticates after fallback removal
- [ ] No tenant loses access after fallback removal (verified by Q2 = 0 gate from R4.9a)
- [ ] CT-1 through CT-7 (H0-PR5 cross-tenant suite) pass under always-run CI (#622)
- [ ] `fg-fast`, `fg-security`, and strict gates green

---

## mount status check (run before R4.9b coding)

```bash
grep -rn "from api.keys\|keys_router\|include_router.*keys\|api\.keys" api/ --include="*.py" | grep -v "__pycache__\|test_"
```

If routes are dead (not mounted), R4.9b shrinks to file deletion + fallback removal.
If live, a route audit and deprecation notice are required.

---

## Finishing invariant

After R4.9b merges:

> Every credential in the system — issuance, validation, rotation, revocation, expiration —
> is processed exclusively through `api/credential_authority.py`. Every authentication event
> has an entry in `tenant_credential_events`. No credential lifecycle operation bypasses
> tenant lifecycle checks, slot serialization, or the authority boundary. The CI gate has
> zero exceptions. The H0-PR5 cross-tenant suite ran against this refactor and passed.

That is the completion of the R4 credential authority work.
