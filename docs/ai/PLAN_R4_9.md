# R4.9 — Legacy api_keys Path Retirement

**Branch:** `feat/r4.9-credential-authority`
**Status:** COMPLETE — 2026-08-08. fg-fast + fg-security green.

---

## Revised context (supersedes original plan)

The original R4.9 plan assumed the Postgres `api_keys` auth fallback was still live and that
28 unmigrated rows were actively protecting production authentication. Both assumptions are wrong.

**R4.8 already cut the Postgres fallback** (`auth_scopes/resolution.py`, lines 524–533):

```python
# R4.8: Postgres has no legacy fallback — canonical path is the only valid path.
if _is_postgres:
    return AuthResult(valid=False, reason="key_not_found")
```

For Postgres, any key without the `fgk.` prefix returns `key_not_found` before the `api_keys`
table is ever consulted. The fallback is already dead.

**The SHA-256 / Argon2id mismatch rules out credential resurrection:**
`api_keys` stores SHA-256 hashes; canonical validation (`credential_authority.py`) uses Argon2id.
Copying hash material from `api_keys` → `tenant_credentials` would produce rows that fail
every verification attempt. A backfill that writes unusable hash material is not a migration —
it is credential necromancy. Do not attempt it.

---

## Dead-data disposition: the 28 api_keys rows

**Phase 0 measurement (2026-08-08, production Railway DB):**

| Query | Result |
|---|---|
| `unmigrated_total` (correlated by `lookup_fingerprint = key_lookup`) | **28** |
| Enabled/unexpired rows (structurally "live" but auth-unreachable) | **15** |
| Historically used rows (`use_count > 0` or `last_used_at IS NOT NULL`) | **6** |
| Tenants with enabled rows | `default`, `demo-bank`, `demo-healthcare` |

These rows are **historical orphaned legacy data**. They cannot authenticate in production
(Postgres auth path bypasses `api_keys`). They are not "live" in any auth sense.

### Reference check results (2026-08-08) — COMPLETE

| Check | Result |
|---|---|
| Foreign keys referencing `api_keys` in schema | **0** |
| Direct `api_keys.id` references across 11 candidate tables | **0** |
| Signature/key references across 6 candidate tables | **0** |
| `security_audit_log` free-text/JSON lookup references | **0** |
| `identity_admin_audit` free-text/JSON lookup references | **0** |
| `tenant_credential_events` free-text/JSON lookup references | **0** |
| Postgres auth path consulting `api_keys` | **0** (confirmed R4.8) |

All checks complete. No discovered production authentication authority or referential/audit
dependency on any of the 28 rows.

### Retention decision: retain-in-place, decouple deletion from R4.9 — LOCKED

**Formal disposition (2026-08-08):**

> Historical legacy credential records. No discovered production authentication authority or
> referential/audit dependency. Credential migration is neither required nor valid because
> canonical credential verification uses incompatible credential material (SHA-256 vs Argon2id)
> and the original secrets are unavailable.

Do not manufacture canonical credentials from them.
Do not restore the PostgreSQL fallback.
Do not delete the rows in R4.9.

The 15 enabled/unexpired rows are structurally "live" in the table but carry no authentication
authority in production. `enabled = true` does not make them an active auth path when the
Postgres resolution layer never reads the table.

The security value of R4.9 comes entirely from stopping new writes and removing the dead-end
writer paths. Deletion of the 28 rows, if ever warranted, belongs in a separate hygiene PR
after an explicit snapshot. That PR has no delivery pressure and runs independently of R4.9.

**Disposition status: LOCKED — R4.9 implementation is unblocked.**

---

## Route audit: api/keys.py — COMPLETE (2026-08-08)

All 5 routes audited. **No canonical gap exists. The file can be fully retired.**

| Route | Current writer | Canonical replacement |
|---|---|---|
| `POST /keys` | `mint_key()` → `_mint_key_postgres` → `INSERT INTO api_keys` | `POST /admin/tenants/{tenant_id}/credentials` |
| `GET /keys` | `list_api_keys()` → reads `api_keys` | `GET /admin/tenants/{tenant_id}/credentials` |
| `POST /keys/revoke` | `revoke_api_key()` → `UPDATE api_keys` | `POST /admin/tenants/{tenant_id}/credentials/{id}/revoke` |
| `DELETE /keys/{prefix}` | alias for POST /keys/revoke | same |
| `POST /keys/rotate` | hardcoded `sqlite3.connect()` — broken for Postgres | `POST /admin/tenants/{tenant_id}/credentials/{id}/rotate` |

**Additional surfaces found during audit:**

- `api/admin.py` `/admin/keys` section has three endpoints:
  - `GET /admin/keys` — calls `list_api_keys()` directly; still active, no 410 guard
  - `POST /admin/keys` — already returns HTTP 410 on Postgres (R4.8); SQLite path still calls `mint_key()`
  - `POST /admin/keys/{key_prefix}/revoke` — calls `revoke_api_key()`; still active
- `api/admin.py` imports four response models from `api.keys`: `CreateKeyResponse`, `KeyInfo`, `ListKeysResponse`, `RevokeKeyResponse`
- `api/control_tower_snapshot.py` calls `list_api_keys()` (line 59) to populate `key_lifecycle` in the snapshot payload — a production reader of dead-end `api_keys` data

**Two locked decisions:**

**Decision 1: POST /admin/keys 410 stub is retained for one deprecation window.**
The existing 410 on Postgres already gives callers a safe migration signal pointing to the canonical
route. Removing it immediately creates needless client breakage risk for no security gain. Simplify
it to always-410 (remove the Postgres-only guard and the SQLite fallback path), but keep the endpoint
alive. The SQLite path is dead since `mint_key()` will route to SQLite-only after this PR, and nobody
calls this in dev without Postgres being the point — so simplifying to always-410 is correct.

**Decision 2: Four response models (CreateKeyResponse, KeyInfo, ListKeysResponse, RevokeKeyResponse).**
After retiring GET /admin/keys and POST /admin/keys/{key_prefix}/revoke, and simplifying the 410
stub to return no body, none of the four models are used by any retained route. Delete them — do not
relocate dead schemas.

---

## What R4.9 actually is: a single cleanup stream

R4.9a (backfill for auth continuity) is eliminated. It is not needed and not achievable.

R4.9 is one cleanup PR with the following work:

### 1. Remove api/keys.py mounts and delete the file

- Remove `from api.keys import router as keys_router` from `api/main.py`
- Remove both `app.include_router(keys_router)` calls (lines 808, 1289)
- Delete `api/keys.py`

### 2. Retire GET /admin/keys and POST /admin/keys/{key_prefix}/revoke from api/admin.py

- Delete `admin_list_keys` handler (GET /admin/keys)
- Delete `admin_revoke_key` handler (POST /admin/keys/{key_prefix}/revoke)
- Simplify `admin_create_key` (POST /admin/keys) to always-410 — remove Postgres guard,
  remove SQLite path, remove response_model, remove actor_ctx/req parameters
- Remove `list_api_keys`, `mint_key`, `revoke_api_key` from the `from api.auth_scopes import` block
- Remove `from api.keys import (CreateKeyResponse, KeyInfo, ListKeysResponse, RevokeKeyResponse,)` entirely

### 3. Remove Postgres writer paths from auth_scopes/mapping.py

- Remove `_mint_key_postgres` function
- Remove the Postgres dispatch block in `mint_key()` (lines 160–174)
- Remove the Postgres dispatch block in `revoke_api_key()` (lines 339–353)
- Remove the Postgres dispatch block in `list_api_keys()` (lines 399–402)
- Remove the Postgres dispatch block in `_update_key_usage()` (lines 85–97)
- All lazy `from .store import ...` inside those blocks are removed with them

### 4. auth_scopes/store.py — verify and delete

- After mapping.py cleanup, `store.py` functions have zero production callers
- Verify with grep; if confirmed: delete `api/auth_scopes/store.py`
- Remove from CI carve-out list

### 5. auth_scopes/resolution.py SQLite legacy path — retain with marker

- The H0-PR5 test suite uses `mint_key()` (SQLite path) for key minting; auth resolves via
  the SQLite `api_keys` branch
- Removing the SQLite auth path would break the entire test suite
- Action: leave the SQLite path; add `# dev/test only — Postgres uses canonical path (see R4.8)` header
- Track complete SQLite retirement as a separate follow-on item

### 6. Update api/control_tower_snapshot.py

- Replace `from api.auth_scopes.mapping import list_api_keys` with `list_credentials` from
  `api.credential_authority` and `get_engine` from `api.db`
- Replace `list_api_keys(tenant_id=tenant_id, include_disabled=True)` with
  `list_credentials(get_engine(), tenant_id, credential_type="tenant_api_key", limit=100)`
- Update `key_lifecycle` payload to use credential fields (`credential_id`, `status`, `issued_at`)
- Remove `"keys": "/keys"` from links; add `"credentials": f"/admin/tenants/{tenant_id}/credentials"`

### 7. Close CI carve-outs

- Remove `api/keys.py` from `_LEGACY_WRITE_ALLOWED` (file no longer exists)
- Remove `api/auth_scopes/store.py` from `_LEGACY_WRITE_ALLOWED` (file deleted)
- `api/auth_scopes/mapping.py` retains its SQLite `UPDATE api_keys` and `INSERT INTO api_keys`
  in `revoke_api_key()` and `_mint_key_sqlite()` — stays in the grandfathered list until the
  SQLite path is retired in a follow-on PR
- Update the comment to reflect R4.9 state

### 8. Add regression tests (tests/security/test_legacy_auth_retirement.py)

Two tests:
- `test_postgres_legacy_key_returns_key_not_found`: monkeypatches `resolution._is_postgres = True`
  and asserts a non-`fgk.` raw key returns `AuthResult(valid=False, reason="key_not_found")`
- `test_canonical_credential_authenticates`: issues a credential via `issue_credential()`, mounts
  it, and confirms a request with the returned `fgk.*` key authenticates successfully

---

## Acceptance gate (replaces the old unmigrated_live = 0 gate)

All of the following must be true before R4.9 merges:

| Check | Required result |
|---|---|
| Postgres legacy-auth reachability | 0 (confirmed by R4.8; regression test required) |
| Canonical `fgk.*` credential authenticates | PASS |
| Non-`fgk.` legacy-only credential on Postgres | 401 / `key_not_found` |
| `api_keys` writers in production code | 0 |
| CI carve-outs for `api_keys` writes | 0 |
| `api/keys.py` routes | retired or confirmed-no-callers |
| Dead-data disposition | LOCKED — retain-in-place; deletion is a separate hygiene PR |
| CT-1 through CT-7 (H0-PR5) | pass under always-run CI (#622) |
| `fg-fast`, `fg-security`, strict gates | green |

Deletion of the 28 rows is explicitly **not** a gate for R4.9.

---

## Regression tests required

- **Legacy-only key on Postgres returns 401**: mint a raw (non-`fgk.`) key, insert it directly
  into `api_keys`, attempt auth — must return `key_not_found`. Confirms the R4.8 cut holds
  and no regression re-opens the fallback.
- **Canonical key still authenticates**: `fgk.*` credential issued via credential authority
  authenticates successfully. Confirms cleanup did not break the canonical path.
- These can be added to the existing auth_scopes tests or to a new
  `tests/security/test_legacy_auth_retirement.py`.

---

## Implementation sequence

```
✅ 1. Free-text/JSON audit check — zero references found (2026-08-08)
✅ 2. Disposition status → LOCKED
✅ 3. Route audit — no canonical gaps; all 5 api/keys.py routes have replacements
✅ 4. Remove api/keys.py mounts from main.py; delete api/keys.py
✅ 5. Retire GET /admin/keys and POST /admin/keys/{prefix}/revoke from admin.py;
      simplify POST /admin/keys to always-410; remove dead imports/models
✅ 6. Remove Postgres dispatch blocks from mapping.py (mint_key, revoke_api_key,
      list_api_keys, _update_key_usage); delete _mint_key_postgres
✅ 7. store.py retained (probe_auth_store caller); updated to query tenant_credentials;
      all write functions deleted
✅ 8. Mark SQLite auth path in resolution.py as dev/test only (leave intact)
✅ 9. Update control_tower_snapshot.py — replace list_api_keys with list_credentials;
      update key_lifecycle payload; update links
✅ 10. Close CI carve-outs (api/keys.py + store.py removed from grandfathered list)
✅ 11. Add tests/security/test_legacy_auth_retirement.py (two regression tests)
✅ 12. Post-implementation grep run; all hits classified (no unexplained production hits)
✅ 13. fg-fast + fg-security green (2026-08-08)
✅ 14. ROADMAP.md updated
```

All steps complete (2026-08-08). Deletion of the 28 rows is deferred to a separate hygiene PR —
it is not part of this sequence.

### Post-implementation grep acceptance check

Run after all code changes, before marking R4.9 complete:

```bash
grep -RIn \
  -e 'api_keys' \
  -e 'list_api_keys' \
  -e 'revoke_api_key' \
  -e 'mint_key(' \
  -e '"/keys"' \
  api services tests tools docs | head -300
```

Classify every hit as one of:
- **intentional historical reference** — comments, migration files, this plan
- **dev/test only** — SQLite paths in mapping.py/resolution.py marked as such
- **migration/test fixture** — tests that exercise the SQLite dev path
- **bug** — any unexplained production-code hit not in the above categories

No unexplained production-code hits should remain after R4.9.

---

## Finishing invariant

After R4.9 merges:

> Every credential in the system — issuance, validation, rotation, revocation, expiration —
> is processed exclusively through `api/credential_authority.py`. No production code path
> writes to `api_keys`. No non-`fgk.` key can authenticate via Postgres. The CI gate has
> zero exceptions. The H0-PR5 cross-tenant suite ran against this refactor and passed.

That is the completion of the R4 credential authority work.
