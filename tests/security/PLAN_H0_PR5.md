# H0-PR5 Plan — Cross-Tenant Regression Suite

**Branch:** `fix/h0-pr5-cross-tenant-regression`
**Status:** IMPLEMENTED — `tests/security/test_cross_tenant_regression.py`

---

## Authority contract

| ID | Invariant | Route | Mechanism |
|---|---|---|---|
| CT-1 | Tenant B key cannot list tenant A's portal grants | `GET /portal/grants` | `require_bound_tenant` + `WHERE tenant_id = ?` |
| CT-2 | Tenant B key cannot revoke tenant A's portal grant | `DELETE /portal/grants/{id}` | `WHERE tenant_id = ?` in `revoke_grant` → 404 |
| CT-3 | Tenant B key cannot create a grant via the engagement-scoped route | `POST /field-assessment/engagements/{id}/portal-grants` | engagement ownership check (same pattern as PR4) |
| CT-4 | Tenant B key cannot read tenant A's engagement | `GET /field-assessment/engagements/{id}` | engagement ownership check |
| CT-5 | Tenant B key cannot list tenant A's engagements | `GET /field-assessment/engagements` | tenant_id scoping on list query |
| CT-6 | Error codes are uniform for cross-tenant operations — no information leakage | All of the above | `ENGAGEMENT_NOT_FOUND` / `GRANT_NOT_FOUND`, not `TENANT_MISMATCH` |
| CT-7 | Full lifecycle: create → grant → list/delete all stay within tenant boundary | All of the above, chained | Compositional |

---

## What H0-PR4 already covers (not repeated here)

- `POST /portal/grants` with cross-tenant `engagement_id` → 404 (PG-1)
- `client_id` in body → 422 (PG-2)
- `client_id` server-derived (PG-3)
- `portal_login_url` present (PG-4)

---

## File to create

**`tests/security/test_cross_tenant_regression.py`**

Single file, single test class `TestCrossTenantRegression`. Shared tenant constants:

```python
_TENANT_A = "h0pr5-ct-a-01"
_TENANT_B = "h0pr5-ct-b-01"
```

Keys needed per test:
- `gov_a` = `governance:read governance:write` scoped to A (create engagement)
- `admin_write_a` = `admin:write` scoped to A (create grant)
- `admin_write_b` = `admin:write` scoped to B (attacker)
- `admin_read_b` = `admin:read` scoped to B (attacker, for list)
- `admin_read_a` = `admin:read` scoped to A (CT-2 survival check: GET /portal/grants requires admin:read)

---

## Tests

### CT-1 — Grant list isolation

```
Setup: A creates engagement → A creates portal grant
Attack: B calls GET /portal/grants (admin:read, tenant B key)
Assert: 200 OK (B has own empty list), grant_id from A is NOT in items
```

Why this matters: `list_portal_grants` does `WHERE tenant_id = ?` but no
explicit test verifies the filter works end-to-end under auth.

### CT-2 — Grant delete isolation

```
Setup: A creates engagement → A creates portal grant → record grant_id
Attack: B calls DELETE /portal/grants/{grant_id} (admin:write, tenant B key)
Assert: 404 GRANT_NOT_FOUND
Verify: A's grant is still active (A can still list it)
```

Why this matters: `revoke_grant` has the tenant_id filter, but the cross-tenant
revoke path has never been exercised in a security test.

### CT-3 — Engagement-scoped grant route isolation

```
Setup: A creates engagement → record eng_id
Attack: B calls POST /field-assessment/engagements/{eng_id}/portal-grants
        (governance:write, tenant B key)
Assert: 404 ENGAGEMENT_NOT_FOUND (strict — 403 would reveal resource existence)
```

Why this matters: This is the OTHER grant creation route. H0-PR4 fixed
`POST /portal/grants`. The engagement-scoped route (`api/field_assessment.py`)
already uses the same ownership pattern but has no cross-tenant security test.

### CT-4 — Engagement read isolation

```
Setup: A creates engagement → record eng_id
Attack: B calls GET /field-assessment/engagements/{eng_id} (governance:read, B key)
Assert: 404 ENGAGEMENT_NOT_FOUND (strict — 403 would reveal resource existence)
```

Why this matters: Single-resource read endpoint. Confirms the ownership
check applies to reads, not just writes.

### CT-5 — Engagement list isolation

```
Setup: A creates engagement with distinctive client_name
Attack: B calls GET /field-assessment/engagements (governance:read, B key)
Assert: 200 OK, A's engagement_id and client_name NOT in items
```

Why this matters: List endpoints are common data leakage vectors. Verifies
the list query is correctly tenant-scoped.

### CT-6 — Error code uniformity (no info leakage)

```
Setup: A creates engagement + grant
Attack: B sends cross-tenant requests to:
  - POST /portal/grants (regression anchor from PG-1)
  - DELETE /portal/grants/{id}
  - GET /field-assessment/engagements/{id}
Assert: All return the canonical not-found code (ENGAGEMENT_NOT_FOUND /
        GRANT_NOT_FOUND), never TENANT_MISMATCH or any code that reveals
        the resource exists in another tenant
```

Why this matters: Uniform 404/not-found codes prevent oracle attacks where
an attacker learns whether an ID exists in the system by comparing error codes.

### CT-7 — Full lifecycle chain

```
Setup: A creates engagement → A creates grant → record both IDs
Attack sequence (all using B's key):
  1. B tries DELETE /portal/grants/{grant_id}     → 404
  2. B tries GET /portal/grants                   → grant not in list
  3. B tries POST /portal/grants {engagement_id}  → 404
  4. B tries POST /field-assessment/engagements/{id}/portal-grants → 404
  5. B tries GET /field-assessment/engagements/{id} → 404
Assert: Each step blocked; A can still use all resources after all attacks
```

Why this matters: Proves the boundary holds across the full lifecycle,
not just at a single gate.

---

## Implementation notes (for when this is executed)

- Use `build_app(auth_enabled=True, api_key="")` pattern from H0-PR4.
- `mint_key` from `api.auth_scopes` for all key generation.
- `_create_engagement` helper identical to H0-PR4.
- `_create_grant` helper: `POST /portal/grants` with `admin:write` key for A.
- CT-7 should run as a single test to keep the chain atomic.
- All tenant IDs must be unique across the test suite (prefix `h0pr5-ct-`).

---

## If CT-3 fails

If `POST /field-assessment/engagements/{id}/portal-grants` does NOT reject a
cross-tenant key, that is a new finding. Stop, report it, and fix it in a
separate PR with its own security contract and audit entry. Do not fix inline.

---

## CI gate impact

- +7 tests to `make fg-fast` (496 → ~503)
- `docs/ai/PR_FIX_LOG.md` entry required (P-63)
- No schema changes, no OpenAPI regen, no migrations
- No `ROADMAP.md` row (security regression, not a feature)

---

## Out of scope for H0-PR5

- Portal named-user cross-tenant (covered by T4 suite, 47 tests)
- Portal session hijacking (separate concern — session tokens are opaque UUIDs)
- Admin audit log isolation (covered by `test_audit_tenant_isolation.py`)
- RAG/evidence cross-tenant (covered by dedicated isolation suites)
