# PR-AUTH-004 — Runtime Principal Authority Cutover

**Phase:** 4 of the identity authority track — runtime cutover
**Status:** ships with PR-AUTH-004
**Depends on:** PR-AUTH-001 (#650), PR-AUTH-002 (#652), PR-AUTH-003A (#653),
PR-AUTH-003B (#654), PR-AUTH-003C, HARD-001 (#657)
**Normative source:** `docs/architecture/IDENTITY_AUTHORITY_DATA_MODEL.md`
**Related:** `docs/architecture/PR_AUTH_003_RECONCILIATION.md`,
`docs/architecture/HARD_001_IDENTITY_AUTHORITY_HARDENING.md`

---

## Purpose

Before PR-AUTH-004, `admin_gateway/identity/invitation_flow.py` flipped
`tenant_users.identity_binding_status` to `'bound'` **without** populating
`tenant_users.principal_id`. HARD-001 documented this bug as the reason the
`chk_bound_requires_principal_id` CHECK could not be enforced in migration
0182 without breaking every invitation acceptance.

PR-AUTH-004 fixes the buggy write order and cuts the runtime binding path
over to the canonical `fg_principals` / `fg_external_identities` authority
that PR-AUTH-001…003C created and reconciled. It is the corresponding
runtime change that HARD-001 explicitly deferred:

> "The partial NOT NULL invariant (BOUND rows require principal_id) has
> been deferred to the runtime authority cutover PR that also updates
> `admin_gateway/identity/invitation_flow.py` to set `principal_id` when
> transitioning a membership to 'bound'."

---

## What PR-AUTH-004 changes

### A. `api/principal_authority.py` — canonical resolver

New function:

```python
def resolve_or_create_principal_for_external_identity(
    conn: Connection | Session,
    *,
    provider: str,
    issuer: str,
    subject: str,
    display_name: str | None = None,
    primary_email: str | None = None,
    provider_email: str | None = None,
) -> PrincipalResolution
```

Behavior:

1. Validate the canonical triple. Raises `PrincipalResolutionError` with
   codes `INVALID_ISSUER`, `INVALID_SUBJECT`, or `UNKNOWN_PROVIDER`.
2. Look up `fg_external_identities` by `(provider, provider_issuer,
   provider_subject)`. If found:
   - If the linked `fg_principals.lifecycle_state` is `'active'` → return
     `PrincipalResolution(created=False)` with the existing principal_id.
   - Otherwise → raise `PrincipalResolutionError("PRINCIPAL_INACTIVE")`.
     Fail closed per ADR-IDENTITY-003.
3. If not found: INSERT `fg_principals` (lifecycle_state='active',
   principal_type='human', mfa_verified=False, authority_version=1) + INSERT
   `fg_external_identities` with the canonical triple. Return
   `PrincipalResolution(created=True)`.
4. If the INSERT races with a concurrent binder and hits
   `uq_fg_external_identities_binding`, the `IntegrityError` is caught, the
   winner is resolved via a repeat lookup, and its principal_id is returned.
   Never creates duplicates.

Idempotent: repeated calls with the same triple return the same
`principal_id` (unless the principal is deactivated between calls).

Never logs raw `subject`. `PrincipalResolutionError.__str__` and
`__repr__` are subject-free — safe for logs and API surfaces.

New dataclass `PrincipalResolution(principal_id, external_identity_id,
created)`.

New exception `PrincipalResolutionError(code, message)`.

### B. `admin_gateway/identity/invitation_flow.py` — atomic BOUND write

The `bind_identity` function is rewritten so the BOUND transition is atomic
with the canonical principal linkage:

```
Before (buggy):
    1. Set membership.identity_provider / issuer / subject
    2. Set membership.identity_binding_status = 'bound'   ← BUG: no principal_id
    3. db.flush()

After (canonical):
    1. Validate the canonical triple (mypy-narrow + fail-closed guard).
    2. resolve_or_create_principal_for_external_identity(...)
       → returns PrincipalResolution(principal_id, ...)
    3. membership.principal_id = resolution.principal_id
    4. Set legacy identity_provider / issuer / subject
       (preserved during migration window per §8 of frozen data model).
    5. membership.identity_binding_status = 'bound'
    6. db.flush()   ← all three invariants satisfied atomically
```

**Error handling fix.** The buggy version wrapped `db.flush()` in a bare
`except IntegrityError` that re-raised every FK / unique / check violation
as `IDENTITY_ALREADY_BOUND (409)`. This hid legitimate faults (principal FK
violation, canonical CHECK violation once it ships) behind a misleading
label. The new code:

- Maps a collision on the shadow index `uq_tenant_users_bound_identity` (or
  any conflict mentioning `identity_subject`) → `IDENTITY_ALREADY_BOUND
  (409)` (preserves existing cross-tenant subject-collision test).
- Maps a `principal_id` / `fg_principals` FK failure → new explicit code
  `PRINCIPAL_LINKAGE_INVALID (500)`.
- Maps any other IntegrityError → `IDENTITY_BINDING_FAILED (500)`.
- Resolver failures propagate their own explicit code (`UNKNOWN_PROVIDER`,
  `INVALID_SUBJECT`, `INVALID_ISSUER`, `PRINCIPAL_INACTIVE`,
  `RESOLVER_RACE_UNRESOLVED`) rather than being remapped.

### C. `admin_gateway/identity/models.py`

Add `principal_id` ORM column mapping to the admin-gateway `TenantUser`
model so the binding flow can write it. Nullable (matches the DB schema —
UNBOUND rows legitimately have NULL principal_id).

### D. Test fixture fix

`tests/test_admin_gateway_identity_enforcement.py` used
`PROVIDER = "oidc"` — a non-canonical string not in the frozen provider
enum. Changed to `PROVIDER = "oidc_generic"` (the canonical value). The
resolver would have rejected the old value with `UNKNOWN_PROVIDER`. This
brings the test in line with the frozen data model.

---

## Deployment order decision: SPLIT

The `chk_bound_requires_principal_id` CHECK constraint documented in
HARD-001 as pending this PR is **not** included here. Rationale:

- Deploy order in this repository is not guaranteed to place all replicas
  of the new application code strictly before migrations run. Migrations
  are applied via an explicit external step (`python api/db_migrations.py
  --backend postgres --apply`); the app image and the migration job can
  run in different orders across environments.
- If the CHECK constraint is added while any replica is still running the
  pre-cutover code (which flips `identity_binding_status='bound'` without
  setting `principal_id`), every invitation acceptance under that replica
  will hit a check-constraint violation. Because the code re-raises the
  `IntegrityError` shape, users see the misleading `IDENTITY_ALREADY_BOUND
  (409)` error.
- The safe sequence is:
  1. **PR-AUTH-004** (this PR) — ship the runtime cutover.
  2. Prove in production: every newly-bound row has a populated
     `principal_id`. Rerun AUTH-003C reconciliation → `migration_closed=True`.
  3. **HARD-002** — add migration 0183 with the CHECK
     constraint using `NOT VALID + VALIDATE CONSTRAINT`. Deployment is
     safe because every replica is now running the resolver.
  4. **AUTH cleanup** (future follow-up) — drop the shadow index
     `uq_tenant_users_bound_identity` and the legacy `identity_*` columns.

This is the same split pattern used by HARD-001 (which itself was split
from AUTH-003C for the same reason).

---

## Ownership boundaries preserved

- `api/principal_authority.py` remains the sole writer of `fg_principals`
  and `fg_external_identities` (per §Ownership Boundaries in the frozen
  data model).
- The invitation flow calls the resolver through the module's public API;
  it does not construct INSERTs to those tables directly.
- No new writers of `tenant_users` are introduced. The flow already owned
  the BOUND transition; it now sets `principal_id` in the same write.

---

## Session / token impact

None in this PR. Session issuance continues to read the membership record
via `admin_gateway.identity.session_service.build_tenant_session_context`,
which returns a `TenantSessionContext` derived from `TenantUser.role`,
`identity_provider`, `identity_issuer`, and `identity_subject`. A future
canonical-session PR may add `principal_id` to the session claims and
switch the role/permission derivation to route via `fg_principals`; that
is out of scope here.

---

## RBAC preservation

The resolver never reads or writes any role table (`tenant_users.role`,
`tenant_credential_roles`, etc.). Roles remain membership-scoped per the
frozen data model. Test group I asserts this at source level.

---

## Concurrency strategy

Two writers may attempt to create a canonical binding for the same IdP
identity simultaneously. The strategy:

1. Both call `resolve_or_create_principal_for_external_identity`.
2. Both see "no existing external identity" (race window).
3. Both attempt `INSERT INTO fg_external_identities`.
4. The unique constraint `uq_fg_external_identities_binding` allows exactly
   one INSERT to succeed. The loser's INSERT raises `IntegrityError`.
5. The loser's resolver catches the error and re-lookups. It returns the
   winner's `principal_id`. Both callers proceed with the same principal.

Test G1 exercises this path with a real unique-index conflict.

If the re-lookup returns nothing (extremely unlikely — implies non-atomic
constraint semantics), the resolver raises
`RESOLVER_RACE_UNRESOLVED (500)` — fail closed rather than silently
duplicate.

---

## Lifecycle enforcement

The resolver denies bindings against principals in `suspended` or
`deactivated` states with `PrincipalResolutionError("PRINCIPAL_INACTIVE")`.
Tests H1 and H2 verify both branches.

The invitation flow surfaces `PRINCIPAL_INACTIVE` as `IdentityFlowError`
with HTTP 409. This is the correct semantics: the invitation cannot bind
because the canonical identity has been retired.

---

## Privacy behavior

- `PrincipalResolutionError` messages never contain the offending
  `subject`. Tests M1 and M2 verify this for both the unknown-provider
  and inactive-principal paths.
- The resolver's `log.warning` and `log.info` calls use structured `extra`
  fields for `lifecycle_state` only — no subject, no email.
- The invitation flow's `_audit_rejection` call already emits
  `identity_subject` only via the audit table (which is the canonical
  place to record it — SOC 2 evidence). It never appears in an HTTP
  response body or an application log line.

---

## Legacy column preservation

Per §8 of the frozen data model, `tenant_users.identity_provider`,
`identity_issuer`, `identity_subject`, `identity_binding_status`, and
related columns remain populated by the invitation flow after cutover.
They are **shadow authorities** — written for backward compat, audit, and
rollback evidence during the migration window; not read for authorization
decisions in canonical mode.

Removal of these columns is a separate post-cutover cleanup PR, not part
of this one.

---

## Rollback strategy

If the runtime cutover needs to be reverted:

1. Revert the invitation_flow.py change. The old code will resume flipping
   `identity_binding_status='bound'` without setting `principal_id`.
2. `principal_id` values already populated by the new code are safe to
   leave in place — they are additive and referentially valid.
3. Because migration 0183 (the CHECK) is *not* in this PR, no schema
   change needs to be rolled back.

If a bad principal was created by mistake, a targeted `UPDATE tenant_users
SET principal_id = NULL WHERE …` followed by `DELETE FROM
fg_external_identities WHERE …` and `DELETE FROM fg_principals WHERE …` is
safe (no FK dependencies from downstream tables under this PR).

---

## Test coverage

`tests/test_pr_auth_004_runtime_principal_authority_cutover.py` — 39 tests
across 14 groups (see module docstring). Highlights:

- Group A (contract): resolver module, signature, dataclass shape.
- Group B (semantics): create / resolve / idempotent / malformed / unknown.
- Group C (atomicity): source-level assertions on the write order in the
  binding flow.
- Group D (invariant): application-level guarantee that BOUND is never
  set without principal_id — the invariant HARD-002 will enforce at DB
  layer later.
- Group E (multi-tenant): same IdP identity → one principal.
- Group F (no fallback): resolver does not read tenant_users; canonical
  import is unconditional.
- Group G (concurrency): unique-index race resolves to a single principal.
- Group H (lifecycle): suspended/deactivated denied.
- Group I (RBAC): resolver does not touch roles.
- Group J (session/token): no new claim added by this PR.
- Group K (legacy preservation): identity_* columns still written.
- Group L (regression): AUTH-003C reconciliation and HARD-001 trigger
  intact.
- Group M (privacy): raw subject never appears in error text or repr.
- Group N (deployment order): migration 0183 intentionally belongs to HARD-002.
- Group P (error semantics): explicit codes preserved; no remap to
  IDENTITY_ALREADY_BOUND for resolver errors.

---

## What comes after PR-AUTH-004

1. **Production proof** — deploy this PR, rerun AUTH-003C reconciliation,
   confirm every newly-bound row has principal_id.
2. **HARD-002** — add migration 0183 with the
   `chk_bound_requires_principal_id` CHECK using
   `NOT VALID + VALIDATE CONSTRAINT`.
3. **Session cutover** — switch session issuance to derive role /
   permissions via `fg_principals` → membership rather than the shadow
   identity columns.
4. **Legacy column drop** — remove `tenant_users.identity_*` and the
   `uq_tenant_users_bound_identity` partial index.

Each is a distinct PR with its own preflight and rollback plan.
