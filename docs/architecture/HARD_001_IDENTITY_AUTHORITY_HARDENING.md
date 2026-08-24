# HARD-001 — Canonical Identity Version Triggers + Bound-State Integrity Hardening

**Phase:** Constraint hardening on top of the frozen identity authority model
**Status:** ships with HARD-001
**Depends on:** PR-AUTH-001 (#650), PR-AUTH-002 (#652), PR-AUTH-003A (#653),
PR-AUTH-003B (#654), PR-AUTH-003C
**Normative source:** `docs/architecture/IDENTITY_AUTHORITY_DATA_MODEL.md`
**Related:** `docs/architecture/PR_AUTH_003_RECONCILIATION.md`

---

## Purpose

AUTH-003C proves the data-migration phase is *closable*
(`migration_closed=True`). HARD-001 is the follow-on that materializes the
already-proven invariants as DB-layer constraints and triggers — defense in
depth against future regressions from ad-hoc SQL, application bugs, or
future code that forgets the invariant.

HARD-001 changes **no runtime behavior**. It adds guardrails that already
hold true today; it fails-closed if a caller ever violates them tomorrow.

---

## What HARD-001 adds

Migration `0182_identity_authority_hardening.sql`:

### A. `chk_bound_requires_principal_id` CHECK on `tenant_users`

```sql
CHECK (
    identity_binding_status <> 'bound'
    OR principal_id IS NOT NULL
)
```

**BOUND predicate:** `identity_binding_status = 'bound'`.

This is the canonical predicate used by the pre-existing partial index
`uq_tenant_users_bound_identity` and is the exact predicate cited in
`IDENTITY_AUTHORITY_DATA_MODEL.md` §2 and §8 for membership rows that carry
authoritative identity.

**Effect:**
- `unbound`, `pending`, `disabled`, `failed` rows may keep `principal_id = NULL`
  (UNBOUND lifecycle preserved — see `PR_AUTH_003_RECONCILIATION.md`).
- `bound` rows must have a non-NULL `principal_id`.
- Attempts to transition an UNBOUND row to `'bound'` without simultaneously
  supplying `principal_id` fail with a check-constraint violation.
- Attempts to null out `principal_id` on a row that remains `'bound'` fail.

**Deployed with `NOT VALID` + `VALIDATE CONSTRAINT`** so the initial DDL is a
brief metadata operation and the row scan happens under `SHARE UPDATE
EXCLUSIVE` (does not block concurrent readers/writers). Deployment is
guarded by the AUTH-003C pre-deployment check: `migration_closed=True` in
every environment before shipping this migration.

### B. `fg_principal_authority_version_enforce` trigger on `fg_principals`

BEFORE UPDATE trigger that maintains the `authority_version` invariant:

- **Meaningful columns** (any change → bump): `display_name`, `primary_email`,
  `lifecycle_state`, `mfa_verified`.
- **Non-meaningful** (change → NOT a bump): `updated_at` (server_default
  now()), `created_at` (immutable), `authority_version` itself.
- **No-op update** (all meaningful columns unchanged): the trigger restores
  `NEW.authority_version := OLD.authority_version`. A caller cannot bump the
  version via an empty write.
- **Meaningful update**: if the caller supplied `NEW.authority_version <=
  OLD.authority_version` (including NULL), the trigger sets
  `NEW.authority_version := OLD.authority_version + 1`. If the caller
  supplied a strictly higher value (bulk-skip semantics), the trigger accepts
  it.
- **Absolute monotonicity guard**: `NEW.authority_version` can never end up
  strictly less than `OLD.authority_version`, regardless of prior branches.
- **Recursion safety**: the trigger computes `NEW.*` only. It never issues
  its own UPDATE — no risk of re-entrance.
- **Rollback restores value**: because the trigger runs BEFORE UPDATE and
  the caller's transaction owns the write, `ROLLBACK` restores the previous
  version exactly as if the update never happened.

### C. Intentional omissions

- **No `authority_version` on `fg_external_identities`.** The frozen data
  model does not define such a field. Introducing one here would extend the
  contract without an architectural decision.
- **No trigger on `tenant_users.membership_version` / `authority_version`.**
  The rename `membership_version → authority_version` is scheduled as
  migration `0186` (`IDENTITY_AUTHORITY_DATA_MODEL.md` §Migration Sequence)
  under a future PR. HARD-001 does not preempt it.
- **No trigger on `tenants.canonical_version`.** Scheduled as migration
  `0185` in a future PR.
- **No changes to `api/principal_authority.py`.** Application-layer version
  management is unchanged. The DB trigger is a mirror; explicit app-layer
  bumps are respected.

### D. Non-goals

HARD-001 explicitly does **not**:

- Cut over the runtime auth path (still reads `tenant_users.identity_*`).
- Drop legacy `tenant_users.identity_*` columns.
- Drop the `uq_tenant_users_bound_identity` partial index.
- Add global `NOT NULL` to `tenant_users.principal_id` (would break UNBOUND
  lifecycle — see `PR_AUTH_003_RECONCILIATION.md`).
- Run any identity backfill (AUTH-003B already did that).
- Auto-repair inconsistent data (fail-closed is intentional).
- Perform fuzzy matching or principal merging.

---

## Deployment procedure

Per environment:

1. Confirm AUTH-003C `migration_closed=True` fingerprint on record.
2. Apply migration 0182 via the standard `python tools/db_apply_migrations.py`
   path (or equivalent Railway/CI job).
3. Verify:
   ```sql
   SELECT COUNT(*)
     FROM pg_constraint
    WHERE conname = 'chk_bound_requires_principal_id'
      AND conrelid = 'tenant_users'::regclass;
   -- expected: 1

   SELECT tgname, tgenabled
     FROM pg_trigger
    WHERE tgname = 'fg_principals_authority_version_bump';
   -- expected: 1 row, tgenabled = 'O'
   ```
4. Smoke-test:
   ```sql
   -- Should raise: chk_bound_requires_principal_id violation
   INSERT INTO tenant_users (id, tenant_id, email, display_name,
                             identity_binding_status)
   VALUES ('probe', 'probe-tenant', 'p@example.com', 'Probe', 'bound');

   -- Should succeed and NOT bump authority_version
   UPDATE fg_principals SET updated_at = NOW() WHERE id = <any-id>;

   -- Should bump authority_version by 1
   UPDATE fg_principals SET display_name = 'Renamed' WHERE id = <any-id>;
   ```

If step 2 fails at `VALIDATE CONSTRAINT`, the deployment aborts and the
constraint is not enforced. This is correct: HARD-001 must not silently
create an invariant that current data violates.

---

## Rollback

```sql
ALTER TABLE tenant_users
    DROP CONSTRAINT IF EXISTS chk_bound_requires_principal_id;

DROP TRIGGER  IF EXISTS fg_principals_authority_version_bump
    ON fg_principals;

DROP FUNCTION IF EXISTS fg_principal_authority_version_enforce();
```

The rollback is safe: neither artifact has downstream FK dependencies.

---

## Test strategy

`tests/test_hard_001_identity_authority_hardening.py` covers:

- **Group A** — migration structure (file present, correct dependencies,
  no destructive DML, idempotent guards, NOT VALID + VALIDATE pattern).
- **Group B** — BOUND state CHECK constraint runtime behavior in SQLite
  (the CHECK is dialect-portable).
- **Group C** — trigger source-level structure (BEFORE UPDATE, meaningful
  column set, `IS DISTINCT FROM` null-safety, monotonicity guard, no
  recursion).
- **Group D** — negative assertions on `fg_external_identities` (nothing
  added).
- **Group E** — negative assertions on `tenant_users` versioning (deferred
  to 0185/0186).
- **Group F** — monotonicity source assertions.
- **Group G** — bulk / transaction behavior for the CHECK.
- **Group H** — AUTH regression stability (imports clean, AUTH-00X test
  counts unchanged).
- **Group I** — reconciliation compatibility (`migration_closed=True`
  survives HARD-001).
- **Group J** — runtime auth unchanged (static file / import surface).
- **Group K** — privacy (trigger + constraint messages carry no raw subject).
- **Group L** — Postgres semantics documented (trigger correctness requires
  Postgres; SQLite tests validate constraint logic + trigger source shape).

Trigger runtime correctness (end-to-end no-op / meaningful / monotonic
behavior) requires Postgres and is out of scope for the default SQLite
test lane. A follow-up may add end-to-end runtime tests under the
`FG_POSTGRES_TESTS=1` lane via `tests/postgres/conftest.py`.

---

## After HARD-001

The next authority-track PRs are:

1. **AUTH cutover** — session issuance reads `principal_id → fg_external_
   identities → fg_principals` instead of `tenant_users.identity_*`.
2. **Legacy column drop** — remove `tenant_users.identity_*` and the
   `uq_tenant_users_bound_identity` partial index once cutover is proven in
   production.
3. **`tenants.canonical_version` trigger (migration 0185)** — enforces the
   BFF staleness contract at the DB layer.
4. **`tenant_users.membership_version → authority_version` rename
   (migration 0186)** — plus the analogous trigger on `tenant_users`.

Each is a distinct PR with its own preflight and rollback plan.
