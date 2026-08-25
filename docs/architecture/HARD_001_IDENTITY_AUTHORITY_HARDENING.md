# HARD-001 — Canonical Identity Version Trigger Hardening

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

HARD-001 changes **no runtime behavior**. It adds the `fg_principals`
authority_version trigger. The BOUND membership `principal_id` CHECK was split
out and is enforced by HARD-002 / migration 0183 after PR-AUTH-004 shipped the
runtime write ordering.

---

## What HARD-001 adds

Migration `0182_identity_authority_hardening.sql`:

### A. `fg_principal_authority_version_enforce` trigger on `fg_principals`

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

### B. Intentional omissions

- **No `authority_version` on `fg_external_identities`.** The frozen data
  model does not define such a field. Introducing one here would extend the
  contract without an architectural decision.
- **No trigger on `tenant_users.membership_version` / `authority_version`.**
  The rename `membership_version → authority_version` is scheduled as
  migration `0186` (`IDENTITY_AUTHORITY_DATA_MODEL.md` §Migration Sequence)
  under a future PR. HARD-001 does not preempt it.
- **No trigger on `tenants.canonical_version`.** Scheduled as migration
  `0185` in a future PR.
- **No `chk_bound_requires_principal_id` CHECK in migration 0182.** That
  invariant is enforced by HARD-002 / migration 0183 after PR-AUTH-004 proved
  the runtime sets `principal_id` before transitioning to `bound`.
- **No changes to `api/principal_authority.py`.** Application-layer version
  management is unchanged. The DB trigger is a mirror; explicit app-layer
  bumps are respected.

### C. Non-goals

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
   SELECT tgname, tgenabled
     FROM pg_trigger
    WHERE tgname = 'fg_principals_authority_version_bump';
   -- expected: 1 row, tgenabled = 'O'
   ```
4. Smoke-test:
   ```sql
   -- Should succeed and NOT bump authority_version
   UPDATE fg_principals SET updated_at = NOW() WHERE id = <any-id>;

   -- Should bump authority_version by 1
   UPDATE fg_principals SET display_name = 'Renamed' WHERE id = <any-id>;
   ```

---

## Rollback

```sql
DROP TRIGGER  IF EXISTS fg_principals_authority_version_bump
    ON fg_principals;

DROP FUNCTION IF EXISTS fg_principal_authority_version_enforce();
```

The rollback is safe: the HARD-001 trigger has no downstream FK dependencies.

---

## Test strategy

`tests/test_hard_001_identity_authority_hardening.py` covers:

- **Group A** — migration structure (file present, correct dependencies,
  no destructive DML, idempotent guards).
- **Group B** — BOUND state compatibility before HARD-002.
- **Group C** — trigger source-level structure (BEFORE UPDATE, meaningful
  column set, `IS DISTINCT FROM` null-safety, monotonicity guard, no
  recursion).
- **Group D** — negative assertions on `fg_external_identities` (nothing
  added).
- **Group E** — negative assertions on `tenant_users` versioning (deferred
  to 0185/0186).
- **Group F** — monotonicity source assertions.
- **Group G** — bulk / transaction behavior for rows unaffected by HARD-001.
- **Group H** — AUTH regression stability (imports clean, AUTH-00X test
  counts unchanged).
- **Group I** — reconciliation compatibility (`migration_closed=True`
  survives HARD-001).
- **Group J** — runtime auth unchanged (static file / import surface).
- **Group K** — privacy (trigger source carries no raw subject).
- **Group L** — Postgres semantics documented (trigger correctness requires
  Postgres; SQLite tests validate trigger source shape).

Trigger runtime correctness (end-to-end no-op / meaningful / monotonic
behavior) requires Postgres and is out of scope for the default SQLite
test lane. A follow-up may add end-to-end runtime tests under the
`FG_POSTGRES_TESTS=1` lane via `tests/postgres/conftest.py`.

---

## After HARD-001

The next authority-track PRs are:

1. **HARD-002** — enforce `chk_bound_requires_principal_id` in migration 0183.
2. **AUTH session cutover** — session issuance reads `principal_id →
   fg_external_identities → fg_principals` instead of `tenant_users.identity_*`.
3. **Legacy column drop** — remove `tenant_users.identity_*` and the
   `uq_tenant_users_bound_identity` partial index once cutover is proven in
   production.
4. **`tenants.canonical_version` trigger (migration 0185)** — enforces the
   BFF staleness contract at the DB layer.
5. **`tenant_users.membership_version → authority_version` rename
   (migration 0186)** — plus the analogous trigger on `tenant_users`.

Each is a distinct PR with its own preflight and rollback plan.
