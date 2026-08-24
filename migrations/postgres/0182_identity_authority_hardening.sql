-- 0182_identity_authority_hardening
-- HARD-001: Canonical identity state invariants — defense-in-depth
--
-- Depends on: 0179 (fg_principals), 0180 (fg_external_identities),
--             0181 (tenant_users.principal_id)
-- Reference:  docs/architecture/IDENTITY_AUTHORITY_DATA_MODEL.md
--             docs/architecture/PR_AUTH_003_RECONCILIATION.md
--             docs/architecture/HARD_001_IDENTITY_AUTHORITY_HARDENING.md
--
-- HARDENS: canonical identity state invariants at the DB layer.
-- DOES NOT: cut over runtime identity authority. Auth code still reads
--           legacy tenant_users.identity_* columns (see AUTH cutover PR).
-- DOES NOT: drop legacy identity columns or the uq_tenant_users_bound_identity
--           partial index (see post-cutover cleanup PR).
-- DOES NOT: run any identity backfill (AUTH-003B already ran; see PR #654).
-- DOES NOT: mutate any row (zero DML in this migration).
--
-- This migration adds three defense-in-depth artifacts:
--   A. CHECK constraint on tenant_users: bound rows must have principal_id
--   B. Trigger on fg_principals: authority_version must advance monotonically
--      when a meaningful column changes; no-op updates do not bump the version
--   C. Nothing on fg_external_identities (no version field in frozen arch)
--   D. Nothing on tenant_users authority (membership_version rename is
--      scheduled as migration 0186 per data model roadmap; not owned here)
--
-- Rollback:
--   ALTER TABLE tenant_users DROP CONSTRAINT chk_bound_requires_principal_id;
--   DROP TRIGGER  IF EXISTS fg_principals_authority_version_bump ON fg_principals;
--   DROP FUNCTION IF EXISTS fg_principal_authority_version_enforce();
--
-- Lock analysis:
--   - Adding a CHECK constraint with NOT VALID acquires ACCESS EXCLUSIVE only
--     briefly for the DDL; existing rows are not scanned.
--   - VALIDATE CONSTRAINT takes SHARE UPDATE EXCLUSIVE (allows reads and
--     writes; does not block SELECT/INSERT/UPDATE/DELETE) and scans the table.
--   - CREATE FUNCTION and CREATE TRIGGER are metadata-only, brief locks.
--   - The migration is safe to run online. No table rewrite. No data movement.

-- ---------------------------------------------------------------------------
-- A. CHECK constraint: BOUND memberships require principal_id
-- ---------------------------------------------------------------------------
--
-- Canonical BOUND predicate: identity_binding_status = 'bound'
-- Rationale: see IDENTITY_AUTHORITY_DATA_MODEL.md sections 2, 8 and the
-- pre-existing uq_tenant_users_bound_identity partial index, which uses the
-- same predicate. AUTH-003B populates tenant_users.principal_id for every
-- READY row, where READY is a superset of BOUND with a complete triple.
-- AUTH-003C proves migration_closed only when every BOUND row is linked.
-- This constraint enforces that invariant at the DB layer as defense-in-depth.
--
-- UNBOUND rows (identity_binding_status IN ('unbound','pending','disabled',
-- 'failed')) legitimately have NULL principal_id and are NOT constrained.
--
-- NOT VALID first, then VALIDATE — allows CI/prod deployment against a
-- populated table without a hard AccessExclusive lock during the row scan.

DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_constraint
         WHERE conname = 'chk_bound_requires_principal_id'
           AND conrelid = 'tenant_users'::regclass
    ) THEN
        ALTER TABLE tenant_users
            ADD CONSTRAINT chk_bound_requires_principal_id
            CHECK (
                identity_binding_status <> 'bound'
                OR principal_id IS NOT NULL
            ) NOT VALID;
    END IF;
END
$do$;

-- Validate the constraint. If any legacy BOUND row lacks a principal_id, this
-- statement fails and the deployment aborts — which is the correct behavior:
-- HARD-001 must not silently create an invariant that the existing data
-- violates. The AUTH-003C reconciliation (migration_closed=True) is the
-- operator's pre-deployment gate.
ALTER TABLE tenant_users
    VALIDATE CONSTRAINT chk_bound_requires_principal_id;

-- ---------------------------------------------------------------------------
-- B. fg_principals.authority_version enforcement trigger
-- ---------------------------------------------------------------------------
--
-- Contract (from IDENTITY_AUTHORITY_DATA_MODEL.md §"Target Schema"):
--   authority_version is incremented when a meaningful column changes.
--   A no-op UPDATE (all meaningful columns unchanged) must NOT advance it.
--   It must never decrease.
--
-- Meaningful columns (identity state that a session issuer or BFF staleness
-- check must react to):
--   display_name       — visible identity label
--   primary_email      — attribute, but observable
--   lifecycle_state    — canonical active/suspended/deactivated
--   mfa_verified       — assurance-level signal
--
-- Excluded from meaning: updated_at (surrogate; would create infinite loops),
-- authority_version itself (the value being computed), created_at (immutable).
--
-- Recursion prevention: the trigger uses BEFORE UPDATE and computes the new
-- version on NEW.* only. It never issues its own UPDATE against the row.
--
-- Monotonicity: if the caller supplies a NEW.authority_version that is lower
-- than OLD.authority_version, the trigger corrects it upward. If the caller
-- supplies one strictly greater than OLD.authority_version + 1 (bulk skip),
-- the trigger accepts it (increments are inclusive of caller intent).
--
-- Defense-in-depth only. Application code (api/principal_authority.py) may
-- also bump the version explicitly; the trigger guarantees invariance even
-- when a caller forgets or an ad-hoc SQL UPDATE bypasses the app.

CREATE OR REPLACE FUNCTION fg_principal_authority_version_enforce()
RETURNS trigger
LANGUAGE plpgsql
AS $body$
DECLARE
    v_meaningful_changed BOOLEAN;
BEGIN
    -- Detect meaningful change. IS DISTINCT FROM handles NULLs correctly.
    v_meaningful_changed :=
           (NEW.display_name     IS DISTINCT FROM OLD.display_name)
        OR (NEW.primary_email    IS DISTINCT FROM OLD.primary_email)
        OR (NEW.lifecycle_state  IS DISTINCT FROM OLD.lifecycle_state)
        OR (NEW.mfa_verified     IS DISTINCT FROM OLD.mfa_verified);

    IF v_meaningful_changed THEN
        -- If the caller did not bump the version (or attempted to lower it),
        -- advance to OLD + 1. If the caller supplied a higher value, keep it
        -- (monotonic upward).
        IF NEW.authority_version IS NULL
           OR NEW.authority_version <= OLD.authority_version THEN
            NEW.authority_version := OLD.authority_version + 1;
        END IF;
    ELSE
        -- No-op UPDATE (only surrogate/timestamp columns changed). The
        -- authority_version must not advance. Restore the old value if the
        -- caller supplied anything different, and never allow a decrease.
        IF NEW.authority_version IS DISTINCT FROM OLD.authority_version THEN
            NEW.authority_version := OLD.authority_version;
        END IF;
    END IF;

    -- Absolute monotonicity guarantee (belt-and-braces).
    IF NEW.authority_version < OLD.authority_version THEN
        NEW.authority_version := OLD.authority_version;
    END IF;

    RETURN NEW;
END
$body$;

DO $do$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM pg_trigger
         WHERE tgname = 'fg_principals_authority_version_bump'
           AND tgrelid = 'fg_principals'::regclass
    ) THEN
        CREATE TRIGGER fg_principals_authority_version_bump
        BEFORE UPDATE ON fg_principals
        FOR EACH ROW
        EXECUTE FUNCTION fg_principal_authority_version_enforce();
    END IF;
END
$do$;

-- ---------------------------------------------------------------------------
-- Notes on what is INTENTIONALLY NOT here
-- ---------------------------------------------------------------------------
--
-- 1. No global `principal_id NOT NULL` on tenant_users. UNBOUND memberships
--    legitimately have NULL principal_id (see PR_AUTH_003_RECONCILIATION.md).
--    The partial constraint above is the correct scoping.
--
-- 2. No trigger on fg_external_identities. The frozen data model does not
--    define an authority_version on that table. Introducing one here would
--    extend the frozen contract without an architectural decision.
--
-- 3. No trigger on tenant_users.membership_version / authority_version. The
--    data model roadmap schedules that rename + trigger as migration 0186 in
--    a separate PR — outside HARD-001 scope.
--
-- 4. No trigger on tenants.canonical_version. That is scheduled as migration
--    0185 in a separate PR — outside HARD-001 scope.
--
-- 5. No changes to api/principal_authority.py behavior. The DB trigger is a
--    defense-in-depth mirror; application-layer version management is
--    unchanged. Any explicit bump the app performs is respected (monotonic
--    upward).
--
-- 6. No auth path change. Session issuance, token verification, RBAC, and
--    identity resolution are untouched. This migration is invisible to the
--    runtime auth path.
