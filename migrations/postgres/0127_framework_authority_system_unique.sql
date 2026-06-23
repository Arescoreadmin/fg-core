-- Migration 0127: NULL-safe uniqueness for SYSTEM-scope framework rows
--
-- UniqueConstraint("scope_type","tenant_id","framework_key","version") does not
-- prevent duplicate SYSTEM rows because PostgreSQL treats NULLs as distinct in
-- unique constraints.  A partial unique index on the system namespace closes the
-- gap without affecting TENANT rows (which have non-NULL tenant_id and are
-- already protected by the multi-column constraint).

CREATE UNIQUE INDEX IF NOT EXISTS uq_fa_frameworks_system_identity
    ON fa_frameworks (framework_key, version)
    WHERE scope_type = 'SYSTEM';
