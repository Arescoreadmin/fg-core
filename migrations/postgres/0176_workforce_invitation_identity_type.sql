-- 0176: Add identity_type column to tenant_invitations.
--
-- The Python model (TenantInvitation) declared identity_type but no migration
-- was ever written for the table column.  The column exists on tenant_users
-- and tenant_identity_audit_events (both added in 0099) but was missed on
-- tenant_invitations, causing POST /workforce/users to 500 on flush.
--
-- Nullable to match the model and avoid backfill on existing rows.

ALTER TABLE tenant_invitations
  ADD COLUMN IF NOT EXISTS identity_type VARCHAR(32);
