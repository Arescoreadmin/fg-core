-- PR Sprint-3: soft-delete and edit support for fa_field_observations
ALTER TABLE fa_field_observations
    ADD COLUMN IF NOT EXISTS updated_at VARCHAR(64),
    ADD COLUMN IF NOT EXISTS deleted_at VARCHAR(64);

CREATE INDEX IF NOT EXISTS ix_fa_field_obs_not_deleted
    ON fa_field_observations (engagement_id, tenant_id)
    WHERE deleted_at IS NULL;
