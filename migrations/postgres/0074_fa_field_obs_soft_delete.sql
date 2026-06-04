-- PR Sprint-3: soft-delete and edit support for fa_field_observations
--
-- Replay-safe:
-- fa_field_observations may be ORM-managed and absent during pure SQL replay.

DO $$
BEGIN
    IF to_regclass('public.fa_field_observations') IS NOT NULL THEN
        ALTER TABLE fa_field_observations
            ADD COLUMN IF NOT EXISTS updated_at VARCHAR(64),
            ADD COLUMN IF NOT EXISTS deleted_at VARCHAR(64);
    END IF;
END $$;

DO $$
BEGIN
    IF to_regclass('public.fa_field_observations') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS ix_fa_field_obs_not_deleted
            ON fa_field_observations (engagement_id, tenant_id)
            WHERE deleted_at IS NULL;
    END IF;
END $$;
