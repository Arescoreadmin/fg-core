-- PR 104: Add client_access_code column to fa_engagements
-- Generated at QA-approve time; null until first QA approval.
--
-- Replay-safe:
-- fa_engagements is ORM-managed in some environments and may not exist during
-- pure SQL migration replay. Guard the ALTER so clean Postgres replay does not
-- fail before ORM-managed field-assessment tables are created.

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'fa_engagements'
    ) THEN
        ALTER TABLE fa_engagements
            ADD COLUMN IF NOT EXISTS client_access_code VARCHAR(64);
    END IF;
END $$;
