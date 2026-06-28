-- PR 17.6B fix pass: RLS, no_change_count column, outcome idempotency unique index

-- ---------------------------------------------------------------------------
-- 1. RLS — fa_governance_learning_records
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_governance_learning_records') IS NOT NULL THEN
        ALTER TABLE fa_governance_learning_records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_governance_learning_records FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_glr_tenant_isolation
            ON fa_governance_learning_records;
        CREATE POLICY fa_glr_tenant_isolation
            ON fa_governance_learning_records
            USING (
                tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. RLS — fa_governance_learning_aggregates
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF to_regclass('public.fa_governance_learning_aggregates') IS NOT NULL THEN
        ALTER TABLE fa_governance_learning_aggregates ENABLE ROW LEVEL SECURITY;
        ALTER TABLE fa_governance_learning_aggregates FORCE ROW LEVEL SECURITY;

        DROP POLICY IF EXISTS fa_gla_tenant_isolation
            ON fa_governance_learning_aggregates;
        CREATE POLICY fa_gla_tenant_isolation
            ON fa_governance_learning_aggregates
            USING (
                tenant_id = current_setting('app.tenant_id', true)
                OR current_setting('app.tenant_id', true) = ''
            );
    END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Add no_change_count to fa_governance_learning_aggregates
--    Tracks neutral NO_CHANGE outcomes (delta > -1.0) that previously fell
--    outside all three buckets and caused total_count=0 on the first ingest.
-- ---------------------------------------------------------------------------

ALTER TABLE fa_governance_learning_aggregates
    ADD COLUMN IF NOT EXISTS no_change_count INTEGER NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- 4. Outcome idempotency — replace plain source_outcome_id index with a
--    partial UNIQUE index on (tenant_id, source_outcome_id).
--    WHERE clause allows multiple NULLs (outcomes without a source_outcome_id).
-- ---------------------------------------------------------------------------

DROP INDEX IF EXISTS idx_gl_record_source_outcome;

CREATE UNIQUE INDEX IF NOT EXISTS uidx_gl_record_tenant_outcome
    ON fa_governance_learning_records(tenant_id, source_outcome_id)
    WHERE source_outcome_id IS NOT NULL;
