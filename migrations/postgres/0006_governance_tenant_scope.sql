DO $$
DECLARE
    col_exists BOOLEAN;
    col_not_null BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'policy_change_requests'
          AND column_name = 'tenant_id'
    )
    INTO col_exists;

    IF NOT col_exists THEN
        ALTER TABLE policy_change_requests
            ADD COLUMN tenant_id VARCHAR(128);
    END IF;

    SELECT (c.is_nullable = 'NO')
    FROM information_schema.columns c
    WHERE c.table_schema = 'public'
      AND c.table_name = 'policy_change_requests'
      AND c.column_name = 'tenant_id'
    INTO col_not_null;

    IF col_not_null THEN
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM policy_change_requests
        WHERE tenant_id IS NULL
        LIMIT 1
    ) THEN
        RAISE EXCEPTION
            'Migration 0006_governance_tenant_scope cannot enforce tenant isolation: policy_change_requests has NULL tenant_id rows. Backfill deterministically (for example: UPDATE ... SET tenant_id = <known-tenant>) and rerun migrations.';
    END IF;

    ALTER TABLE policy_change_requests
        ALTER COLUMN tenant_id SET NOT NULL;
END $$;

CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_proposed_id
    ON policy_change_requests(tenant_id, proposed_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_id_id
    ON policy_change_requests(tenant_id, id);
