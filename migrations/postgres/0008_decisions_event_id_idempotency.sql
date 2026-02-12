DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM decisions
        WHERE event_id IS NOT NULL
        GROUP BY tenant_id, event_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Migration 0008_decisions_event_id_idempotency cannot enforce idempotency: duplicate (tenant_id, event_id) rows already exist in decisions.';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_decisions_tenant_event_id
    ON decisions(tenant_id, event_id)
    WHERE event_id IS NOT NULL;

COMMENT ON INDEX uq_decisions_tenant_event_id IS
    'Correctness guardrail for ingest idempotency (not a performance index): enforces tenant-scoped uniqueness of client-generated stable event_id values.';
