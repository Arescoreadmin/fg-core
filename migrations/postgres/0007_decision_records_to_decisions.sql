DO $$
DECLARE
    has_decision_records BOOLEAN;
    has_decisions BOOLEAN;
BEGIN
    SELECT to_regclass('public.decision_records') IS NOT NULL INTO has_decision_records;
    SELECT to_regclass('public.decisions') IS NOT NULL INTO has_decisions;

    IF has_decision_records AND NOT has_decisions THEN
        ALTER TABLE decision_records RENAME TO decisions;
        has_decisions := TRUE;
        has_decision_records := FALSE;
    END IF;

    IF has_decision_records AND has_decisions THEN
        INSERT INTO decisions (
            id,
            created_at,
            tenant_id,
            source,
            event_id,
            event_type,
            policy_hash,
            threat_level,
            anomaly_score,
            ai_adversarial_score,
            pq_fallback,
            rules_triggered_json,
            decision_diff_json,
            request_json,
            response_json,
            prev_hash,
            chain_hash,
            chain_alg,
            chain_ts
        )
        SELECT
            dr.id,
            dr.created_at,
            dr.tenant_id,
            dr.source,
            dr.event_id,
            dr.event_type,
            dr.policy_hash,
            dr.threat_level,
            dr.anomaly_score,
            dr.ai_adversarial_score,
            dr.pq_fallback,
            dr.rules_triggered_json,
            dr.decision_diff_json,
            dr.request_json,
            dr.response_json,
            dr.prev_hash,
            dr.chain_hash,
            dr.chain_alg,
            dr.chain_ts
        FROM decision_records dr
        LEFT JOIN decisions d ON d.id = dr.id
        WHERE d.id IS NULL;

        DROP TABLE decision_records;
    END IF;

    IF to_regclass('public.decisions') IS NOT NULL THEN
        PERFORM setval(
            pg_get_serial_sequence('decisions', 'id'),
            GREATEST(COALESCE((SELECT MAX(id) FROM decisions), 1), 1),
            true
        );
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_id ON decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_decisions_event_id ON decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions(created_at);

ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE decisions FORCE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'decisions'
          AND policyname = 'decisions_tenant_isolation'
    ) THEN
        CREATE POLICY decisions_tenant_isolation ON decisions
            USING (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            )
            WITH CHECK (
                tenant_id IS NOT NULL
                AND current_setting('app.tenant_id', true) IS NOT NULL
                AND tenant_id = current_setting('app.tenant_id', true)
            );
    END IF;
END $$;
