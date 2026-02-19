-- additive ai plane hardening tables/columns + tenant RLS

ALTER TABLE IF EXISTS ai_inference_records
    ADD COLUMN IF NOT EXISTS output_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS retrieval_id TEXT,
    ADD COLUMN IF NOT EXISTS policy_result TEXT;

UPDATE ai_inference_records
SET output_sha256 = COALESCE(output_sha256, ''),
    retrieval_id = COALESCE(retrieval_id, 'stub'),
    policy_result = COALESCE(policy_result, 'pass')
WHERE output_sha256 IS NULL OR retrieval_id IS NULL OR policy_result IS NULL;

ALTER TABLE IF EXISTS ai_inference_records
    ALTER COLUMN output_sha256 SET NOT NULL,
    ALTER COLUMN retrieval_id SET NOT NULL,
    ALTER COLUMN policy_result SET NOT NULL;

CREATE TABLE IF NOT EXISTS ai_policy_violations (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    violation_code TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE IF EXISTS ai_inference_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE IF EXISTS ai_policy_violations ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ai_inference_records'
          AND policyname = 'ai_inference_records_tenant_isolation'
    ) THEN
        CREATE POLICY ai_inference_records_tenant_isolation ON ai_inference_records
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

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = 'ai_policy_violations'
          AND policyname = 'ai_policy_violations_tenant_isolation'
    ) THEN
        CREATE POLICY ai_policy_violations_tenant_isolation ON ai_policy_violations
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
