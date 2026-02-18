ALTER TABLE IF EXISTS ai_token_usage
    ADD COLUMN IF NOT EXISTS usage_record_id TEXT;

ALTER TABLE IF EXISTS ai_token_usage
    ADD COLUMN IF NOT EXISTS metering_mode TEXT NOT NULL DEFAULT 'unknown';

ALTER TABLE IF EXISTS ai_token_usage
    ADD COLUMN IF NOT EXISTS estimation_mode TEXT NOT NULL DEFAULT 'estimated';

UPDATE ai_token_usage
SET usage_record_id = COALESCE(
    usage_record_id,
    md5(
        COALESCE(tenant_id, '') || '|' ||
        COALESCE(device_id, '') || '|' ||
        COALESCE(request_hash, '') || '|' ||
        COALESCE(created_at::text, '')
    )
)
WHERE usage_record_id IS NULL;

ALTER TABLE IF EXISTS ai_token_usage
    ALTER COLUMN usage_record_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_ai_token_usage_record_id
    ON ai_token_usage(usage_record_id);
