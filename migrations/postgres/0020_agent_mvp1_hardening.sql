ALTER TABLE agent_enrollment_tokens
    ADD COLUMN IF NOT EXISTS created_by VARCHAR(128) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS reason VARCHAR(256) NOT NULL DEFAULT 'unspecified',
    ADD COLUMN IF NOT EXISTS ticket VARCHAR(128);

ALTER TABLE agent_device_keys
    ADD COLUMN IF NOT EXISTS hmac_secret_enc TEXT;

UPDATE agent_device_keys
SET hmac_secret_enc = COALESCE(hmac_secret_enc, '')
WHERE hmac_secret_enc IS NULL;

ALTER TABLE agent_device_keys
    ALTER COLUMN hmac_secret_enc SET NOT NULL;

CREATE TABLE IF NOT EXISTS agent_device_nonces (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL,
    nonce_hash VARCHAR(64) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_device_nonces_device_id
    ON agent_device_nonces (device_id);

CREATE INDEX IF NOT EXISTS ix_agent_device_nonces_nonce_hash
    ON agent_device_nonces (nonce_hash);

CREATE INDEX IF NOT EXISTS ix_agent_device_nonces_device_created
    ON agent_device_nonces (device_id, created_at);
