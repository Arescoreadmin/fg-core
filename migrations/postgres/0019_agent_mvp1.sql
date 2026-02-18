CREATE TABLE IF NOT EXISTS agent_enrollment_tokens (
    id BIGSERIAL PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(128) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_enrollment_tokens_tenant_id
    ON agent_enrollment_tokens (tenant_id);

CREATE TABLE IF NOT EXISTS agent_device_registry (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL UNIQUE,
    tenant_id VARCHAR(128) NOT NULL,
    fingerprint_hash VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active',
    suspicious BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NULL,
    last_ip VARCHAR(64) NULL,
    last_version VARCHAR(64) NULL
);

CREATE INDEX IF NOT EXISTS ix_agent_device_registry_tenant_id
    ON agent_device_registry (tenant_id);

CREATE INDEX IF NOT EXISTS ix_agent_device_registry_status
    ON agent_device_registry (status);

CREATE TABLE IF NOT EXISTS agent_device_keys (
    id BIGSERIAL PRIMARY KEY,
    device_id VARCHAR(64) NOT NULL REFERENCES agent_device_registry(device_id),
    tenant_id VARCHAR(128) NOT NULL,
    key_prefix VARCHAR(32) NOT NULL UNIQUE,
    key_hash TEXT NOT NULL,
    key_lookup VARCHAR(64) NOT NULL,
    hash_alg VARCHAR(32) NOT NULL DEFAULT 'argon2id',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_agent_device_keys_device
    ON agent_device_keys (device_id, tenant_id);
