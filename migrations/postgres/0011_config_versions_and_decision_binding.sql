CREATE TABLE IF NOT EXISTS config_versions (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    config_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by TEXT,
    config_json JSONB NOT NULL,
    config_json_canonical TEXT NOT NULL,
    parent_hash TEXT,
    CONSTRAINT uq_config_versions_tenant_hash UNIQUE (tenant_id, config_hash)
);

CREATE TABLE IF NOT EXISTS tenant_config_active (
    tenant_id TEXT PRIMARY KEY,
    active_config_hash TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_tenant_active_config FOREIGN KEY (tenant_id, active_config_hash)
        REFERENCES config_versions(tenant_id, config_hash)
        ON UPDATE RESTRICT ON DELETE RESTRICT
);

ALTER TABLE decisions
    ADD COLUMN IF NOT EXISTS config_hash TEXT;

INSERT INTO config_versions (tenant_id, config_hash, created_by, config_json, config_json_canonical)
SELECT DISTINCT tenant_id, 'legacy_config_hash', 'migration', '{"legacy":true}'::jsonb, '{"legacy":true}'
FROM decisions
WHERE tenant_id IS NOT NULL
ON CONFLICT (tenant_id, config_hash) DO NOTHING;

UPDATE decisions
SET config_hash = 'legacy_config_hash'
WHERE config_hash IS NULL;

INSERT INTO tenant_config_active (tenant_id, active_config_hash)
SELECT DISTINCT tenant_id, 'legacy_config_hash'
FROM decisions
WHERE tenant_id IS NOT NULL
ON CONFLICT (tenant_id) DO NOTHING;

ALTER TABLE decisions
    ALTER COLUMN config_hash SET NOT NULL;

CREATE INDEX IF NOT EXISTS ix_decisions_tenant_config_created
    ON decisions (tenant_id, config_hash, created_at DESC);

ALTER TABLE decisions
    ADD CONSTRAINT fk_decisions_config_version
    FOREIGN KEY (tenant_id, config_hash)
    REFERENCES config_versions(tenant_id, config_hash)
    ON UPDATE RESTRICT ON DELETE RESTRICT;

COMMENT ON INDEX ix_decisions_tenant_config_created IS 'used for decision→config forensic joins; do not drop without replacing';
