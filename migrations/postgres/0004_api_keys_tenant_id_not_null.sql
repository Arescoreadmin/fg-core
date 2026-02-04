UPDATE api_keys SET tenant_id = 'unknown' WHERE tenant_id IS NULL;

ALTER TABLE api_keys
    ALTER COLUMN tenant_id SET DEFAULT 'unknown',
    ALTER COLUMN tenant_id SET NOT NULL;
