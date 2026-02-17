CREATE TABLE IF NOT EXISTS audit_exports (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    export_id TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    export_hash TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    storage_uri TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    triggered_by TEXT NOT NULL,
    purpose TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    kid TEXT NOT NULL,
    signature_algo TEXT NOT NULL,
    CONSTRAINT uq_audit_exports_dedupe UNIQUE (tenant_id, export_hash, manifest_hash)
);

CREATE TABLE IF NOT EXISTS audit_chain_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    checkpoint_id TEXT NOT NULL,
    record_seq BIGINT NOT NULL,
    root_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_audit_chain_checkpoint_tenant_checkpoint UNIQUE (tenant_id, checkpoint_id)
);

CREATE TABLE IF NOT EXISTS audit_anchors (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    anchor_day TEXT NOT NULL,
    day_root_hash TEXT NOT NULL,
    trust_domain TEXT NOT NULL,
    anchor_status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_audit_anchors_day UNIQUE (tenant_id, anchor_day)
);

CREATE INDEX IF NOT EXISTS ix_audit_exports_tenant_id ON audit_exports(tenant_id);
CREATE INDEX IF NOT EXISTS ix_audit_chain_checkpoints_tenant_id ON audit_chain_checkpoints(tenant_id);
CREATE INDEX IF NOT EXISTS ix_audit_anchors_tenant_id ON audit_anchors(tenant_id);

ALTER TABLE audit_exports ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_exports_tenant_isolation ON audit_exports;
CREATE POLICY audit_exports_tenant_isolation ON audit_exports
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');

ALTER TABLE audit_chain_checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_checkpoints FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_chain_checkpoints_tenant_isolation ON audit_chain_checkpoints;
CREATE POLICY audit_chain_checkpoints_tenant_isolation ON audit_chain_checkpoints
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');

ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_anchors_tenant_isolation ON audit_anchors;
CREATE POLICY audit_anchors_tenant_isolation ON audit_anchors
USING (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system')
WITH CHECK (tenant_id = current_setting('app.tenant_id', true) OR current_setting('app.tenant_id', true) = 'system');
