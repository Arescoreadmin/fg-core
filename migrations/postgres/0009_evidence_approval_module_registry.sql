CREATE TABLE IF NOT EXISTS evidence_bundles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    bundle_json JSONB NOT NULL,
    bundle_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_evidence_bundles_subject
    ON evidence_bundles(tenant_id, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS approval_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    entry_json JSONB NOT NULL,
    entry_hash TEXT NOT NULL,
    prev_chain_hash TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_approval_seq UNIQUE (tenant_id, subject_type, subject_id, seq)
);

CREATE INDEX IF NOT EXISTS idx_approval_logs_subject
    ON approval_logs(tenant_id, subject_type, subject_id);

CREATE TABLE IF NOT EXISTS module_registry (
    module_id TEXT NOT NULL,
    version TEXT NOT NULL,
    record_json JSONB NOT NULL,
    registration_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (module_id, version)
);

CREATE INDEX IF NOT EXISTS idx_module_registry_module_id
    ON module_registry(module_id);

CREATE INDEX IF NOT EXISTS idx_module_registry_registered_at
    ON module_registry(registered_at);
