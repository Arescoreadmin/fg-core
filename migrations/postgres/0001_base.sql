CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id SERIAL PRIMARY KEY,
    name VARCHAR(128) NOT NULL DEFAULT 'default',
    prefix VARCHAR(64) NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_lookup VARCHAR(64),
    hash_alg VARCHAR(32),
    hash_params JSONB,
    scopes_csv TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    version INTEGER NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ,
    rotated_from VARCHAR(64),
    last_used_at TIMESTAMPTZ,
    use_count INTEGER NOT NULL DEFAULT 0,
    tenant_id VARCHAR(128),
    created_by VARCHAR(128),
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_lookup ON api_keys(key_lookup);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_id ON api_keys(tenant_id);

CREATE TABLE IF NOT EXISTS security_audit_log (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type VARCHAR(64) NOT NULL,
    event_category VARCHAR(32) NOT NULL DEFAULT 'security',
    severity VARCHAR(16) NOT NULL DEFAULT 'info',
    tenant_id VARCHAR(128),
    key_prefix VARCHAR(64),
    client_ip VARCHAR(45),
    user_agent VARCHAR(512),
    request_id VARCHAR(64),
    request_path VARCHAR(256),
    request_method VARCHAR(16),
    success BOOLEAN NOT NULL DEFAULT TRUE,
    reason VARCHAR(256),
    details_json JSONB
);

CREATE INDEX IF NOT EXISTS idx_security_audit_log_event_type ON security_audit_log(event_type);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_tenant_id ON security_audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_request_id ON security_audit_log(request_id);
CREATE INDEX IF NOT EXISTS idx_security_audit_log_created_at ON security_audit_log(created_at);

CREATE TABLE IF NOT EXISTS decisions (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id VARCHAR(128),
    source TEXT,
    event_id TEXT,
    event_type TEXT,
    policy_hash VARCHAR(64),
    threat_level TEXT,
    anomaly_score DOUBLE PRECISION,
    ai_adversarial_score DOUBLE PRECISION,
    pq_fallback BOOLEAN,
    rules_triggered_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    decision_diff_json JSONB,
    request_json JSONB NOT NULL,
    response_json JSONB NOT NULL,
    prev_hash VARCHAR(64),
    chain_hash VARCHAR(64),
    chain_alg VARCHAR(64),
    chain_ts TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_decisions_tenant_id ON decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_decisions_event_id ON decisions(event_id);
CREATE INDEX IF NOT EXISTS idx_decisions_created_at ON decisions(created_at);

CREATE TABLE IF NOT EXISTS decision_evidence_artifacts (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id VARCHAR(128),
    decision_id INTEGER NOT NULL,
    evidence_sha256 VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    payload_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decision_evidence_tenant_id ON decision_evidence_artifacts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_decision_evidence_decision_id ON decision_evidence_artifacts(decision_id);
CREATE INDEX IF NOT EXISTS idx_decision_evidence_created_at ON decision_evidence_artifacts(created_at);

CREATE TABLE IF NOT EXISTS policy_change_requests (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(128) NOT NULL,
    change_id VARCHAR(64) NOT NULL UNIQUE,
    change_type VARCHAR(64) NOT NULL,
    proposed_by VARCHAR(128) NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    justification TEXT NOT NULL,
    rule_definition_json JSONB,
    roe_update_json JSONB,
    simulation_results_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    estimated_false_positives INTEGER NOT NULL DEFAULT 0,
    estimated_true_positives INTEGER NOT NULL DEFAULT 0,
    confidence VARCHAR(16) NOT NULL DEFAULT 'medium',
    requires_approval_from_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    approvals_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    deployed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_policy_change_requests_change_id ON policy_change_requests(change_id);
CREATE INDEX IF NOT EXISTS idx_policy_change_requests_status ON policy_change_requests(status);
CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_proposed_id ON policy_change_requests(tenant_id, proposed_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_policy_change_requests_tenant_id_id ON policy_change_requests(tenant_id, id);
