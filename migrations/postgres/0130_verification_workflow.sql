-- PR 14.6.6: Verification Workflow Authority
-- fa_verification_requests: workflow state machine per evidence verification
CREATE TABLE IF NOT EXISTS fa_verification_requests (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    workflow_state VARCHAR(32) NOT NULL DEFAULT 'REQUESTED',
    requested_by VARCHAR(255) NOT NULL,
    requester_actor_type VARCHAR(64) NOT NULL DEFAULT 'human',
    requested_at VARCHAR(64) NOT NULL,
    assignee_id VARCHAR(255),
    assignee_type VARCHAR(64),
    assigned_at VARCHAR(64),
    priority INTEGER NOT NULL DEFAULT 50,
    notes TEXT,
    review_due_at VARCHAR(64),
    decision_due_at VARCHAR(64),
    escalation_due_at VARCHAR(64),
    assigned_due_at VARCHAR(64),
    completed_at VARCHAR(64),
    cancelled_at VARCHAR(64),
    expired_at VARCHAR(64),
    escalation_count INTEGER NOT NULL DEFAULT 0,
    last_escalation_type VARCHAR(64),
    last_escalated_at VARCHAR(64),
    last_escalated_by VARCHAR(255),
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_verification_requests_tenant ON fa_verification_requests(tenant_id);
CREATE INDEX IF NOT EXISTS idx_fa_verification_requests_evidence ON fa_verification_requests(tenant_id, evidence_id);
CREATE INDEX IF NOT EXISTS idx_fa_verification_requests_state ON fa_verification_requests(tenant_id, workflow_state);

-- append-only enforcement
CREATE OR REPLACE FUNCTION prevent_vr_update() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_verification_results is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION prevent_vra_update() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'fa_verification_request_audits is append-only'; END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS fa_verification_results (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    result VARCHAR(32) NOT NULL,
    decided_by VARCHAR(255) NOT NULL,
    decider_actor_type VARCHAR(64) NOT NULL DEFAULT 'human',
    decision_notes TEXT,
    decided_at VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_verification_results_request ON fa_verification_results(tenant_id, request_id);

CREATE OR REPLACE TRIGGER trg_vr_immutable_update
    BEFORE UPDATE ON fa_verification_results
    FOR EACH ROW EXECUTE FUNCTION prevent_vr_update();

CREATE OR REPLACE TRIGGER trg_vr_immutable_delete
    BEFORE DELETE ON fa_verification_results
    FOR EACH ROW EXECUTE FUNCTION prevent_vr_update();

CREATE TABLE IF NOT EXISTS fa_verification_request_audits (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    evidence_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    actor_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(64) NOT NULL DEFAULT 'human',
    old_state VARCHAR(32),
    new_state VARCHAR(32),
    details TEXT,
    occurred_at VARCHAR(64) NOT NULL,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_fa_vra_request ON fa_verification_request_audits(tenant_id, request_id);

CREATE OR REPLACE TRIGGER trg_vra_immutable_update
    BEFORE UPDATE ON fa_verification_request_audits
    FOR EACH ROW EXECUTE FUNCTION prevent_vra_update();

CREATE OR REPLACE TRIGGER trg_vra_immutable_delete
    BEFORE DELETE ON fa_verification_request_audits
    FOR EACH ROW EXECUTE FUNCTION prevent_vra_update();
