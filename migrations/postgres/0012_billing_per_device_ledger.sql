CREATE TABLE IF NOT EXISTS billing_devices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    device_key TEXT NOT NULL,
    device_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    labels JSONB NOT NULL DEFAULT '{}'::jsonb,
    identity_confidence INTEGER NOT NULL DEFAULT 0,
    collision_signal BOOLEAN NOT NULL DEFAULT false,
    billable_state TEXT NOT NULL DEFAULT 'billable',
    CONSTRAINT uq_billing_devices_tenant_key UNIQUE (tenant_id, device_key),
    CONSTRAINT uq_billing_devices_tenant_device_id UNIQUE (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS billing_identity_claims (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    claimed_id_type TEXT NOT NULL,
    claimed_id_value TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    source_agent_id TEXT,
    source_ip TEXT,
    attestation_level TEXT NOT NULL DEFAULT 'none',
    conflict_state TEXT NOT NULL DEFAULT 'clean',
    CONSTRAINT uq_billing_identity_claims_tenant_claim UNIQUE (
        tenant_id,
        claimed_id_type,
        claimed_id_value
    ),
    CONSTRAINT fk_billing_identity_claims_device FOREIGN KEY (tenant_id, device_id)
        REFERENCES billing_devices(tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS billing_identity_claim_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    claim_id BIGINT NOT NULL REFERENCES billing_identity_claims(id),
    sequence INTEGER NOT NULL,
    transition TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT,
    reason TEXT,
    prev_hash TEXT NOT NULL,
    self_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_identity_claim_events_seq UNIQUE (tenant_id, claim_id, sequence)
);



CREATE TABLE IF NOT EXISTS billing_invoice_state_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    invoice_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    transition TEXT NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    authority_ticket_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    self_hash TEXT NOT NULL UNIQUE,
    signature TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_invoice_state_events_seq UNIQUE (tenant_id, invoice_id, sequence)
);

CREATE TABLE IF NOT EXISTS billing_credit_notes (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    credit_note_id TEXT NOT NULL,
    invoice_id TEXT NOT NULL,
    amount NUMERIC(18,6) NOT NULL,
    currency TEXT NOT NULL DEFAULT 'USD',
    reason TEXT NOT NULL,
    ticket_id TEXT NOT NULL,
    created_by TEXT NOT NULL,
    credit_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    credit_sha256 TEXT NOT NULL,
    evidence_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_credit_notes_tenant_credit UNIQUE (tenant_id, credit_note_id)
);

CREATE TABLE IF NOT EXISTS billing_device_enrollments (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    attestation_type TEXT NOT NULL,
    attestation_payload_hash TEXT NOT NULL,
    enrolled_by TEXT NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_device_enrollments_device UNIQUE (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS billing_device_activity_proofs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    activity_day DATE NOT NULL,
    proof_type TEXT NOT NULL,
    proof_hash TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_activity_proof UNIQUE (tenant_id, device_id, activity_day, proof_hash)
);

CREATE TABLE IF NOT EXISTS pricing_versions (
    pricing_version_id TEXT PRIMARY KEY,
    effective_at TIMESTAMPTZ NOT NULL,
    rates_json JSONB NOT NULL,
    sha256_hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS tenant_contracts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    pricing_version_id TEXT NOT NULL REFERENCES pricing_versions(pricing_version_id),
    discount_rules_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    commitment_minimum NUMERIC(18,6) NOT NULL DEFAULT 0,
    start_at TIMESTAMPTZ NOT NULL,
    end_at TIMESTAMPTZ,
    contract_hash TEXT NOT NULL DEFAULT '',
    CONSTRAINT uq_tenant_contracts_tenant_contract UNIQUE (tenant_id, contract_id)
);

CREATE TABLE IF NOT EXISTS device_coverage_ledger (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    plan_id TEXT,
    action TEXT NOT NULL,
    effective_from TIMESTAMPTZ NOT NULL,
    effective_to TIMESTAMPTZ,
    pricing_version_id TEXT,
    config_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    prev_hash TEXT NOT NULL,
    self_hash TEXT NOT NULL UNIQUE,
    signature TEXT,
    CONSTRAINT uq_device_coverage_ledger_tenant_event UNIQUE (tenant_id, event_id),
    CONSTRAINT fk_device_coverage_ledger_device FOREIGN KEY (tenant_id, device_id)
        REFERENCES billing_devices(tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS billing_coverage_daily_state (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    device_id UUID NOT NULL,
    coverage_day DATE NOT NULL,
    coverage_state TEXT NOT NULL,
    plan_id TEXT,
    source_event_id TEXT NOT NULL,
    source_event_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_coverage_daily_state_tenant_device_day UNIQUE (
        tenant_id,
        device_id,
        coverage_day
    )
);

CREATE TABLE IF NOT EXISTS billing_daily_counts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    day DATE NOT NULL,
    plan_id TEXT NOT NULL,
    covered_count INTEGER NOT NULL,
    computed_from_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_daily_counts_tenant_day_plan UNIQUE (tenant_id, day, plan_id)
);

CREATE TABLE IF NOT EXISTS billing_count_sync_checkpoints (
    tenant_id TEXT PRIMARY KEY,
    last_ledger_id BIGINT NOT NULL DEFAULT 0,
    processed_digest TEXT NOT NULL DEFAULT 'GENESIS',
    prev_hash TEXT NOT NULL DEFAULT 'GENESIS',
    self_hash TEXT NOT NULL DEFAULT 'GENESIS',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS billing_count_sync_checkpoint_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    from_ledger_id BIGINT NOT NULL,
    to_ledger_id BIGINT NOT NULL,
    processed_digest TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    self_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_sync_checkpoint_events_seq UNIQUE (tenant_id, sequence)
);

CREATE TABLE IF NOT EXISTS billing_invoices (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    invoice_id TEXT NOT NULL,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    pricing_version_id TEXT NOT NULL,
    pricing_hash TEXT NOT NULL DEFAULT '',
    contract_hash TEXT NOT NULL DEFAULT '',
    config_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    invoice_json JSONB NOT NULL,
    invoice_sha256 TEXT NOT NULL,
    evidence_path TEXT,
    invoice_state TEXT NOT NULL DEFAULT 'draft',
    finalized_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_invoices_tenant_invoice UNIQUE (tenant_id, invoice_id)
);

CREATE TABLE IF NOT EXISTS billing_runs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    replay_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    pricing_version_id TEXT NOT NULL DEFAULT '',
    contract_hash TEXT NOT NULL DEFAULT '',
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    invoice_id TEXT,
    export_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_billing_runs_tenant_run UNIQUE (tenant_id, run_id),
    CONSTRAINT uq_billing_runs_tenant_idempotency UNIQUE (tenant_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS ix_billing_devices_tenant_status ON billing_devices(tenant_id, status);
CREATE INDEX IF NOT EXISTS ix_billing_identity_claims_tenant_device ON billing_identity_claims(tenant_id, device_id);
CREATE INDEX IF NOT EXISTS ix_billing_identity_claim_events_tenant_claim ON billing_identity_claim_events(tenant_id, claim_id, sequence);

CREATE INDEX IF NOT EXISTS ix_billing_invoice_state_events_tenant_invoice ON billing_invoice_state_events(tenant_id, invoice_id, sequence);
CREATE INDEX IF NOT EXISTS ix_billing_credit_notes_tenant_invoice ON billing_credit_notes(tenant_id, invoice_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_billing_device_enrollments_tenant_device ON billing_device_enrollments(tenant_id, device_id);
CREATE INDEX IF NOT EXISTS ix_billing_device_activity_tenant_day ON billing_device_activity_proofs(tenant_id, activity_day);
CREATE INDEX IF NOT EXISTS ix_device_coverage_ledger_tenant_device_from ON device_coverage_ledger(tenant_id, device_id, effective_from);
CREATE INDEX IF NOT EXISTS ix_billing_coverage_daily_state_tenant_day ON billing_coverage_daily_state(tenant_id, coverage_day);
CREATE INDEX IF NOT EXISTS ix_billing_coverage_daily_state_tenant_day_state ON billing_coverage_daily_state(tenant_id, coverage_day, coverage_state);
CREATE INDEX IF NOT EXISTS ix_billing_coverage_daily_state_tenant_device_day ON billing_coverage_daily_state(tenant_id, device_id, coverage_day);
CREATE INDEX IF NOT EXISTS ix_billing_daily_counts_tenant_day ON billing_daily_counts(tenant_id, day);
CREATE INDEX IF NOT EXISTS ix_billing_invoices_tenant_period ON billing_invoices(tenant_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS ix_billing_runs_tenant_period ON billing_runs(tenant_id, period_start, period_end);
CREATE INDEX IF NOT EXISTS ix_billing_runs_tenant_created_desc ON billing_runs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_billing_count_sync_checkpoints_tenant_self_hash ON billing_count_sync_checkpoints(tenant_id, self_hash);

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'billing_devices',
        'billing_identity_claims',
        'billing_identity_claim_events',
        'billing_invoice_state_events',
        'billing_credit_notes',
        'billing_device_enrollments',
        'billing_device_activity_proofs',
        'device_coverage_ledger',
        'billing_coverage_daily_state',
        'tenant_contracts',
        'billing_daily_counts',
        'billing_count_sync_checkpoints',
        'billing_count_sync_checkpoint_events',
        'billing_invoices',
        'billing_runs'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %%I FORCE ROW LEVEL SECURITY', t);
        IF EXISTS (
            SELECT 1 FROM information_schema.columns
            WHERE table_schema='public' AND table_name=t AND column_name='tenant_id'
        ) AND NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname='public' AND tablename=t AND policyname=t || '_tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY %%I ON %%I USING (tenant_id IS NOT NULL AND current_setting(''app.tenant_id'', true) IS NOT NULL AND tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id IS NOT NULL AND current_setting(''app.tenant_id'', true) IS NOT NULL AND tenant_id = current_setting(''app.tenant_id'', true))',
                t || '_tenant_isolation',
                t
            );
        END IF;
    END LOOP;
END $$;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_identity_claim_events_append_only_update') THEN
        CREATE TRIGGER billing_identity_claim_events_append_only_update
        BEFORE UPDATE ON billing_identity_claim_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_identity_claim_events_append_only_delete') THEN
        CREATE TRIGGER billing_identity_claim_events_append_only_delete
        BEFORE DELETE ON billing_identity_claim_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;



    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_invoice_state_events_append_only_update') THEN
        CREATE TRIGGER billing_invoice_state_events_append_only_update
        BEFORE UPDATE ON billing_invoice_state_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_invoice_state_events_append_only_delete') THEN
        CREATE TRIGGER billing_invoice_state_events_append_only_delete
        BEFORE DELETE ON billing_invoice_state_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_credit_notes_append_only_update') THEN
        CREATE TRIGGER billing_credit_notes_append_only_update
        BEFORE UPDATE ON billing_credit_notes
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_credit_notes_append_only_delete') THEN
        CREATE TRIGGER billing_credit_notes_append_only_delete
        BEFORE DELETE ON billing_credit_notes
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_device_enrollments_append_only_update') THEN
        CREATE TRIGGER billing_device_enrollments_append_only_update
        BEFORE UPDATE ON billing_device_enrollments
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_device_enrollments_append_only_delete') THEN
        CREATE TRIGGER billing_device_enrollments_append_only_delete
        BEFORE DELETE ON billing_device_enrollments
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_device_activity_proofs_append_only_update') THEN
        CREATE TRIGGER billing_device_activity_proofs_append_only_update
        BEFORE UPDATE ON billing_device_activity_proofs
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_device_activity_proofs_append_only_delete') THEN
        CREATE TRIGGER billing_device_activity_proofs_append_only_delete
        BEFORE DELETE ON billing_device_activity_proofs
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_coverage_daily_state_append_only_update') THEN
        CREATE TRIGGER billing_coverage_daily_state_append_only_update
        BEFORE UPDATE ON billing_coverage_daily_state
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_coverage_daily_state_append_only_delete') THEN
        CREATE TRIGGER billing_coverage_daily_state_append_only_delete
        BEFORE DELETE ON billing_coverage_daily_state
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'device_coverage_ledger_append_only_update') THEN
        CREATE TRIGGER device_coverage_ledger_append_only_update
        BEFORE UPDATE ON device_coverage_ledger
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'device_coverage_ledger_append_only_delete') THEN
        CREATE TRIGGER device_coverage_ledger_append_only_delete
        BEFORE DELETE ON device_coverage_ledger
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_count_sync_checkpoint_events_append_only_update') THEN
        CREATE TRIGGER billing_count_sync_checkpoint_events_append_only_update
        BEFORE UPDATE ON billing_count_sync_checkpoint_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'billing_count_sync_checkpoint_events_append_only_delete') THEN
        CREATE TRIGGER billing_count_sync_checkpoint_events_append_only_delete
        BEFORE DELETE ON billing_count_sync_checkpoint_events
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'pricing_versions_append_only_update') THEN
        CREATE TRIGGER pricing_versions_append_only_update
        BEFORE UPDATE ON pricing_versions
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'pricing_versions_append_only_delete') THEN
        CREATE TRIGGER pricing_versions_append_only_delete
        BEFORE DELETE ON pricing_versions
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'tenant_contracts_append_only_update') THEN
        CREATE TRIGGER tenant_contracts_append_only_update
        BEFORE UPDATE ON tenant_contracts
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'tenant_contracts_append_only_delete') THEN
        CREATE TRIGGER tenant_contracts_append_only_delete
        BEFORE DELETE ON tenant_contracts
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
END $$;
