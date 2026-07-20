-- Migration 0160: tenant_credential_events — R4.5 audit events
--
-- Append-only audit log for all credential lifecycle and validation events.
-- Written exclusively by api/credential_authority.py (same write-authority
-- contract as tenant_credentials and credential_slots).
--
-- Event types:
--   issued             — new credential generation issued
--   rotated            — credential rotated (new generation activated)
--   revoked            — credential explicitly revoked
--   expired            — credential marked expired by sweep or lazy enforcement
--   validated          — successful authentication (best-effort, hot path)
--   validation_failed  — failed authentication attempt (best-effort, hot path)
--   denied_tenant_state — blocked by tenant lifecycle (best-effort, hot path)
--
-- Lifecycle events (issued, rotated, revoked, expired) are emitted within
-- the credential write transaction — atomic with the credential mutation.
--
-- Validation telemetry (validated, validation_failed, denied_tenant_state)
-- is emitted best-effort in a separate connection after the validation result
-- is determined.  Emission failure never blocks the validation response.
--
-- RLS: same tenant_id-scoped policy as tenant_credentials.

CREATE TABLE IF NOT EXISTS tenant_credential_events (
    event_id          VARCHAR(64)   NOT NULL,
    tenant_id         VARCHAR(128)  NOT NULL REFERENCES tenants(tenant_id),
    credential_id     VARCHAR(64),
    credential_type   VARCHAR(64),
    credential_slot   VARCHAR(128),
    generation        INTEGER,
    event_type        VARCHAR(64)   NOT NULL
        CONSTRAINT tce_event_type_valid CHECK (event_type IN (
            'issued', 'rotated', 'revoked', 'expired',
            'validated', 'validation_failed', 'denied_tenant_state'
        )),
    actor_id          VARCHAR(256),
    request_id        VARCHAR(128),
    occurred_at       TEXT          NOT NULL,
    outcome           VARCHAR(16)   NOT NULL DEFAULT 'success'
        CONSTRAINT tce_outcome_valid CHECK (outcome IN ('success', 'failure', 'denied')),
    failure_reason    TEXT,
    metadata          TEXT,
    schema_version    INTEGER       NOT NULL DEFAULT 1,

    PRIMARY KEY (event_id)
);

ALTER TABLE tenant_credential_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_credential_events_tenant_isolation
    ON tenant_credential_events;
CREATE POLICY tenant_credential_events_tenant_isolation
    ON tenant_credential_events
    FOR ALL
    USING (tenant_id = current_setting('app.tenant_id', true));

-- Append-only enforcement: prevent any UPDATE or DELETE on audit rows.
CREATE OR REPLACE FUNCTION tce_prevent_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'tenant_credential_events is append-only: % on row % is not permitted',
        TG_OP, OLD.event_id;
END;
$$;

CREATE TRIGGER tce_no_update_or_delete
    BEFORE UPDATE OR DELETE ON tenant_credential_events
    FOR EACH ROW EXECUTE FUNCTION tce_prevent_mutation();

-- Tenant-ordered timeline — primary read pattern.
CREATE INDEX IF NOT EXISTS ix_tce_tenant_occurred
    ON tenant_credential_events (tenant_id, occurred_at DESC);

-- Per-credential history.
CREATE INDEX IF NOT EXISTS ix_tce_credential_id
    ON tenant_credential_events (credential_id)
    WHERE credential_id IS NOT NULL;

-- Event-type filtering within a tenant.
CREATE INDEX IF NOT EXISTS ix_tce_tenant_event_type
    ON tenant_credential_events (tenant_id, event_type, occurred_at DESC);
