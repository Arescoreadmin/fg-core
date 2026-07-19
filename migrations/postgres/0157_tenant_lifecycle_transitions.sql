-- Migration 0157: tenant lifecycle transitions
-- R3 Tenant Lifecycle Authority — per-transition audit record.
--
-- Every state change on a tenant (active/suspended/archived/deleted) is
-- recorded here before the tenants row is updated.  This table is the
-- append-only audit trail consumed by CGIN, Governance Digital Twin, and AGOC.
--
-- transition_id:   caller-supplied or generated UUID — stable across retries
-- idempotency_key: optional caller key; UNIQUE prevents duplicate transitions

CREATE TABLE IF NOT EXISTS tenant_lifecycle_transitions (
    transition_id       VARCHAR(64)     PRIMARY KEY,
    tenant_id           VARCHAR(128)    NOT NULL REFERENCES tenants(tenant_id),
    from_state          VARCHAR(32)     NOT NULL,
    to_state            VARCHAR(32)     NOT NULL,
    reason              TEXT,
    actor_id            TEXT,
    request_id          TEXT,
    idempotency_key     TEXT,
    occurred_at         TIMESTAMPTZ     NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_tlt_tenant_id
    ON tenant_lifecycle_transitions (tenant_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS ix_tlt_to_state
    ON tenant_lifecycle_transitions (to_state);
-- Idempotency key is scoped per-tenant so the same key used by two different
-- tenants is allowed; only the (tenant_id, key) pair must be unique.
CREATE UNIQUE INDEX IF NOT EXISTS ix_tlt_idempotency_key
    ON tenant_lifecycle_transitions (tenant_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
