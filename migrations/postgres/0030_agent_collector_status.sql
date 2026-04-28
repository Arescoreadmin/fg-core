-- 0030_agent_collector_status.sql
-- Per-device, per-collector last-known run status reported via heartbeat.
-- Introduced in task 17.5 (agent observability).

CREATE TABLE IF NOT EXISTS agent_collector_statuses (
    id              BIGSERIAL PRIMARY KEY,
    device_id       VARCHAR(64)  NOT NULL REFERENCES agent_device_registry(device_id),
    tenant_id       VARCHAR(128) NOT NULL,
    collector_name  VARCHAR(128) NOT NULL,
    last_outcome    VARCHAR(16)  NOT NULL,  -- 'ran' | 'failed' | 'skipped'
    last_run_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_error      TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_agent_collector_statuses_device_name
    ON agent_collector_statuses (device_id, collector_name);

CREATE INDEX IF NOT EXISTS ix_agent_collector_statuses_device
    ON agent_collector_statuses (device_id);

CREATE INDEX IF NOT EXISTS ix_agent_collector_statuses_tenant
    ON agent_collector_statuses (tenant_id);
