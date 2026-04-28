-- 0029_agent_tenant_config.sql
-- Per-tenant agent lifecycle configuration: version floor and audit metadata.
-- Introduced in task 17.4 (agent lifecycle controls).

CREATE TABLE IF NOT EXISTS agent_tenant_configs (
    tenant_id   VARCHAR(128) PRIMARY KEY,
    version_floor VARCHAR(64),
    updated_at  TIMESTAMPTZ,
    updated_by  VARCHAR(128)
);
