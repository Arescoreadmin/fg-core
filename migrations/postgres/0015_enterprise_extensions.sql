-- additive enterprise extension tables

CREATE TABLE IF NOT EXISTS enterprise_framework_catalog (
    framework_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS enterprise_control_catalog (
    control_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS enterprise_control_crosswalk (
    crosswalk_id TEXT PRIMARY KEY,
    control_id TEXT NOT NULL REFERENCES enterprise_control_catalog(control_id),
    framework_id TEXT NOT NULL REFERENCES enterprise_framework_catalog(framework_id),
    framework_control_ref TEXT NOT NULL,
    mapping_strength TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tenant_control_state (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    control_id TEXT NOT NULL,
    status TEXT NOT NULL,
    note TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, control_id)
);

CREATE TABLE IF NOT EXISTS evidence_anchor_records (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    anchored_at_utc TEXT NOT NULL,
    external_anchor_ref TEXT,
    immutable_retention BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
