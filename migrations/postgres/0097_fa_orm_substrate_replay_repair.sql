-- Migration 0097: Replay repair for ORM-managed Field Assessment substrate.
--
-- The frostgate-migrate container runs SQL migrations directly. It does not run
-- init_db()/Base.metadata.create_all() first, so ORM-managed FA substrate tables
-- must exist in SQL replay for db_migrations assertions to pass.

CREATE TABLE IF NOT EXISTS fa_engagements (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    status VARCHAR(64) NOT NULL,
    created_by VARCHAR(255),
    created_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS fa_scan_results (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    source_type VARCHAR(64) NOT NULL,
    source_label VARCHAR(255),
    payload_hash VARCHAR(64) NOT NULL,
    raw_payload TEXT NOT NULL,
    normalized_summary TEXT,
    imported_by VARCHAR(255),
    imported_at VARCHAR(64) NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fa_document_analyses (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    document_type VARCHAR(64),
    analysis_json TEXT NOT NULL,
    uploaded_by VARCHAR(255),
    uploaded_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS fa_field_observations (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    observation_type VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    notes TEXT,
    observed_by VARCHAR(255),
    observed_at VARCHAR(64) NOT NULL,
    updated_at VARCHAR(64),
    deleted_at VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS fa_normalized_findings (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    description TEXT NOT NULL,
    source_ref VARCHAR(255),
    framework_mappings TEXT,
    remediation TEXT,
    confidence VARCHAR(32),
    created_at VARCHAR(64) NOT NULL,
    asset_id VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS fa_evidence_links (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(255) NOT NULL,
    engagement_id VARCHAR(64) NOT NULL,
    finding_id VARCHAR(64),
    evidence_type VARCHAR(64) NOT NULL,
    evidence_ref VARCHAR(255) NOT NULL,
    description TEXT,
    created_at VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_fa_engagements_tenant
    ON fa_engagements (tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_scan_results_engagement_tenant
    ON fa_scan_results (engagement_id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_document_analyses_engagement_tenant
    ON fa_document_analyses (engagement_id, tenant_id);

CREATE INDEX IF NOT EXISTS ix_fa_field_obs_not_deleted
    ON fa_field_observations (engagement_id, tenant_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS ix_fa_findings_asset
    ON fa_normalized_findings (asset_id);

CREATE INDEX IF NOT EXISTS ix_fa_evidence_links_engagement_tenant
    ON fa_evidence_links (engagement_id, tenant_id);

DO $$
DECLARE
    r RECORD;
    policy_name TEXT;
BEGIN
    FOR r IN
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name IN (
              'fa_engagements',
              'fa_scan_results',
              'fa_document_analyses',
              'fa_field_observations',
              'fa_normalized_findings',
              'fa_evidence_links'
          )
        ORDER BY table_name
    LOOP
        policy_name := r.table_name || '_tenant_isolation';

        EXECUTE 'ALTER TABLE public.' || quote_ident(r.table_name) ||
            ' ENABLE ROW LEVEL SECURITY';

        EXECUTE 'ALTER TABLE public.' || quote_ident(r.table_name) ||
            ' FORCE ROW LEVEL SECURITY';

        EXECUTE 'DROP POLICY IF EXISTS ' || quote_ident(policy_name) ||
            ' ON public.' || quote_ident(r.table_name);

        EXECUTE 'CREATE POLICY ' || quote_ident(policy_name) ||
            ' ON public.' || quote_ident(r.table_name) ||
            ' USING (
                tenant_id = current_setting(''app.current_tenant_id'', true)
                OR current_setting(''app.current_tenant_id'', true) = ''''
            )';
    END LOOP;
END $$;
