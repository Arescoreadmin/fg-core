CREATE TABLE IF NOT EXISTS compliance_requirements (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    req_id TEXT NOT NULL,
    source TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    effective_date_utc TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    owner TEXT NOT NULL,
    source_name TEXT,
    source_version TEXT,
    published_at_utc TEXT,
    retrieved_at_utc TEXT,
    bundle_sha256 TEXT,
    tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at_utc TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS compliance_findings (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    req_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    title TEXT NOT NULL,
    details TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    waiver_json JSONB,
    detected_at_utc TEXT NOT NULL,
    evidence_refs_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at_utc TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    snapshot_id TEXT NOT NULL UNIQUE,
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_utc TEXT NOT NULL,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE TABLE IF NOT EXISTS compliance_requirement_updates (
    id BIGSERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    update_id TEXT NOT NULL UNIQUE,
    source_name TEXT NOT NULL,
    source_version TEXT NOT NULL,
    published_at_utc TEXT NOT NULL,
    retrieved_at_utc TEXT NOT NULL,
    bundle_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    diff_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_record_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    signature TEXT NOT NULL,
    key_id TEXT NOT NULL,
    created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_exam_sessions (
    id BIGSERIAL PRIMARY KEY,
    exam_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    window_start_utc TEXT NOT NULL,
    window_end_utc TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    export_path TEXT,
    reproduce_json JSONB,
    previous_record_hash TEXT NOT NULL DEFAULT 'GENESIS',
    record_hash TEXT NOT NULL UNIQUE DEFAULT '',
    signature TEXT NOT NULL DEFAULT '',
    key_id TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS ix_compliance_requirements_tenant_req ON compliance_requirements(tenant_id, req_id, id);
CREATE INDEX IF NOT EXISTS ix_compliance_findings_tenant_find ON compliance_findings(tenant_id, finding_id, id);
CREATE INDEX IF NOT EXISTS ix_compliance_snapshots_tenant ON compliance_snapshots(tenant_id, id);
CREATE INDEX IF NOT EXISTS ix_compliance_updates_tenant ON compliance_requirement_updates(tenant_id, id);

DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['compliance_requirements','compliance_findings','compliance_snapshots','audit_exam_sessions','compliance_requirement_updates']
  LOOP
    EXECUTE format('DROP TRIGGER IF EXISTS %I_append_only_update ON %I', t, t);
    EXECUTE format('DROP TRIGGER IF EXISTS %I_append_only_delete ON %I', t, t);
    EXECUTE format('CREATE TRIGGER %I_append_only_update BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION append_only_guard()', t, t);
    EXECUTE format('CREATE TRIGGER %I_append_only_delete BEFORE DELETE ON %I FOR EACH ROW EXECUTE FUNCTION append_only_guard()', t, t);

    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS %I_tenant_isolation ON %I', t, t);
    EXECUTE format($fmt$
      CREATE POLICY %I_tenant_isolation ON %I
      USING (tenant_id = current_setting('app.tenant_id', true))
      WITH CHECK (tenant_id = current_setting('app.tenant_id', true))
    $fmt$, t, t);
  END LOOP;
END;
$$;

ALTER TABLE audit_exam_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_exam_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_exam_sessions_tenant_isolation ON audit_exam_sessions;
CREATE POLICY audit_exam_sessions_tenant_isolation
ON audit_exam_sessions
USING (tenant_id = current_setting('app.tenant_id', true))
WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

REVOKE TRUNCATE ON compliance_requirements, compliance_findings, compliance_snapshots, audit_exam_sessions, compliance_requirement_updates FROM PUBLIC;
