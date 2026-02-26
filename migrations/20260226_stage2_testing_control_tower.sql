-- Stage 2 Testing Evolution: Control Tower + Intelligence registry
BEGIN;

CREATE TABLE IF NOT EXISTS testing_runs (
  run_id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  lane TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ NULL,
  duration_ms BIGINT NOT NULL DEFAULT 0,
  commit_sha TEXT NOT NULL,
  ref TEXT NOT NULL,
  triggered_by TEXT NOT NULL,
  triage_schema_version TEXT NOT NULL DEFAULT '2.0',
  summary_md TEXT NOT NULL DEFAULT '',
  canonical_payload_hash CHAR(64) NOT NULL DEFAULT '',
  triage_category_counts JSONB NOT NULL DEFAULT '{}'::jsonb,
  request_signature TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_testing_runs_tenant_started ON testing_runs (tenant_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_testing_runs_lane_status ON testing_runs (lane, status);

CREATE TABLE IF NOT EXISTS testing_run_artifacts (
  artifact_id UUID PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES testing_runs(run_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  artifact_path TEXT NOT NULL,
  artifact_sha256 CHAR(64) NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(run_id, artifact_path)
);

CREATE INDEX IF NOT EXISTS idx_testing_run_artifacts_tenant ON testing_run_artifacts (tenant_id, run_id);

CREATE TABLE IF NOT EXISTS testing_flake_registry (
  nodeid TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  reason TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at DATE NOT NULL,
  sla_days INTEGER NOT NULL,
  last_seen_run_id UUID NULL REFERENCES testing_runs(run_id),
  trend JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS testing_invariant_registry (
  invariant_id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  severity TEXT NOT NULL,
  owner TEXT NOT NULL,
  description TEXT NOT NULL,
  enforced_by JSONB NOT NULL DEFAULT '[]'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


CREATE TABLE IF NOT EXISTS testing_run_audit (
  audit_id BIGSERIAL PRIMARY KEY,
  run_id UUID NOT NULL REFERENCES testing_runs(run_id),
  tenant_id TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS testing_health_snapshot (
  snapshot_id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  lane TEXT NOT NULL,
  mean_duration_ms DOUBLE PRECISION NOT NULL,
  flake_rate DOUBLE PRECISION NOT NULL,
  invariant_coverage_count INTEGER NOT NULL,
  category_frequency JSONB NOT NULL DEFAULT '{}'::jsonb,
  sample_size INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE FUNCTION deny_testing_runs_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'testing_runs rows are immutable';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_testing_runs_no_update ON testing_runs;
CREATE TRIGGER trg_testing_runs_no_update BEFORE UPDATE ON testing_runs FOR EACH ROW EXECUTE FUNCTION deny_testing_runs_mutation();
DROP TRIGGER IF EXISTS trg_testing_runs_no_delete ON testing_runs;
CREATE TRIGGER trg_testing_runs_no_delete BEFORE DELETE ON testing_runs FOR EACH ROW EXECUTE FUNCTION deny_testing_runs_mutation();

ALTER TABLE testing_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE testing_run_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE testing_flake_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE testing_invariant_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE testing_run_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE testing_health_snapshot ENABLE ROW LEVEL SECURITY;

CREATE POLICY testing_runs_tenant_isolation ON testing_runs
USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY testing_run_artifacts_tenant_isolation ON testing_run_artifacts
USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY testing_flake_registry_tenant_isolation ON testing_flake_registry
USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY testing_invariant_registry_tenant_isolation ON testing_invariant_registry
USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY testing_run_audit_tenant_isolation ON testing_run_audit
USING (tenant_id = current_setting('app.tenant_id', true));

CREATE POLICY testing_health_snapshot_tenant_isolation ON testing_health_snapshot
USING (tenant_id = current_setting('app.tenant_id', true));

COMMIT;
