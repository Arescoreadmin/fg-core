ALTER TABLE decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE decision_evidence_artifacts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS decisions_tenant_isolation ON decisions;
CREATE POLICY decisions_tenant_isolation ON decisions
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

DROP POLICY IF EXISTS decision_evidence_artifacts_tenant_isolation ON decision_evidence_artifacts;
CREATE POLICY decision_evidence_artifacts_tenant_isolation ON decision_evidence_artifacts
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));
