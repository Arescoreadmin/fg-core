DROP POLICY IF EXISTS decisions_tenant_isolation ON decisions;
DROP POLICY IF EXISTS decision_evidence_artifacts_tenant_isolation ON decision_evidence_artifacts;

ALTER TABLE decisions DISABLE ROW LEVEL SECURITY;
ALTER TABLE decision_evidence_artifacts DISABLE ROW LEVEL SECURITY;
