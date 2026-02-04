CREATE OR REPLACE FUNCTION fg_guard_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS decisions_append_only_update ON decisions;
DROP TRIGGER IF EXISTS decisions_append_only_delete ON decisions;
DROP TRIGGER IF EXISTS decision_evidence_artifacts_append_only_update ON decision_evidence_artifacts;
DROP TRIGGER IF EXISTS decision_evidence_artifacts_append_only_delete ON decision_evidence_artifacts;

CREATE TRIGGER decisions_append_only_update
BEFORE UPDATE ON decisions
FOR EACH ROW
EXECUTE FUNCTION fg_guard_append_only();

CREATE TRIGGER decisions_append_only_delete
BEFORE DELETE ON decisions
FOR EACH ROW
EXECUTE FUNCTION fg_guard_append_only();

CREATE TRIGGER decision_evidence_artifacts_append_only_update
BEFORE UPDATE ON decision_evidence_artifacts
FOR EACH ROW
EXECUTE FUNCTION fg_guard_append_only();

CREATE TRIGGER decision_evidence_artifacts_append_only_delete
BEFORE DELETE ON decision_evidence_artifacts
FOR EACH ROW
EXECUTE FUNCTION fg_guard_append_only();
