DROP TRIGGER IF EXISTS decisions_append_only_update ON decisions;
DROP TRIGGER IF EXISTS decisions_append_only_delete ON decisions;
DROP TRIGGER IF EXISTS decision_evidence_artifacts_append_only_update ON decision_evidence_artifacts;
DROP TRIGGER IF EXISTS decision_evidence_artifacts_append_only_delete ON decision_evidence_artifacts;

DROP FUNCTION IF EXISTS fg_guard_append_only();
