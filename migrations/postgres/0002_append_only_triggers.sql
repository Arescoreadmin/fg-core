CREATE OR REPLACE FUNCTION fg_append_only_enforcer()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION USING
        MESSAGE = 'append-only violation on ' || TG_TABLE_NAME,
        ERRCODE = 'check_violation';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'decisions_append_only_update'
    ) THEN
        CREATE TRIGGER decisions_append_only_update
        BEFORE UPDATE ON decisions
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'decisions_append_only_delete'
    ) THEN
        CREATE TRIGGER decisions_append_only_delete
        BEFORE DELETE ON decisions
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'decision_evidence_artifacts_append_only_update'
    ) THEN
        CREATE TRIGGER decision_evidence_artifacts_append_only_update
        BEFORE UPDATE ON decision_evidence_artifacts
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'decision_evidence_artifacts_append_only_delete'
    ) THEN
        CREATE TRIGGER decision_evidence_artifacts_append_only_delete
        BEFORE DELETE ON decision_evidence_artifacts
        FOR EACH ROW EXECUTE FUNCTION fg_append_only_enforcer();
    END IF;
END $$;
