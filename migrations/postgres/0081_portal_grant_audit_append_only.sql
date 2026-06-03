-- Migration 0081: Enforce append-only semantics on portal_grant_audit_events.
--
-- portal_grant_audit_events is declared append-only in code and in RLS
-- (SELECT + INSERT policies only, no UPDATE/DELETE policy). This migration
-- adds BEFORE UPDATE and BEFORE DELETE triggers at the DB layer for defence
-- in depth, using the shared append_only_guard() function from migration 0013.
--
-- Uses to_regclass() guard so the block is safe to run even if the table
-- was not yet created by create_all() (e.g. migration replay against empty schema).
-- Triggers are created with DROP IF EXISTS first so the block is idempotent.

DO $$
BEGIN
    IF to_regclass('public.portal_grant_audit_events') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS portal_grant_audit_events_append_only_update
            ON portal_grant_audit_events;
        CREATE TRIGGER portal_grant_audit_events_append_only_update
            BEFORE UPDATE ON portal_grant_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS portal_grant_audit_events_append_only_delete
            ON portal_grant_audit_events;
        CREATE TRIGGER portal_grant_audit_events_append_only_delete
            BEFORE DELETE ON portal_grant_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
