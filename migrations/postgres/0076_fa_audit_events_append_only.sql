-- Migration 0076: Enforce append-only semantics on fa_engagement_audit_events.
--
-- fa_engagement_audit_events is declared append-only in code but had no
-- database-level enforcement.  This migration adds BEFORE UPDATE and BEFORE
-- DELETE triggers that reject any mutation, using the shared append_only_guard()
-- function that was established in migration 0013.
--
-- The table is ORM-managed (no CREATE TABLE migration), so a to_regclass() guard
-- makes the DO block safe to run even if create_all() has not yet been called
-- (e.g. when running migrations in isolation against an empty schema).
--
-- Triggers are created with DROP IF EXISTS first so the block is idempotent.

DO $$
BEGIN
    IF to_regclass('public.fa_engagement_audit_events') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS fa_engagement_audit_events_append_only_update
            ON fa_engagement_audit_events;
        CREATE TRIGGER fa_engagement_audit_events_append_only_update
            BEFORE UPDATE ON fa_engagement_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();

        DROP TRIGGER IF EXISTS fa_engagement_audit_events_append_only_delete
            ON fa_engagement_audit_events;
        CREATE TRIGGER fa_engagement_audit_events_append_only_delete
            BEFORE DELETE ON fa_engagement_audit_events
            FOR EACH ROW
            EXECUTE FUNCTION append_only_guard();
    END IF;
END $$;
