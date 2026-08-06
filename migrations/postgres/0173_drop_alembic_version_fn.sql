-- Migration 0173: drop any stored functions referencing alembic_version.
--
-- The production database contains one or more stored functions whose bodies
-- query alembic_version (SQLAlchemy migration table). FrostGate uses
-- schema_migrations instead; alembic_version was never part of this schema.
-- The orphaned function(s) cause pg_restore to fail with --exit-on-error
-- during the C1 restore drill.
--
-- Uses quote_ident() + concatenation rather than PostgreSQL format() to avoid
-- psycopg3 treating format specifiers as Python placeholders.
-- Uses strpos() rather than LIKE to avoid bare percent signs in SQL text.

DO $$
DECLARE
    r RECORD;
    drop_sql TEXT;
BEGIN
    FOR r IN
        SELECT
            n.nspname                                         AS schema_name,
            p.proname                                         AS func_name,
            pg_get_function_identity_arguments(p.oid)        AS func_args
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE strpos(p.prosrc, 'alembic_version') > 0
    LOOP
        drop_sql := 'DROP FUNCTION IF EXISTS '
            || quote_ident(r.schema_name) || '.'
            || quote_ident(r.func_name)   || '('
            || r.func_args || ') CASCADE';
        EXECUTE drop_sql;
        RAISE NOTICE 'migration 0173: dropped alembic_version function';
    END LOOP;
END
$$;
