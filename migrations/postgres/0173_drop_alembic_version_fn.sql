-- Migration 0173: drop any stored functions referencing alembic_version.
--
-- The production database contains one or more stored functions whose bodies
-- query alembic_version (SQLAlchemy's migration table). FrostGate uses
-- schema_migrations instead; alembic_version never existed in this schema.
-- The orphaned function(s) cause pg_restore to fail with --exit-on-error
-- during the C1 restore drill, as the table they reference is not in the dump.
--
-- This DO block is self-discovering and idempotent: it drops every function
-- whose prosrc contains 'alembic_version', regardless of name or arity.
-- Safe to run on any environment; does nothing if no such functions exist.

DO $$
DECLARE
    r RECORD;
    drop_sql TEXT;
BEGIN
    FOR r IN
        SELECT
            p.oid,
            n.nspname                                         AS schema_name,
            p.proname                                         AS func_name,
            pg_get_function_identity_arguments(p.oid)        AS func_args
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE p.prosrc LIKE '%alembic_version%'
    LOOP
        drop_sql := format(
            'DROP FUNCTION IF EXISTS %I.%I(%s) CASCADE',
            r.schema_name, r.func_name, r.func_args
        );
        EXECUTE drop_sql;
        RAISE NOTICE 'migration 0173: dropped % (%.%(%s))',
            drop_sql, r.schema_name, r.func_name, r.func_args;
    END LOOP;
END
$$;
