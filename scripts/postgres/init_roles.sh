#!/usr/bin/env bash
set -euo pipefail

# Demote the default Docker superuser so the app role satisfies
# assert_db_role_safe() (no SUPERUSER, no BYPASSRLS).
#
# CURRENT_USER is a SQL keyword supported since PG 9.0, so no
# dynamic-SQL / quote_ident dance is needed.

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<'SQL'
ALTER ROLE CURRENT_USER NOSUPERUSER NOBYPASSRLS;

-- Verify the demotion actually took effect
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = current_user
          AND (rolsuper OR rolbypassrls)
    ) THEN
        RAISE EXCEPTION 'init_roles: role "%" is still superuser or has BYPASSRLS', current_user;
    END IF;
END $$;
SQL
