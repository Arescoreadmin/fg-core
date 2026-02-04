#!/usr/bin/env bash
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<'SQL'
DO $$
BEGIN
    BEGIN
        EXECUTE 'ALTER ROLE '
            || quote_ident(current_user)
            || ' NOSUPERUSER NOBYPASSRLS';
    EXCEPTION
        WHEN insufficient_privilege THEN
            NULL;
    END;
END $$;
SQL
