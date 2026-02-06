#!/usr/bin/env bash
set -euo pipefail

# The Docker POSTGRES_USER is the bootstrap superuser — PostgreSQL forbids
# removing SUPERUSER from the bootstrap role.  Instead we create a dedicated
# application role (fg_app) that owns the database and satisfies
# assert_db_role_safe() (NOSUPERUSER, NOBYPASSRLS).

APP_USER="${POSTGRES_APP_USER:-fg_app}"
APP_PASS="${POSTGRES_APP_PASSWORD:-${POSTGRES_PASSWORD}}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${POSTGRES_DB}" <<SQL
-- Create the application role (idempotent)
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN
        CREATE ROLE ${APP_USER} WITH LOGIN PASSWORD '${APP_PASS}'
            NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
    END IF;
END \$\$;

-- Let the app role own the target database so it can CREATE/ALTER objects
ALTER DATABASE ${POSTGRES_DB} OWNER TO ${APP_USER};

-- Ensure schema access
GRANT ALL ON SCHEMA public TO ${APP_USER};
SQL
