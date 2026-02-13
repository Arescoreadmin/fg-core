#!/usr/bin/env bash
set -euo pipefail

# Bootstrap user is POSTGRES_USER (superuser created by the image).
# We create a least-privilege app role that satisfies assert_db_role_safe()
# (NOSUPERUSER, NOBYPASSRLS) and owns the DB objects.

APP_USER="${POSTGRES_APP_USER:-fg_app}"
APP_PASS="${POSTGRES_APP_PASSWORD:-${POSTGRES_PASSWORD}}"
DB_NAME="${POSTGRES_DB:?POSTGRES_DB must be set}"

psql -v ON_ERROR_STOP=1 --username "${POSTGRES_USER}" --dbname "${DB_NAME}" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN
    CREATE ROLE "${APP_USER}" WITH LOGIN PASSWORD '${APP_PASS}'
      NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
\$\$;

-- Ensure app role can connect to the database
GRANT CONNECT ON DATABASE "${DB_NAME}" TO "${APP_USER}";

-- Ensure app role can use/create in public schema (DEV-friendly; tighten later if needed)
GRANT USAGE, CREATE ON SCHEMA public TO "${APP_USER}";

-- Make app role the database owner (so migrations can create/alter tables, policies, triggers)
ALTER DATABASE "${DB_NAME}" OWNER TO "${APP_USER}";

-- Ensure future objects created by the owner grant appropriate access (keeps privileges sane)
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${APP_USER}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "${APP_USER}";
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO "${APP_USER}";
SQL
