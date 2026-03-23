#!/usr/bin/env bash
set -euo pipefail

# Bootstrap user is POSTGRES_USER (superuser created by the image).
# We create/repair a least-privilege app role that satisfies assert_db_role_safe()
# (NOSUPERUSER, NOBYPASSRLS) and owns the app database objects.

BOOTSTRAP_USER="${POSTGRES_USER:?POSTGRES_USER must be set}"
BOOTSTRAP_DB="${POSTGRES_DB:?POSTGRES_DB must be set}"

APP_USER="${POSTGRES_APP_USER:?POSTGRES_APP_USER must be set}"
APP_PASS="${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD must be set}"
APP_DB="${POSTGRES_APP_DB:?POSTGRES_APP_DB must be set}"

psql_base=(psql -v ON_ERROR_STOP=1 --username "${BOOTSTRAP_USER}" --dbname "${BOOTSTRAP_DB}")

# 1) Ensure the application role exists and ALWAYS has the expected password/attributes.
"${psql_base[@]}" <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}') THEN
    CREATE ROLE "${APP_USER}" WITH LOGIN PASSWORD '${APP_PASS}'
      NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  ELSE
    ALTER ROLE "${APP_USER}" WITH LOGIN PASSWORD '${APP_PASS}'
      NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END
\$\$;
SQL

# 2) Ensure the application database exists and is owned by the application role.
"${psql_base[@]}" <<SQL
SELECT format('CREATE DATABASE "%s" OWNER "%s"', '${APP_DB}', '${APP_USER}')
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${APP_DB}')
\gexec
SQL

# 3) Align ownership/connect privileges on the application database.
"${psql_base[@]}" <<SQL
ALTER DATABASE "${APP_DB}" OWNER TO "${APP_USER}";
GRANT CONNECT ON DATABASE "${APP_DB}" TO "${APP_USER}";
SQL

# 4) Ensure schema privileges inside the application database.
psql_app=(psql -v ON_ERROR_STOP=1 --username "${BOOTSTRAP_USER}" --dbname "${APP_DB}")

"${psql_app[@]}" <<SQL
GRANT USAGE, CREATE ON SCHEMA public TO "${APP_USER}";

ALTER DEFAULT PRIVILEGES FOR ROLE "${APP_USER}" IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${APP_USER}";
ALTER DEFAULT PRIVILEGES FOR ROLE "${APP_USER}" IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO "${APP_USER}";
ALTER DEFAULT PRIVILEGES FOR ROLE "${APP_USER}" IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO "${APP_USER}";
SQL
