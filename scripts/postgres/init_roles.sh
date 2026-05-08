#!/usr/bin/env bash
set -euo pipefail

# Bootstrap user is POSTGRES_USER (superuser created by the image).
# We create/repair a least-privilege app role that satisfies assert_db_role_safe()
# (NOSUPERUSER, NOBYPASSRLS) and owns the app database objects.
#
# Production goals:
# - idempotent
# - safe quoting for role/database/password values
# - no shell interpolation into SQL literals
# - no psql variable usage inside DO $$ bodies

BOOTSTRAP_USER="${POSTGRES_USER:?POSTGRES_USER must be set}"
BOOTSTRAP_DB="${POSTGRES_DB:?POSTGRES_DB must be set}"

APP_USER="${POSTGRES_APP_USER:?POSTGRES_APP_USER must be set}"
APP_PASS="${POSTGRES_APP_PASSWORD:?POSTGRES_APP_PASSWORD must be set}"
APP_DB="${POSTGRES_APP_DB:?POSTGRES_APP_DB must be set}"

psql_base=(
  psql
  -v ON_ERROR_STOP=1
  --username "${BOOTSTRAP_USER}"
  --dbname "${BOOTSTRAP_DB}"
)

# 1) Ensure the application role exists.
# CREATE only if missing, then always ALTER to enforce expected password/attributes.
"${psql_base[@]}" \
  -v app_user="${APP_USER}" \
  -v app_pass="${APP_PASS}" <<'SQL'
SELECT format(
  'CREATE ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB',
  :'app_user',
  :'app_pass'
)
WHERE NOT EXISTS (
  SELECT FROM pg_roles WHERE rolname = :'app_user'
)
\gexec

SELECT format(
  'ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB',
  :'app_user',
  :'app_pass'
)
\gexec
SQL

# 2) Ensure the application database exists and is owned by the application role.
"${psql_base[@]}" \
  -v app_db="${APP_DB}" \
  -v app_user="${APP_USER}" <<'SQL'
SELECT format(
  'CREATE DATABASE %I OWNER %I',
  :'app_db',
  :'app_user'
)
WHERE NOT EXISTS (
  SELECT FROM pg_database WHERE datname = :'app_db'
)
\gexec
SQL

# 3) Align ownership/connect privileges on the application database.
"${psql_base[@]}" \
  -v app_db="${APP_DB}" \
  -v app_user="${APP_USER}" <<'SQL'
SELECT format('ALTER DATABASE %I OWNER TO %I', :'app_db', :'app_user') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'app_db', :'app_user') \gexec
SQL

# 4) Ensure schema privileges inside the application database.
psql_app=(
  psql
  -v ON_ERROR_STOP=1
  --username "${BOOTSTRAP_USER}"
  --dbname "${APP_DB}"
)

"${psql_app[@]}" \
  -v app_user="${APP_USER}" <<'SQL'
SELECT format('GRANT USAGE, CREATE ON SCHEMA public TO %I', :'app_user') \gexec

SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
  :'app_user',
  :'app_user'
) \gexec

SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO %I',
  :'app_user',
  :'app_user'
) \gexec

SELECT format(
  'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO %I',
  :'app_user',
  :'app_user'
) \gexec
SQL

# 5) Pre-seed the pgvector extension in the application database.
#    Migration 0038 runs CREATE EXTENSION IF NOT EXISTS vector as the application
#    role (fg_user), which is NOSUPERUSER.  PostgreSQL requires superuser to
#    install non-trusted extensions, and pgvector's vector.control has
#    trusted=false.  Pre-creating the extension here as the bootstrap superuser
#    means the migration step becomes a safe no-op (IF NOT EXISTS skips
#    creation and requires no privilege when the extension already exists).
#
#    Exits non-zero with a clear message if the postgres image does not ship
#    pgvector — use pgvector/pgvector:pg16 instead of plain postgres:16.
if ! "${psql_app[@]}" -tAc \
    "SELECT 1 FROM pg_available_extensions WHERE name='vector';" \
    | grep -q 1; then
  echo "ERROR: pgvector extension not available on this postgres server." >&2
  echo "ERROR: docker-compose.yml must use image: pgvector/pgvector:pg16" >&2
  exit 1
fi
"${psql_app[@]}" -c "CREATE EXTENSION IF NOT EXISTS vector;"