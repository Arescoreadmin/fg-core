#!/usr/bin/env bash
set -euo pipefail

db_name="${1:-frostgate}"
if [[ ! "${db_name}" =~ ^[a-zA-Z0-9_]+$ ]]; then
  echo "invalid database name: ${db_name}" >&2
  exit 2
fi

app_user="$(docker compose exec -T postgres printenv POSTGRES_APP_USER | tr -d '')"
if [[ ! "${app_user}" =~ ^[a-zA-Z0-9_]+$ ]]; then
  echo "invalid application role: ${app_user}" >&2
  exit 2
fi

docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='${db_name}' AND pid <> pg_backend_pid();"
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c "DROP DATABASE IF EXISTS "${db_name}";"
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d postgres -c "CREATE DATABASE "${db_name}" OWNER "${app_user}";"
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U postgres -d "${db_name}" -c "CREATE EXTENSION IF NOT EXISTS vector;"
