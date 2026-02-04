#!/usr/bin/env bash
set -euo pipefail

retries=${1:-30}

pg_user=$(docker compose exec -T postgres sh -lc 'printf "%s" "$POSTGRES_USER"')
pg_db=$(docker compose exec -T postgres sh -lc 'printf "%s" "$POSTGRES_DB"')

for i in $(seq 1 "$retries"); do
  if docker compose exec -T postgres pg_isready -U "$pg_user" -d "$pg_db" -h 127.0.0.1 >/dev/null 2>&1; then
    echo "✅ Postgres ready"
    exit 0
  fi
  sleep 2
  echo "Waiting for Postgres ($i/$retries)..."
done

echo "❌ Postgres did not become ready in time" >&2
exit 1
