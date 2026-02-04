#!/usr/bin/env bash
set -euo pipefail

TIMEOUT_SEC="${FG_PG_WAIT_TIMEOUT:-60}"
SLEEP_SEC="${FG_PG_WAIT_INTERVAL:-2}"
SERVICE_NAME="${FG_PG_SERVICE:-postgres}"

start_ts="$(date +%s)"

while true; do
  if command -v docker >/dev/null 2>&1; then
    container_id="$(docker compose ps -q "${SERVICE_NAME}" 2>/dev/null || true)"
    if [ -n "${container_id}" ]; then
      pg_user="${POSTGRES_BOOTSTRAP_USER:-${POSTGRES_USER:-fg_user}}"
      if docker compose exec -T "${SERVICE_NAME}" pg_isready -U "${pg_user}" -d "${POSTGRES_DB:-frostgate}" -h 127.0.0.1 >/dev/null 2>&1; then
        echo "Postgres is ready (via docker compose)."
        exit 0
      fi
    fi
  fi

  if command -v pg_isready >/dev/null 2>&1; then
    pg_user="${PGUSER:-${POSTGRES_BOOTSTRAP_USER:-${POSTGRES_USER:-fg_user}}}"
    if pg_isready -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" -U "${pg_user}" -d "${PGDATABASE:-frostgate}" >/dev/null 2>&1; then
      echo "Postgres is ready."
      exit 0
    fi
  fi

  if ! command -v docker >/dev/null 2>&1 && ! command -v pg_isready >/dev/null 2>&1; then
    echo "pg_isready not found and docker not available."
    exit 1
  fi

  now_ts="$(date +%s)"
  if (( now_ts - start_ts > TIMEOUT_SEC )); then
    echo "Timed out waiting for Postgres after ${TIMEOUT_SEC}s."
    exit 1
  fi
  sleep "${SLEEP_SEC}"
done
