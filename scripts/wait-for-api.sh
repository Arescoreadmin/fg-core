#!/usr/bin/env bash
set -euo pipefail

SERVICE="frostgate-core"

CID="$(docker compose ps -q "$SERVICE")"

if [ -z "$CID" ]; then
  echo "❌ container for $SERVICE not found"
  docker compose ps
  exit 1
fi

echo "⏳ waiting for $SERVICE health=healthy..."

until [ "$(docker inspect -f '{{.State.Health.Status}}' "$CID")" = "healthy" ]; do
  docker compose ps
  sleep 0.5
done

echo "✅ API is healthy."
