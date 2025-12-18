#!/usr/bin/env bash
set -euo pipefail

CORE="${CORE:-http://localhost:18080}"

FG_ADMIN_KEY="$(grep -E '^FG_ADMIN_KEY=' .env | cut -d= -f2-)"
FG_AGENT_KEY="$(grep -E '^FG_AGENT_KEY=' .env | cut -d= -f2-)"

echo "[1/4] Health"
curl -fsS "$CORE/health/live" >/dev/null
echo "OK"

echo "[2/4] Agent ingest should PASS (200)"
curl -fsS -H "x-api-key: $FG_AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"events":[{"tenant_id":"t1","source":"agent1","timestamp":"2025-12-16T00:00:00Z","event_type":"heartbeat","subject":"agent1","features":{"alive":true}}]}' \
  "$CORE/ingest" >/dev/null
echo "OK"

echo "[3/4] Agent defend should FAIL (403)"
set +e
code=$(curl -s -o /dev/null -w "%{http_code}" -H "x-api-key: $FG_AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"source":"edge1","tenant_id":"t1","timestamp":"2025-12-16T00:00:00Z","payload":{"event_type":"auth","failed_auths":7,"src_ip":"1.2.3.4"}}' \
  "$CORE/defend")
set -e
if [[ "$code" != "403" ]]; then
  echo "Expected 403, got $code"
  exit 1
fi
echo "OK"

echo "[4/4] Admin defend should PASS (200)"
curl -fsS -H "x-api-key: $FG_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"source":"edge1","tenant_id":"t1","timestamp":"2025-12-16T00:00:00Z","payload":{"event_type":"auth","failed_auths":7,"src_ip":"1.2.3.4"}}' \
  "$CORE/defend" >/dev/null
echo "OK"

echo "DONE"
