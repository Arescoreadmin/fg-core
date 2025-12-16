#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:18080}"

FG_ADMIN_KEY="$(grep ^FG_ADMIN_KEY= .env | cut -d= -f2-)"
FG_AGENT_KEY="$(grep ^FG_AGENT_KEY= .env | cut -d= -f2-)"

echo "[1/4] health"
curl -fsS "$BASE_URL/health/live" >/dev/null
echo "OK"

payload='{"source":"edge1","tenant_id":"t1","timestamp":"2025-12-16T23:46:00Z","payload":{"event_type":"auth","failed_auths":7,"src_ip":"1.2.3.4"}}'

echo "[2/4] agent defend should be 403"
code="$(curl -s -o /dev/null -w "%{http_code}" \
  -H "x-api-key: $FG_AGENT_KEY" -H "Content-Type: application/json" \
  -d "$payload" "$BASE_URL/defend")"
if [[ "$code" != "403" ]]; then
  echo "FAIL: agent /defend expected 403 got $code"
  exit 1
fi
echo "OK"

echo "[3/4] admin defend should be 200"
code="$(curl -s -o /dev/null -w "%{http_code}" \
  -H "x-api-key: $FG_ADMIN_KEY" -H "Content-Type: application/json" \
  -d "$payload" "$BASE_URL/defend")"
if [[ "$code" != "200" ]]; then
  echo "FAIL: admin /defend expected 200 got $code"
  exit 1
fi
echo "OK"

echo "[4/4] decisions should be readable by both"
curl -fsS -H "x-api-key: $FG_ADMIN_KEY" "$BASE_URL/decisions?page_size=1" >/dev/null
curl -fsS -H "x-api-key: $FG_AGENT_KEY" "$BASE_URL/decisions?page_size=1" >/dev/null
echo "OK"
