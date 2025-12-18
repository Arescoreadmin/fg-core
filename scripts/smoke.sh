#!/usr/bin/env bash
set -euo pipefail

SERVICE="frostgate-core"
CID="$(docker compose ps -q "$SERVICE")"
ADMIN_KEY="$(grep -E '^FG_ADMIN_KEY=' .env | cut -d= -f2-)"

echo "[1] waiting for container health=healthy..."
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$CID")" = "healthy" ]; do
  sleep 0.5
done
echo "ok"

echo "[2] health endpoints..."
curl -fsS http://localhost:18080/health/live >/dev/null
curl -fsS http://localhost:18080/health/ready >/dev/null
echo "ok"

echo "[3] auth must block..."
code="$(curl -s -o /dev/null -w "%{http_code}" http://localhost:18080/decisions || true)"
test "$code" != "200"
echo "ok"

echo "[4] generate a decision + verify persisted..."
curl -fsS http://localhost:18080/defend \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ADMIN_KEY" \
  -d "$(python - <<'PY'
import json, datetime
print(json.dumps({
  "tenant_id":"local",
  "source":"smoke",
  "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
  "payload": {"event_type":"auth.bruteforce","source_ip":"1.2.3.4","fail_count": 12}
}))
PY
)" >/dev/null

resp="$(curl -fsS "http://localhost:18080/decisions?limit=1&include_raw=false" \
  -H "X-API-Key: $ADMIN_KEY")"

echo "$resp" | jq -e '
  def items:
    if type=="object" and has("items") then .items
    elif type=="array" then .
    else error("unexpected /decisions JSON shape")
    end;

  (items|length)>=1
' >/dev/null

echo "✅ smoke test passed"
