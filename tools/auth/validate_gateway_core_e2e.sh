#!/usr/bin/env bash
# tools/auth/validate_gateway_core_e2e.sh
#
# Proves the full IdP → admin-gateway auth chain at runtime (Task 6.2):
#
#   A) fg-idp issues a client_credentials token
#   B) admin-gateway /auth/token-exchange creates a session cookie from that token
#   C) /admin/me returns 200 with the correct subject using the session cookie
#   D) Structural header check: X-FG-Internal-Token present in proxy headers for prod-like env
#
# The admin-gateway is started locally (uvicorn) against the running fg-idp container.
# Core is NOT required for steps A–C (they do not proxy to core).
#
# Usage:
#   bash tools/auth/validate_gateway_core_e2e.sh
#
# Env overrides:
#   FG_KEYCLOAK_CLIENT_ID      (default: fg-service)
#   FG_KEYCLOAK_CLIENT_SECRET  (default: fg-service-ci-secret)
#   FG_KEYCLOAK_REALM          (default: FrostGate)
#   KC_TEARDOWN                (default: 1; set to 0 to leave fg-idp running)
#   AG_PORT                    (default: 28080; admin-gateway local listen port)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT}"

KC_CLIENT_ID="${FG_KEYCLOAK_CLIENT_ID:-fg-service}"
KC_CLIENT_SECRET="${FG_KEYCLOAK_CLIENT_SECRET:-fg-service-ci-secret}"
KC_REALM="${FG_KEYCLOAK_REALM:-FrostGate}"
KC_HOST_URL="http://localhost:8081"
KC_CONTAINER="fg-core-fg-idp-1"
TEARDOWN="${KC_TEARDOWN:-1}"
AG_PORT="${AG_PORT:-28080}"
AG_BASE_URL="http://127.0.0.1:${AG_PORT}"
AG_PID=""

# Temp env file: satisfies compose :? interpolation without affecting runtime.
FG_VALIDATE_ENV="$(mktemp /tmp/fg.e2e.validate.XXXXXX.env)"

_cleanup() {
  if [ -n "${AG_PID}" ] && kill -0 "${AG_PID}" 2>/dev/null; then
    echo ""
    echo "==> Stopping admin-gateway (pid=${AG_PID})"
    kill "${AG_PID}" 2>/dev/null || true
    wait "${AG_PID}" 2>/dev/null || true
  fi
  if [ "${TEARDOWN}" = "1" ]; then
    echo ""
    echo "==> Tearing down fg-idp"
    docker compose --env-file "${FG_VALIDATE_ENV}" --profile idp \
      down fg-idp 2>/dev/null || \
      docker rm -f fg-core-fg-idp-1 2>/dev/null || true
  fi
  rm -f "${FG_VALIDATE_ENV}"
  rm -f /tmp/fg.e2e.token.json /tmp/fg.e2e.exchange.json /tmp/fg.e2e.me.json
}
trap _cleanup EXIT

# CI-safe placeholders for all :? compose vars (never used at runtime).
cat > "${FG_VALIDATE_ENV}" <<'ENV'
DATABASE_URL=postgres://ci:ci@localhost:5432/ci
FG_SIGNING_SECRET=ci-signing-secret-32-bytes-minimum
FG_INTERNAL_AUTH_SECRET=ci-internal-auth-secret-32-bytes
FG_API_KEY=ci-api-key-placeholder
FG_WEBHOOK_SECRET=ci-webhook-secret-placeholder
REDIS_PASSWORD=ci-redis-password
NATS_AUTH_TOKEN=ci-nats-token
POSTGRES_PASSWORD=ci-postgres-password
POSTGRES_APP_PASSWORD=ci-postgres-password
ENV

# ---------------------------------------------------------------------------
echo "==> [0] Starting fg-idp (Keycloak 24.0, profile: idp)"
docker compose --env-file "${FG_VALIDATE_ENV}" --profile idp up -d fg-idp

echo "==> [0] Waiting for fg-idp healthy (max 120s)"
bash tools/ci/wait_healthy.sh "${KC_CONTAINER}" 120
echo "    fg-idp healthy"

# ---------------------------------------------------------------------------
echo ""
echo "==> [0] Starting admin-gateway (uvicorn, port=${AG_PORT})"

VENV_PY="${ROOT}/.venv/bin/python"
if [ ! -x "${VENV_PY}" ]; then
  echo "ERROR: venv not found at ${VENV_PY} — run: make venv" >&2
  exit 1
fi

env \
  PYTHONPATH="${ROOT}" \
  FG_ENV=dev \
  FG_DEV_AUTH_BYPASS="false" \
  FG_KEYCLOAK_BASE_URL="${KC_HOST_URL}" \
  FG_KEYCLOAK_REALM="${KC_REALM}" \
  FG_KEYCLOAK_CLIENT_ID="${KC_CLIENT_ID}" \
  FG_KEYCLOAK_CLIENT_SECRET="${KC_CLIENT_SECRET}" \
  FG_OIDC_REDIRECT_URL="${AG_BASE_URL}/auth/callback" \
  FG_SESSION_SECRET="e2e-test-session-secret-32-bytes-ok" \
  "${VENV_PY}" -m uvicorn admin_gateway.main:build_app \
    --factory \
    --host 127.0.0.1 \
    --port "${AG_PORT}" \
    --log-level warning \
  > /tmp/fg.e2e.ag.log 2>&1 &

AG_PID="$!"
echo "    admin-gateway pid=${AG_PID}"

echo "==> [0] Waiting for admin-gateway /health (max 30s)"
for i in $(seq 1 30); do
  if curl -fsS "${AG_BASE_URL}/health" > /dev/null 2>&1; then
    echo "    admin-gateway healthy"
    break
  fi
  if ! kill -0 "${AG_PID}" 2>/dev/null; then
    echo "ERROR: admin-gateway process died — log:" >&2
    cat /tmp/fg.e2e.ag.log >&2
    exit 1
  fi
  sleep 1
done

if ! curl -fsS "${AG_BASE_URL}/health" > /dev/null 2>&1; then
  echo "ERROR: admin-gateway /health not ready after 30s — log:" >&2
  cat /tmp/fg.e2e.ag.log >&2
  exit 1
fi

# ---------------------------------------------------------------------------
echo ""
echo "==> [A] Token issuance — client_credentials from fg-idp"

curl -fsS -X POST \
  "${KC_HOST_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${KC_CLIENT_ID}" \
  --data-urlencode "client_secret=${KC_CLIENT_SECRET}" \
  > /tmp/fg.e2e.token.json

python3 - /tmp/fg.e2e.token.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get('access_token'):
    print(f'FAIL: no access_token: {d}', file=sys.stderr); sys.exit(1)
print(f'    Token OK  token_type={d["token_type"]}')
PY

ACCESS_TOKEN="$(python3 -c "import json; print(json.load(open('/tmp/fg.e2e.token.json'))['access_token'])")"

# ---------------------------------------------------------------------------
echo ""
echo "==> [B] Token exchange — POST ${AG_BASE_URL}/auth/token-exchange"

HTTP_STATUS="$(curl \
  -o /tmp/fg.e2e.exchange.json \
  -w '%{http_code}' \
  -s -X POST \
  "${AG_BASE_URL}/auth/token-exchange" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -c /tmp/fg.e2e.cookies.txt)"

python3 - /tmp/fg.e2e.exchange.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status != '200':
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read()
    print(f'FAIL: token-exchange HTTP={status} body={body}', file=sys.stderr); sys.exit(1)
d = json.load(open(path))
if not d.get('session_id'):
    print(f'FAIL: no session_id in response: {d}', file=sys.stderr); sys.exit(1)
if not d.get('user_id'):
    print(f'FAIL: no user_id in response: {d}', file=sys.stderr); sys.exit(1)
print(f'    Token exchange OK  user_id={d["user_id"]} session_id={d["session_id"][:12]}...')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [C] Session cookie → GET ${AG_BASE_URL}/admin/me"

HTTP_STATUS="$(curl \
  -o /tmp/fg.e2e.me.json \
  -w '%{http_code}' \
  -s \
  "${AG_BASE_URL}/admin/me" \
  -b /tmp/fg.e2e.cookies.txt)"

python3 - /tmp/fg.e2e.me.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status != '200':
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read()
    print(f'FAIL: /admin/me HTTP={status} body={body}', file=sys.stderr); sys.exit(1)
d = json.load(open(path))
if not d.get('user_id'):
    print(f'FAIL: no user_id in /admin/me response: {d}', file=sys.stderr); sys.exit(1)
print(f'    /admin/me OK  user_id={d["user_id"]} scopes={d.get("scopes", [])}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [D] Structural check — X-FG-Internal-Token present in prod-like proxy headers"

python3 - <<PY
import os, sys
os.environ["PYTHONPATH"] = "."
sys.path.insert(0, ".")

from unittest.mock import MagicMock, patch

# Simulate prod-like env with AG_CORE_INTERNAL_TOKEN set.
with patch.dict(os.environ, {
    "FG_ENV": "production",
    "AG_CORE_INTERNAL_TOKEN": "test-internal-token-value",
}):
    from admin_gateway.routers.admin import _core_proxy_headers
    mock_request = MagicMock()
    mock_request.state.request_id = "test-req-id"
    headers = _core_proxy_headers(mock_request)

if "X-FG-Internal-Token" not in headers:
    print("FAIL: X-FG-Internal-Token not present in prod proxy headers", file=sys.stderr)
    sys.exit(1)
if headers["X-FG-Internal-Token"] != "test-internal-token-value":
    print(f'FAIL: X-FG-Internal-Token value mismatch: {headers["X-FG-Internal-Token"]}', file=sys.stderr)
    sys.exit(1)
if "X-Admin-Gateway-Internal" not in headers:
    print("FAIL: X-Admin-Gateway-Internal not present in prod proxy headers", file=sys.stderr)
    sys.exit(1)
print(f"    Header check OK  X-FG-Internal-Token=<present> X-Admin-Gateway-Internal={headers['X-Admin-Gateway-Internal']}")
PY

# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Gateway/Core e2e auth validation: ALL CHECKS PASSED"
echo "   A) Keycloak token issuance:    OK (client_credentials)"
echo "   B) Token exchange → session:   OK (POST /auth/token-exchange)"
echo "   C) Protected endpoint access:  OK (GET /admin/me)"
echo "   D) Proxy header structure:     OK (X-FG-Internal-Token present)"
echo "============================================================"
rm -f /tmp/fg.e2e.cookies.txt
