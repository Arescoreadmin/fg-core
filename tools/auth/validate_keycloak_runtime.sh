#!/usr/bin/env bash
# tools/auth/validate_keycloak_runtime.sh
#
# Proves Keycloak runtime: discovery, token issuance,
# container-network reachability, and negative-path enforcement.
#
# Usage:
#   bash tools/auth/validate_keycloak_runtime.sh
#
# Env overrides:
#   FG_KEYCLOAK_CLIENT_ID      (default: fg-service)
#   FG_KEYCLOAK_CLIENT_SECRET  (default: fg-service-ci-secret)
#   FG_KEYCLOAK_REALM          (default: FrostGate)
#   KC_TEARDOWN                (default: 1; set to 0 to leave Keycloak running)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT}"

KC_CLIENT_ID="${FG_KEYCLOAK_CLIENT_ID:-fg-service}"
KC_CLIENT_SECRET="${FG_KEYCLOAK_CLIENT_SECRET:-fg-service-ci-secret}"
KC_REALM="${FG_KEYCLOAK_REALM:-FrostGate}"
KC_HOST_URL="http://localhost:8081"
KC_INTERNAL_URL="http://fg-idp:8080"
KC_CONTAINER="fg-core-fg-idp-1"
TEARDOWN="${KC_TEARDOWN:-1}"
COMPOSE_NETWORK="fg-core_internal"

# Temp env file: satisfies compose :? interpolation for non-idp services
# without affecting runtime. Only the fg-idp service actually starts.
FG_VALIDATE_ENV="$(mktemp /tmp/fg.idp.validate.XXXXXX.env)"

_cleanup() {
  if [ "${TEARDOWN}" = "1" ]; then
    echo ""
    echo "==> Tearing down fg-idp"
    docker compose --env-file "${FG_VALIDATE_ENV}" --profile idp \
      down fg-idp 2>/dev/null || \
      docker rm -f fg-core-fg-idp-1 2>/dev/null || true
  fi
  rm -f "${FG_VALIDATE_ENV}"
}
trap _cleanup EXIT

# Write CI-safe placeholders for all :? required vars in docker-compose.yml
# These are never used at runtime — only satisfy compose file interpolation.
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
echo "==> [1] Starting fg-idp (Keycloak 24.0, profile: idp)"
docker compose --env-file "${FG_VALIDATE_ENV}" --profile idp up -d fg-idp

echo "==> [2] Waiting for fg-idp healthy (max 120s)"
bash tools/ci/wait_healthy.sh "${KC_CONTAINER}" 120
echo "    fg-idp healthy"

# ---------------------------------------------------------------------------
echo ""
echo "==> [A] Host-side discovery (published port — localhost:8081)"

curl -fsS \
  "${KC_HOST_URL}/realms/${KC_REALM}/.well-known/openid-configuration" \
  > /tmp/fg.oidc.discovery.json

python3 - /tmp/fg.oidc.discovery.json "${KC_REALM}" <<'PY'
import json, sys
path, realm = sys.argv[1], sys.argv[2]
d = json.load(open(path))
required = ['issuer', 'token_endpoint', 'jwks_uri', 'authorization_endpoint']
missing = [k for k in required if not d.get(k)]
if missing:
    print(f'FAIL: missing discovery keys: {missing}', file=sys.stderr); sys.exit(1)
if f'/realms/{realm}' not in d['issuer']:
    print(f'FAIL: issuer missing /realms/{realm}: {d["issuer"]}', file=sys.stderr); sys.exit(1)
print(f'    Discovery OK  issuer={d["issuer"]}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [B] Container-network reachability (docker run on ${COMPOSE_NETWORK})"
echo "        target: ${KC_INTERNAL_URL}/realms/${KC_REALM}/.well-known/openid-configuration"

docker run --rm \
  --network "${COMPOSE_NETWORK}" \
  curlimages/curl:latest \
  -fsS \
  "${KC_INTERNAL_URL}/realms/${KC_REALM}/.well-known/openid-configuration" \
  > /tmp/fg.oidc.internal.discovery.json

python3 - /tmp/fg.oidc.internal.discovery.json "${KC_REALM}" <<'PY'
import json, sys
path, realm = sys.argv[1], sys.argv[2]
d = json.load(open(path))
if f'/realms/{realm}' not in d.get('issuer', ''):
    print(f'FAIL: container-side issuer mismatch: {d.get("issuer")}', file=sys.stderr); sys.exit(1)
print(f'    Container-network OK  issuer={d["issuer"]}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [C] Token issuance (client_credentials, client_id=${KC_CLIENT_ID})"

curl -fsS -X POST \
  "${KC_HOST_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${KC_CLIENT_ID}" \
  --data-urlencode "client_secret=${KC_CLIENT_SECRET}" \
  > /tmp/fg.oidc.token.json

python3 - /tmp/fg.oidc.token.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get('access_token'):
    print(f'FAIL: no access_token: {d}', file=sys.stderr); sys.exit(1)
if d.get('token_type', '').lower() != 'bearer':
    print(f'FAIL: token_type not bearer: {d.get("token_type")}', file=sys.stderr); sys.exit(1)
print(f'    Token issuance OK  token_type={d["token_type"]} access_token=<present>')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [D] Negative path — wrong client secret must be rejected"

HTTP_STATUS="$(curl \
  -o /tmp/fg.oidc.negative.json \
  -w '%{http_code}' \
  -s -X POST \
  "${KC_HOST_URL}/realms/${KC_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=${KC_CLIENT_ID}" \
  --data-urlencode "client_secret=wrong-secret-intentionally")"

python3 - /tmp/fg.oidc.negative.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path))
except Exception:
    d = {}
if d.get('access_token'):
    print('FAIL: wrong secret returned a valid token — auth NOT enforced', file=sys.stderr)
    sys.exit(1)
print(f'    Negative path OK  HTTP={status} error={d.get("error", "<no-token>")}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Keycloak runtime validation: ALL CHECKS PASSED"
echo "   A) Host-side discovery:       OK"
echo "   B) Container-network proof:   OK (via fg-core_internal)"
echo "   C) Token issuance:            OK (client_credentials)"
echo "   D) Negative path:             OK (wrong secret rejected)"
echo "============================================================"
