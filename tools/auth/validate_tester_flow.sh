#!/usr/bin/env bash
# tools/auth/validate_tester_flow.sh
#
# End-to-end runtime proof of the canonical tester path:
#   password-grant token → token-exchange → /admin/me tenant assertion
#   → /admin/audit/search → /admin/audit/export → wrong-tenant denial
#
# Requires running services:
#   - Keycloak IdP (default: http://localhost:8081)
#   - Admin gateway (default: http://localhost:8100)
#
# SKIP (exit 0) if services are not reachable — CI without running services
# FAIL (exit 1) if services are reachable but any assertion fails
#
# Usage:
#   bash tools/auth/validate_tester_flow.sh
#
# Env overrides:
#   FG_KEYCLOAK_BASE_URL     (default: http://localhost:8081)
#   FG_KEYCLOAK_REALM        (default: FrostGate)
#   FG_KEYCLOAK_CLIENT_ID    (default: fg-tester)
#   FG_KEYCLOAK_CLIENT_SECRET (default: fg-tester-ci-secret)
#   FG_TESTER_USER           (default: fg-tester-admin)
#   FG_TESTER_PASSWORD       (default: fg-tester-password)
#   AG_BASE_URL              (default: http://localhost:8100)
#   CANONICAL_TENANT         (default: tenant-seed-primary)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
cd "${ROOT}"

KC_BASE="${FG_KEYCLOAK_BASE_URL:-http://localhost:8081}"
KC_REALM="${FG_KEYCLOAK_REALM:-FrostGate}"
KC_CLIENT_ID="${FG_KEYCLOAK_CLIENT_ID:-fg-tester}"
KC_CLIENT_SECRET="${FG_KEYCLOAK_CLIENT_SECRET:-fg-tester-ci-secret}"
TESTER_USER="${FG_TESTER_USER:-fg-tester-admin}"
TESTER_PASSWORD="${FG_TESTER_PASSWORD:-fg-tester-password}"
AG_BASE="${AG_BASE_URL:-http://localhost:8100}"
CANONICAL_TENANT="${CANONICAL_TENANT:-tenant-seed-primary}"
WRONG_TENANT="tenant-does-not-exist-intentionally"

COOKIES_FILE="$(mktemp /tmp/fg.tester.flow.XXXXXX.cookies)"
_cleanup() { rm -f "${COOKIES_FILE}"; }
trap _cleanup EXIT

# ---------------------------------------------------------------------------
# Service availability — SKIP (exit 0) if services are not reachable
# ---------------------------------------------------------------------------

echo "==> [pre] Service availability check"

KC_DISCOVERY="${KC_BASE}/realms/${KC_REALM}/.well-known/openid-configuration"
if ! curl -fsS --max-time 5 "${KC_DISCOVERY}" >/dev/null 2>&1; then
    echo "SKIP: Keycloak not reachable at ${KC_BASE} — services must be running for end-to-end validation"
    echo "      To start: KC_TEARDOWN=0 bash tools/auth/validate_keycloak_runtime.sh"
    exit 0
fi

if ! curl -fsS --max-time 5 "${AG_BASE}/health" >/dev/null 2>&1; then
    echo "SKIP: Admin gateway not reachable at ${AG_BASE} — services must be running for end-to-end validation"
    echo "      To start: uvicorn admin_gateway.asgi:app --host 0.0.0.0 --port 8100"
    exit 0
fi

echo "    Keycloak:      reachable at ${KC_BASE}"
echo "    Admin gateway: reachable at ${AG_BASE}"

# ---------------------------------------------------------------------------
echo ""
echo "==> [1] OIDC token — password grant (client=${KC_CLIENT_ID}, user=${TESTER_USER})"

curl -fsS -X POST \
    "${KC_BASE}/realms/${KC_REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "grant_type=password" \
    --data-urlencode "client_id=${KC_CLIENT_ID}" \
    --data-urlencode "client_secret=${KC_CLIENT_SECRET}" \
    --data-urlencode "username=${TESTER_USER}" \
    --data-urlencode "password=${TESTER_PASSWORD}" \
    >/tmp/fg.tester.token.json

KC_ACCESS_TOKEN="$(python3 - /tmp/fg.tester.token.json <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
if not d.get('access_token'):
    print(f'FAIL: no access_token in response: {d}', file=sys.stderr); sys.exit(1)
print(d['access_token'])
PY
)"
echo "    Token obtained  access_token=<present>"

# Verify allowed_tenants claim is present and contains canonical tenant
python3 - "${KC_ACCESS_TOKEN}" "${CANONICAL_TENANT}" <<'PY'
import base64, json, sys
token, tenant = sys.argv[1], sys.argv[2]
try:
    seg = token.split('.')[1]
    seg += '=' * (4 - len(seg) % 4)
    claims = json.loads(base64.urlsafe_b64decode(seg))
except Exception as exc:
    print(f'FAIL: cannot decode token payload: {exc}', file=sys.stderr); sys.exit(1)
allowed = claims.get('allowed_tenants', [])
if isinstance(allowed, str):
    allowed = [allowed]
if tenant not in allowed:
    print(
        f'FAIL: allowed_tenants claim missing {tenant!r} — got: {allowed}\n'
        f'      Ensure fg-tester client has the allowed-tenants protocol mapper '
        f'in keycloak/realms/frostgate-realm.json',
        file=sys.stderr,
    )
    sys.exit(1)
print(f'    Token claims OK  allowed_tenants={allowed}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [2] Token exchange → gateway session (POST ${AG_BASE}/auth/token-exchange)"

HTTP_STATUS="$(curl \
    -o /tmp/fg.tester.exchange.json \
    -w '%{http_code}' \
    -s -c "${COOKIES_FILE}" \
    -X POST "${AG_BASE}/auth/token-exchange" \
    -H "Authorization: Bearer ${KC_ACCESS_TOKEN}")"

python3 - /tmp/fg.tester.exchange.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status != '200':
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read(500)
    print(f'FAIL: token exchange returned HTTP {status}: {body}', file=sys.stderr); sys.exit(1)
body = json.load(open(path))
if not body.get('session_id'):
    print(f'FAIL: no session_id in exchange response: {body}', file=sys.stderr); sys.exit(1)
print(f'    Token exchange OK  session_id=<present>  user_id={body.get("user_id")}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [3] Session identity — GET ${AG_BASE}/admin/me"

HTTP_STATUS="$(curl \
    -o /tmp/fg.tester.me.json \
    -w '%{http_code}' \
    -s -b "${COOKIES_FILE}" \
    "${AG_BASE}/admin/me")"

python3 - /tmp/fg.tester.me.json "${HTTP_STATUS}" "${CANONICAL_TENANT}" <<'PY'
import json, sys
path, status, tenant = sys.argv[1], sys.argv[2], sys.argv[3]
if status != '200':
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read(500)
    print(f'FAIL: /admin/me returned HTTP {status}: {body}', file=sys.stderr); sys.exit(1)
body = json.load(open(path))
tenants = body.get('tenants', [])
if tenant not in tenants:
    print(
        f'FAIL: /admin/me tenants does not include {tenant!r}\n'
        f'      Got: {tenants}\n'
        f'      Token must carry allowed_tenants=["{tenant}"] claim',
        file=sys.stderr,
    )
    sys.exit(1)
print(f'    /admin/me OK  tenants={tenants}  current_tenant={body.get("current_tenant")}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [4] Audit search — GET ${AG_BASE}/admin/audit/search?tenant_id=${CANONICAL_TENANT}"

HTTP_STATUS="$(curl \
    -o /tmp/fg.tester.audit.search.json \
    -w '%{http_code}' \
    -s -b "${COOKIES_FILE}" \
    "${AG_BASE}/admin/audit/search?tenant_id=${CANONICAL_TENANT}&page_size=5")"

python3 - /tmp/fg.tester.audit.search.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status != '200':
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read(500)
    print(f'FAIL: audit search returned HTTP {status}: {body}', file=sys.stderr); sys.exit(1)
body = json.load(open(path))
if 'items' not in body:
    print(f'FAIL: audit search response missing "items": {body}', file=sys.stderr); sys.exit(1)
print(f'    Audit search OK  items={len(body["items"])}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [5] Audit export — POST ${AG_BASE}/admin/audit/export"

HTTP_STATUS="$(curl \
    -o /tmp/fg.tester.export.ndjson \
    -w '%{http_code}' \
    -s -b "${COOKIES_FILE}" \
    -X POST "${AG_BASE}/admin/audit/export" \
    -H "Content-Type: application/json" \
    -d "{\"format\":\"json\",\"tenant_id\":\"${CANONICAL_TENANT}\",\"page_size\":10}")"

python3 - /tmp/fg.tester.export.ndjson "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status != '200':
    try:
        body = open(path).read(500)
    except Exception:
        body = '<unreadable>'
    print(f'FAIL: audit export returned HTTP {status}: {body!r}', file=sys.stderr); sys.exit(1)
content = open(path).read().strip()
lines = [ln for ln in content.split('\n') if ln.strip()]
if lines:
    try:
        json.loads(lines[0])
    except json.JSONDecodeError as exc:
        print(f'FAIL: export first line is not valid JSON: {exc}', file=sys.stderr); sys.exit(1)
    print(f'    Audit export OK  lines={len(lines)}')
else:
    print('    Audit export OK  (empty result — seed may not have run yet)')
PY

# ---------------------------------------------------------------------------
echo ""
echo "==> [6] Negative — wrong tenant must be denied (tenant=${WRONG_TENANT})"

HTTP_STATUS="$(curl \
    -o /tmp/fg.tester.negative.json \
    -w '%{http_code}' \
    -s -b "${COOKIES_FILE}" \
    "${AG_BASE}/admin/audit/search?tenant_id=${WRONG_TENANT}&page_size=5")"

python3 - /tmp/fg.tester.negative.json "${HTTP_STATUS}" <<'PY'
import json, sys
path, status = sys.argv[1], sys.argv[2]
if status not in ('403', '404'):
    try:
        body = json.load(open(path))
    except Exception:
        body = open(path).read(500)
    print(
        f'FAIL: wrong-tenant request returned HTTP {status} (expected 403/404)\n'
        f'      body={body}\n'
        f'      Tenant isolation is NOT enforced — this is a security defect.',
        file=sys.stderr,
    )
    sys.exit(1)
try:
    body = json.load(open(path))
    detail = body.get('detail', '')
except Exception:
    detail = ''
print(f'    Negative path OK  HTTP={status}  detail={detail!r}')
PY

# ---------------------------------------------------------------------------
echo ""
echo "============================================================"
echo " Canonical tester flow: ALL ASSERTIONS PASSED"
echo "   1) OIDC token (password grant, ${TESTER_USER}):  OK"
echo "   2) Token exchange → session cookie:               OK"
echo "   3) /admin/me tenant membership:                   OK (tenant=${CANONICAL_TENANT})"
echo "   4) /admin/audit/search canonical tenant:          OK"
echo "   5) /admin/audit/export canonical tenant:          OK"
echo "   6) Wrong-tenant request denied:                   OK"
echo "============================================================"
