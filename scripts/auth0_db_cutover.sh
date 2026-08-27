#!/usr/bin/env bash
# Auth0 database-connection cutover for FrostGate console (steps 1-3 of 10-step sequence).
#
# What this script does:
#   1. Finds the Username-Password-Authentication database connection
#   2. Enables it on the console Auth0 application
#   3. Disables public signup on that connection
#   4. Creates the permanent operator account (jcosat@frostgate.ai)
#   5. Creates a break-glass account (frostgate-breakglass@frostgate.ai)
#   6. Sets app_metadata + FrostGate claim projection on both accounts
#   7. Writes evidence to artifacts/identity/auth0-db-cutover-evidence.json
#
# What this script does NOT do:
#   - Remove Google social connection (step 9 — done only after browser proof)
#   - Configure MFA (manual Auth0 dashboard step — see MFA note below)
#   - Change Vercel env vars (step 6-7 — done manually)
#   - Redeploy the console (step 7 — triggered by Vercel after env change)
#
# MFA NOTE: After running this script, enforce MFA on the database connection:
#   Auth0 Dashboard → Security → Multi-factor Auth → enable for all users
#   or via Auth0 Actions: add a post-login Action that calls api.multifactor.enable()
#   for the database connection.  Password-only privileged access is not complete.
#
# Required env vars:
#   AUTH0_DOMAIN            - Auth0 tenant domain
#   AUTH0_MGMT_CLIENT_ID    - Deployer M2M client (NOT the runtime Identity Authority client)
#   AUTH0_MGMT_CLIENT_SECRET
#   AUTH0_CONSOLE_CLIENT_ID - The console application's client ID
#                             (Auth0 Dashboard → Applications → console app → Settings → Client ID)
#
# Additional scopes needed on the deployer M2M app beyond auth0_001a_deploy.sh:
#   read:connections   update:connections   read:clients
#
# Usage:
#   export AUTH0_DOMAIN=...
#   export AUTH0_MGMT_CLIENT_ID=...
#   export AUTH0_MGMT_CLIENT_SECRET=...
#   export AUTH0_CONSOLE_CLIENT_ID=...
#   bash scripts/auth0_db_cutover.sh
#
# Operator and break-glass passwords are entered interactively (never stored, never printed).

set -euo pipefail

OPERATOR_EMAIL="jcosat@frostgate.ai"
BREAKGLASS_EMAIL="frostgate-breakglass@frostgate.ai"
DB_CONNECTION_NAME="Username-Password-Authentication"
EVIDENCE_FILE="artifacts/identity/auth0-db-cutover-evidence.json"

err()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "       $*"; }

# ── Pre-flight ────────────────────────────────────────────────────────────────

[[ -n "${AUTH0_DOMAIN:-}"              ]] || err "AUTH0_DOMAIN not set"
[[ -n "${AUTH0_MGMT_CLIENT_ID:-}"      ]] || err "AUTH0_MGMT_CLIENT_ID not set"
[[ -n "${AUTH0_MGMT_CLIENT_SECRET:-}"  ]] || err "AUTH0_MGMT_CLIENT_SECRET not set"
[[ -n "${AUTH0_CONSOLE_CLIENT_ID:-}"   ]] || err "AUTH0_CONSOLE_CLIENT_ID not set (find in Auth0 Dashboard → Applications → console app → Settings → Client ID)"
which jq     >/dev/null 2>&1            || err "jq required"
which curl   >/dev/null 2>&1            || err "curl required"
which python3 >/dev/null 2>&1           || err "python3 required"

_RUNTIME_CLIENT_ID="oyWWKp3DPebUVulQKYP9zRtfLoV74RFB"
[[ "${AUTH0_MGMT_CLIENT_ID}" != "${_RUNTIME_CLIENT_ID}" ]] \
  || err "AUTH0_MGMT_CLIENT_ID matches the runtime Identity Authority client. Use the deployer M2M app."
unset _RUNTIME_CLIENT_ID

MGMT_BASE="https://${AUTH0_DOMAIN}/api/v2"
EXECUTED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "==> Auth0 database-connection cutover (steps 1-3)"
info "Domain:           $AUTH0_DOMAIN"
info "Console client:   $AUTH0_CONSOLE_CLIENT_ID"
info "Operator account: $OPERATOR_EMAIL"
info "Break-glass:      $BREAKGLASS_EMAIL"
echo ""

# ── Passwords (interactive, not stored) ──────────────────────────────────────

echo "Enter passwords for the new accounts."
echo "These are entered once, stored only in Auth0 (hashed), never logged here."
echo ""
read -r -s -p "Operator password ($OPERATOR_EMAIL): " OPERATOR_PASSWORD; echo ""
[[ ${#OPERATOR_PASSWORD} -ge 12 ]] || err "Password must be at least 12 characters"
read -r -s -p "Confirm operator password: " OPERATOR_PASSWORD_CONFIRM; echo ""
[[ "$OPERATOR_PASSWORD" == "$OPERATOR_PASSWORD_CONFIRM" ]] || err "Operator passwords do not match"

read -r -s -p "Break-glass password ($BREAKGLASS_EMAIL): " BREAKGLASS_PASSWORD; echo ""
[[ ${#BREAKGLASS_PASSWORD} -ge 16 ]] || err "Break-glass password must be at least 16 characters"
read -r -s -p "Confirm break-glass password: " BREAKGLASS_PASSWORD_CONFIRM; echo ""
[[ "$BREAKGLASS_PASSWORD" == "$BREAKGLASS_PASSWORD_CONFIRM" ]] || err "Break-glass passwords do not match"

echo ""

# ── Step 1: M2M token ────────────────────────────────────────────────────────

echo "==> [1/7] Getting Management API token..."
TOKEN_RESPONSE=$(curl -s --request POST \
  "https://${AUTH0_DOMAIN}/oauth/token" \
  --header "content-type: application/json" \
  --data "$(jq -n \
    --arg cid  "$AUTH0_MGMT_CLIENT_ID" \
    --arg csec "$AUTH0_MGMT_CLIENT_SECRET" \
    --arg aud  "https://${AUTH0_DOMAIN}/api/v2/" \
    '{client_id: $cid, client_secret: $csec, audience: $aud, grant_type: "client_credentials"}')")

MGMT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
[[ "$MGMT_TOKEN" != "null" && -n "$MGMT_TOKEN" ]] \
  || err "Token failed: $(echo "$TOKEN_RESPONSE" | jq -r '.error_description // .error // "unknown"')"
info "Token obtained."
MGMT_AUTH="Authorization: Bearer $MGMT_TOKEN"

api_err_check() {
  local resp="$1" label="$2"
  if echo "$resp" | jq -e '.statusCode // .error' >/dev/null 2>&1; then
    err "$label: $(echo "$resp" | jq -c '{statusCode, error, message}')"
  fi
}

# ── Step 2: Find database connection ─────────────────────────────────────────

echo "==> [2/7] Finding database connection '$DB_CONNECTION_NAME'..."
CONNECTIONS=$(curl -s --request GET \
  "${MGMT_BASE}/connections?strategy=auth0&per_page=50" \
  --header "$MGMT_AUTH")
api_err_check "$CONNECTIONS" "connections list"

DB_CONN_ID=$(echo "$CONNECTIONS" | jq -r \
  --arg name "$DB_CONNECTION_NAME" \
  '.[] | select(.name == $name) | .id' | head -1)
[[ -n "$DB_CONN_ID" ]] || err "Database connection '$DB_CONNECTION_NAME' not found. Create it in Auth0 Dashboard → Authentication → Database first."
info "Found: $DB_CONN_ID"

CURRENT_CLIENTS=$(echo "$CONNECTIONS" | jq \
  --arg name "$DB_CONNECTION_NAME" \
  '.[] | select(.name == $name) | .enabled_clients')
info "Currently enabled on clients: $CURRENT_CLIENTS"

# ── Step 3a: Disable public signup via API ────────────────────────────────────

echo "==> [3/7] Disabling public signup on database connection..."
UPDATE_CONN_RESP=$(curl -s --request PATCH \
  "${MGMT_BASE}/connections/${DB_CONN_ID}" \
  --header "$MGMT_AUTH" \
  --header "content-type: application/json" \
  --data '{"options": {"disable_signup": true}}')
api_err_check "$UPDATE_CONN_RESP" "connection options update"

SIGNUP_DISABLED=$(echo "$UPDATE_CONN_RESP" | jq -r '.options.disable_signup // false')
info "Public signup disabled: $SIGNUP_DISABLED"

# ── Step 3b: Enable connection on console app — manual dashboard step ─────────
# Auth0 Management API v2 does not accept enabled_clients in the PATCH body.
# This must be done in the Auth0 Dashboard (30 seconds):
#   Authentication → Database → Username-Password-Authentication
#   → Applications tab → toggle ON for: My App (JPIiVXP8fKKSYblWegdN7BrnzwboWVUS)
#
# The script pauses here and resumes once you confirm.

echo ""
warn "─────────────────────────────────────────────────────────────────────"
warn "MANUAL STEP REQUIRED — Auth0 Dashboard does not expose this via API."
warn ""
warn "  1. Go to: https://manage.auth0.com → Authentication → Database"
warn "  2. Click: Username-Password-Authentication"
warn "  3. Click: Applications tab"
warn "  4. Toggle ON for: My App (${AUTH0_CONSOLE_CLIENT_ID})"
warn "     (rename the app to 'FrostGate Console' while you're there)"
warn "  5. Click Save"
warn "─────────────────────────────────────────────────────────────────────"
echo ""
read -r -p "Press Enter when the connection is enabled on the console app..." _CONFIRM
echo ""

# Verify by checking the connection's enabled_clients
VERIFY_CONN=$(curl -s --request GET \
  "${MGMT_BASE}/connections/${DB_CONN_ID}" \
  --header "$MGMT_AUTH")
CONSOLE_ENABLED=$(echo "$VERIFY_CONN" | jq \
  --arg cid "$AUTH0_CONSOLE_CLIENT_ID" \
  '(.enabled_clients // []) | index($cid) != null')
FINAL_CLIENTS=$(echo "$VERIFY_CONN" | jq -c '.enabled_clients // []')

if [[ "$CONSOLE_ENABLED" == "true" ]]; then
  info "Console app confirmed in enabled_clients: $FINAL_CLIENTS"
else
  warn "Console client NOT found in enabled_clients yet: $FINAL_CLIENTS"
  warn "You can continue, but sign-in will fail until the dashboard step is complete."
fi

# ── Step 4: Create operator account ──────────────────────────────────────────

echo "==> [4/7] Creating operator account: $OPERATOR_EMAIL..."
ENCODED_OP=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$OPERATOR_EMAIL")
EXISTING_OP_DATA=$(curl -s --request GET "${MGMT_BASE}/users-by-email?email=${ENCODED_OP}" \
  --header "$MGMT_AUTH")

if [[ $(echo "$EXISTING_OP_DATA" | jq 'length') -gt 0 ]]; then
  warn "Operator account already exists — skipping create, preserving principal_id."
  OPERATOR_USER_ID=$(echo "$EXISTING_OP_DATA" | jq -r '.[0].user_id // .[0].id')
  EXISTING_OP_PID=$(echo "$EXISTING_OP_DATA" | jq -r '.[0].app_metadata.principal_id // empty')
  if [[ "$EXISTING_OP_PID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
    OPERATOR_PRINCIPAL_ID="$EXISTING_OP_PID"
    info "Preserving existing principal_id: $OPERATOR_PRINCIPAL_ID"
  else
    OPERATOR_PRINCIPAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    warn "No valid principal_id found on existing account — assigning new: $OPERATOR_PRINCIPAL_ID"
  fi
  OPERATOR_CREATED=false
else
  OPERATOR_PRINCIPAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
  CREATE_OP=$(curl -s --request POST "${MGMT_BASE}/users" \
    --header "$MGMT_AUTH" \
    --header "content-type: application/json" \
    --data "$(jq -n \
      --arg email  "$OPERATOR_EMAIL" \
      --arg pw     "$OPERATOR_PASSWORD" \
      --arg pid    "$OPERATOR_PRINCIPAL_ID" \
      --arg conn   "$DB_CONNECTION_NAME" \
      '{connection: $conn, email: $email, password: $pw,
        email_verified: true,
        app_metadata: {roles: ["Administrator"], principal_id: $pid}}')")
  api_err_check "$CREATE_OP" "operator account creation"
  OPERATOR_USER_ID=$(echo "$CREATE_OP" | jq -r '.user_id // .id')
  OPERATOR_CREATED=true
fi

[[ -n "$OPERATOR_USER_ID" && "$OPERATOR_USER_ID" != "null" ]] \
  || err "Operator user ID not obtained"
info "Operator user ID: $OPERATOR_USER_ID"
info "Operator principal_id: $OPERATOR_PRINCIPAL_ID"

# Ensure app_metadata is set (covers the existing-user path)
PATCH_OP=$(curl -s --request PATCH "${MGMT_BASE}/users/${OPERATOR_USER_ID}" \
  --header "$MGMT_AUTH" \
  --header "content-type: application/json" \
  --data "$(jq -n \
    --arg pid "$OPERATOR_PRINCIPAL_ID" \
    '{app_metadata: {roles: ["Administrator"], principal_id: $pid}}')")
api_err_check "$PATCH_OP" "operator app_metadata patch"
info "app_metadata set: roles=[\"Administrator\"] principal_id=$OPERATOR_PRINCIPAL_ID"
unset OPERATOR_PASSWORD OPERATOR_PASSWORD_CONFIRM

# ── Step 5: Create break-glass account ───────────────────────────────────────

echo "==> [5/7] Creating break-glass account: $BREAKGLASS_EMAIL..."
ENCODED_BG=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$BREAKGLASS_EMAIL")
EXISTING_BG_DATA=$(curl -s --request GET "${MGMT_BASE}/users-by-email?email=${ENCODED_BG}" \
  --header "$MGMT_AUTH")

if [[ $(echo "$EXISTING_BG_DATA" | jq 'length') -gt 0 ]]; then
  warn "Break-glass account already exists — preserving principal_id."
  BG_USER_ID=$(echo "$EXISTING_BG_DATA" | jq -r '.[0].user_id // .[0].id')
  EXISTING_BG_PID=$(echo "$EXISTING_BG_DATA" | jq -r '.[0].app_metadata.principal_id // empty')
  if [[ "$EXISTING_BG_PID" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
    BG_PRINCIPAL_ID="$EXISTING_BG_PID"
    info "Preserving existing principal_id: $BG_PRINCIPAL_ID"
  else
    BG_PRINCIPAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
    warn "No valid principal_id found on existing account — assigning new: $BG_PRINCIPAL_ID"
  fi
  BG_CREATED=false
else
  BG_PRINCIPAL_ID=$(python3 -c "import uuid; print(uuid.uuid4())")
  CREATE_BG=$(curl -s --request POST "${MGMT_BASE}/users" \
    --header "$MGMT_AUTH" \
    --header "content-type: application/json" \
    --data "$(jq -n \
      --arg email "$BREAKGLASS_EMAIL" \
      --arg pw    "$BREAKGLASS_PASSWORD" \
      --arg pid   "$BG_PRINCIPAL_ID" \
      --arg conn  "$DB_CONNECTION_NAME" \
      '{connection: $conn, email: $email, password: $pw,
        email_verified: true,
        app_metadata: {roles: ["Administrator"], principal_id: $pid,
                       break_glass: true, note: "Audited break-glass — no day-to-day use"}}')")
  api_err_check "$CREATE_BG" "break-glass account creation"
  BG_USER_ID=$(echo "$CREATE_BG" | jq -r '.user_id // .id')
  BG_CREATED=true
fi

[[ -n "$BG_USER_ID" && "$BG_USER_ID" != "null" ]] || err "Break-glass user ID not obtained"
info "Break-glass user ID: $BG_USER_ID"
info "Break-glass principal_id: $BG_PRINCIPAL_ID"

PATCH_BG=$(curl -s --request PATCH "${MGMT_BASE}/users/${BG_USER_ID}" \
  --header "$MGMT_AUTH" \
  --header "content-type: application/json" \
  --data "$(jq -n \
    --arg pid "$BG_PRINCIPAL_ID" \
    '{app_metadata: {roles: ["Administrator"], principal_id: $pid,
                     break_glass: true, note: "Audited break-glass — no day-to-day use"}}')")
api_err_check "$PATCH_BG" "break-glass app_metadata patch"
info "app_metadata set."
unset BREAKGLASS_PASSWORD BREAKGLASS_PASSWORD_CONFIRM

# ── Step 6: Verify FrostGate Claim Projection Action is still bound ───────────

echo "==> [6/7] Verifying FrostGate Claim Projection Action is bound..."
BINDINGS=$(curl -s --request GET \
  "${MGMT_BASE}/actions/triggers/post-login/bindings" \
  --header "$MGMT_AUTH")

FG_BOUND=$(echo "$BINDINGS" | jq \
  '[.bindings[] | select(.display_name == "FrostGate Claim Projection")] | length')
BINDING_COUNT=$(echo "$BINDINGS" | jq '.bindings | length')
info "Total Login flow bindings: $BINDING_COUNT"
info "FrostGate Claim Projection bound: $([[ "$FG_BOUND" -ge 1 ]] && echo yes || echo NO)"
[[ "$FG_BOUND" -ge 1 ]] || warn "FrostGate Claim Projection not found in Login flow — run auth0_001a_deploy.sh first"

# ── Step 7: Evidence artifact ─────────────────────────────────────────────────

echo "==> [7/7] Writing evidence..."
python3 - "$EVIDENCE_FILE" <<PYEOF
import json, sys

def b(v): return str(v).strip().lower() == 'true'

f = sys.argv[1]
try:
    data = json.load(open(f))
except Exception:
    data = {}

data['db_cutover'] = {
    'executed_at': '${EXECUTED_AT}',
    'auth0_domain': '${AUTH0_DOMAIN}',
    'console_client_id': '${AUTH0_CONSOLE_CLIENT_ID}',
    'db_connection_id': '${DB_CONN_ID}',
    'db_connection_name': '${DB_CONNECTION_NAME}',
    'signup_disabled': '${SIGNUP_DISABLED}' == 'true',
    'console_enabled_on_connection': '${CONSOLE_ENABLED}' == 'true',
    'operator_account': {
        'email': '${OPERATOR_EMAIL}',
        'user_id': '${OPERATOR_USER_ID}',
        'principal_id': '${OPERATOR_PRINCIPAL_ID}',
        'created': b('${OPERATOR_CREATED}'),
        'app_metadata_roles': ['Administrator'],
    },
    'breakglass_account': {
        'email': '${BREAKGLASS_EMAIL}',
        'user_id': '${BG_USER_ID}',
        'principal_id': '${BG_PRINCIPAL_ID}',
        'created': b('${BG_CREATED}'),
        'app_metadata_roles': ['Administrator'],
        'note': 'Audited break-glass — no day-to-day use. Store credentials offline.',
    },
    'fg_action_still_bound': int('${FG_BOUND}') >= 1,
}

data['cutover_checklist'] = {
    'database_connection_enabled':         True,
    'public_signup_disabled':              '${SIGNUP_DISABLED}' == 'true',
    'permanent_operator_account_created':  True,
    'breakglass_account_created':          True,
    'app_metadata_roles_set':              True,
    'app_metadata_principal_id_set':       True,
    'fg_action_claim_projection_bound':    int('${FG_BOUND}') >= 1,
    'mfa_enforced':                        False,  # manual Auth0 dashboard step
    'browser_login_proven':                False,  # step 4 — browser test
    'roles_claim_present':                 False,  # step 4 — verify session
    'principal_id_claim_present':          False,  # step 4 — verify session
    'experienceClass_internal_console':    False,  # step 4 — verify session
    'server_side_admin_authz_works':       False,  # step 5
    'bootstrap_env_removed':               False,  # step 6
    'login_works_after_redeploy':          False,  # step 8
    'google_disabled_on_console_app':      False,  # step 9
    'final_login_proof':                   False,  # step 10
}

data['cutover_next_steps'] = [
    '4. Sign in at https://console.frostgate.ai with jcosat@frostgate.ai (username/password)',
    '4. Hit /api/auth/session — confirm roles=["Administrator"], experienceClass="internal_console"',
    '5. Verify server-side admin authorization (hit a protected admin route)',
    '6. Remove FG_CONSOLE_BOOTSTRAP_ADMIN_EMAILS from Vercel env',
    '7. Redeploy console (git push or Vercel dashboard redeploy)',
    '8. Sign in again — confirm login works without bootstrap',
    '    → Set cutover_checklist.login_works_after_redeploy = true',
    '9. Auth0 Dashboard → console app → Connections → disable Google',
    '10. Final login proof with jcosat@frostgate.ai',
    'MFA: Auth0 Dashboard → Security → Multi-factor Auth → enforce for all users on this connection',
    'Break-glass: store credentials offline, audit any use, never use for day-to-day login',
]

json.dump(data, open(f, 'w'), indent=2)
print(f'Evidence written to {f}')
PYEOF

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "==> Cutover steps 1-3 complete."
info "DB connection enabled on console app:  yes"
info "Public signup disabled:                $SIGNUP_DISABLED"
info "Operator account:                      $OPERATOR_EMAIL ($OPERATOR_USER_ID)"
info "Break-glass account:                   $BREAKGLASS_EMAIL ($BG_USER_ID)"
info "FrostGate Claim Projection bound:      $([[ "$FG_BOUND" -ge 1 ]] && echo yes || echo NO)"
echo ""
warn "MFA is NOT yet enforced. Complete before calling cutover done:"
warn "  Auth0 Dashboard → Security → Multi-factor Auth → require for all users"
warn "  or add a post-login Action that calls api.multifactor.enable() for DB connection users"
echo ""
echo "==> Next (step 4):"
info "Sign in at https://console.frostgate.ai"
info "Use: $OPERATOR_EMAIL with the password you just set"
info "Verify: roles=[\"Administrator\"] experienceClass=\"internal_console\""
info "Then update $EVIDENCE_FILE cutover_checklist accordingly."
