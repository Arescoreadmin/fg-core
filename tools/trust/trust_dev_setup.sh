#!/usr/bin/env bash
# Configure a running local Vault dev server for FrostGate Customer-Zero development.
#
# DEVELOPMENT ONLY — this script creates development trust infrastructure.
# It does NOT produce CUSTOMER-ZERO-TRUST-001 completion evidence.
# Production ceremony requires HCP Vault Dedicated with audit log, HA, and
# non-exportable key provenance verified by the controlled trust ceremony.
#
# Prerequisites:
#   vault CLI in PATH
#   VAULT_ADDR=http://127.0.0.1:8200  (set by trust-dev-up)
#   VAULT_TOKEN=<dev-root-token>      (set by trust-dev-up)
#
# Usage: called by `make trust-dev-up`; safe to re-run (idempotent).

set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_ADDR

echo "==> Trust dev setup: Vault at ${VAULT_ADDR}"

# ── Transit secrets engine ────────────────────────────────────────────────────
if vault secrets list -format=json | grep -q '"transit/"'; then
  echo "    transit: already enabled"
else
  vault secrets enable transit
  echo "    transit: enabled"
fi

# ── Three non-exportable Ed25519 keys ─────────────────────────────────────────
for KEY in customer-zero-identity customer-zero-acceptance customer-zero-approval; do
  if vault read -field=type "transit/keys/${KEY}" 2>/dev/null | grep -q 'ed25519'; then
    echo "    key ${KEY}: exists"
  else
    vault write "transit/keys/${KEY}" type=ed25519
    vault write "transit/keys/${KEY}/config" deletion_allowed=false
    echo "    key ${KEY}: created (ed25519, deletion_allowed=false)"
  fi
done

# ── Vault policies ────────────────────────────────────────────────────────────
vault policy write frostgate-cz-identity - << 'POLICY'
path "transit/sign/customer-zero-identity" { capabilities = ["create", "update"] }
path "transit/keys/customer-zero-identity" { capabilities = ["read"] }
POLICY
echo "    policy frostgate-cz-identity: applied"

vault policy write frostgate-cz-acceptance - << 'POLICY'
path "transit/sign/customer-zero-acceptance" { capabilities = ["create", "update"] }
path "transit/keys/customer-zero-acceptance" { capabilities = ["read"] }
POLICY
echo "    policy frostgate-cz-acceptance: applied"

vault policy write frostgate-cz-approval - << 'POLICY'
path "transit/sign/customer-zero-approval" { capabilities = ["create", "update"] }
path "transit/keys/customer-zero-approval" { capabilities = ["read"] }
POLICY
echo "    policy frostgate-cz-approval: applied"

# ── AppRole auth mount ────────────────────────────────────────────────────────
if vault auth list -format=json | grep -q '"approle/"'; then
  echo "    approle: already enabled"
else
  vault auth enable approle
  echo "    approle: enabled"
fi

# ── Three bounded AppRole roles ───────────────────────────────────────────────
for ROLE in frostgate-cz-identity frostgate-cz-acceptance frostgate-cz-approval; do
  # Derive policy name (same as role name)
  POLICY_NAME="${ROLE}"
  vault write "auth/approle/role/${ROLE}" \
    token_policies="${POLICY_NAME}" \
    token_ttl=3600s \
    token_max_ttl=7200s \
    bind_secret_id=true \
    token_no_default_policy=true \
    token_type=service
  echo "    approle ${ROLE}: configured"
done

echo ""
echo "==> Trust dev setup: COMPLETE"
echo "    Three Ed25519 Transit keys: identity, acceptance, approval"
echo "    Three scoped policies: one per authority"
echo "    Three AppRole roles: bound to own policy only"
echo ""
echo "    DEVELOPMENT ONLY — not production Customer-Zero evidence"
