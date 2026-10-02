# =============================================================================
# Vault least-privilege policies — one per Customer-Zero trust role
#
# Each policy grants the MINIMUM capability required for its trust role:
#   sign using exactly its own Transit key
#   read the public key of its own Transit key (for anchor enrollment)
#
# All other paths are implicitly DENIED by Vault's default-deny model.
# Cross-role signing is structurally impossible: the policy does not grant
# access to any other Transit key path.
#
# Runtime principals (frostgate-cz-identity/acceptance/approval) must not
# receive any policy that grants Transit admin, sys/, auth admin, or any
# path beyond what is listed here. These policies are the authoritative
# statement of that boundary.
# =============================================================================

# ── IDENTITY policy ───────────────────────────────────────────────────────────
# Grants: sign + read-public-key for customer-zero-identity only.
# Denies by default: all other Transit keys, sys/*, auth/*, secret/*, etc.
resource "vault_policy" "identity" {
  name = "frostgate-cz-identity"

  policy = <<-VAULT_POLICY
    # FrostGate Customer-Zero identity trust role — least-privilege policy
    # Ceremony: customer-zero-trust-2026-10-02-001
    # Allows signing using the customer-zero-identity Transit key only.

    path "transit/sign/customer-zero-identity" {
      capabilities = ["create", "update"]
    }

    # Read public key for trust-anchor enrollment and verification.
    path "transit/keys/customer-zero-identity" {
      capabilities = ["read"]
    }

    # Explicit structural prohibition: this policy intentionally does not
    # grant access to customer-zero-acceptance or customer-zero-approval keys.
    # Vault's default-deny model enforces this without explicit deny statements.
  VAULT_POLICY
}

# ── ACCEPTANCE policy ─────────────────────────────────────────────────────────
# Grants: sign + read-public-key for customer-zero-acceptance only.
resource "vault_policy" "acceptance" {
  name = "frostgate-cz-acceptance"

  policy = <<-VAULT_POLICY
    # FrostGate Customer-Zero acceptance trust role — least-privilege policy
    # Ceremony: customer-zero-trust-2026-10-02-001
    # Allows signing using the customer-zero-acceptance Transit key only.

    path "transit/sign/customer-zero-acceptance" {
      capabilities = ["create", "update"]
    }

    path "transit/keys/customer-zero-acceptance" {
      capabilities = ["read"]
    }
  VAULT_POLICY
}

# ── APPROVAL policy ───────────────────────────────────────────────────────────
# Grants: sign + read-public-key for customer-zero-approval only.
resource "vault_policy" "approval" {
  name = "frostgate-cz-approval"

  policy = <<-VAULT_POLICY
    # FrostGate Customer-Zero approval trust role — least-privilege policy
    # Ceremony: customer-zero-trust-2026-10-02-001
    # Allows signing using the customer-zero-approval Transit key only.

    path "transit/sign/customer-zero-approval" {
      capabilities = ["create", "update"]
    }

    path "transit/keys/customer-zero-approval" {
      capabilities = ["read"]
    }
  VAULT_POLICY
}
