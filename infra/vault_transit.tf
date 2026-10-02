# =============================================================================
# Vault Transit secrets engine — Customer-Zero trust keys
#
# Three non-exportable Ed25519 keys with permanent history retention.
# Each key is bound exclusively to one trust role. No sharing.
#
# COST: Vault Transit operations are included in the Vault Dedicated cluster
# subscription. No separate per-key or per-operation charges beyond the
# cluster tier cost.
#
# APPLY ORDER: Vault provider must be authenticated with the bootstrap admin
# token (or a post-provisioning admin token) before these resources are applied.
# The vault provider address and token are set via workspace variables or the
# VAULT_ADDR / VAULT_TOKEN environment variables — never committed to .tfvars.
# =============================================================================

# Transit secrets engine mount
resource "vault_mount" "transit" {
  path                      = "transit"
  type                      = "transit"
  description               = "Customer-Zero trust signing — frostgate-customer-zero"
  default_lease_ttl_seconds = 0
  max_lease_ttl_seconds     = 0

  lifecycle {
    prevent_destroy = true
  }
}

# ── IDENTITY trust key ────────────────────────────────────────────────────────
# Bound exclusively to the customer-zero-identity trust role.
# Must not be used for acceptance or approval signing.
resource "vault_transit_secret_backend_key" "customer_zero_identity" {
  backend = vault_mount.transit.path
  name    = "customer-zero-identity"
  type    = "ed25519"

  # Safety invariants — match the FrostGate trust-evidence schema requirements
  exportable       = false
  deletion_allowed = false
  derived          = false

  # Retain all historical key versions for signature verification.
  # Vault Transit retains all versions by default; min_decryption_version
  # is left at the provider default (1) to allow historical verification.
  min_encryption_version = 1

  lifecycle {
    prevent_destroy = true
    # Changing exportable or deletion_allowed on an existing key requires
    # destroy+recreate — flag this as an explicit break of security invariants.
    ignore_changes = []
  }
}

# ── ACCEPTANCE trust key ──────────────────────────────────────────────────────
# Bound exclusively to the customer-zero-acceptance trust role.
resource "vault_transit_secret_backend_key" "customer_zero_acceptance" {
  backend = vault_mount.transit.path
  name    = "customer-zero-acceptance"
  type    = "ed25519"

  exportable       = false
  deletion_allowed = false
  derived          = false

  min_encryption_version = 1

  lifecycle {
    prevent_destroy = true
  }
}

# ── APPROVAL trust key ────────────────────────────────────────────────────────
# Bound exclusively to the customer-zero-approval trust role.
resource "vault_transit_secret_backend_key" "customer_zero_approval" {
  backend = vault_mount.transit.path
  name    = "customer-zero-approval"
  type    = "ed25519"

  exportable       = false
  deletion_allowed = false
  derived          = false

  min_encryption_version = 1

  lifecycle {
    prevent_destroy = true
  }
}
