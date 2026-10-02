# =============================================================================
# Vault AppRole authentication — three separated runtime principals
#
# Each AppRole is bound exclusively to its corresponding policy.
# No shared credentials. No shared policies. No cross-role fallback.
#
# Role IDs are non-secret identifiers — safe to read and record.
# SecretIDs are SECRET — generated separately, transferred directly to
# Railway runtime secret storage, never passed through this Terraform
# configuration or committed to any file.
#
# TTL configuration is consistent with the FrostGate bounded-session
# requirements (PR #717 / vault_transit.py AppRoleAuthenticator):
#   token_ttl:      initial session lifetime
#   token_max_ttl:  maximum lifetime including renewals (forces re-auth)
#   Renewal is managed by AppRoleAuthenticator.session()
# =============================================================================

# AppRole auth backend
resource "vault_auth_backend" "approle" {
  type        = "approle"
  path        = "approle"
  description = "Customer-Zero runtime trust role authentication"

  lifecycle {
    prevent_destroy = true
  }
}

# ── IDENTITY AppRole ──────────────────────────────────────────────────────────
resource "vault_approle_auth_backend_role" "identity" {
  backend   = vault_auth_backend.approle.path
  role_name = "frostgate-cz-identity"

  # Bind to the identity-only policy
  token_policies = [vault_policy.identity.name]

  # Bounded session — consistent with AppRoleAuthenticator expectations
  token_ttl     = var.vault_token_ttl
  token_max_ttl = var.vault_token_max_ttl

  # Require SecretID for authentication — no unauthenticated role ID use
  bind_secret_id = true

  # No default policy — explicit minimum privilege
  token_no_default_policy = true

  # Token type: service (renewable, standard Vault token)
  token_type = "service"

  lifecycle {
    prevent_destroy = true
    # Role ID must remain stable — re-creation breaks enrolled trust anchors
  }
}

# ── ACCEPTANCE AppRole ────────────────────────────────────────────────────────
resource "vault_approle_auth_backend_role" "acceptance" {
  backend   = vault_auth_backend.approle.path
  role_name = "frostgate-cz-acceptance"

  token_policies          = [vault_policy.acceptance.name]
  token_ttl               = var.vault_token_ttl
  token_max_ttl           = var.vault_token_max_ttl
  bind_secret_id          = true
  token_no_default_policy = true
  token_type              = "service"

  lifecycle {
    prevent_destroy = true
  }
}

# ── APPROVAL AppRole ──────────────────────────────────────────────────────────
resource "vault_approle_auth_backend_role" "approval" {
  backend   = vault_auth_backend.approle.path
  role_name = "frostgate-cz-approval"

  token_policies          = [vault_policy.approval.name]
  token_ttl               = var.vault_token_ttl
  token_max_ttl           = var.vault_token_max_ttl
  bind_secret_id          = true
  token_no_default_policy = true
  token_type              = "service"

  lifecycle {
    prevent_destroy = true
  }
}

# ── Role ID outputs (non-secret, required for evidence manifest) ──────────────
# Role IDs are non-secret identifiers. They are included in the trust evidence
# manifest as auth_role_id for each trust role. They are NOT credentials.
# The corresponding SecretIDs are generated separately and handled exclusively
# through Railway's secret interface — never through Terraform.
