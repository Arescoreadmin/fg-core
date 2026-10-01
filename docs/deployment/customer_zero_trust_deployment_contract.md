# Customer-Zero Trust Deployment Contract

**Work item:** CUSTOMER-ZERO-TRUST-001
**Production mode:** AppRole (HCP Vault Dedicated)
**Service:** `api` (Railway)

This document is the durable production configuration contract for Customer-Zero Vault
trust. It survives a fresh clone and is the authoritative reference for which environment
variables must be set in the production deployment.

Railway is **dashboard-managed** for this repository — no `.railway/railway.ts` or
equivalent IaC file is committed to source control. Configure environment variables
via the Railway dashboard Variables tab for the `api` service. See also
`docs/deployment/projection-worker-railway.md` for the established Railway pattern.

---

## Production environment variables

All variables are consumed by `services/cgin/key_management/vault_transit.py` via
`signer_from_environment()` (AppRole path). This table is derived from runtime
code, not inferred. A regression test in `tests/test_customer_zero_deployment_contract.py`
verifies that this table stays in sync with the runtime.

| Variable | Required | Class | Default | Runtime consumer | Notes |
|----------|----------|-------|---------|-----------------|-------|
| `FG_CUSTOMER_ZERO_VAULT_AUTH_MODE` | YES | NON_SECRET | (none) | `signer_from_environment` | Must be `approle` in production |
| `FG_CUSTOMER_ZERO_VAULT_ADDR` | YES | NON_SECRET | (none) | `from_approle_environment`, `from_environment` (VaultCustomerZeroConfig) | HCP Vault public HTTPS endpoint |
| `FG_CUSTOMER_ZERO_VAULT_NAMESPACE` | NO | NON_SECRET | (none, no header sent) | `from_approle_environment` | HCP Vault namespace; required for HCP Dedicated |
| `FG_CUSTOMER_ZERO_VAULT_ISSUER` | NO | NON_SECRET | `vault-transit` | `VaultCustomerZeroConfig.from_environment` | Trust anchor label stored on signed artifacts |
| `FG_CUSTOMER_ZERO_IDENTITY_KEY_ID` | YES | NON_SECRET | (none) | `VaultCustomerZeroConfig.from_environment` | Vault Transit key name for IDENTITY role |
| `FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID` | YES | NON_SECRET | (none) | `VaultCustomerZeroConfig.from_environment` | Vault Transit key name for ACCEPTANCE role |
| `FG_CUSTOMER_ZERO_APPROVAL_KEY_ID` | YES | NON_SECRET | (none) | `VaultCustomerZeroConfig.from_environment` | Vault Transit key name for APPROVAL role |
| `FG_CUSTOMER_ZERO_IDENTITY_VAULT_ROLE_ID` | YES | NON_SECRET | (none) | `from_approle_environment` | AppRole role ID for IDENTITY (non-secret identifier; see note) |
| `FG_CUSTOMER_ZERO_IDENTITY_VAULT_SECRET_ID` | YES | **SECRET** | (none) | `from_approle_environment` | AppRole SecretID for IDENTITY; issued out-of-band via Vault CLI |
| `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_ROLE_ID` | YES | NON_SECRET | (none) | `from_approle_environment` | AppRole role ID for ACCEPTANCE |
| `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_SECRET_ID` | YES | **SECRET** | (none) | `from_approle_environment` | AppRole SecretID for ACCEPTANCE; issued out-of-band |
| `FG_CUSTOMER_ZERO_APPROVAL_VAULT_ROLE_ID` | YES | NON_SECRET | (none) | `from_approle_environment` | AppRole role ID for APPROVAL |
| `FG_CUSTOMER_ZERO_APPROVAL_VAULT_SECRET_ID` | YES | **SECRET** | (none) | `from_approle_environment` | AppRole SecretID for APPROVAL; issued out-of-band |

**Total: 13 production variables (11 required, 2 optional).**

**Note on Role IDs:** Vault AppRole role IDs are non-secret identifiers (analogous to a
username) and are output by Terraform in `frostgate-infra/outputs.tf`. They are recorded
in the trust evidence manifest as `auth_role_id`. They must not be confused with
**SecretIDs**, which are credentials.

---

## Variables NOT for production

These variables appear in the runtime source but must not be set in production deployments:

| Variable | Why excluded |
|----------|-------------|
| `FG_CUSTOMER_ZERO_VAULT_TOKEN` | Static-token authentication; explicitly blocked by `from_environment()` unless `FG_CUSTOMER_ZERO_ENVIRONMENT` is `test`/`development`/`local` |
| `FG_CUSTOMER_ZERO_ENVIRONMENT` | Used only as a guard in `from_environment()` (static-token path); production uses AppRole |

---

## Secret delivery model

AppRole SecretIDs are **never generated or stored by Terraform**. They are issued
via the Vault CLI by a human operator during the production ceremony and loaded
directly into Railway secrets. See `docs/deployment/customer_zero_trust_recovery.md`
for the rotation procedure.

Never set an actual SecretID value in source control, CI variables, shell history,
or chat. Railway's Variables tab is the only authorized storage location for
production SecretIDs.

---

## Verification

After deployment, verify that signing and verification work end-to-end:

```bash
# Validate the ceremony evidence manifest (non-secret check)
python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json

# Verify anchor enrollment
python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
```

These commands inspect names, fingerprints, and provenance only. No secret values are
required or produced.
