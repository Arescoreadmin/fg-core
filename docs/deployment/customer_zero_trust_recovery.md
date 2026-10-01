# Customer-Zero Trust Recovery

**Work item:** CUSTOMER-ZERO-TRUST-001
**Recovery state established by this document:** RESTORE_DOCUMENTED

## Recovery state model

Three states must be reached in sequence before recovery is considered proven:

| State | Meaning | Evidence required |
|-------|---------|-------------------|
| `BACKUP_AVAILABLE` | Non-secret public verification material is durably stored outside the Vault cluster | `artifacts/trust/` contains the signed ceremony evidence JSON with public keys and fingerprints |
| `RESTORE_DOCUMENTED` | A tested restoration procedure exists in writing | **This document** |
| `RESTORE_TESTED` | A full recovery drill has been executed against a non-production Vault cluster | Drill execution record with SHA, timestamp, and operator sign-off |

**Current state: RESTORE_DOCUMENTED only.** `RESTORE_TESTED` requires an actual drill execution and cannot be declared by documentation alone.

---

## What is recoverable and what is not

### Verifiability of previously issued signatures

Ed25519 signatures issued under a Customer-Zero trust role remain independently verifiable as long as the public verification material survives:

- the public key (or public key fingerprint committed to the trust evidence manifest)
- the original signed payload bytes
- the signature string
- the key provenance metadata (issuer, key ID, key version)

**Cluster destruction or key deletion destroys future signing capability only.** Signatures already issued and stored in the database remain cryptographically verifiable by any party holding the public key. The `TrustAnchor.verify()` method in `services/cgin/key_management/vault_transit.py` performs this verification without a live Vault connection. The public keys committed to `artifacts/trust/customer_zero_trust_evidence.json` are the canonical public anchors.

### What cannot be recovered after key deletion

- The ability to issue new signatures under a deleted key version
- Session tokens and AppRole secret IDs (these are ephemeral and must be re-issued)
- The Vault audit log for deleted transit keys (log entries survive in CloudWatch; key material does not)

---

## Recovery scenarios

### Scenario 1 — Vault cluster temporarily unavailable (signing blocked, verification unaffected)

**Impact:** New governance artifact signatures cannot be issued. Existing signatures remain verifiable from database-stored public key material and the trust evidence manifest.

**Resolution:**
1. Verify the HCP Vault cluster status in the HCP portal.
2. Check CloudWatch for Vault audit log entries indicating errors.
3. If the cluster is degraded, follow the HCP incident response procedure (SLA-defined for standard_small tier).
4. Once the cluster recovers, AppRole session renewal is automatic on next signing request.

### Scenario 2 — AppRole secret IDs rotated or expired

**Impact:** Signing requests fail with authentication errors. Verification is unaffected.

**Resolution:**
1. Generate new secret IDs via Terraform for each trust role:
   ```
   cd ~/Projects/frostgate-infra
   terraform apply -target=vault_approle_auth_backend_role_secret_id.customer_zero_identity_secret_id
   terraform apply -target=vault_approle_auth_backend_role_secret_id.customer_zero_acceptance_secret_id
   terraform apply -target=vault_approle_auth_backend_role_secret_id.customer_zero_approval_secret_id
   ```
2. Update Railway secrets: `FG_CUSTOMER_ZERO_IDENTITY_VAULT_SECRET_ID`, `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_SECRET_ID`, `FG_CUSTOMER_ZERO_APPROVAL_VAULT_SECRET_ID`.
3. Redeploy the api service to pick up the new secret IDs.
4. Verify signing works by running a test qualification signing operation.

### Scenario 3 — Transit key rotation required

**Impact:** Key version increments. Old signatures remain verifiable. New signatures use the new key version. Trust anchors in `artifacts/trust/` must be updated.

**Resolution:**
1. Rotate the key via Terraform or Vault UI:
   ```
   vault write -f transit/keys/customer-zero-identity/rotate
   ```
2. Update the trust evidence manifest to record the new key version and public key.
3. Re-run `python tools/customer_zero_trust_evidence.py update-anchors` to capture updated public keys.
4. Commit the updated manifest to `artifacts/trust/customer_zero_trust_evidence.json`.
5. Update the `PUBLIC_ANCHORS` dimension to `PASS` after verification.

### Scenario 4 — Cluster destruction (catastrophic)

**Impact:** Future signing capability is permanently lost unless a new cluster is provisioned and new keys are generated. Previously issued signatures **remain verifiable** from the public key material in `artifacts/trust/customer_zero_trust_evidence.json`.

**Resolution:**
1. Confirm destruction is intentional. Vault Dedicated clusters have `prevent_destroy = true` in Terraform (`hcp_cluster.tf`). Destruction requires explicit Terraform override.
2. Audit the impact: identify all governance artifacts with trust signatures. These signatures remain valid. Clients holding the public keys can verify them independently.
3. If new signing capability is required, provision a new Vault cluster following CUSTOMER-ZERO-TRUST-001 ceremony procedures from scratch.
4. New keys will have new key IDs. Old signatures signed under the previous keys remain independently verifiable if the public anchor data was preserved.

---

## Canonical public anchor location

Non-secret public verification material is stored at:

```
artifacts/trust/customer_zero_trust_evidence.json
```

This file is the source of truth for:
- Public keys for all three Customer-Zero trust roles
- Key versions and public key fingerprints
- Ceremony ID and environment binding
- Evidence dimensions and their proof state

The evidence CLI at `tools/customer_zero_trust_evidence.py` manages this file. The validator at `services/cgin/key_management/trust_evidence.py` verifies its integrity.

---

## Pre-requisites for achieving RESTORE_TESTED

A recovery drill must execute the following and produce a signed execution record:

1. Provision a disposable non-production Vault cluster (can use local dev Vault).
2. Restore the trust role configuration (keys, policies, AppRoles) from IaC.
3. Confirm signing works for all three trust roles.
4. Confirm old signatures from pre-drill public keys are still verifiable using `TrustAnchor.verify()`.
5. Destroy the disposable cluster.
6. Document the drill: SHA of source used, cluster address, operator identity, timestamp, pass/fail result.
7. Commit the drill record to `artifacts/trust/recovery_drill_<date>.json`.

Once a drill record exists, update the `RECOVERY` dimension in `artifacts/trust/customer_zero_trust_evidence.json` to `PASS` and set `recovery_evidence_ref` to the drill record path.
