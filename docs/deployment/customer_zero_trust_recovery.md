# Customer-Zero Trust Recovery

**Work item:** CUSTOMER-ZERO-TRUST-001
**Recovery state established by this document:** RESTORE_DOCUMENTED

## Recovery state model

Three states must be reached in sequence before recovery is considered proven:

| State | Meaning | Evidence required |
|-------|---------|-------------------|
| `BACKUP_AVAILABLE` | Non-secret public verification material is durably stored outside the Vault cluster | `artifacts/trust/` contains the signed ceremony evidence JSON with public keys and fingerprints |
| `RESTORE_DOCUMENTED` | A restoration procedure exists in writing | **This document** |
| `RESTORE_TESTED` | A full recovery drill has been executed against a non-production Vault cluster | Drill execution record with SHA, timestamp, and operator sign-off |

**Current state: RESTORE_DOCUMENTED only.** `RESTORE_TESTED` requires an actual drill execution and cannot be declared by documentation alone.

---

## What is recoverable and what is not

### Verifiability of previously issued signatures

Ed25519 signatures issued under a Customer-Zero trust role remain independently verifiable
as long as the public verification material survives:

- the canonical signed payload bytes (deterministically reconstructable from governance record fields)
- the signature string
- a trusted public key that can be bound to the signer's identity
- the key provenance metadata (issuer, key ID, key version)

**Cluster destruction or key deletion destroys future signing capability only.** Signatures
already issued and stored in the database remain cryptographically verifiable. The
`TrustAnchor.verify()` method in `services/cgin/key_management/vault_transit.py` performs
this verification without a live Vault connection.

`artifacts/trust/customer_zero_trust_evidence.json` is FrostGate's canonical retained
evidence source for Customer-Zero public keys. It is not the only mathematically possible
verification path — any party holding the correct public key from a trusted source can
verify signatures independently. However, it is the designated durable artifact that must
survive a cluster loss event.

### What cannot be recovered after key deletion

- The ability to issue new signatures under a deleted key version
- AppRole SecretIDs (these are credentials and must be re-issued via Vault CLI)
- The Vault audit log for deleted transit keys (log entries survive in CloudWatch; key material does not)

---

## Recovery scenarios

### Scenario 1 — Vault cluster temporarily unavailable

**Impact:** New governance artifact signatures cannot be issued. Existing signatures remain
verifiable from database-stored public key material and the trust evidence manifest.

**Resolution:**
1. Verify the HCP Vault cluster status in the HCP portal.
2. Check CloudWatch for Vault audit log entries indicating errors.
3. If the cluster is degraded, follow the HCP incident response procedure (SLA-defined for
   `standard_small` tier).
4. Once the cluster recovers, AppRole session renewal is automatic on the next signing request.

**Command security:** SAFE_NON_SECRET — no credentials produced or required.

---

### Scenario 2 — AppRole SecretID rotation

**Impact:** Signing requests fail with authentication errors. Verification is unaffected.

**Why AppRole SecretIDs are not Terraform-managed:** `frostgate-infra` deliberately does not
contain a `vault_approle_auth_backend_role_secret_id` Terraform resource. Storing
credential-producing resources in Terraform state is a known anti-pattern that would expose
SecretID material in the state file. SecretIDs are issued exclusively via the Vault CLI and
transferred directly to Railway secrets by the operator.

**Resolution:**

> **HUMAN SECRET BOUNDARY** — steps marked SECRET require an authorized human operator
> acting directly in the Vault CLI and Railway dashboard. Claude must stop at these steps.
> No secret value should be provided to Claude, committed to code, echoed to shell history,
> or stored outside the authorized credential store.

1. Authenticate to the HCP Vault cluster with an operator token that has permission to
   generate AppRole SecretIDs.

2. **[SECRET — OPERATOR ACTION]** Generate a new SecretID for each trust role directly via
   the Vault CLI. Avoid `--field` or `-format=json` flags that would write the SecretID to
   terminal history:
   ```
   vault write -force auth/approle/role/frostgate-cz-identity/secret-id
   vault write -force auth/approle/role/frostgate-cz-acceptance/secret-id
   vault write -force auth/approle/role/frostgate-cz-approval/secret-id
   ```
   Each command returns a `secret_id` value. Do not log, copy, or record this value
   anywhere other than the authorized destination in step 3.

3. **[SECRET — OPERATOR ACTION]** Load each SecretID into Railway's Variables tab for the
   `api` service as:
   - `FG_CUSTOMER_ZERO_IDENTITY_VAULT_SECRET_ID`
   - `FG_CUSTOMER_ZERO_ACCEPTANCE_VAULT_SECRET_ID`
   - `FG_CUSTOMER_ZERO_APPROVAL_VAULT_SECRET_ID`

   Enter values directly in the Railway dashboard. Do not pass them as shell arguments.

4. Redeploy the `api` service to pick up the new SecretIDs.

5. **[NON-SECRET verification]** Confirm signing resumes by checking that the next
   governed-delivery-authorization or report creation succeeds. Confirm authentication
   via Vault audit logs in CloudWatch (shows role authentication events without credential material).

**Safe completion evidence to record:** timestamp of rotation, Railway deployment SHA,
CloudWatch audit confirmation. Never the SecretID itself.

---

### Scenario 3 — Transit key rotation

**Impact:** Key version increments. Old signatures remain verifiable under the previous key
version. New signatures use the new key version. Trust anchors in `artifacts/trust/` must
be updated.

**Resolution:**

1. **[NON-SECRET]** Rotate the key via Vault CLI (key rotation does not produce secret material):
   ```
   vault write -force transit/keys/customer-zero-identity/rotate
   vault write -force transit/keys/customer-zero-acceptance/rotate
   vault write -force transit/keys/customer-zero-approval/rotate
   ```

2. **[NON-SECRET]** Retrieve the new public key for each role:
   ```
   vault read transit/keys/customer-zero-identity
   vault read transit/keys/customer-zero-acceptance
   vault read transit/keys/customer-zero-approval
   ```
   The `keys` field in the response maps version numbers to public key material (non-secret).

3. Update `artifacts/trust/customer_zero_trust_evidence.json` to reflect the new key version,
   public key, and public key fingerprint for each affected trust role. Follow the schema in
   `schemas/artifacts/customer_zero_trust_evidence.schema.json`.

4. Validate the updated manifest:
   ```
   python tools/customer_zero_trust_evidence.py validate artifacts/trust/customer_zero_trust_evidence.json
   python tools/customer_zero_trust_evidence.py verify-anchors artifacts/trust/customer_zero_trust_evidence.json
   ```

5. Commit the updated manifest to `artifacts/trust/customer_zero_trust_evidence.json`. Confirm
   `codex_gates.sh` passes (the manifest is covered by the repository secret scan).

6. Update the `PUBLIC_ANCHORS` dimension to `PASS` in the manifest after verification passes.

**Old signatures remain valid.** `TrustAnchor.verify()` matches the `key_version` in the
signature string (`vault:v<N>:...`) against the registered public key for that version. Previous
key versions can be preserved in the evidence manifest's `trust_roles` array.

---

### Scenario 4 — Cluster destruction (catastrophic)

**Impact:** Future signing capability is permanently lost unless a new cluster is provisioned
and new keys generated. Previously issued signatures **remain verifiable** if durable public
verification material was retained before the cluster was destroyed.

**Prerequisite check:** Vault Dedicated clusters have `prevent_destroy = true` in
`frostgate-infra/hcp_cluster.tf`. Destruction requires an explicit Terraform lifecycle
override. Confirm the action is intentional before proceeding.

**Resolution:**
1. Before initiating destruction: export all public keys and key metadata from Vault Transit
   for all three trust roles. Ensure `artifacts/trust/customer_zero_trust_evidence.json` is
   committed and has `BACKUP_AVAILABLE` evidence.

2. Audit the impact: query governance records with `trust_signature IS NOT NULL` to identify
   all signed artifacts. These signatures remain cryptographically valid provided the public
   anchor data is retained.

3. If new signing capability is required, provision a new Vault cluster following
   CUSTOMER-ZERO-TRUST-001 ceremony procedures from scratch. **This is a cost-bearing step**
   (HCP Vault Dedicated) that requires explicit authorization.

4. New keys will have new key IDs and versions. Old signatures signed under the previous keys
   remain independently verifiable using the retained public material, regardless of whether
   the new cluster uses the same key names.

---

## Canonical retained evidence location

Non-secret public verification material is stored at:

```
artifacts/trust/customer_zero_trust_evidence.json
```

This file is FrostGate's canonical retained evidence source for:
- Public keys for all three Customer-Zero trust roles
- Key versions and public key fingerprints
- Ceremony ID, environment binding, and operator identity
- Evidence dimension states and audit references

The evidence CLI at `tools/customer_zero_trust_evidence.py` validates this file. Valid
subcommands: `validate`, `inspect`, `fingerprint`, `status`, `verify-anchors`,
`verify-role-separation`, `verify-provenance`, `verify-complete`.

The validator at `services/cgin/key_management/trust_evidence.py` also scans the manifest
for secret-bearing field names and rejects any manifest that contains them.

---

## Pre-requisites for achieving RESTORE_TESTED

A recovery drill must execute the following steps and produce a signed execution record:

1. Provision a disposable non-production Vault cluster (local `vault server -dev` is
   sufficient for a drill). This does not require HCP and is $0.
2. Configure the trust role setup (Transit keys, policies, AppRoles) in the disposable cluster.
3. Confirm signing works for all three trust roles using `VaultTransitClient` (not `from_environment()`).
4. Confirm that signatures issued in step 3 are verifiable offline using `TrustAnchor.verify()`
   with the retained public key — without any network connection to the disposable cluster.
5. Destroy the disposable cluster.
6. Confirm that the signatures verified in step 4 remain verifiable after cluster destruction.
7. Document the drill: SHA of source used, cluster address, operator identity, timestamp, pass/fail.
8. Commit the drill record to `artifacts/trust/recovery_drill_<date>.json`.

Once a drill record exists:
- Update the `RECOVERY` dimension in `artifacts/trust/customer_zero_trust_evidence.json` to `PASS`
- Set `recovery_evidence_ref` to the drill record path
- Recovery state advances to `RESTORE_TESTED`
