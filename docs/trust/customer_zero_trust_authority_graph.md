# CUSTOMER-ZERO-TRUST-001 — Trust Authority Graph

**Status:** CEREMONY-READINESS (PRODUCTION_CEREMONY_NOT_READY until live HCP Vault proof).
**Scope:** audit the actual call paths producing or verifying production trust signatures for the three Customer-Zero trust roles.
**Boundary:** no live infrastructure touched; this document and its sibling tests prove static properties only.

## 1. The three trust roles

| Trust role | Vault Transit key | Trust domain | Governance artefact |
|---|---|---|---|
| IDENTITY | `customer-zero-identity` | `frostgate.report-proof.v1` | governance report |
| APPROVAL | `customer-zero-approval` | `frostgate.production-qualification.v1` | qualification decision |
| ACCEPTANCE | `customer-zero-acceptance` | `frostgate.governed-delivery-authorization.v1` | delivery authorization |

The role→domain→artefact binding is **hard-coded** in `services/governance/trust_binding.py` and is not caller-overridable.

## 2. Call paths — who invokes which role

### 2.1 IDENTITY (report signing)

```
api/field_assessment.py:9612
  └─ _report_trust_authority.sign_report(_report_payload)
       └─ services.governance.trust_binding.TrustBindingAuthority.sign_report()
            │ domain prefix = DOMAIN_REPORT ("frostgate.report-proof.v1")
            │ canonical bytes = f"{domain}\n{sort_keys_json(payload)}".encode()
            └─ backend.sign(TrustRole.IDENTITY, canonical_bytes)
                 └─ VaultBackend ──► VaultCustomerZeroSigner.sign(IDENTITY)
                                          └─ VaultTransitClient.sign(key_id="customer-zero-identity")
                                                via AppRoleAuthenticator (role=frostgate-cz-identity)
```

Report consumer verification paths:

```
api/field_assessment.py qa_approve_report_route
api/field_assessment.py export_engagement_report_route
api/field_assessment.py verify_engagement_report_route
  └─ TrustBindingAuthority.verify_report(payload, reconstructed_envelope)
       └─ pre-crypto guards (role, domain, algorithm, schema, key_id, key_version,
                              public_key_fingerprint, issuer, signed_payload_sha256)
       └─ backend.verify(IDENTITY, canonical_bytes, signature)
            └─ TrustAnchor.verify() (independent fingerprint re-derivation)
```

### 2.2 APPROVAL (qualification decision signing)

```
api/field_assessment.py:8349  (qualify_report_finalize_route)
  └─ _trust_authority.sign_qualification(_qual_payload)
       └─ TrustBindingAuthority.sign_qualification()
            │ domain prefix = DOMAIN_QUALIFICATION
            │                 ("frostgate.production-qualification.v1")
            └─ backend.sign(TrustRole.APPROVAL, canonical_bytes)
                 └─ VaultCustomerZeroSigner.sign(APPROVAL)
                      └─ VaultTransitClient.sign("customer-zero-approval")
                           via AppRole frostgate-cz-approval
```

Verification: governed_delivery_route re-verifies qualification trust before issuing authorization.

### 2.3 ACCEPTANCE (governed-delivery authorization signing)

```
api/field_assessment.py:14276 (governed_delivery_route)
api/field_assessment.py:14576 (second governed-delivery call site)
  └─ _trust_authority_del.sign_delivery_authorization(_del_payload)
       └─ TrustBindingAuthority.sign_delivery_authorization()
            │ domain prefix = DOMAIN_DELIVERY_AUTHORIZATION
            │                 ("frostgate.governed-delivery-authorization.v1")
            └─ backend.sign(TrustRole.ACCEPTANCE, canonical_bytes)
                 └─ VaultCustomerZeroSigner.sign(ACCEPTANCE)
                      └─ VaultTransitClient.sign("customer-zero-acceptance")
                           via AppRole frostgate-cz-acceptance
```

Verification: governed_delivery_execute_route re-verifies delivery authorization trust before transport.

## 3. Authority construction (environment selection)

```
api/field_assessment.py:1301  _get_trust_binding_authority()
  if FG_ENV in {"test", "development", "local"}:
      return make_test_authority()               # TrustBindingFake (ephemeral Ed25519)
  return TrustBindingAuthority.from_environment()
       └─ _reject_env_key_in_canonical_path()
       └─ signer_from_environment()
            └─ VaultCustomerZeroConfig.from_environment()
                 requires: FG_CUSTOMER_ZERO_VAULT_ADDR
                           FG_CUSTOMER_ZERO_IDENTITY_KEY_ID
                           FG_CUSTOMER_ZERO_ACCEPTANCE_KEY_ID
                           FG_CUSTOMER_ZERO_APPROVAL_KEY_ID
                           FG_CUSTOMER_ZERO_VAULT_AUTH_MODE=approle (operational)
            └─ VaultTransitClient.from_approle_environment()
                 requires: FG_CUSTOMER_ZERO_{IDENTITY,ACCEPTANCE,APPROVAL}_VAULT_ROLE_ID
                           FG_CUSTOMER_ZERO_{IDENTITY,ACCEPTANCE,APPROVAL}_VAULT_SECRET_ID
```

**Fail-closed invariant:** `signer_from_environment()` raises `ValueError` if the Vault address or any of the three key IDs is missing. There is no silent fallback to the legacy `FG_REPORT_SIGNING_KEY` path.

## 4. Legacy env-key path (`FG_REPORT_SIGNING_KEY`)

`services/governance/report/signing.py` retains the legacy Ed25519 env-key signer used by `_persist_report_signature` in `api/reports_engine.py`. Audit result:

| Property | Finding |
|---|---|
| Can the legacy signer satisfy `TrustBindingAuthority.verify_report()`? | **No.** It emits a 64-byte hex signature, not a `vault:vN:` envelope. Pre-crypto guards reject it. |
| Can the legacy path be invoked in prod/staging without a key? | **No.** `_persist_report_signature` raises `RuntimeError` when `is_production_env()` is True and the key is absent. |
| Can the legacy path replace the Vault authority? | **No.** The canonical paths (`qualify_report_finalize_route`, `governed_delivery_route`, `governed_delivery_execute_route`) consume the Vault-issued envelope exclusively. |
| Is the legacy path exposed in the ceremony contract? | **No.** It is a report-level HTTP header convenience retained for parity with pre-TRUST-BINDING-001 reports. |

**Defect assessment:** acceptable. The legacy path is bounded (prod/staging raise without a key) and cannot produce a canonical Customer-Zero envelope. See `tests/test_customer_zero_trust_ceremony_readiness.py::test_b6_env_key_report_signing_cannot_mint_customer_zero_envelope`.

## 5. Test authority (`TrustBindingFake`)

`services/governance/trust_binding_fake.py`:

- Ephemeral per-process Ed25519 keys, one per role (keys are **not** shared across roles).
- Refuses to construct if `FG_ENV` or `FG_CUSTOMER_ZERO_ENVIRONMENT` ∈ {production, staging, prod}.
- Produces `vault:vN:` style signatures so the pre-crypto guards operate identically to the production path.
- No key material is exposed via `__dict__`, `repr`, or any public API.

**Defect assessment:** acceptable. The fake preserves every structural invariant of the live path except role-level Vault policy enforcement (which is a live-only concern — captured by ceremony §N).

## 6. Signature envelope (canonical public verification material)

```
SignatureEnvelope {
  issuer                   : "vault-transit"             # non-secret
  trust_role               : "customer-zero-{identity|acceptance|approval}"
  key_id                   : <Vault Transit key name>
  key_version              : int ≥ 1
  algorithm                : "ed25519"
  public_key_fingerprint   : SHA-256 (raw Ed25519 pub bytes)   # 64 hex chars
  signature                : "vault:v<N>:<base64 raw signature>"
  domain                   : <frostgate.*.v1 domain prefix>
  signed_payload_sha256    : SHA-256 of (domain + "\n" + canonical_json(payload))
  schema_version           : "1"
}
```

Every field is public. No private material; no Vault tokens; no AppRole SecretIDs.

Pre-crypto rejection (any one causes verify() → False):
- unknown or mismatched `trust_role`
- domain not matching the artefact's canonical domain
- `algorithm` not in `{"ed25519"}`
- `schema_version` ≠ `"1"`
- empty `key_id`
- `key_version` < 1
- empty `public_key_fingerprint` or `issuer`
- `signed_payload_sha256` not matching recomputed canonical bytes

## 7. Role substitution resistance (3×3 deny matrix — locally proven)

| sign\verify | report (IDENTITY) | qualification (APPROVAL) | delivery (ACCEPTANCE) |
|---|---|---|---|
| IDENTITY | ✅ allow | ❌ deny (a1) | ❌ deny (a2) |
| APPROVAL | ❌ deny (a3) | ✅ allow | ❌ deny (a4) |
| ACCEPTANCE | ❌ deny (a5) | ❌ deny (a6) | ✅ allow |

Test IDs refer to `tests/test_customer_zero_trust_ceremony_readiness.py`. The six off-diagonal denies are triggered by two independent guards (role claim mismatch + domain prefix mismatch), both of which are hashed into the signed bytes.

## 8. Public anchor verification (no Vault required)

`TrustAnchor.verify()` runs offline against an enrolled anchor record. The ceremony manifest `artifacts/trust/customer_zero_trust_evidence.json` is the public anchor registry; it carries only non-secret material (`public_key`, `public_key_fingerprint`, `issuer`, `trust_role`, `key_id`, `key_version`, `algorithm`, `status`). Operators and external verifiers can validate signatures without any HCP Vault connection.

See `test_g1_verify_without_vault_connection` and the schema in `services/cgin/key_management/trust_evidence.py` enforced by `validate_manifest()`.

## 9. Defects found and repaired in this readiness pass

- **Open gap — provenance field binding not enforced in `verify_*`:** `TrustBindingAuthority.verify_report()`, `verify_qualification()`, and `verify_delivery_authorization()` check that `key_id`, `issuer`, `public_key_fingerprint`, and `key_version` are non-empty, but do NOT compare these fields against the enrolled anchor. A stored envelope with forged provenance metadata (different `key_id`, `issuer`, or `public_key_fingerprint`) but a cryptographically valid signature will pass `verify_*`. `TrustAnchor.verify()` (offline path) does perform independent fingerprint re-derivation — the gap is in the online `TrustBindingAuthority` path only. Tests J1–J3 in `tests/test_customer_zero_trust_ceremony_readiness.py` document the current behavior; they will fail (and must be updated) when anchor comparison is implemented.
- The legacy `FG_REPORT_SIGNING_KEY` path remains fenced (prod/staging raise without a key; it cannot mint a Customer-Zero envelope).
- Structural test gaps closed in this PR by `tests/test_customer_zero_trust_ceremony_readiness.py` (A–J) and `tests/test_customer_zero_trust_terraform_safety.py` (T1–T16).

## 10. Classification per audit dimension

| Dimension | State |
|---|---|
| Ambiguous authority | COMPLETE — role bindings are hard-coded, not caller-overridable |
| Shared authority | COMPLETE — three distinct keys, three distinct Vault policies, three distinct AppRoles |
| Bypass paths | COMPLETE — legacy env-key path cannot satisfy canonical verify |
| Fallback signers | COMPLETE — no silent fallback; prod/staging raise fail-closed |
| Insecure defaults | COMPLETE — `TrustBindingAuthority.from_environment()` requires explicit Vault config |
| Test-mode leakage | COMPLETE — `TrustBindingFake` refuses production environments |
| Unsigned success paths | COMPLETE — empty signatures fail pre-crypto guards |
| Role substitution | LOCAL_PASS_LIVE_PROOF_REQUIRED — 9 adversarial tests prove local denial; LIVE_PROOF_REQUIRED for Vault policy enforcement |
| Unverifiable signatures | COMPLETE — every envelope is independently verifiable via `TrustAnchor.verify()` |
| Missing provenance | PARTIAL — envelope records all provenance fields; `TrustAnchor.verify()` (offline) re-derives fingerprint; `TrustBindingAuthority.verify_*` (online) checks fields non-empty but does NOT compare against enrolled anchor (open gap — see §9) |
