# CUSTOMER-ZERO-TRUST-001 → CUSTOMER-ZERO-ACCEPT-001 — Handoff Contract

**Direction:** CUSTOMER-ZERO-TRUST-001 produces trust outputs; CUSTOMER-ZERO-ACCEPT-001 consumes them.
**Status:** CEREMONY-READINESS. The contract is defined; the live production outputs are produced by the operational ceremony.

## 1. Purpose

CUSTOMER-ZERO-ACCEPT-001 is the open acceptance parent for Customer-Zero. Its `SIGNED_PROOF` dimension cannot reach `PASS` without canonical Customer-Zero trust signatures bound to the exact corpus, expected outcomes, and runtime evidence. This document fixes the exact set of trust outputs the acceptance runner must consume and the exact invariants it must preserve.

## 2. Outputs required from CUSTOMER-ZERO-TRUST-001

The live ceremony MUST produce the following artifacts, retained in `artifacts/trust/` and the governance DB:

### 2.1 Public trust anchors (one per role)

Stored in `artifacts/trust/customer_zero_trust_evidence.json`. Each `trust_roles[]` record carries:

| Field | Example | Non-secret? |
|---|---|---|
| `trust_role` | `customer-zero-approval` | ✅ |
| `issuer` | `vault-transit` | ✅ |
| `auth_role_id` | `frostgate-cz-approval` | ✅ (non-secret identifier) |
| `policy_id` | `frostgate-cz-approval` | ✅ |
| `policy_fingerprint` | SHA-256 of the Vault policy HCL | ✅ |
| `key_id` | `customer-zero-approval` | ✅ |
| `key_version` | `1` | ✅ |
| `algorithm` | `ed25519` | ✅ |
| `exportable` | `false` | ✅ |
| `deletion_allowed` | `false` | ✅ |
| `public_key` | base64 Ed25519 public key | ✅ (public only) |
| `public_key_fingerprint` | SHA-256 of raw public key | ✅ |
| `anchor_status` | `active` | ✅ |
| `public_anchor` | nested anchor record (role/key_id/key_version/fingerprint) | ✅ |

**Forbidden:** `secret_id`, `token`, `private_key`, `authorization`, `bearer`, `recovery_key`, `unseal` fields. `validate_manifest()` fails closed on any match.

### 2.2 Signed governance artefacts (one envelope per artefact)

Produced at live-ceremony invocation and persisted alongside the artefact:

| Governance artefact | Trust role | Signing path |
|---|---|---|
| Governance report | IDENTITY | `TrustBindingAuthority.sign_report()` |
| Qualification decision | APPROVAL | `TrustBindingAuthority.sign_qualification()` |
| Governed-delivery authorization | ACCEPTANCE | `TrustBindingAuthority.sign_delivery_authorization()` |

Each envelope carries the fields in §6 of `customer_zero_trust_authority_graph.md`.

### 2.3 Ceremony evidence manifest

`artifacts/trust/customer_zero_trust_evidence.json` passes `validate_manifest()` with `state=PASS` on all dimensions (or `NOT_PROVEN` on those explicitly deferred — e.g., `RECOVERY` until a drill is executed). The manifest fingerprint is deterministic and recorded in the ceremony commit message.

## 3. Invariants the acceptance runner MUST preserve

CUSTOMER-ZERO-ACCEPT-001 MUST NOT:

1. **Fabricate signatures.** The acceptance runner cannot mint envelopes using any key it owns — it is a verifier, not an authority.
2. **Weaken `SIGNED_PROOF` to pass with a non-Vault signer.** The current `tools/customer_zero_acceptance.py` approval record uses `FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX` for `record_signature` of the acceptance *bundle*; that is a separate concept from the governance-artefact signatures. The acceptance bundle signature is a bundle-level attestation produced by the acceptance operator; it does **not** satisfy the `SIGNED_PROOF` dimension on its own.
3. **Trust an envelope whose public anchor is not enrolled in `artifacts/trust/customer_zero_trust_evidence.json`.** Verification must consult the public anchor registry and refuse unknown `(issuer, trust_role, key_id, key_version)` tuples.
4. **Accept an envelope whose `signed_payload_sha256` does not match the recomputed canonical bytes.**
5. **Accept an envelope under a trust role not matching the artefact type** (see 3×3 matrix in authority graph §7).
6. **Expose any secret in acceptance evidence.** The acceptance bundle is append-only and committed; its `_contains_secret_field` scanner applies.

## 4. Transition path for `tools/customer_zero_acceptance.py`

The current acceptance runner reads `FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX` to sign the approval record. This is a **bundle-signature** path — not a canonical Customer-Zero trust path. Two future options:

### Option A (minimal) — keep bundle signature as-is, prove governance signatures separately

The acceptance runner continues to sign the bundle record with an operator-held key. The `SIGNED_PROOF` dimension is satisfied by verifying the governance report, qualification decision, and delivery authorization envelopes (produced by the live ceremony) against the enrolled public anchors.

Acceptance runner changes (future PR, not this one):
- Load `artifacts/trust/customer_zero_trust_evidence.json`.
- Build `TrustAnchorRegistry` from the enrolled anchors.
- For each governance artefact in the bundle, call `registry.verify(issuer, role, key_id, key_version, canonical_bytes, signature)`.
- Only set `SIGNED_PROOF=PASS` if all three artefact types verify.
- `SIGNED_PROOF=NOT_PROVEN` otherwise (never fabricate).

### Option B (future) — bind the bundle itself via the APPROVAL role

The acceptance runner replaces `FG_CUSTOMER_ZERO_APPROVAL_PRIVATE_KEY_HEX` with a call to the APPROVAL trust role via Vault. This requires:
- A new Vault policy path or a dedicated signing role for the approval bundle.
- A clear boundary: the APPROVAL trust role currently signs *qualification decisions* (`frostgate.production-qualification.v1`); using it for the bundle would require a distinct domain (`frostgate.acceptance-approval.v1` or similar).

**Recommendation:** Option A for the immediate acceptance proof; Option B deferred until a second paying client requires a stronger bundle attestation (freeze law).

## 5. Verification surface for CUSTOMER-ZERO-ACCEPT-001

The acceptance runner's `SIGNED_PROOF` dimension must prove **all** of the following:

1. The ceremony evidence manifest validates (`state=PASS` or acceptable `NOT_PROVEN`).
2. The three governance envelopes (report, qualification, delivery authorization) exist and verify under the enrolled anchors.
3. The `signed_payload_sha256` recorded in each envelope matches the recomputed canonical bytes of the exact artefact it accompanies.
4. Each envelope's `trust_role` matches the fixed role for its artefact type.
5. Each envelope's `domain` matches the fixed domain for its artefact type.
6. The enrolled anchor's `public_key_fingerprint` matches the envelope's `public_key_fingerprint`.
7. No secret material appears in any file consumed by the acceptance runner.

A single failure in 1–6 forces `SIGNED_PROOF=FAIL`. A missing or incomplete artefact forces `SIGNED_PROOF=NOT_PROVEN`. There is no path to `PASS` without live-ceremony outputs.

## 6. Non-handoff items (out of scope for CUSTOMER-ZERO-TRUST-001)

- Customer-Zero corpus content (`customer_one/customer_zero_corpus.json`) — defined independently.
- Expected outcomes (`customer_one/customer_zero_expected_outcomes.json`) — defined independently.
- Runtime acceptance evidence (findings, determinations, replay) — produced by the acceptance runner, not the trust ceremony.
- Portal-recipient governed-delivery execution — tracked by GOV-DELIVERY-TRANSPORT-001 remainder.

## 7. Non-regression contract

The following constants are the external contract shipped to the acceptance runner. Any change requires a documented migration:

```
TrustRole.IDENTITY   = "customer-zero-identity"
TrustRole.ACCEPTANCE = "customer-zero-acceptance"
TrustRole.APPROVAL   = "customer-zero-approval"

DOMAIN_REPORT                 = "frostgate.report-proof.v1"
DOMAIN_QUALIFICATION          = "frostgate.production-qualification.v1"
DOMAIN_DELIVERY_AUTHORIZATION = "frostgate.governed-delivery-authorization.v1"

SignatureEnvelope.schema_version = "1"
Algorithm                        = "ed25519"
Issuer                           = "vault-transit" (configurable via FG_CUSTOMER_ZERO_VAULT_ISSUER)
```

Pinned by `tests/test_customer_zero_trust_ceremony_readiness.py::test_i1..i3`.
