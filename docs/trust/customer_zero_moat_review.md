# CUSTOMER-ZERO-TRUST-001 — Moat Review

## The question

Does FrostGate possess a defensible governance trust system — or is it "Vault signing things"?

## Twelve moat properties

Each row names a property, its current state, and whether a competitor replicating "Vault + Ed25519" would acquire it for free.

| # | Property | Current state | Replicable by generic Vault setup? |
|---|---|---|---|
| 1 | **Semantic role binding** — three distinct trust roles whose *meaning* (identity / acceptance / approval) is wired into the governance domain model, not just a key-name convention | COMPLETE — `TrustRole` enum, three hard-coded `_ROLE_*` constants in `trust_binding.py`, matching Vault keys/policies/AppRoles | ❌ No. A generic Vault deployment has keys, not roles with governance meaning. |
| 2 | **Domain separation** — `frostgate.<artefact>.v1` prefix prepended to every signing byte sequence so a signature cannot be replayed across artefact types even with the same key | COMPLETE — `_prepare_signing_bytes()` + `DOMAIN_*` constants; tested by `test_a9_envelope_role_claim_cannot_outvote_domain_check` | ❌ No. Would require a parallel semantic framework. |
| 3 | **Independent authority** — the three Transit keys are *structurally* separate (three keys, three policies, three AppRoles) rather than three logical names for the same key | COMPLETE — enforced by `infra/vault_transit.tf`, `vault_policies.tf`, `vault_approle.tf`; pinned by `test_t5`, `test_t7`, `test_t8` | ❌ No. Default Vault practice shares keys and relies on policy; FrostGate requires three structurally independent authorities. |
| 4 | **Canonical signing bytes** — deterministic payloads (sort_keys, no volatile fields, no timestamps in signed bytes), so the operator can recompute the signing input bit-identically | COMPLETE — tested by `test_d1`–`test_d4`; invariant `signed_payload_sha256 == sha256(domain + "\n" + canonical_json(payload))` | ❌ No. Most governance-signing systems treat timestamps as part of the signed payload — making replay verification impossible. |
| 5 | **Provenance binding** — issuer, trust role, key_id, key_version, algorithm, public_key_fingerprint, and signed_payload_sha256 are all captured in the envelope and persisted alongside the artefact | COMPLETE — `SignatureEnvelope` dataclass; schema version pinned at 1; whitelisted field set | ❌ No. Generic signers emit a signature only, not a provenance envelope. |
| 6 | **Public verification** — anchors are enrollable in a static registry; `TrustAnchor.verify()` runs with no Vault connection, letting operators and customers verify independently | COMPLETE — `TrustAnchorRegistry` + `TrustAnchor.verify()`; tested by `test_g1_verify_without_vault_connection` | ❌ No. "You must call back to our Vault to verify" is a lock-in anti-pattern. FrostGate's design is operator-verifiable. |
| 7 | **Historical verification** — rotated-away key versions remain enrolled, so a signature from v1 remains verifiable even after rotation to v2 | COMPLETE (schema + local model); LIVE_PROOF_REQUIRED | ❌ No. Rotation without historical anchor retention is the default in most systems; FrostGate's evidence manifest enforces retention. |
| 8 | **Key rotation semantics** — rotation produces a *new* key version (not a replaced key); old envelopes carry the version they used; the registry resolves by `(issuer, role, key_id, version)` | COMPLETE (schema); LIVE_PROOF_REQUIRED via CHECKPOINT P | ❌ No. Generic "key rotation" usually drops the old key and silently breaks historical verification. |
| 9 | **Fail-closed behavior** — Vault unavailable, malformed response, wrong algorithm, tampered bytes, missing anchor, inactive status → all deny, no silent degradation | COMPLETE — tested by `test_f1`–`test_f5`, `test_g2`–`test_g4`, `test_e2` | ❌ No. "Try to sign; if that fails, log a warning and continue" is a very common and very wrong failure mode. |
| 10 | **Operational negative proof** — the 3×3 role-substitution deny matrix, forbidden-signer rejection, and secret-boundary scanning run on every CI build | COMPLETE — new suite `tests/test_customer_zero_trust_ceremony_readiness.py` (41 adversarial tests + 32 TF-safety tests) | ❌ No. Few systems commit to negative test coverage of signing authority. |
| 11 | **Evidence lineage** — ceremony evidence manifest is canonical, deterministic (same inputs → same fingerprint), scanned for secret-field names, and schema-validated by `validate_manifest()` | COMPLETE — `services/cgin/key_management/trust_evidence.py`; 25-test coverage in `tests/test_customer_zero_trust_evidence.py` | ❌ No. Governance "evidence" in competitors is usually a free-form markdown report. |
| 12 | **Deterministic replay / authority substitution resistance** — attempting to replace the authority with a raw ephemeral signer (or a different authority instance) fails verification; same input produces same canonical digest | COMPLETE — tested by `test_b5_raw_ephemeral_signer_cannot_satisfy_production_verify`, `test_d4` | ❌ No. Most systems trust "a valid Ed25519 signature over the payload" without binding to a specific public anchor. |

## Why "Vault + Ed25519" is not the moat

The moat is the composition:

```
semantic role binding
  × domain separation
  × independent authority
  × canonical signing bytes
  × provenance binding
  × public verification
  × historical verification
  × key rotation semantics
  × fail-closed behavior
  × operational negative proof
  × evidence lineage
  × deterministic replay
```

Each property individually is a defensible engineering decision. The composition is the thing a competitor would have to re-derive — and would do wrong on the first attempt in several places.

A competitor's first attempt is usually:
1. One key, three "trust labels" in metadata. (We refuse — three structurally distinct keys.)
2. Timestamps in the signed payload. (We refuse — deterministic canonical bytes.)
3. Online-only verification. (We refuse — anchors are public and offline-verifiable.)
4. Rotation deletes old versions. (We refuse — historical anchors retained.)
5. "If Vault is down, sign with the local ephemeral key." (We refuse — fail-closed.)
6. "Trust any valid Ed25519 signature over the right payload." (We refuse — bound to the enrolled public anchor.)

Each of these refusals is a decision point where a reasonable engineer would make the wrong choice under schedule pressure. FrostGate's refusals are enforced by code, tests, and the CI gate — not by convention.

## What becomes materially harder to replicate after this PR

- **The 3×3 deny matrix is now a shipping artefact.** Any PR that silently loosens role separation fails `test_customer_zero_trust_ceremony_readiness.py` A1–A9.
- **Terraform safety is now enforced from the test tree.** `prevent_destroy`, non-exportable keys, scoped IAM, pinned provider versions — all are statically verified by `tests/test_customer_zero_trust_terraform_safety.py`.
- **The authority graph is public documentation.** `docs/trust/customer_zero_trust_authority_graph.md` makes it impossible to drift the role-to-domain binding without updating the graph (and failing the pinned-constant tests `test_i1`–`test_i3`).
- **The acceptance handoff contract is published.** CUSTOMER-ZERO-ACCEPT-001 cannot drift away from "verify against the enrolled anchor; never fabricate" without an explicit documented change.

## What the moat is not

- **It is not Vault.** HCP Vault Dedicated is the chosen production provider; the architecture also works against a self-hosted Vault, and (with a different adapter) against any provider that exposes a non-exportable managed signing API.
- **It is not Ed25519.** The algorithm is a pinned detail (`test_i3`), but the moat is the composition of properties around it.
- **It is not the ceremony runbook.** The runbook is the operator's checklist; the moat is the architecture it instantiates.

The moat is the governance meaning + cryptographic authority + deterministic evidence + independent verification + operational proof, composed and enforced by code.
